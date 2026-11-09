#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
AbuseIPDB API v2 client: check, check-block, and report.

One client for every AbuseIPDB call site, so quota is spent once per IP and the
retry/circuit-breaker behaviour is identical in the aggregate, the unified score,
the curated report, and the reporting tool.

Facts encoded here come from the official API docs (docs.abuseipdb.com, checked
2026-11-09):
- ``/check`` accepts one IPv4/IPv6 address; ``maxAgeInDays`` is 1..365 (default 30).
  The docs say to url-encode the address because IPv6 contains colons.
- ``/check-block`` takes a CIDR in ``network``. The published plan table caps IPv4
  at /24 Standard, /20 Basic, /16 Premium and does not mention IPv6 at all, so the
  IPv6 /112 bound here is a local safety limit, not a vendor rule: an upstream 402
  surfaces as ``plan_limit``. It returns only addresses that already have reports.
- ``/report`` is a form-encoded POST; ``ip`` is documented as "a valid IPv4 or IPv6
  address"; ``categories`` is required; the same IP can be reported once per 15
  minutes; comments must not contain PII.
"""
from __future__ import annotations

import asyncio
import base64
import hmac
import ipaddress
import logging
import re
import threading
import time
import unicodedata
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Iterable
from urllib.parse import unquote, urlsplit

import httpx

from mcp_server import (ABUSEIPDB_API_KEY, ABUSEIPDB_BASE_URL,
                        ABUSEIPDB_BOOTSTRAP_BUDGET,
                        ABUSEIPDB_BOOTSTRAP_CONCURRENCY, ABUSEIPDB_CACHE_TTL,
                        ABUSEIPDB_CHECK_BLOCK_MAX_PREFIX, ABUSEIPDB_PLAN,
                        ABUSEIPDB_QUOTA_RESERVE, ABUSEIPDB_REPORT_MIN_INTERVAL)
from mcp_server.core.http_client import (CircuitOpenError, _api_call as _api_call_raw,
                                         _classify_api_error)
from mcp_server.threat_intel._cache import (cache_delete_prefix, cache_get,
                                            cache_set, get_limiter)

logger = logging.getLogger("blue_team_mcp.abuseipdb")


CHECK_LIMITER = get_limiter("abuseipdb_check", max_concurrent=2, min_interval=0.2)
REPORT_LIMITER = get_limiter("abuseipdb_report", max_concurrent=1,
                             min_interval=ABUSEIPDB_REPORT_MIN_INTERVAL)

REPORT_DUPLICATE_WINDOW_SECONDS = 15 * 60
MAX_COMMENT_LENGTH = 500
SIGNATURE = "Reported by TangerangKota-CSIRT."

# Configured subscription reference. Runtime response headers always win; these
# values are only a display fallback and never override an observed limit.
PREMIUM_DAILY_LIMITS: dict[str, int] = {
    "check": 50_000,
    "reports": 25_000,
    "blacklist": 500,
    "report": 50_000,
    "check-block": 5_000,
    "bulk-report": 500,
    "clear-address": 500,
}
# Only the Standard limits AbuseIPDB publishes are listed; unknown endpoints
# stay absent rather than inventing a number.
STANDARD_DAILY_LIMITS: dict[str, int] = {
    "check": 1_000,
    "report": 1_000,
    "check-block": 100,
}
CONFIGURED_DAILY_LIMITS = (PREMIUM_DAILY_LIMITS if ABUSEIPDB_PLAN == "premium"
                           else STANDARD_DAILY_LIMITS)
ENDPOINT_NAMES = frozenset({"check", "check-block", "report", "reports",
                            "blacklist", "bulk-report", "clear-address"})
ENDPOINT_METHODS = {
    "check": "get", "check-block": "get", "report": "post",
    "reports": "get", "blacklist": "get", "bulk-report": "post",
    "clear-address": "delete",
}
# Only these three have a client and a tool. Everything else fails closed even
# though its quota bucket is in the Premium reference table.
SUPPORTED_ENDPOINTS = frozenset({"check", "check-block", "report"})
# A /16 has 65,536 addresses; cap the parsed list so one sweep cannot exhaust
# the tool response. The API still counts it as one check-block request.
CHECK_BLOCK_MAX_RESULTS = 10_000
# The published plan table caps the IPv4 prefix (/24 Standard, /16 Premium) and
# says nothing about IPv6 prefixes. This is a local safety bound, not a vendor
# rule: /112 is the IPv6 analogue of the /16 host count.
CHECK_BLOCK_MAX_PREFIX_V6 = 112

# Mandatory egress invariant: these ranges never reach /report. The check is
# explicit so it survives a stdlib change or a swap of the broader is_global
# predicate. Keep in sync with tests/test_abuseipdb_private_ip_egress.py.
RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)

# Official category table, https://www.abuseipdb.com/categories
CATEGORY_NAMES: dict[int, str] = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
    4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
    7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy", 10: "Web Spam",
    11: "Email Spam", 12: "Blog Spam", 13: "VPN IP", 14: "Port Scan",
    15: "Hacking", 16: "SQL Injection", 17: "Spoofing", 18: "Brute-Force",
    19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
    22: "SSH", 23: "IoT Targeted",
}
VALID_CATEGORY_IDS = frozenset(CATEGORY_NAMES)

_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Raw log lines and named identities are the parts of a log that must not reach a
# public report. Generic words ("user enumeration", "login attempts") stay allowed.
_RAW_LOG_RE = re.compile(
    r"\b(?:failed password|invalid user|accepted password|sshd\[|pam_unix)\b",
    re.IGNORECASE)
_IDENTITY_RE = re.compile(r"\b(?:user(?:name)?|account|agent)\s+([\w.@-]+)",
                          re.IGNORECASE)
_IDENTITY_GENERIC = frozenset({
    "enumeration", "login", "authentication", "activity", "attempts", "access",
    "account", "agent", "service", "session",
})


class AbuseIPDBError(Exception):
    """A failed AbuseIPDB call with a machine-readable kind."""

    def __init__(self, message: str, kind: str = "upstream_error",
                 status: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.kind = kind
        self.status = status


# Local report ledger. AbuseIPDB enforces one report per IP per 15 minutes; this
# stops us spending a request to learn that. In-memory only: a restart loses it,
# and the upstream 429 remains the hard backstop.
_LAST_REPORT: dict[str, float] = {}
_LAST_REPORT_LOCK = threading.Lock()

# Process-local view of the endpoint quotas. AbuseIPDB is the authority; this
# only remembers the last X-RateLimit headers seen by this process. A second
# instance sharing the same key has its own view, so a guard here can never
# claim account-wide accuracy.
_QUOTA_STATE: dict[str, dict[str, Any]] = {}
_QUOTA_LOCK = threading.Lock()


def endpoint_for(method: str, url: str) -> str | None:
    """Map an AbuseIPDB URL to its quota bucket, or None for an unknown path."""
    raw = (url or "").strip()
    try:
        path = httpx.URL(raw).path
    except (httpx.InvalidURL, ValueError):
        path = urlsplit(raw).path
    segment = path.split(";", 1)[0].rstrip("/").lower().rsplit("/", 1)[-1]
    if segment not in ENDPOINT_NAMES:
        return None
    if (method or "").strip().lower() != ENDPOINT_METHODS[segment]:
        return None
    return segment


def normalize_host(value: str | None) -> str:
    """Normalize a hostname for allowlist comparison."""
    return unquote(str(value or "")).strip().rstrip(".").lower()


def configured_abuseipdb_hosts() -> set[str]:
    """Hosts allowed to carry the AbuseIPDB credential."""
    hosts = {"api.abuseipdb.com"}
    try:
        base_host = normalize_host(httpx.URL(ABUSEIPDB_BASE_URL).host)
    except (httpx.InvalidURL, ValueError):
        base_host = ""
    if base_host:
        hosts.add(base_host)
    return hosts


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _source_items(source):
    """Header/query items from a mapping, httpx object, or list of pairs."""
    if not source:
        return []
    try:
        return source.multi_items()
    except AttributeError:
        pass
    try:
        return source.items()
    except AttributeError:
        pass
    if isinstance(source, (list, tuple)):
        return source
    return []


def _contains_secret(value, secret: str) -> bool:
    if isinstance(value, str):
        if secret in value or secret in unquote(value):
            return True
        if value.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(value.split(" ", 1)[1]).decode(
                    "utf-8", "ignore")
            except (ValueError, TypeError):
                return False
            return secret in decoded
        return False
    if isinstance(value, bytes):
        if secret.encode() in value:
            return True
        return secret in unquote(value.decode("utf-8", "ignore"))
    if isinstance(value, dict):
        return any(_contains_secret(k, secret) or _contains_secret(v, secret)
                   for k, v in value.items())
    if isinstance(value, (list, tuple, set)):
        return any(_contains_secret(item, secret) for item in value)
    if isinstance(value, httpx.Auth):
        try:
            attrs = vars(value)
        except TypeError:
            return False
        return any(_contains_secret(item, secret) for item in attrs.values())
    return False


def request_carries_configured_key(kw: dict, url: str = "") -> bool:
    """True when an inspectable request component contains the configured key.

    Covers the URL, every header, params, cookies, form/JSON/raw content,
    str/bytes file contents, auth, and extensions. Opaque Auth objects and
    streaming bodies are outside this check; unrelated credentials pass.
    """
    secret = ABUSEIPDB_API_KEY
    if not secret:
        return False
    if _contains_secret(url if isinstance(url, str) else str(url), secret):
        return True
    for name in ("headers", "params", "cookies"):
        source = kw.get(name)
        if isinstance(source, str):
            if _contains_secret(source, secret):
                return True
            continue
        for _, value in _source_items(source):
            if _contains_secret(value, secret):
                return True
    for name in ("data", "json", "content", "files", "auth", "extensions"):
        if _contains_secret(kw.get(name), secret):
            return True
    return False


def _carries_key(headers, params) -> bool:
    for source in (headers, params):
        if any(str(k).lower() == "key" for k, _ in _source_items(source)):
            return True
    return False


def enforce_transport_policy(method: str, url: str, *, verify: bool = True,
                             headers=None, params=None,
                             strict_host: bool = False) -> None:
    """Require HTTPS, a DNS AbuseIPDB host, and certificate verification.

    ``strict_host`` is used by the provider-specific wrapper, where every URL is
    an AbuseIPDB request. The shared transport uses the default and treats an
    IP-literal URL as AbuseIPDB only when it also carries the AbuseIPDB key on
    one of the API paths.
    """
    try:
        parsed = httpx.URL(url)
    except (httpx.InvalidURL, ValueError) as exc:
        raise AbuseIPDBError(f"invalid AbuseIPDB URL: {exc}", "bad_request") from exc
    host = normalize_host(parsed.host)
    abuse_host = host in configured_abuseipdb_hosts()
    is_ip = _is_ip_literal(host)
    if not abuse_host:
        if is_ip and (strict_host or (
                endpoint_for(method, url) and _carries_key(headers, params))):
            raise AbuseIPDBError(
                "AbuseIPDB requests must use the configured DNS hostname, not an IP literal",
                "insecure_transport")
        if strict_host and host:
            raise AbuseIPDBError(
                "AbuseIPDB requests must use the configured hostname",
                "insecure_transport")
        return
    if parsed.scheme.lower() != "https":
        raise AbuseIPDBError("AbuseIPDB requests must use HTTPS",
                             "insecure_transport")
    if endpoint_for(method, url) not in SUPPORTED_ENDPOINTS:
        raise AbuseIPDBError("unsupported AbuseIPDB endpoint",
                             "unsupported_endpoint")
    if is_ip:
        raise AbuseIPDBError(
            "AbuseIPDB requests must use the configured DNS hostname, not an IP literal",
            "insecure_transport")
    if verify is False:
        raise AbuseIPDBError(
            "AbuseIPDB requests must keep TLS certificate verification enabled",
            "insecure_transport")


def _int_header(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        number = int(float(str(value).strip()))
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def _parse_reset_header(value: str | None) -> str | None:
    """UTC ISO timestamp from an epoch or ISO ``X-RateLimit-Reset`` value."""
    text = str(value or "").strip()
    if not text:
        return None
    try:
        number = float(text)
    except ValueError:
        number = None
    if number is not None:
        if number > 10**12:  # milliseconds
            number /= 1000.0
        try:
            return datetime.fromtimestamp(number, tz=timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def _parse_retry_after_header(value: str | None) -> int | None:
    """Seconds from a numeric or HTTP-date ``Retry-After`` value."""
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return max(0, int(float(text)))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(text)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0, int((when - datetime.now(timezone.utc)).total_seconds()))


def _response_headers(response) -> dict[str, str]:
    headers = getattr(response, "headers", None)
    if headers is None:
        return {}
    try:
        return {str(k).lower(): str(v) for k, v in headers.items()}
    except (AttributeError, TypeError, ValueError):
        return {}


class _QuotaReservation:
    """One local in-flight request against an endpoint bucket."""
    __slots__ = ("endpoint", "released")

    def __init__(self, endpoint: str) -> None:
        self.endpoint = endpoint
        self.released = False


def _bootstrap_limit() -> int:
    return max(1, int(ABUSEIPDB_BOOTSTRAP_CONCURRENCY))


def _bootstrap_budget() -> int:
    return max(1, int(ABUSEIPDB_BOOTSTRAP_BUDGET))


def _reserve_quota(endpoint: str | None) -> _QuotaReservation | None:
    """Atomically reserve one unit, or raise when no safe capacity remains.

    Before the first header, the bootstrap concurrency and budget apply; after
    that the allowance is ``remaining - inflight`` with the configured reserve.
    """
    if not endpoint:
        return None
    with _QUOTA_LOCK:
        state = _QUOTA_STATE.get(endpoint)
        if state is None:
            state = _QUOTA_STATE[endpoint] = {"inflight": 0}
        if state.get("reset_at") and _reset_in_past(state.get("reset_at")):
            _QUOTA_STATE.pop(endpoint, None)
            state = _QUOTA_STATE[endpoint] = {"inflight": 0}
        if (state.get("reset_at") is None and state.get("remaining") is not None
                and _observation_is_stale(state.get("observed_at"))):
            _QUOTA_STATE.pop(endpoint, None)
            state = _QUOTA_STATE[endpoint] = {"inflight": 0}
        inflight = max(0, int(state.get("inflight", 0)))
        until = state.get("retry_after_until")
        if until is not None and float(until) > time.time():
            wait = max(1, int(float(until) - time.time()))
            raise AbuseIPDBError(
                f"AbuseIPDB /{endpoint} is rate limited for another {wait}s",
                "rate_limited")
        remaining = state.get("remaining")
        if remaining is None:
            used = max(0, int(state.get("bootstrap_used", 0)))
            budget = _bootstrap_budget()
            if used >= budget:
                raise AbuseIPDBError(
                    f"AbuseIPDB /{endpoint} local bootstrap budget exhausted "
                    f"({used}/{budget}) with no authoritative quota headers. "
                    "Restart or raise BLUETEAM_ABUSEIPDB_BOOTSTRAP_BUDGET after review.",
                    "quota_exhausted")
            limit = _bootstrap_limit()
            if inflight >= limit:
                raise AbuseIPDBError(
                    f"AbuseIPDB /{endpoint} has no observed quota headers; "
                    f"bootstrap concurrency {limit} reached ({inflight} in flight). "
                    "Wait for the first response header.",
                    "quota_exhausted")
            state["bootstrap_used"] = used + 1
            state["inflight"] = inflight + 1
            return _QuotaReservation(endpoint)
        reserve = max(0, int(ABUSEIPDB_QUOTA_RESERVE))
        if remaining - inflight <= reserve:
            reset_at = state.get("reset_at")
            retry_after = state.get("retry_after_seconds")
            window = f"; resets {reset_at}" if reset_at else "; reset time not reported"
            retry = f"; retry after {retry_after}s" if retry_after else ""
            raise AbuseIPDBError(
                f"AbuseIPDB /{endpoint} quota reserve reached: {remaining} request(s) "
                f"left, {inflight} in flight, reserve {reserve}{window}{retry}. "
                "Wait for the reset; cached checks are still served.",
                "quota_exhausted")
        state["inflight"] = inflight + 1
        return _QuotaReservation(endpoint)


def _iso_epoch(value: str | None) -> float | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _release_quota(reservation: _QuotaReservation | None, response=None,
                   consumed: bool | None = None,
                   endpoint: str | None = None) -> None:
    """Release a reservation and reconcile it with the response headers.

    A newer reset window replaces the state; an equal window keeps the lower
    ``remaining``; an older window is ignored. ``consumed`` applies only
    without a response: ``False`` = never sent, ``True`` = may have been
    processed, ``None`` = unknown.
    """
    target = reservation.endpoint if reservation is not None else endpoint
    if not target:
        return
    if reservation is not None and reservation.released:
        return
    if reservation is None and response is None:
        return
    headers = _response_headers(response) if response is not None else {}
    if reservation is None and not headers:
        return
    with _QUOTA_LOCK:
        state = _QUOTA_STATE.setdefault(target, {})
        if reservation is not None and not reservation.released:
            reservation.released = True
            state["inflight"] = max(0, int(state.get("inflight", 0)) - 1)
        now = datetime.now(timezone.utc).isoformat()
        if response is None:
            if consumed and state.get("remaining") is not None:
                state["remaining"] = max(0, int(state["remaining"]) - 1)
                state["observed_at"] = now
            return
        limit = _int_header(headers.get("x-ratelimit-limit"))
        remaining = _int_header(headers.get("x-ratelimit-remaining"))
        reset_at = _parse_reset_header(headers.get("x-ratelimit-reset"))
        retry_after = _parse_retry_after_header(headers.get("retry-after"))
        status = getattr(response, "status_code", None)
        retry_until = ((datetime.now(timezone.utc) + timedelta(seconds=retry_after)).timestamp()
                       if retry_after is not None else None)
        if limit is None and remaining is None and reset_at is None and retry_after is None:
            if state.get("remaining") is not None:
                state["remaining"] = max(0, int(state["remaining"]) - 1)
                state["observed_at"] = now
            if status is not None and int(status) < 400:
                state.pop("retry_after_until", None)
            return
        reset_epoch = _iso_epoch(reset_at)
        current_epoch = state.get("reset_epoch")
        if reset_epoch is not None and (current_epoch is None or reset_epoch > current_epoch):
            # A later reset window is authoritative, including a missing remaining.
            state["remaining"] = remaining
            state["reset_at"] = reset_at
            state["reset_epoch"] = reset_epoch
            if limit is not None:
                state["limit"] = limit
            if retry_after is not None:
                state["retry_after_seconds"] = retry_after
            if retry_until is not None:
                state["retry_after_until"] = retry_until
            elif status is not None and int(status) < 400:
                state.pop("retry_after_until", None)
            if remaining is not None:
                state["bootstrap_used"] = 0
            state["observed_at"] = now
        elif reset_epoch is not None and current_epoch == reset_epoch:
            if remaining is not None:
                current = state.get("remaining")
                state["remaining"] = remaining if current is None else min(
                    int(current), remaining)
            if limit is not None:
                state["limit"] = limit
            if retry_after is not None:
                state["retry_after_seconds"] = retry_after
            if retry_until is not None:
                state["retry_after_until"] = retry_until
            elif status is not None and int(status) < 400:
                state.pop("retry_after_until", None)
            if remaining is not None:
                state["bootstrap_used"] = 0
            state["observed_at"] = now
        elif reset_epoch is not None and current_epoch is not None and reset_epoch < current_epoch:
            # An older window cannot reduce or overwrite the current window.
            pass
        else:
            # No reset header: the window is unknown; never raise availability.
            if remaining is not None:
                current = state.get("remaining")
                state["remaining"] = remaining if current is None else min(
                    int(current), remaining)
            if limit is not None:
                state["limit"] = limit
            if retry_after is not None:
                state["retry_after_seconds"] = retry_after
            if retry_until is not None:
                state["retry_after_until"] = retry_until
            elif status is not None and int(status) < 400:
                state.pop("retry_after_until", None)
            if remaining is not None:
                state["bootstrap_used"] = 0
            state["observed_at"] = now


def quota_snapshot(endpoint: str) -> dict:
    """Configured reference plus the last headers observed for an endpoint."""
    with _QUOTA_LOCK:
        state = dict(_QUOTA_STATE.get(endpoint) or {})
    configured = CONFIGURED_DAILY_LIMITS.get(endpoint)
    observed_limit = state.get("limit")
    remaining = state.get("remaining")
    inflight = max(0, int(state.get("inflight", 0)))
    bootstrap = remaining is None
    used = max(0, int(state.get("bootstrap_used", 0))) if bootstrap else 0
    budget = _bootstrap_budget() if bootstrap else None
    return {
        "endpoint": endpoint,
        "configured_limit": configured,
        "limit": observed_limit if observed_limit is not None else configured,
        "limit_source": "response" if observed_limit is not None else "configured",
        "remaining": remaining,
        "inflight": inflight,
        "bootstrap": bootstrap,
        "bootstrap_limit": _bootstrap_limit() if bootstrap else None,
        "bootstrap_budget": budget,
        "bootstrap_used": used,
        "bootstrap_remaining": (max(0, budget - used) if budget is not None else None),
        "local_available": (max(0, int(remaining) - inflight)
                            if remaining is not None else None),
        "reset_at": state.get("reset_at"),
        "observed_at": state.get("observed_at"),
        "retry_after_seconds": state.get("retry_after_seconds"),
        "retry_after_until": state.get("retry_after_until"),
        "reserve": max(0, int(ABUSEIPDB_QUOTA_RESERVE)),
        "available": not bootstrap,
    }


def _reset_in_past(value: str | None) -> bool:
    if not value:
        return False
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed <= datetime.now(timezone.utc)


def _observation_is_stale(value: str | None, hours: int = 24) -> bool:
    """A header-less observation older than a daily window must not wedge us."""
    if not value:
        return False
    try:
        observed = datetime.fromisoformat(value)
    except ValueError:
        return False
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - observed >= timedelta(hours=hours)


def _quota_guard(endpoint: str | None) -> None:
    """Refuse before the request when the observed quota is at the reserve."""
    if not endpoint:
        return
    with _QUOTA_LOCK:
        state = _QUOTA_STATE.get(endpoint)
        if not state:
            return
        if _reset_in_past(state.get("reset_at")):
            _QUOTA_STATE.pop(endpoint, None)
            return
        if state.get("reset_at") is None and _observation_is_stale(
                state.get("observed_at")):
            _QUOTA_STATE.pop(endpoint, None)
            return
        until = state.get("retry_after_until")
        if until is not None and float(until) > time.time():
            wait = max(1, int(float(until) - time.time()))
            raise AbuseIPDBError(
                f"AbuseIPDB /{endpoint} is rate limited for another {wait}s",
                "rate_limited")
        remaining = state.get("remaining")
        inflight = max(0, int(state.get("inflight", 0)))
        if remaining is None:
            used = max(0, int(state.get("bootstrap_used", 0)))
            budget = _bootstrap_budget()
            if used >= budget:
                raise AbuseIPDBError(
                    f"AbuseIPDB /{endpoint} local bootstrap budget exhausted "
                    f"({used}/{budget}) with no authoritative quota headers. "
                    "Restart or raise BLUETEAM_ABUSEIPDB_BOOTSTRAP_BUDGET after review.",
                    "quota_exhausted")
            limit = _bootstrap_limit()
            if inflight >= limit:
                raise AbuseIPDBError(
                    f"AbuseIPDB /{endpoint} has no observed quota headers; "
                    f"bootstrap concurrency {limit} reached ({inflight} in flight). "
                    "Wait for the first response header.",
                    "quota_exhausted")
            return
        reserve = max(0, int(ABUSEIPDB_QUOTA_RESERVE))
        if remaining - inflight > reserve:
            return
        reset_at = state.get("reset_at")
        retry_after = state.get("retry_after_seconds")
    window = f"; resets {reset_at}" if reset_at else "; reset time not reported"
    retry = f"; retry after {retry_after}s" if retry_after else ""
    raise AbuseIPDBError(
        f"AbuseIPDB /{endpoint} quota reserve reached: {remaining} request(s) "
        f"left, {inflight} in flight, reserve {reserve}{window}{retry}. "
        "Wait for the reset; cached checks are still served.",
        "quota_exhausted")


def reset_quota_state() -> None:
    """Drop observed quota state (tests, or an explicit operator reset)."""
    with _QUOTA_LOCK:
        _QUOTA_STATE.clear()


def begin_quota_reservation(endpoint: str | None) -> _QuotaReservation | None:
    """Public reservation entry used by the shared HTTP client."""
    return _reserve_quota(endpoint)


def finish_quota_reservation(reservation: _QuotaReservation | None,
                             response=None, consumed: bool | None = None,
                             endpoint: str | None = None) -> None:
    """Public reconciliation entry used by the shared HTTP client."""
    _release_quota(reservation, response, consumed=consumed, endpoint=endpoint)


def quota_consumed_on_failure(exc: BaseException | None) -> bool | None:
    """Whether a response-less failure may already have spent one unit.

    ``False``: the request demonstrably never reached AbuseIPDB (DNS, TCP, TLS,
    connect timeout, pool timeout, circuit open). ``True``: it may have been
    processed (read/write timeout, read/write error, protocol error,
    cancellation). ``None``: an HTTP response exists and its headers decide.
    """
    if exc is None:
        return None
    if getattr(exc, "response", None) is not None:
        return None
    if isinstance(exc, CircuitOpenError):
        return False
    if isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout,
                        httpx.PoolTimeout)):
        return False
    if isinstance(exc, (httpx.WriteTimeout, httpx.ReadTimeout, httpx.ReadError,
                        httpx.WriteError, httpx.RemoteProtocolError,
                        asyncio.CancelledError)):
        return True
    return False


def is_rfc1918(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True when the parsed address is inside 10/8, 172.16/12, or 192.168/16."""
    return isinstance(address, ipaddress.IPv4Address) and any(
        address in network for network in RFC1918_NETWORKS)


def normalize_public_ip(value: str) -> str:
    """Parse, normalize, and reject non-public addresses (IPv4 or IPv6)."""
    raw = (value or "").strip()
    try:
        parsed = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise ValueError(f"'{value}' is not a valid IP address.") from exc
    mapped = getattr(parsed, "ipv4_mapped", None)
    if mapped is not None:
        parsed = mapped
    if is_rfc1918(parsed):
        raise ValueError(f"'{value}' is an RFC 1918 private address.")
    # is_global is True for multicast in CPython, so this needs its own check.
    if parsed.is_multicast:
        raise ValueError(f"'{value}' is a multicast address.")
    if not parsed.is_global:
        raise ValueError(f"'{value}' is a private/reserved IP address.")
    return str(parsed)


def _api_key() -> str:
    if not ABUSEIPDB_API_KEY:
        raise AbuseIPDBError(
            "ABUSEIPDB_API_KEY is not set. Get a key at "
            "https://www.abuseipdb.com/account/api", "not_configured")
    return ABUSEIPDB_API_KEY


def _error_from_exception(exc: Exception) -> AbuseIPDBError:
    """Keep the upstream detail (429 duplicate, 422 field error) in the message."""
    detail = ""
    status = None
    response = getattr(exc, "response", None)
    if response is not None:
        status = getattr(response, "status_code", None)
        try:
            body = response.json()
        except ValueError:
            body = None
        if isinstance(body, dict):
            errors = body.get("errors")
            if isinstance(errors, list) and errors and isinstance(errors[0], dict):
                detail = str(errors[0].get("detail") or "")
    text = detail or str(exc) or type(exc).__name__
    if status == 402:
        kind = "plan_limit"
    elif status == 422:
        kind = "bad_request"
    else:
        kind = _classify_api_error(exc)
    return AbuseIPDBError(text, kind, status)


def is_report_request(method: str, url: str) -> bool:
    """True for a POST whose resolved path ends in /report, including /report/.

    Uses the transport's URL parser, so percent-encoded segments, dot segments,
    matrix parameters, and backslashes resolve before the comparison.
    """
    if (method or "").strip().lower() != "post":
        return False
    raw = (url or "").strip()
    try:
        resolved = httpx.URL(raw).path
    except (httpx.InvalidURL, ValueError):
        resolved = urlsplit(raw).path
    if "\x00" in resolved:
        return True
    resolved = resolved.replace("\\", "/").split(";", 1)[0]
    return resolved.rstrip("/").lower().endswith("/report")


def _report_egress_payload(data: dict | None) -> dict:
    """Validate the form body that is about to be POSTed to /report.

    Runs on the actual payload rather than an upstream guess, so a future
    caller that bypasses ``report_ip`` still cannot publish a non-public
    address or a comment containing a different IPv4 address.
    """
    if not isinstance(data, dict):
        raise AbuseIPDBError("report payload is missing", "bad_request")
    raw_ip = data.get("ip")
    if not isinstance(raw_ip, str):
        raise AbuseIPDBError("report payload has no IP address", "bad_request")
    try:
        normalized = normalize_public_ip(raw_ip)
    except ValueError as exc:
        raise AbuseIPDBError(str(exc), "bad_request") from exc
    body = {**data, "ip": normalized}
    comment = body.get("comment")
    if comment is not None:
        body["comment"] = sanitize_comment(str(comment), allowed_ip=normalized)
    return body


def guard_report_payload(data: dict | None) -> dict:
    """Public transport-boundary validator for the shared HTTP client."""
    return _report_egress_payload(data)


async def _api_call(method: str, url: str, *, client_name: str | None = None,
                    verify: bool = True, max_retries: int = 1,
                    backoff: float = 0.2, **kw) -> Any:
    """Provider-level guard for every AbuseIPDB request.

    Enforces HTTPS, a DNS host, certificate verification, and the supported
    endpoint mapping, and validates the ``/report`` form body. The shared
    transport below is the single quota-reservation boundary, so a direct
    ``core._api_call`` caller cannot skip it and this wrapper cannot double it.
    """
    enforce_transport_policy(method, url, verify=verify,
                             headers=kw.get("headers"),
                             params=kw.get("params"), strict_host=True)
    if is_report_request(method, url):
        try:
            kw["data"] = _report_egress_payload(kw.get("data"))
        except AbuseIPDBError:
            logger.warning("blocked AbuseIPDB /report transport: payload failed "
                           "the public-IP or comment check")
            raise
    try:
        return await _api_call_raw(method, url, client_name=client_name,
                                   verify=verify, max_retries=max_retries,
                                   backoff=backoff, **kw)
    except AbuseIPDBError:
        raise
    except Exception as exc:
        raise _error_from_exception(exc) from exc


async def _request(method: str, path: str, *, limiter, max_retries: int = 1,
                   params: dict | None = None, data: dict | None = None):
    # Last egress boundary: before key lookup, rate limiting, or any HTTP call.
    if is_report_request(method, path):
        try:
            data = _report_egress_payload(data)
        except AbuseIPDBError:
            logger.warning("blocked AbuseIPDB /report egress: payload failed the "
                           "public-IP or comment check")
            raise
    _quota_guard(endpoint_for(method, path))
    key = _api_key()
    headers = {"Key": key, "Accept": "application/json"}
    # httpx only accepts body kwargs on the verb helpers that take a body;
    # AsyncClient.get() rejects data=/json=/content= outright.
    body = {"data": data} if data is not None else {}
    try:
        async with limiter:
            return await _api_call(method, f"{ABUSEIPDB_BASE_URL.rstrip('/')}{path}",
                                   headers=headers, params=params,
                                   max_retries=max_retries, **body)
    except AbuseIPDBError:
        raise
    except Exception as exc:
        raise _error_from_exception(exc) from exc


def _check_cache_key(ip: str, max_age_days: int, verbose: bool) -> str:
    return f"check:{ip}:{max_age_days}:{int(verbose)}"


def _normalize_check(data: dict) -> dict:
    if not isinstance(data, dict):
        raise AbuseIPDBError("malformed AbuseIPDB response (data missing)")
    if "abuseConfidenceScore" not in data:
        raise AbuseIPDBError(
            "malformed AbuseIPDB response (abuseConfidenceScore missing)")
    score = data.get("abuseConfidenceScore")
    if not isinstance(score, (int, float)) or isinstance(score, bool):
        raise AbuseIPDBError(
            "malformed AbuseIPDB response (abuseConfidenceScore is not a number)")
    score = int(score)
    if score >= 75:
        band = "high"
    elif score >= 50:
        band = "medium"
    elif score >= 25:
        band = "low"
    else:
        band = "none"
    return {
        "ip": data.get("ipAddress", ""),
        "is_public": data.get("isPublic"),
        "ip_version": data.get("ipVersion"),
        "is_whitelisted": data.get("isWhitelisted"),
        "abuse_confidence_score": score,
        "risk_band": band,
        "is_malicious": score >= 50,
        "total_reports": data.get("totalReports", 0),
        "num_distinct_users": data.get("numDistinctUsers", 0),
        "last_reported_at": data.get("lastReportedAt"),
        "country_code": data.get("countryCode"),
        "country_name": data.get("countryName"),
        "usage_type": data.get("usageType"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "hostnames": data.get("hostnames") or [],
        "is_tor": data.get("isTor"),
        "reports": [
            {"reported_at": row.get("reportedAt"),
             "categories": row.get("categories") or [],
             # Third-party comments can carry victim logs and PII; keep the
             # structured fields and never forward the free text.
             "comment": "[third-party comment omitted]"}
            for row in (data.get("reports") or []) if isinstance(row, dict)
        ],
    }


async def check_ip(ip: str, max_age_days: int = 30, *, verbose: bool = False) -> dict:
    """Return a normalized AbuseIPDB ``/check`` result.

    Raises ``AbuseIPDBError`` on an unavailable or malformed upstream response.
    A cached answer carries ``cached=True``; an unavailable provider is never
    returned as a clean result.
    """
    try:
        normalized_ip = normalize_public_ip(ip)
    except ValueError as exc:
        raise AbuseIPDBError(str(exc), "bad_request") from exc
    if not isinstance(max_age_days, int) or not 1 <= max_age_days <= 365:
        raise AbuseIPDBError("max_age_days must be between 1 and 365", "bad_request")

    cache_key = _check_cache_key(normalized_ip, max_age_days, verbose)
    cached = cache_get("abuseipdb", cache_key)
    if cached is not None:
        return {**cached, "cached": True, "quota": quota_snapshot("check")}

    params: dict[str, Any] = {"ipAddress": normalized_ip,
                              "maxAgeInDays": max_age_days}
    if verbose:
        params["verbose"] = "true"
    response = await _request("get", "/check", limiter=CHECK_LIMITER, params=params)
    try:
        body = response.json()
    except ValueError as exc:
        raise AbuseIPDBError(
            "malformed AbuseIPDB response (body is not JSON)") from exc
    if not isinstance(body, dict) or not isinstance(body.get("data"), dict):
        raise AbuseIPDBError("malformed AbuseIPDB response (data missing)")
    result = _normalize_check(body["data"])
    cache_set("abuseipdb", cache_key, result, ABUSEIPDB_CACHE_TTL)
    return {**result, "cached": False, "quota": quota_snapshot("check")}


async def check_block(network: str, max_age_days: int = 30) -> dict:
    """Return a normalized ``/check-block`` result for one CIDR network.

    IPv4 follows the published plan table (/24 Standard, /16 Premium). IPv6 is
    passed through as an IPv6 CIDR: the official endpoint documentation does not
    state an IPv6 prefix limit, so the local bound is /112 (the host-count
    analogue of a /16) and an upstream rejection surfaces as a typed error rather
    than being pre-empted here.

    ``/check-block`` is a subnet triage call, not a per-IP check: it reports only
    addresses that already have reports. The network size is one request
    regardless of host count.
    """
    try:
        net = ipaddress.ip_network((network or "").strip(), strict=False)
    except ValueError as exc:
        raise AbuseIPDBError(f"'{network}' is not a valid CIDR network", "bad_request") from exc
    if net.version == 4:
        if net.prefixlen < ABUSEIPDB_CHECK_BLOCK_MAX_PREFIX:
            raise AbuseIPDBError(
                f"check-block accepts /{ABUSEIPDB_CHECK_BLOCK_MAX_PREFIX} or "
                f"narrower on the {ABUSEIPDB_PLAN} plan", "bad_request")
    elif net.prefixlen < CHECK_BLOCK_MAX_PREFIX_V6:
        raise AbuseIPDBError(
            f"check-block accepts /{CHECK_BLOCK_MAX_PREFIX_V6} or narrower for "
            f"IPv6 (local safety bound)", "bad_request")
    if not net.network_address.is_global:
        raise AbuseIPDBError(f"'{network}' is a private/reserved network", "bad_request")
    if not 1 <= max_age_days <= 365:
        raise AbuseIPDBError("max_age_days must be between 1 and 365", "bad_request")

    cache_key = f"block:{net}:{max_age_days}"
    cached = cache_get("abuseipdb", cache_key)
    if cached is not None:
        return {**cached, "cached": True, "quota": quota_snapshot("check-block")}

    response = await _request("get", "/check-block", limiter=CHECK_LIMITER,
                              params={"network": str(net),
                                      "maxAgeInDays": max_age_days})
    try:
        body = response.json()
    except ValueError as exc:
        raise AbuseIPDBError(
            "malformed AbuseIPDB response (body is not JSON)") from exc
    if not isinstance(body, dict) or not isinstance(body.get("data"), dict):
        raise AbuseIPDBError("malformed AbuseIPDB response (data missing)")
    data = body["data"]
    reported = []
    truncated = False
    for row in data.get("reportedAddress") or []:
        if not (isinstance(row, dict) and row.get("ipAddress")):
            continue
        if len(reported) >= CHECK_BLOCK_MAX_RESULTS:
            truncated = True
            break
        reported.append({
            "ip": row.get("ipAddress"),
            "num_reports": row.get("numReports", 0),
            "last_reported_at": row.get("mostRecentReport"),
            "abuse_confidence_score": row.get("abuseConfidenceScore"),
            "country_code": row.get("countryCode"),
        })
    result = {
        "network": str(net),
        "network_address": data.get("networkAddress", ""),
        "netmask": data.get("netmask"),
        "min_address": data.get("minAddress"),
        "max_address": data.get("maxAddress"),
        "num_possible_hosts": data.get("numPossibleHosts"),
        "address_space": data.get("addressSpaceDesc"),
        "reported_addresses": reported,
        "returned_count": len(reported),
        "truncated": truncated,
    }
    cache_set("abuseipdb", cache_key, result, ABUSEIPDB_CACHE_TTL)
    return {**result, "cached": False, "quota": quota_snapshot("check-block")}


def validate_categories(categories: Iterable[int]) -> list[int]:
    """Deduplicate, sort, and bound AbuseIPDB category IDs."""
    values: list[int] = []
    for value in categories:
        if isinstance(value, bool) or not isinstance(value, int):
            raise AbuseIPDBError(f"category '{value}' is not an integer", "bad_request")
        if value not in VALID_CATEGORY_IDS:
            raise AbuseIPDBError(f"category {value} is not in the AbuseIPDB table",
                                 "bad_request")
        values.append(value)
    unique = sorted(set(values))
    if not unique:
        raise AbuseIPDBError("at least one category is required", "bad_request")
    if len(unique) > 30:
        raise AbuseIPDBError("at most 30 categories are allowed", "bad_request")
    return unique


def _signature_once(text: str) -> str:
    """Remove every copy of the signature, then append exactly one at the end."""
    without = re.sub(r"\s*" + re.escape(SIGNATURE) + r"\s*", " ", text,
                     flags=re.IGNORECASE).strip()
    return f"{without} {SIGNATURE}".strip() if without else SIGNATURE


def sanitize_comment(comment: str, *, allowed_ip: str | None = None) -> str:
    """One line, no PII, at most 500 chars, exactly one CIRT signature."""
    text = " ".join(str(comment or "").split())
    # NFKC plus format-character stripping makes fullwidth punctuation and hidden
    # joiners visible to the content checks, without changing the text sent.
    scan = "".join(ch for ch in unicodedata.normalize("NFKC", text)
                   if unicodedata.category(ch) != "Cf")
    if _EMAIL_RE.search(scan):
        raise AbuseIPDBError("comment contains an email address; remove PII first",
                             "bad_request")
    if _URL_RE.search(scan):
        raise AbuseIPDBError("comment contains a URL; remove victim-identifying text first",
                             "bad_request")
    if _RAW_LOG_RE.search(scan):
        raise AbuseIPDBError("comment contains a raw log line; use a summary instead",
                             "bad_request")
    identity = _IDENTITY_RE.search(scan)
    if identity and identity.group(1).lower() not in _IDENTITY_GENERIC:
        raise AbuseIPDBError("comment names a user or agent; remove that identity",
                             "bad_request")
    if allowed_ip:
        for candidate in _IPV4_RE.findall(scan):
            if candidate != allowed_ip:
                raise AbuseIPDBError(
                    "comment contains a different IP address; remove victim or third-party addresses",
                    "bad_request")
    text = _signature_once(text)
    if len(text) > MAX_COMMENT_LENGTH:
        # Truncate the description, never the signature.
        keep = MAX_COMMENT_LENGTH - len(SIGNATURE) - 1
        text = f"{text[:keep].rstrip()} {SIGNATURE}"
    return text


def build_comment(alert_count: int, first_seen: str, last_seen: str,
                  rule_ids: Iterable[str]) -> str:
    """Build a factual comment from counts, window, and numeric rule IDs only.

    No rule description, username, email, agent name, or raw log line is included:
    those fields routinely carry victim PII and internal hostnames.
    """
    ids = [str(r) for r in rule_ids if str(r).isdigit()][:5]
    window = f" between {first_seen} and {last_seen}" if first_seen and last_seen else ""
    id_text = f" (Wazuh rule IDs: {', '.join(ids)})" if ids else ""
    return sanitize_comment(
        f"{max(0, int(alert_count))} attack alert(s) observed{window}{id_text}.")


def categories_for_evidence(groups: Iterable[str]) -> tuple[list[int], str]:
    """Map Wazuh rule groups to AbuseIPDB categories, or request manual review.

    Category 15 is deliberately not a fallback: an unknown attack type must be
    reviewed by an analyst rather than published as "Hacking".
    """
    tokens = {str(g).strip().lower() for g in groups if str(g).strip()}
    text = " ".join(tokens)

    if any(t in tokens for t in ("sshd", "ssh")) or "ssh" in text:
        return [18, 22], "ssh_bruteforce"
    if any(t in tokens for t in ("authentication_failed", "authentication_failures",
                                 "bruteforce", "brute_force")):
        return [18], "brute_force"
    if any(t in tokens for t in ("sql_injection", "sqli")) or "sql injection" in text:
        return [16, 21], "sql_injection"
    if any(t in tokens for t in ("scan", "scanner", "recon", "portscan",
                                 "port_scan")):
        return [14], "port_scan"
    if any(t in tokens for t in ("malware", "exploit", "rootkit", "backdoor",
                                 "trojan", "virus", "webshell")):
        return [20], "exploited_host"
    if any(t in tokens for t in ("web", "web_attack", "web_scan", "accesslog",
                                 "xss", "lfi", "rfi")):
        return [21], "web_app_attack"
    if any(t in tokens for t in ("ddos", "dos", "flood")):
        return [4], "ddos"
    if any(t in tokens for t in ("spam", "postfix")):
        return [11], "email_spam"
    if any(t in tokens for t in ("bot", "crawler")):
        return [19], "bad_web_bot"
    if any(t in tokens for t in ("iot",)):
        return [23], "iot_targeted"
    return [], "manual_review"


def _parse_timestamp(value: str | None) -> str:
    if not value:
        return datetime.now(timezone.utc).isoformat()
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise AbuseIPDBError(
            "timestamp must be ISO 8601, e.g. 2026-11-06T12:00:00+00:00",
            "bad_request") from exc
    if parsed.tzinfo is None:
        raise AbuseIPDBError("timestamp must include a timezone offset", "bad_request")
    parsed = parsed.astimezone(timezone.utc)
    if parsed.timestamp() > time.time() + 300:
        raise AbuseIPDBError("timestamp is in the future", "bad_request")
    return parsed.isoformat()


def report_retry_after(ip: str) -> int:
    """Seconds until this IP may be reported again, 0 when it is clear."""
    try:
        normalized = normalize_public_ip(ip)
    except ValueError:
        return 0
    now = time.monotonic()
    with _LAST_REPORT_LOCK:
        last = _LAST_REPORT.get(normalized)
        if last is None:
            return 0
        remaining = REPORT_DUPLICATE_WINDOW_SECONDS - (now - last)
        return max(1, int(remaining)) if remaining > 0 else 0


async def report_ip(ip: str, categories: Iterable[int], *,
                    comment: str | None = None,
                    timestamp: str | None = None,
                    alert_count: int = 1,
                    first_seen: str = "",
                    last_seen: str = "",
                    rule_ids: Iterable[str] = ()) -> dict:
    """Submit one report unless the same IP was reported here in the last 15 min.

    The caller must already have passed the env gate, ``dry_run=False``, and
    ``confirm=True``; this function performs the external write with no further
    safety prompt.
    """
    try:
        normalized_ip = normalize_public_ip(ip)
    except ValueError as exc:
        raise AbuseIPDBError(str(exc), "bad_request") from exc
    cat_ids = validate_categories(categories)
    text = comment if comment is not None else build_comment(
        alert_count, first_seen, last_seen, rule_ids)
    text = sanitize_comment(text, allowed_ip=normalized_ip)
    when = _parse_timestamp(timestamp)

    now = time.monotonic()
    with _LAST_REPORT_LOCK:
        last = _LAST_REPORT.get(normalized_ip)
        if last is not None and now - last < REPORT_DUPLICATE_WINDOW_SECONDS:
            remaining = max(1, int(REPORT_DUPLICATE_WINDOW_SECONDS - (now - last)))
            return {"ip": normalized_ip, "status": "duplicate_local",
                    "retry_after_seconds": remaining,
                    "comment": text, "categories": cat_ids,
                    "quota": quota_snapshot("report")}

    try:
        # A POST is not retried: a 5xx may arrive after the report was accepted,
        # and a blind retry would either duplicate it or spend a second request.
        response = await _request(
            "post", "/report", limiter=REPORT_LIMITER, max_retries=0,
            data={"ip": normalized_ip,
                  "categories": ",".join(str(c) for c in cat_ids),
                  "comment": text,
                  "timestamp": when})
    except AbuseIPDBError as exc:
        # The upstream says this IP already has a report in the 15-minute window.
        # Remember it locally so a retry does not spend another request.
        if exc.kind == "rate_limited" and "15 minutes" in exc.message:
            with _LAST_REPORT_LOCK:
                _LAST_REPORT[normalized_ip] = time.monotonic()
        raise
    try:
        body = response.json()
    except ValueError:
        body = None
    data = body.get("data") if isinstance(body, dict) else None
    raw_score = data.get("abuseConfidenceScore") if isinstance(data, dict) else None
    verified = isinstance(raw_score, (int, float)) and not isinstance(raw_score, bool)
    score = raw_score if verified else None

    with _LAST_REPORT_LOCK:
        _LAST_REPORT[normalized_ip] = time.monotonic()
    # A write changes the score returned by /check, including any verbose variant.
    cache_delete_prefix("abuseipdb", f"check:{normalized_ip}:")
    cache_delete_prefix("abuseipdb", "block:")

    return {"ip": normalized_ip, "status": "reported", "verified": verified,
            "abuse_confidence_score": score, "categories": cat_ids,
            "comment": text, "timestamp": when,
            "quota": quota_snapshot("report")}
