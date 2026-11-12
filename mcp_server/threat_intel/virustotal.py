#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Shared VirusTotal request control: validation, persistent budget/quota, and process-local cache.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import time
import unicodedata
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Literal, TypedDict

import httpx

from mcp_server import (VIRUSTOTAL_ALLOWED_HOSTS, VIRUSTOTAL_API_KEY,
                        VIRUSTOTAL_AUTOINIT, VIRUSTOTAL_BASE_URL,
                        VIRUSTOTAL_BUDGET, VIRUSTOTAL_BUDGET_HOURS,
                        VIRUSTOTAL_CACHE_TTL,
                        VIRUSTOTAL_DAILY_LIMIT, VIRUSTOTAL_MAX_RESPONSE_BYTES,
                        VIRUSTOTAL_RATE_PER_MINUTE, VIRUSTOTAL_STATE)
from mcp_server.core.http_client import (CircuitOpenError, ResponseTooLargeError,
                                         _api_call, normalize_public_ip)
from mcp_server.core.url_policy import validate_https_base_url
from mcp_server.threat_intel._cache import cache_delete_prefix, cache_get, cache_set
from mcp_server.threat_intel.virustotal_consent import (consume_consent,
                                                        issue_consent,
                                                        reset_consent_state)
from mcp_server.threat_intel.virustotal_quota import (VirusTotalQuota,
                                                      VirusTotalQuotaError)

logger = logging.getLogger("blue_team_mcp.threat_intel.virustotal")

KINDS = frozenset({"ip_addresses", "domains", "files"})
DEFAULT_COOLDOWN_SECONDS = 60.0

_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_HASH = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$")
_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+!|>~<>&])")

_STAT_KEYS = ("malicious", "suspicious", "harmless", "undetected", "timeout",
              "confirmed-timeout", "failure", "type-unsupported")
_CORE_STATS = ("malicious", "suspicious", "harmless", "undetected", "timeout")

_NOW = time.time
_QUOTA: VirusTotalQuota | None = None
_QUOTA_SIG: tuple | None = None
_SEMAPHORE: asyncio.Semaphore | None = None
_SEMAPHORE_LOOP = None


VirusTotalErrorKind = Literal[
    "rate_limited", "cooldown", "not_configured", "unsupported_type",
    "consent_required",
    "upstream_error", "timeout", "auth_error", "not_found", "bad_request",
    "circuit_open", "budget_closed", "not_armed", "arm_expired",
    "budget_exhausted", "daily_exhausted", "storage_unavailable",
    "state_corrupt", "state_missing", "policy_mismatch", "state_exists",
    "config_invalid",
]


class VirusTotalSuccess(TypedDict, total=False):
    """Canonical success payload returned by ``lookup``."""
    indicator: str
    kind: str
    http_status: int
    analysis_stats: dict[str, int]
    stats_complete: bool
    missing_stats: list[str]
    malicious: int
    suspicious: int | None
    harmless: int | None
    undetected: int | None
    timeout: int | None
    total_engines: int | None
    detection_percent: int | None
    any_detection: bool
    community_reputation: int | None
    as_owner: str | None
    asn: int | None
    network: str | None
    country: str | None
    total_votes: dict[str, int] | None
    tags: list[str] | None
    last_analysis_date: int | None
    retrieved_at: str
    cached: bool
    cache_age_seconds: int | None
    cache_ttl_seconds: int
    cache_expired: bool


class VirusTotalError(Exception):
    """A VirusTotal call failure with a machine-readable kind."""

    def __init__(self, message: str, kind: VirusTotalErrorKind = "upstream_error",
                 retry_after_seconds: int | None = None,
                 http_status: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.kind = kind
        self.retry_after_seconds = retry_after_seconds
        self.http_status = http_status


def normalize_domain(value: str) -> str:
    """Return an ASCII IDNA hostname, or raise ValueError.

    Only a DNS name with at least two labels is accepted. Slashes, queries,
    fragments, userinfo, ports, percent escapes, whitespace, and control
    characters are rejected before a caller can reach URL construction.
    """
    raw = value or ""
    if raw != raw.strip():
        raise ValueError("domain must not contain leading or trailing whitespace")
    text = raw.lower().rstrip(".")
    if not text:
        raise ValueError("domain is empty")
    if len(text) > 253:
        raise ValueError("domain is longer than 253 characters")
    if any(ch in text for ch in "/\\?#@:%") or any(ch.isspace() for ch in text):
        raise ValueError("domain contains a path, query, userinfo, port, or whitespace")
    if any(not ch.isprintable() for ch in text):
        raise ValueError("domain contains a control character")
    try:
        ipaddress.ip_address(text)
    except ValueError:
        pass
    else:
        raise ValueError("domain must not be an IP address")
    labels = text.split(".")
    if len(labels) < 2:
        raise ValueError("domain must contain at least two labels")
    ascii_labels: list[str] = []
    for label in labels:
        if not label:
            raise ValueError("domain contains an empty label")
        try:
            encoded = label.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("domain label is not valid IDNA") from exc
        if len(encoded) > 63 or not _DOMAIN_LABEL.fullmatch(encoded):
            raise ValueError("domain label is not a valid hostname label")
        ascii_labels.append(encoded)
    result = ".".join(ascii_labels)
    if len(result) > 253:
        raise ValueError("domain is longer than 253 characters")
    return result


def normalize_hash(value: str) -> str:
    """Return a lowercase MD5, SHA-1, or SHA-256 hex digest, or raise ValueError."""
    raw = value or ""
    if raw != raw.strip():
        raise ValueError("hash must not contain leading or trailing whitespace")
    text = raw.lower()
    if not _HASH.fullmatch(text):
        raise ValueError("hash must be 32, 40, or 64 hexadecimal characters")
    return text


def _normalize(kind: str, indicator: str) -> str:
    text = indicator or ""
    if kind == "ip_addresses":
        return normalize_public_ip(text)
    if kind == "domains":
        return normalize_domain(text)
    return normalize_hash(text)


def _base_url() -> str:
    try:
        return validate_https_base_url(
            VIRUSTOTAL_BASE_URL, VIRUSTOTAL_ALLOWED_HOSTS, required_path="/api/v3")
    except ValueError as exc:
        raise VirusTotalError(f"VIRUSTOTAL_BASE_URL is invalid: {exc}",
                              "not_configured") from exc


def _get_quota() -> VirusTotalQuota:
    global _QUOTA, _QUOTA_SIG
    signature = (str(VIRUSTOTAL_STATE), int(VIRUSTOTAL_BUDGET),
                 float(VIRUSTOTAL_BUDGET_HOURS), int(VIRUSTOTAL_RATE_PER_MINUTE),
                 int(VIRUSTOTAL_DAILY_LIMIT))
    if _QUOTA is None or _QUOTA_SIG != signature:
        _QUOTA = VirusTotalQuota(
            VIRUSTOTAL_STATE, budget=VIRUSTOTAL_BUDGET,
            hours=VIRUSTOTAL_BUDGET_HOURS,
            rate_per_minute=VIRUSTOTAL_RATE_PER_MINUTE,
            daily_limit=VIRUSTOTAL_DAILY_LIMIT, clock=_NOW)
        _QUOTA_SIG = signature
    return _QUOTA


def _semaphore() -> asyncio.Semaphore:
    """One in-process VirusTotal request at a time, recreated per event loop."""
    global _SEMAPHORE, _SEMAPHORE_LOOP
    loop = asyncio.get_running_loop()
    if _SEMAPHORE is None or _SEMAPHORE_LOOP is not loop:
        _SEMAPHORE = asyncio.Semaphore(1)
        _SEMAPHORE_LOOP = loop
    return _SEMAPHORE


def _safe_text(value, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    chars: list[str] = []
    for char in value:
        category = unicodedata.category(char)
        if category in ("Cf", "Cs"):
            continue
        if category == "Cc":
            if char.isspace():
                chars.append(" ")
            continue
        chars.append(char)
    text = " ".join("".join(chars).split())
    return text[:limit] or None


def _safe_tags(value) -> list[str] | None:
    if not isinstance(value, list):
        return None
    tags: list[str] = []
    for item in value[:20]:
        if not isinstance(item, str):
            continue
        text = _safe_text(item, 64)
        if text:
            tags.append(text)
    return tags or None


def _safe_votes(value) -> dict[str, int] | None:
    if not isinstance(value, dict):
        return None
    votes: dict[str, int] = {}
    for key in ("harmless", "malicious"):
        item = value.get(key)
        if isinstance(item, int) and not isinstance(item, bool):
            votes[key] = item
    return votes or None


def cache_metadata(data: dict, *, now: datetime | None = None) -> dict:
    """Return cache provenance and age for a normalized result."""
    retrieved_at = data.get("retrieved_at")
    ttl = max(0, int(VIRUSTOTAL_CACHE_TTL))
    age = None
    if isinstance(retrieved_at, str):
        try:
            then = datetime.fromisoformat(retrieved_at)
            if then.tzinfo is None:
                then = then.replace(tzinfo=timezone.utc)
            current = now or datetime.now(timezone.utc)
            age = max(0, int((current - then).total_seconds()))
        except ValueError:
            age = None
    cached = bool(data.get("cached"))
    return {
        "cached": cached,
        "retrieved_at": retrieved_at,
        "cache_age_seconds": age,
        "cache_ttl_seconds": ttl,
        "cache_expired": bool(cached and age is not None and ttl > 0 and age > ttl),
    }


def _optional_int(value) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _normalize_response(response, indicator: str, kind: str) -> dict:
    try:
        body = response.json()
    except ValueError as exc:
        raise VirusTotalError(
            "malformed VirusTotal response (not JSON)", "upstream_error") from exc
    data = body.get("data") if isinstance(body, dict) else None
    attrs = data.get("attributes") if isinstance(data, dict) else None
    if not isinstance(attrs, dict):
        raise VirusTotalError(
            "malformed VirusTotal response (data missing)", "upstream_error")
    stats = attrs.get("last_analysis_stats")
    if not isinstance(stats, dict) or "malicious" not in stats:
        raise VirusTotalError(
            "malformed VirusTotal response (last_analysis_stats missing)",
            "upstream_error")

    counts: dict[str, int] = {}
    for key in _STAT_KEYS:
        if key not in stats:
            continue
        value = stats[key]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise VirusTotalError(
                f"malformed VirusTotal response ({key} is not a non-negative integer)",
                "upstream_error")
        counts[key] = value
    missing = [key for key in _CORE_STATS if key not in counts]
    complete = not missing
    total = sum(counts.values())
    malicious = counts["malicious"]
    if malicious > total:
        raise VirusTotalError(
            "malformed VirusTotal response (malicious exceeds total)", "upstream_error")
    return {
        "indicator": indicator,
        "kind": kind,
        "http_status": response.status_code,
        "analysis_stats": counts,
        "stats_complete": complete,
        "missing_stats": missing,
        "malicious": malicious,
        "suspicious": counts.get("suspicious"),
        "harmless": counts.get("harmless"),
        "undetected": counts.get("undetected"),
        "timeout": counts.get("timeout"),
        "total_engines": total if complete else None,
        "detection_percent": (int(malicious / total * 100) if complete and total
                              else 0 if complete else None),
        "any_detection": malicious > 0,
        "community_reputation": _optional_int(attrs.get("reputation")),
        "as_owner": _safe_text(attrs.get("as_owner"), 200),
        "asn": _optional_int(attrs.get("asn")),
        "network": _safe_text(attrs.get("network"), 120),
        "country": _safe_text(attrs.get("country"), 64),
        "total_votes": _safe_votes(attrs.get("total_votes")),
        "tags": _safe_tags(attrs.get("tags")),
        "last_analysis_date": _optional_int(attrs.get("last_analysis_date")),
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
    }


VTVerdict = Literal["malicious", "suspicious", "no_detections", "inconclusive"]


def classify_report(data: dict) -> tuple[str | None, bool | None, VTVerdict]:
    """Map engine counts onto ``(risk level, malicious vote, verdict)``.

    One flagged engine is a detection; the 50% line is display only. Incomplete
    statistics are inconclusive, and zero detections is not proof of safety.
    """
    malicious = int(data.get("malicious") or 0)
    suspicious = int(data.get("suspicious") or 0)
    score = data.get("detection_percent")
    if not data.get("stats_complete") or score is None:
        return None, None, "inconclusive"
    if malicious > 0:
        return ("high" if score >= 50 else "medium"), True, "malicious"
    if suspicious > 0:
        return "medium", None, "suspicious"
    return "none", False, "no_detections"


def preflight() -> dict:
    """Return the quota snapshot, or refuse before any transport is attempted.

    The checks mirror the order ``lookup()`` hits them: budget, state, arm,
    cooldown, then per-window and daily capacity. A missing or corrupt state is
    reported, never recreated here; ``VIRUSTOTAL_AUTOINIT`` stays the only
    opt-in that creates one, and it does so inside ``lookup()``.
    """
    if not VIRUSTOTAL_API_KEY:
        raise VirusTotalError("VIRUSTOTAL_API_KEY is not set", "not_configured")
    _base_url()  # fails closed on an invalid base URL or allowlist before prompting
    if int(VIRUSTOTAL_BUDGET) <= 0:
        raise VirusTotalError("VirusTotal budget is closed at 0 requests",
                              "budget_closed")
    try:
        snapshot = _get_quota().state()
    except VirusTotalQuotaError as exc:
        raise VirusTotalError(exc.message, exc.kind,
                              exc.retry_after_seconds) from exc
    if not snapshot["window_open"]:
        raise VirusTotalError(
            "VirusTotal arm window has expired; run the rearm command",
            "arm_expired")
    cooldown = int(snapshot.get("cooldown_remaining_seconds") or 0)
    if cooldown > 0:
        raise VirusTotalError("VirusTotal rate limit cooldown is active",
                              "cooldown", max(1, cooldown))
    if snapshot["remaining"] < 1:
        raise VirusTotalError(
            f"VirusTotal budget exhausted: {snapshot['spent']}/{snapshot['budget']} "
            "requests used in this arm window", "budget_exhausted")
    if snapshot["daily_spent"] >= snapshot["daily_limit"]:
        raise VirusTotalError(
            f"VirusTotal daily provider limit reached: "
            f"{snapshot['daily_spent']}/{snapshot['daily_limit']} requests today",
            "daily_exhausted")
    return snapshot


def markdown_text(value, limit: int = 200) -> str:
    """Project one untrusted value into a safe Markdown scalar."""
    text = _safe_text(value, limit) or "-"
    return _MD_SPECIAL.sub(r"\\\1", text)


def _retry_after_seconds(response) -> int | None:
    raw = response.headers.get("Retry-After") if response is not None else None
    if not raw:
        return None
    try:
        return max(0, int(float(raw)))
    except (ValueError, OverflowError):
        pass
    try:
        when = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0, int((when - datetime.now(timezone.utc)).total_seconds()))


def _consumed_on_failure(exc: Exception) -> bool:
    """False only when the failure proves no HTTP request reached VirusTotal."""
    if isinstance(exc, CircuitOpenError):
        return False
    if isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout,
                        httpx.InvalidURL, httpx.UnsupportedProtocol)):
        return False
    return True


def _finalize(quota: VirusTotalQuota, reservation_id: int, consumed: bool) -> None:
    try:
        quota.finalize(reservation_id, consumed=consumed)
    except VirusTotalQuotaError as exc:
        raise VirusTotalError("VirusTotal quota state is unavailable", exc.kind) from exc


def _error_from_exception(exc: Exception) -> VirusTotalError:
    if isinstance(exc, VirusTotalError):
        return exc
    if isinstance(exc, CircuitOpenError):
        return VirusTotalError(str(exc), "circuit_open")
    if isinstance(exc, ResponseTooLargeError):
        return VirusTotalError(
            f"VirusTotal response exceeded {exc.max_bytes} bytes", "upstream_error")
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        if status == 429:
            delay = _retry_after_seconds(exc.response)
            if delay is None:
                delay = int(DEFAULT_COOLDOWN_SECONDS)
            try:
                _get_quota().set_cooldown(delay, _NOW())
            except VirusTotalQuotaError as quota_exc:
                return VirusTotalError(
                    "VirusTotal quota state is unavailable after a 429",
                    quota_exc.kind)
            return VirusTotalError(
                "VirusTotal rate limit exceeded", "rate_limited",
                max(1, delay), http_status=429)
        kind = ("auth_error" if status in (401, 403)
                else "not_found" if status == 404
                else "upstream_error")
        return VirusTotalError(str(exc), kind, http_status=status)
    if isinstance(exc, httpx.TimeoutException):
        return VirusTotalError(str(exc), "timeout")
    return VirusTotalError(str(exc), "upstream_error")


async def lookup(kind: str, indicator: str, *,
                 consent_token: str | None = None) -> VirusTotalSuccess:
    """Return a normalized VirusTotal report, using the shared cache and limits.

    ``consent_token`` is a single-use, indicator-bound approval issued only after
    the MCP host or the live-validator operator approves sharing. It is consumed
    before the cache lookup, so a cached report also requires fresh consent and
    never triggers a new API request.
    """
    if kind not in KINDS:
        raise VirusTotalError(f"unsupported VirusTotal kind '{kind}'", "unsupported_type")
    try:
        value = _normalize(kind, indicator)
    except ValueError as exc:
        raise VirusTotalError(str(exc), "bad_request") from exc

    consume_consent(consent_token, kind, value)
    base_url = _base_url()
    cache_key = f"{kind}:{value}"
    cached = cache_get("virustotal", cache_key)
    if cached is not None:
        result = {**cached, "cached": True}
        result.update(cache_metadata(result))
        return result

    if not VIRUSTOTAL_API_KEY:
        raise VirusTotalError("VIRUSTOTAL_API_KEY is not set", "not_configured")

    try:
        quota = _get_quota()
    except VirusTotalQuotaError as exc:
        raise VirusTotalError(exc.message, exc.kind) from exc
    async with _semaphore():
        cached = cache_get("virustotal", cache_key)
        if cached is not None:
            result = {**cached, "cached": True}
            result.update(cache_metadata(result))
            return result

        autoinit_tried = False
        while True:
            try:
                reserved = quota.reserve(_NOW())
            except VirusTotalQuotaError as exc:
                if (exc.kind == "state_missing" and VIRUSTOTAL_AUTOINIT
                        and not autoinit_tried):
                    # Opt-in: the budget comes from the operator's env, never
                    # from the caller. The audit entry names the file only.
                    try:
                        quota.auto_initialize()
                    except VirusTotalQuotaError as init_exc:
                        # Same mapping as reserve(): a failed init is a provider
                        # error, never an exception escaping the aggregate.
                        raise VirusTotalError(
                            init_exc.message, init_exc.kind,
                            init_exc.retry_after_seconds) from init_exc
                    autoinit_tried = True
                    from mcp_server.core.audit import _audit_log
                    try:
                        _audit_log("virustotal_quota_autoinit",
                                   {"state": str(VIRUSTOTAL_STATE)})
                    except Exception:  # audit is evidence, not a gate
                        logger.warning("virustotal_quota_autoinit not audited")
                    continue
                raise VirusTotalError(
                    exc.message, exc.kind, exc.retry_after_seconds) from exc
            if reserved.wait_seconds <= 0:
                reservation_id = reserved.reservation_id
                break
            await asyncio.sleep(reserved.wait_seconds)

        url = f"{base_url}/{kind}/{value}"
        try:
            response = await _api_call(
                "get", url,
                headers={"x-apikey": VIRUSTOTAL_API_KEY,
                         "Accept": "application/json"},
                client_name="virustotal", max_retries=0,
                max_response_bytes=VIRUSTOTAL_MAX_RESPONSE_BYTES,
                verify=True)
        except asyncio.CancelledError:
            _finalize(quota, reservation_id, True)
            raise
        except Exception as exc:
            _finalize(quota, reservation_id, _consumed_on_failure(exc))
            raise _error_from_exception(exc) from exc
        else:
            _finalize(quota, reservation_id, True)

        if response.status_code != 200:
            raise VirusTotalError(
                f"unexpected VirusTotal HTTP status {response.status_code}",
                "upstream_error", http_status=response.status_code)
        result = _normalize_response(response, value, kind)
        cache_set("virustotal", cache_key, result, VIRUSTOTAL_CACHE_TTL)
        result = {**result, "cached": False}
        result.update(cache_metadata(result))
        return result


def reset_state() -> None:
    """Clear the process-local cache and quota handle; leave the state file intact."""
    global _QUOTA, _QUOTA_SIG, _SEMAPHORE, _SEMAPHORE_LOOP
    _QUOTA = None
    _QUOTA_SIG = None
    _SEMAPHORE = None
    _SEMAPHORE_LOOP = None
    reset_consent_state()
    cache_delete_prefix("virustotal", "")
