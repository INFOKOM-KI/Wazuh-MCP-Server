#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
AbuseIPDB API v2 client: check, check-block, and report.

One client for every AbuseIPDB call site, so quota is spent once per IP and the
retry/circuit-breaker behaviour is identical in the aggregate, the unified score,
the curated report, and the reporting tool.

Facts encoded here come from the official API docs (checked 2026-11-06):
- ``/check`` accepts one IPv4/IPv6 address; ``maxAgeInDays`` is 1..365 (default 30).
- ``/check-block`` accepts a CIDR; the Standard plan caps IPv4 at /24 and returns
  only addresses that already have reports.
- ``/report`` is a form-encoded POST; ``categories`` is required; the same IP can
  be reported once per 15 minutes; comments must not contain PII.
"""
from __future__ import annotations

import ipaddress
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any, Iterable

from mcp_server import (ABUSEIPDB_API_KEY, ABUSEIPDB_BASE_URL, ABUSEIPDB_CACHE_TTL,
                        ABUSEIPDB_REPORT_MIN_INTERVAL)
from mcp_server.core.http_client import _api_call, _classify_api_error
from mcp_server.threat_intel._cache import (cache_delete_prefix, cache_get,
                                            cache_set, get_limiter)


CHECK_LIMITER = get_limiter("abuseipdb_check", max_concurrent=2, min_interval=0.2)
REPORT_LIMITER = get_limiter("abuseipdb_report", max_concurrent=1,
                             min_interval=ABUSEIPDB_REPORT_MIN_INTERVAL)

REPORT_DUPLICATE_WINDOW_SECONDS = 15 * 60
MAX_COMMENT_LENGTH = 500
SIGNATURE = "Reported by TangerangKota-CSIRT"

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


async def _request(method: str, path: str, *, limiter, max_retries: int = 1,
                   params: dict | None = None, data: dict | None = None):
    key = _api_key()
    headers = {"Key": key, "Accept": "application/json"}
    try:
        async with limiter:
            return await _api_call(method, f"{ABUSEIPDB_BASE_URL.rstrip('/')}{path}",
                                   headers=headers, params=params, data=data,
                                   max_retries=max_retries)
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
        return {**cached, "cached": True}

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
    return {**result, "cached": False}


async def check_block(network: str, max_age_days: int = 30) -> dict:
    """Return a normalized ``/check-block`` result for an IPv4 /24 or narrower.

    ``/check-block`` is a subnet triage call, not a per-IP check: it reports only
    addresses that already have reports. Broader IPv4 blocks require a paid plan,
    so they are rejected before spending a request.
    """
    try:
        net = ipaddress.ip_network((network or "").strip(), strict=False)
    except ValueError as exc:
        raise AbuseIPDBError(f"'{network}' is not a valid CIDR network", "bad_request") from exc
    if net.version != 4:
        raise AbuseIPDBError(
            "check-block currently accepts IPv4 only; use ip= for an IPv6 check",
            "unsupported_type")
    if net.prefixlen < 24:
        raise AbuseIPDBError(
            "check-block accepts /24 or narrower on the Standard plan", "bad_request")
    if not net.network_address.is_global:
        raise AbuseIPDBError(f"'{network}' is a private/reserved network", "bad_request")
    if not 1 <= max_age_days <= 365:
        raise AbuseIPDBError("max_age_days must be between 1 and 365", "bad_request")

    cache_key = f"block:{net}:{max_age_days}"
    cached = cache_get("abuseipdb", cache_key)
    if cached is not None:
        return {**cached, "cached": True}

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
    for row in data.get("reportedAddress") or []:
        if isinstance(row, dict) and row.get("ipAddress"):
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
    }
    cache_set("abuseipdb", cache_key, result, ABUSEIPDB_CACHE_TTL)
    return {**result, "cached": False}


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
    if _EMAIL_RE.search(text):
        raise AbuseIPDBError("comment contains an email address; remove PII first",
                             "bad_request")
    if _URL_RE.search(text):
        raise AbuseIPDBError("comment contains a URL; remove victim-identifying text first",
                             "bad_request")
    if _RAW_LOG_RE.search(text):
        raise AbuseIPDBError("comment contains a raw log line; use a summary instead",
                             "bad_request")
    identity = _IDENTITY_RE.search(text)
    if identity and identity.group(1).lower() not in _IDENTITY_GENERIC:
        raise AbuseIPDBError("comment names a user or agent; remove that identity",
                             "bad_request")
    if allowed_ip:
        for candidate in _IPV4_RE.findall(text):
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
                    "comment": text, "categories": cat_ids}

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
            "comment": text, "timestamp": when}
