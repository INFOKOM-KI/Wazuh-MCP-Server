#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
AbuseIPDB check tools: one IP, or an IPv4 /24 block.
"""
from __future__ import annotations

import ipaddress
import json
import logging
from datetime import datetime, timezone
from typing import Literal, Optional

import httpx
from pydantic import (BaseModel, ConfigDict, Field, field_validator,
                      model_validator)

from mcp_server import (ABUSEIPDB_CHECK_BLOCK_MAX_PREFIX, ABUSEIPDB_EXCLUDE,
                        ABUSEIPDB_PLAN, ABUSEIPDB_REPORTING_ENABLED,
                        ABUSEIPDB_REPORT_MAX_PER_CALL, WAZUH_INDEXER_PASSWORD,
                        WAZUH_INDEXER_URL, mcp)
from mcp_server.core.audit import _audit_log, _escape_md_table, _truncate_if_needed
from mcp_server.core.exceptions import ThreatIntelError
from mcp_server.threat_intel.abuseipdb import (AbuseIPDBError, CATEGORY_NAMES,
                                               build_comment,
                                               categories_for_evidence,
                                               check_block, check_ip,
                                               normalize_public_ip,
                                               quota_snapshot,
                                               report_ip, report_retry_after,
                                               sanitize_comment,
                                               validate_categories)
from mcp_server.wazuh.indexer import (_correct_srcip_counts,
                                      _srcip_aggs_merged,
                                      _wazuh_indexer_post)
from mcp_server.wazuh.time_utils import _parse_time_window

logger = logging.getLogger("blue_team_mcp.abuseipdb_tool")


class AbuseIPDBCheckInput(BaseModel):
    """Input for ``blueteam_abuseipdb_check``."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    ip: Optional[str] = Field(
        default=None, max_length=45,
        description="Public IPv4/IPv6 address to check.")
    network: Optional[str] = Field(
        default=None, max_length=64,
        description=(f"Public IPv4 CIDR, /{ABUSEIPDB_CHECK_BLOCK_MAX_PREFIX} or "
                     f"narrower ({ABUSEIPDB_PLAN} plan), for a check-block sweep."))
    max_age_days: int = Field(
        default=30, ge=1, le=365,
        description="Only count reports from the last N days (default 30).")
    verbose: bool = Field(
        default=False,
        description="Include the per-report rows returned by AbuseIPDB.")
    response_format: Literal["markdown", "json"] = Field(default="markdown")

    @field_validator("ip")
    @classmethod
    def _valid_ip(cls, value: Optional[str]) -> Optional[str]:
        if value is None or value == "":
            return None
        return normalize_public_ip(value)

    @field_validator("network")
    @classmethod
    def _valid_network(cls, value: Optional[str]) -> Optional[str]:
        if value is None or value == "":
            return None
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError(f"'{value}' is not a valid CIDR network.") from exc
        if net.version != 4:
            raise ValueError("network must be IPv4; use ip= for IPv6.")
        if net.prefixlen < ABUSEIPDB_CHECK_BLOCK_MAX_PREFIX:
            raise ValueError(
                f"network must be /{ABUSEIPDB_CHECK_BLOCK_MAX_PREFIX} or narrower "
                f"on the {ABUSEIPDB_PLAN} plan.")
        if not net.network_address.is_global:
            raise ValueError(f"'{value}' is a private/reserved network.")
        return str(net)

    @model_validator(mode="after")
    def _one_target(self):
        if bool(self.ip) == bool(self.network):
            raise ValueError("provide exactly one of ip or network")
        return self


def _quota_line(quota: dict | None) -> str:
    """One markdown line; never turns an unobserved remaining count into a value."""
    if not quota:
        return "- **Quota**: unavailable (no rate-limit headers observed)"
    limit = quota.get("limit")
    remaining = quota.get("remaining")
    source = quota.get("limit_source", "configured")
    reset = quota.get("reset_at") or "unknown"
    if remaining is None:
        bootstrap = quota.get("bootstrap_limit")
        budget = quota.get("bootstrap_budget")
        used = quota.get("bootstrap_used")
        left = quota.get("bootstrap_remaining")
        inflight = int(quota.get("inflight", 0) or 0)
        extra = ""
        if budget is not None:
            extra += f"; bootstrap {used}/{budget} used, {left} left"
        if bootstrap:
            extra += f"; concurrency {bootstrap}"
        if inflight:
            extra += f", {inflight} in flight"
        return (f"- **Quota**: remaining unknown (configured limit "
                f"{limit if limit is not None else 'unknown'}, source {source}); "
                f"resets {reset}{extra}")
    retry = quota.get("retry_after_seconds")
    wait = f"; retry after {retry}s" if retry else ""
    inflight = int(quota.get("inflight", 0) or 0)
    local = quota.get("local_available")
    flight = f"; {inflight} in flight" if inflight else ""
    local_text = f", local {local}" if inflight and local is not None else ""
    return (f"- **Quota**: {remaining}/{limit if limit is not None else '?'} "
            f"remaining ({source}){flight}{local_text}; resets {reset}; reserve "
            f"{quota.get('reserve', 0)}{wait}")


def _quota_markdown(quota: dict) -> list[str]:
    rows = [q for q in (quota or {}).values() if isinstance(q, dict)]
    if not rows:
        return []
    lines = ["", "## Quota", "",
             "| Endpoint | Limit | Remaining | Resets (UTC) | Source |",
             "|---|---|---|---|---|"]
    for q in rows:
        limit = q.get("limit")
        remaining = q.get("remaining")
        lines.append(
            f"| `{q.get('endpoint')}` | {limit if limit is not None else '-'} "
            f"| {remaining if remaining is not None else 'unknown'} "
            f"| {q.get('reset_at') or '-'} | {q.get('limit_source', 'configured')} |")
    return lines


def _render_check(result: dict, verbose: bool) -> str:
    score = result.get("abuse_confidence_score")
    lines = [
        f"# AbuseIPDB Check - `{result.get('ip', '?')}`",
        "",
        f"- **Abuse confidence**: **{score}/100** ({result.get('risk_band', '?')})",
        f"- **Malicious (>=50)**: {'yes' if result.get('is_malicious') else 'no'}",
        f"- **Reports**: {result.get('total_reports', 0)} from "
        f"{result.get('num_distinct_users', 0)} distinct users",
        f"- **Last reported**: {result.get('last_reported_at') or 'never'}",
        f"- **Country / ISP**: {result.get('country_code') or '-'} / "
        f"{result.get('isp') or '-'}",
        f"- **Usage type**: {result.get('usage_type') or '-'}",
        f"- **Tor / whitelisted**: {result.get('is_tor')} / {result.get('is_whitelisted')}",
        f"- **Source**: {'cache' if result.get('cached') else 'live API'}",
        _quota_line(result.get("quota")),
    ]
    reports = result.get("reports") or []
    if verbose and reports:
        lines.extend(["", f"## Recent reports ({len(reports)})", "",
                      "| Reported at | Categories |",
                      "|---|---|"])
        for row in reports[:10]:
            cats = ", ".join(str(c) for c in (row.get("categories") or []))
            lines.append(f"| {row.get('reported_at', '-')} | {cats or '-'} |")
    return "\n".join(lines)


def _render_block(result: dict) -> str:
    rows = result.get("reported_addresses") or []
    lines = [
        f"# AbuseIPDB Check-Block - `{result.get('network', '?')}`",
        "",
        "This endpoint returns only addresses that **already have reports**; "
        "an absent address is not a clean verdict.",
        "",
        f"- **Possible hosts**: {result.get('num_possible_hosts', '?')}",
        f"- **Address space**: {result.get('address_space') or '-'}",
        f"- **Reported addresses**: {result.get('returned_count', len(rows))}"
        f"{' (truncated)' if result.get('truncated') else ''}",
        f"- **Source**: {'cache' if result.get('cached') else 'live API'}",
        _quota_line(result.get("quota")),
    ]
    if rows:
        lines.extend(["", "| IP | Score | Reports | Last reported |", "|---|---|---|---|"])
        for row in rows[:50]:
            lines.append(f"| `{row.get('ip')}` | {row.get('abuse_confidence_score', '?')} "
                         f"| {row.get('num_reports', 0)} | {row.get('last_reported_at') or '-'} |")
    return "\n".join(lines)


@mcp.tool(
    name="blueteam_abuseipdb_check",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": True},
)
async def blueteam_abuseipdb_check(params: AbuseIPDBCheckInput) -> str:
    """Check one public IP, or sweep an IPv4 /16 (Premium) or /24, against AbuseIPDB.

    Returns the abuse confidence score, report volume, last report time, country,
    ISP, usage type, Tor and whitelist flags. A check-block sweep is **not** a
    per-IP verdict: it lists only addresses that already have reports.

    **Worked Examples**

    1. *Check one IP*:
       ``blueteam_abuseipdb_check(ip="118.25.6.39")``

    2. *Check one IP with recent report rows*:
       ``blueteam_abuseipdb_check(ip="118.25.6.39", verbose=True)``

    3. *Sweep a /16 for already-reported hosts*:
       ``blueteam_abuseipdb_check(network="8.8.0.0/16", max_age_days=90)``

    **Required Permissions**: ``ABUSEIPDB_API_KEY``. Premium reference: 50,000
    checks/day and 5,000 check-block calls/day; Standard: 1,000 and 100. The
    configured plan is only a fallback: ``X-RateLimit-*`` response headers are
    authoritative and are reported back per endpoint. Checks are cached for 15
    minutes (``ABUSEIPDB_CACHE_TTL``), so repeating the same IP does not spend
    quota. ``maxAgeInDays`` is 1..365.

    **Error Handling**: private/reserved/CGNAT input is rejected before any
    request. Quota below the configured reserve (``BLUETEAM_ABUSEIPDB_QUOTA_RESERVE``)
    is refused before a request is sent, with the observed reset time. A timeout,
    401/403, 402 plan limit, 429, malformed body, or open circuit is raised as a
    tool error, never returned as a clean result. ``cached=true`` means the answer
    is a cached check, not a skipped lookup.
    """
    _audit_log("blueteam_abuseipdb_check",
               {"ip": params.ip, "network": params.network,
                "max_age_days": params.max_age_days})
    try:
        if params.network:
            result = await check_block(params.network, params.max_age_days)
            result = {**result, "mode": "block"}
        else:
            result = await check_ip(params.ip or "", params.max_age_days,
                                    verbose=params.verbose)
            result = {**result, "mode": "ip"}
    except AbuseIPDBError as exc:
        raise ThreatIntelError(
            f"[blueteam_abuseipdb_check] {exc.kind}: {exc.message}") from exc

    if params.response_format == "json":
        if result.get("mode") == "block":
            result.pop("mode", None)
        return _truncate_if_needed(json.dumps(result, indent=2, default=str))
    if result.get("mode") == "block":
        return _truncate_if_needed(_render_block(result))
    return _truncate_if_needed(_render_check(result, params.verbose))


# Category names are exported for the report tool and the skill documentation.
__all__ = ["blueteam_abuseipdb_check", "AbuseIPDBCheckInput", "CATEGORY_NAMES"]


# Reporting: evidence -> candidate -> preview -> explicit submission

_DSTIP_FIELDS = ("data.dstip", "data.dst_ip", "data.destination_ip",
                 "data.dest_ip")


class AbuseIPDBReportInput(BaseModel):
    """Input for ``blueteam_abuseipdb_report``."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    srcips: list[str] = Field(
        default_factory=list, max_length=50,
        description="Explicit public source IPs. Mutually exclusive with from_alerts.")
    from_alerts: bool = Field(
        default=False,
        description="Harvest public source IPs from Wazuh alerts instead of srcips.")
    since: str = Field(default="24h", max_length=30)
    until: Optional[str] = Field(default=None, max_length=30)
    min_alerts: int = Field(default=3, ge=1, le=10000,
                            description="Minimum alerts for a harvested IP.")
    min_level: int = Field(default=7, ge=0, le=16,
                           description="Minimum Wazuh rule level for a harvested IP.")
    max_candidates: int = Field(default=50, ge=1, le=50)
    max_age_days: int = Field(default=30, ge=1, le=365)
    exclude_srcips: list[str] = Field(
        default_factory=list, max_length=100,
        description=("IPs or CIDRs excluded from from_alerts harvesting. "
                     "Explicit srcips are not filtered by this list; private "
                     "and reserved addresses are always rejected."))
    categories: Literal["auto"] | list[int] = Field(
        default="auto",
        description="'auto' maps Wazuh groups; a list sets categories explicitly.")
    comment: Optional[str] = Field(
        default=None, max_length=500,
        description="Custom comment for one explicit IP. The CIRT signature is appended.")
    timestamp: Optional[str] = Field(
        default=None, max_length=64,
        description="ISO 8601 earliest observance; explicit single-IP mode only.")
    dry_run: bool = Field(
        default=True,
        description="Preview only. Set false only when the current user prompt explicitly requests reporting.")
    confirm: bool = Field(
        default=False,
        description="Set true only when the current user prompt explicitly authorizes this submission; this is not a request for a second approval prompt.")
    response_format: Literal["markdown", "json"] = Field(default="markdown")

    @field_validator("srcips")
    @classmethod
    def _valid_srcips(cls, values: list[str]) -> list[str]:
        out: list[str] = []
        for value in values:
            normalized = normalize_public_ip(value)
            if normalized not in out:
                out.append(normalized)
        if len(out) > 50:
            raise ValueError("at most 50 source IPs per call")
        return out

    @field_validator("exclude_srcips")
    @classmethod
    def _valid_excludes(cls, values: list[str]) -> list[str]:
        out: list[str] = []
        for value in values:
            raw = value.strip()
            if "/" in raw:
                out.append(str(ipaddress.ip_network(raw, strict=False)))
            else:
                out.append(str(ipaddress.ip_address(raw)))
        return out

    @field_validator("comment")
    @classmethod
    def _valid_comment(cls, value):
        if value is None:
            return None
        try:
            sanitize_comment(value)
        except AbuseIPDBError as exc:
            raise ValueError(exc.message) from exc
        return value

    @field_validator("categories")
    @classmethod
    def _valid_categories(cls, value):
        if value == "auto":
            return value
        if not isinstance(value, list):
            raise ValueError("categories must be 'auto' or a list of integers")
        try:
            return validate_categories(value)
        except AbuseIPDBError as exc:
            raise ValueError(exc.message) from exc

    @model_validator(mode="after")
    def _shape(self):
        if self.from_alerts == bool(self.srcips):
            raise ValueError("provide exactly one of srcips or from_alerts=true")
        if self.from_alerts and self.comment:
            raise ValueError("comment is not accepted for harvested batches")
        if self.srcips and not self.comment:
            raise ValueError("explicit srcips require a comment describing the evidence")
        if (self.comment or self.timestamp) and len(self.srcips) != 1:
            raise ValueError("comment/timestamp require exactly one explicit srcip")
        return self


def _parse_exclude_patterns(values: list[str]) -> list[str]:
    out = []
    for value in values:
        try:
            raw = value.strip()
            if not raw:
                continue
            out.append(str(ipaddress.ip_network(raw, strict=False))
                       if "/" in raw else str(ipaddress.ip_address(raw)))
        except ValueError:
            logger.warning("ignoring invalid AbuseIPDB exclude pattern: %r", value)
            continue
    return out


def _is_excluded(ip: str, patterns: list[str]) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return True
    for pattern in patterns:
        try:
            if "/" in pattern:
                if address in ipaddress.ip_network(pattern, strict=False):
                    return True
            elif address == ipaddress.ip_address(pattern):
                return True
        except ValueError:
            continue
    return False


def _agg_time(node) -> str:
    if not isinstance(node, dict):
        return ""
    text = node.get("value_as_string")
    if text:
        return str(text)
    value = node.get("value")
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value / 1000, tz=timezone.utc).isoformat()
    return ""


def _bucket_keys(node) -> list[str]:
    if not isinstance(node, dict):
        return []
    return [str(b.get("key")) for b in node.get("buckets") or []
            if b.get("key") is not None]


async def _harvest_candidates(params: AbuseIPDBReportInput) -> tuple[list[dict], dict]:
    """Aggregate public source IPs with enough evidence to be a candidate.

    Only ``srcip`` paths are harvested; an IP that also appears as a destination
    in the same window is dropped as ambiguous. Destination-role verification is
    fail-closed: if neither destination query completes, no report is allowed.
    """
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        raise ThreatIntelError(
            "[blueteam_abuseipdb_report] WAZUH_INDEXER_URL and "
            "WAZUH_INDEXER_PASSWORD are required for from_alerts=true")
    try:
        since_iso, until_iso = _parse_time_window(params.since, params.until)
    except ValueError as exc:
        raise ThreatIntelError(f"[blueteam_abuseipdb_report] {exc}") from exc

    filters = [
        {"range": {"@timestamp": {"gte": since_iso, "lt": until_iso,
                                  "format": "strict_date_optional_time"}}},
        {"range": {"rule.level": {"gte": params.min_level}}},
    ]
    query = {"bool": {"filter": filters}}
    terms_size = max(50, params.max_candidates * 3)
    agg_spec = {
        "srcips": {
            "terms": {"field": "data.srcip", "size": terms_size,
                      "order": {"_count": "desc"}},
            "aggs": {
                "first_seen": {"min": {"field": "@timestamp"}},
                "last_seen": {"max": {"field": "@timestamp"}},
                "max_level": {"max": {"field": "rule.level"}},
                "rule_ids": {"terms": {"field": "rule.id", "size": 10}},
                "rule_groups": {"terms": {"field": "rule.groups", "size": 10}},
            },
        },
    }
    merged, _live_paths, errors = await _srcip_aggs_merged(query, agg_spec)
    if not merged and errors:
        raise ThreatIntelError(
            "[blueteam_abuseipdb_report] Indexer aggregation failed: "
            + "; ".join(errors[:3]))

    buckets = (merged.get("srcips") or {}).get("buckets") or []
    counts_exact = True
    if buckets:
        try:
            await _correct_srcip_counts(buckets, query)
        except (httpx.HTTPError, RuntimeError, ValueError, KeyError, TypeError) as exc:
            counts_exact = False
            logger.warning("source-IP count correction failed: %s", exc)

    excludes = _parse_exclude_patterns(
        list(params.exclude_srcips)
        + [p for p in ABUSEIPDB_EXCLUDE.split(",") if p])
    excluded = {"private_or_reserved": 0, "invalid": 0,
                "below_min_alerts": 0, "allowlisted": 0}
    alerts_in_returned_buckets = 0
    eligible: list[dict] = []
    for bucket in buckets:
        ip = str(bucket.get("key") or "")
        count = int(bucket.get("doc_count") or 0)
        alerts_in_returned_buckets += count
        try:
            normalized = normalize_public_ip(ip)
        except ValueError:
            try:
                ipaddress.ip_address(ip)
                excluded["private_or_reserved"] += 1
            except ValueError:
                excluded["invalid"] += 1
            continue
        if count < params.min_alerts:
            excluded["below_min_alerts"] += 1
            continue
        if _is_excluded(normalized, excludes):
            excluded["allowlisted"] += 1
            continue
        eligible.append({
            "ip": normalized,
            "alert_count": count,
            "first_seen": _agg_time(bucket.get("first_seen")),
            "last_seen": _agg_time(bucket.get("last_seen")),
            "max_level": (bucket.get("max_level") or {}).get("value"),
            "rule_ids": _bucket_keys(bucket.get("rule_ids")),
            "rule_groups": _bucket_keys(bucket.get("rule_groups")),
            "source": "alerts",
            "role": "srcip",
        })

    if eligible:
        # Role ambiguity is a property of the whole window, not only of alerts at
        # or above min_level: a lower-level destination observation still matters.
        destination_hits, role_status = await _dstip_role(
            filters[:1], [b["ip"] for b in eligible])
        if role_status == "unavailable":
            raise ThreatIntelError(
                "[blueteam_abuseipdb_report] cannot verify srcip/dstip role; "
                "refusing to report without that check")
        for candidate in eligible:
            if candidate["ip"] in destination_hits:
                candidate["role"] = "ambiguous"
                candidate["skip_reason"] = "appears as both source and destination"
            else:
                candidate["role_check"] = "checked"
    else:
        role_status = "not_needed"

    other = int((merged.get("srcips") or {}).get("sum_other_doc_count") or 0)
    effective_cap = min(params.max_candidates, max(1, ABUSEIPDB_REPORT_MAX_PER_CALL))
    selected = eligible[:effective_cap]
    remaining = other + max(0, len(eligible) - len(selected))
    meta = {
        "window": {"since": since_iso, "until": until_iso},
        "source": "alerts",
        "srcip_paths": _live_paths,
        "indexer_errors": errors,
        "role_check": role_status,
        "alerts_examined": alerts_in_returned_buckets + other,
        "alerts_examined_exact": counts_exact,
        "unique_srcip_buckets": len(buckets),
        "unreturned_bucket_docs": other,
        "excluded": excluded,
        "excluded_total": sum(excluded.values()),
        "remaining_candidates": remaining,
        "remaining_candidates_exact": other == 0,
        "truncated": remaining > 0,
        "candidates_eligible": len(eligible),
    }
    return selected, meta


async def _dstip_role(filters: list[dict], candidate_ips: list[str]) -> tuple[set[str], str]:
    """Return candidate IPs that appear as a destination, and a status.

    The query is fail-closed: if the destination field cannot be queried, the
    caller must not report. A deployment that maps ``data.dstip`` as text rather
    than keyword will land here, and the tool will ask for review instead.
    """
    if not candidate_ips:
        return set(), "not_needed"
    hits: set[str] = set()
    successes = 0
    failures = 0
    for field in _DSTIP_FIELDS:
        body = {
            "size": 0,
            "query": {"bool": {"filter": filters + [{"terms": {field: candidate_ips}}]}},
            "aggs": {"matched": {"terms": {"field": field,
                                            "size": len(candidate_ips) + 10}}},
        }
        raw = await _wazuh_indexer_post(body)
        if not isinstance(raw, dict) or "error" in raw:
            failures += 1
            continue
        successes += 1
        hits.update(_bucket_keys((raw.get("aggregations") or {}).get("matched")))
    if failures or successes == 0:
        return set(), "unavailable"
    return hits, "checked"


def _candidate_status(candidate: dict, categories: list[int],
                      checked: dict | None) -> tuple[str, str]:
    if candidate.get("role") == "ambiguous":
        return "manual_review", "source/destination role is ambiguous"
    if not categories:
        return "manual_review", "attack type could not be established"
    if checked is not None and checked.get("is_public") is False:
        return "skipped_not_public", "AbuseIPDB reports isPublic=false"
    if checked is not None and checked.get("is_whitelisted") is True:
        return "skipped_whitelist", "AbuseIPDB whitelist hit"
    retry_after = report_retry_after(candidate["ip"])
    if retry_after > 0:
        return "duplicate_local", f"already reported here; retry in {retry_after}s"
    return "eligible", ""


async def _evaluate(candidates: list[dict],
                    params: AbuseIPDBReportInput) -> list[dict]:
    evaluated: list[dict] = []
    for candidate in candidates:
        checked = None
        check_status = "unavailable"
        check_error = ""
        try:
            checked = await check_ip(candidate["ip"], params.max_age_days)
            check_status = "cached" if checked.get("cached") else "checked"
        except AbuseIPDBError as exc:
            if exc.kind in ("auth_error", "not_configured", "quota_exhausted"):
                raise ThreatIntelError(
                    f"[blueteam_abuseipdb_report] AbuseIPDB {exc.kind}: {exc.message}"
                ) from exc
            check_status = "unavailable"
            check_error = f"{exc.kind}: {exc.message}"

        if params.categories == "auto":
            cat_ids, category_reason = categories_for_evidence(
                candidate.get("rule_groups") or [])
        else:
            cat_ids, category_reason = list(params.categories), "explicit"

        status, skip_reason = _candidate_status(candidate, cat_ids, checked)
        if params.comment is not None:
            comment = sanitize_comment(params.comment, allowed_ip=candidate["ip"])
        elif candidate.get("source") == "alerts":
            comment = build_comment(
                int(candidate.get("alert_count") or 0),
                candidate.get("first_seen") or "",
                candidate.get("last_seen") or "",
                candidate.get("rule_ids") or [])
        else:
            comment = sanitize_comment("Manually reported after analyst review.")

        evaluated.append({
            **candidate,
            "categories": cat_ids,
            "category_reason": category_reason,
            "check_status": check_status,
            "check_error": check_error,
            "abuse_confidence_score": (checked or {}).get("abuse_confidence_score"),
            "total_reports": (checked or {}).get("total_reports"),
            "last_reported_at": (checked or {}).get("last_reported_at"),
            "is_whitelisted": (checked or {}).get("is_whitelisted"),
            "comment": comment,
            "timestamp_used": params.timestamp or candidate.get("first_seen") or None,
            "status": status,
            "skip_reason": skip_reason,
        })
    return evaluated


def _summary(evaluated: list[dict], meta: dict, params: AbuseIPDBReportInput,
             preview_reason: str = "") -> dict:
    def count(*statuses: str) -> int:
        return sum(1 for c in evaluated if c.get("status") in statuses)

    failed = count("failed")
    reported = count("reported")
    would = count("would_report")
    manual = count("manual_review")
    skipped = sum(1 for c in evaluated if str(c.get("status", "")).startswith("skipped")
                  or c.get("status") == "duplicate_local")
    check_counts = {
        "checked": sum(1 for c in evaluated if c.get("check_status") == "checked"),
        "cached": sum(1 for c in evaluated if c.get("check_status") == "cached"),
        "unavailable": sum(1 for c in evaluated if c.get("check_status") == "unavailable"),
    }
    remaining = int(meta.get("remaining_candidates") or 0)
    return {
        "mode": meta.get("source", "explicit"),
        "dry_run": params.dry_run,
        "confirmed": params.confirm,
        "reporting_enabled": bool(ABUSEIPDB_REPORTING_ENABLED),
        "preview_reason": preview_reason,
        "window": meta.get("window"),
        "alerts_examined": meta.get("alerts_examined"),
        "alerts_examined_exact": bool(meta.get("alerts_examined_exact", True)),
        "unique_srcip_buckets": meta.get("unique_srcip_buckets"),
        "unreturned_bucket_docs": meta.get("unreturned_bucket_docs"),
        "excluded": meta.get("excluded") or {},
        "excluded_total": int(meta.get("excluded_total") or 0),
        "candidates_processed": len(evaluated),
        "would_report": would,
        "reported": reported,
        "manual_review": manual,
        "skipped": skipped,
        "failed": failed,
        "check_counts": check_counts,
        "external_check_calls": check_counts["checked"],
        "remaining_candidates": remaining,
        "remaining_candidates_exact": bool(meta.get("remaining_candidates_exact", True)),
        "truncated": bool(meta.get("truncated")),
        "partial": (bool(meta.get("truncated")) or not bool(meta.get("alerts_examined_exact", True))
                    or failed > 0 or manual > 0 or remaining > 0),
        "role_check": meta.get("role_check"),
        "quota": {endpoint: quota_snapshot(endpoint)
                  for endpoint in ("check", "report")},
        "results": evaluated,
    }


def _render_report_output(output: dict) -> str:
    mode = "preview" if output.get("preview_reason") or output.get("dry_run") else "submission"
    lines = [
        f"# AbuseIPDB Report - {mode}",
        "",
        f"- **Mode**: `{output.get('mode')}` | **Dry run**: {output.get('dry_run')} "
        f"| **Reporting enabled**: {output.get('reporting_enabled')}",
        f"- **Alerts examined**: {(('' if output.get('alerts_examined_exact', True) else 'at least ') + str(output.get('alerts_examined'))) if output.get('alerts_examined') is not None else 'n/a'} "
        f"| **Unique srcip buckets**: {output.get('unique_srcip_buckets') if output.get('unique_srcip_buckets') is not None else 'n/a'} "
        f"| **Unreturned bucket docs**: {output.get('unreturned_bucket_docs', 0)}",
        f"- **Candidates processed**: {output.get('candidates_processed')} "
        f"| **Would report**: {output.get('would_report')} "
        f"| **Reported**: {output.get('reported')}",
        f"- **Manual review**: {output.get('manual_review')} "
        f"| **Skipped**: {output.get('skipped')} | **Failed**: {output.get('failed')}",
        f"- **Remaining candidates**: {('' if output.get('remaining_candidates_exact', True) else 'at least ') + str(output.get('remaining_candidates'))} "
        f"| **Truncated**: {output.get('truncated')} | **Partial**: {output.get('partial')}",
        f"- **Excluded**: {output.get('excluded_total', 0)} "
        f"({', '.join(f'{k}={v}' for k, v in (output.get('excluded') or {}).items()) or 'none'})",
        f"- **Checks**: {output.get('check_counts', {}).get('checked', 0)} live, "
        f"{output.get('check_counts', {}).get('cached', 0)} cached, "
        f"{output.get('check_counts', {}).get('unavailable', 0)} unavailable",
    ]
    lines.extend(_quota_markdown(output.get("quota") or {}))
    if output.get("preview_reason"):
        lines.append(f"- **Submission blocked**: {output['preview_reason']}")
    rows = output.get("results") or []
    if rows:
        lines.extend(["", "| IP | Alerts | Categories | Check | Status | Comment |",
                      "|---|---|---|---|---|---|"])
        for row in rows:
            cats = ", ".join(str(c) for c in (row.get("categories") or [])) or "-"
            comment = _escape_md_table(str(row.get("comment") or ""))[:160]
            status = str(row.get("status"))
            if status == "reported" and row.get("verified") is False:
                status = "reported (unverified)"
            lines.append(
                f"| `{_escape_md_table(str(row.get('ip')))}` "
                f"| {row.get('alert_count', '-')} | {cats} | {row.get('check_status')} "
                f"| {status} | {comment} |")
        alerts_rows = [r for r in rows if r.get("source") == "alerts"]
        if alerts_rows:
            lines.extend(["", "## Provenance", ""])
            for row in alerts_rows[:20]:
                lines.append(
                    f"- `{row.get('ip')}`: {row.get('alert_count')} alert(s), "
                    f"max level {row.get('max_level')}, role {row.get('role')}, "
                    f"{row.get('first_seen')} to {row.get('last_seen')}, rules "
                    f"{', '.join(row.get('rule_ids') or []) or '-'}, groups "
                    f"{', '.join(row.get('rule_groups') or []) or '-'}")
        if mode == "preview":
            lines.extend(["", "## Final comments", ""])
            for row in rows:
                lines.append(f"- `{row.get('ip')}`: {row.get('comment') or '-'}")
        failures = [r for r in rows if r.get("status") == "failed"]
        if failures:
            lines.extend(["", "## Failures", ""])
            for row in failures[:20]:
                lines.append(f"- `{row.get('ip')}`: {row.get('error_kind')} - {row.get('error')}")
        manual = [r for r in rows if r.get("status") == "manual_review"]
        if manual:
            lines.extend(["", "## Requires manual review", ""])
            for row in manual[:20]:
                lines.append(f"- `{row.get('ip')}`: {row.get('skip_reason') or 'no category'}")
    return "\n".join(lines)


@mcp.tool(
    name="blueteam_abuseipdb_report",
    annotations={"readOnlyHint": False, "destructiveHint": True,
                 "idempotentHint": False, "openWorldHint": True},
)
async def blueteam_abuseipdb_report(params: AbuseIPDBReportInput) -> str:
    """Preview and explicitly submit AbuseIPDB reports for Wazuh-observed IPs.

    Reports are off by default. A submission requires **all three**:
    ``BLUETEAM_ABUSEIPDB_REPORTING_ENABLED=true``, ``dry_run=false``, and
    ``confirm=true``. The default call is a preview that checks each candidate and
    shows the exact final comment, including the
    ``Reported by TangerangKota-CSIRT`` signature.

    An explicit user prompt to report malicious IPs is the authorization for that
    one call: set ``dry_run=false`` and ``confirm=true`` and report each eligible
    IP without a separate per-IP confirmation. A request to check, analyze,
    monitor, or preview does not authorize submission, and the authorization does
    not carry over to a later call. Scheduled and background workflows never
    submit.

    **Evidence rules**

    - Harvested candidates are public **source** IPs with at least ``min_alerts``
      alerts at or above ``min_level`` in the window.
    - An IP that also appears as a destination in the window is marked
      ``manual_review``; it is never reported automatically.
    - ``categories="auto"`` maps Wazuh rule groups. When the attack type cannot be
      established the candidate is ``manual_review``; category 15 is never a
      fallback.
    - Harvested comments contain counts, timestamps, and numeric rule IDs only. Explicit
      reports require a comment describing the evidence. No raw logs, usernames, mail
      addresses, agent names, or victim IPv4 addresses in either path; IPv6 comment
      scanning is out of scope.
    - A local 15-minute ledger prevents duplicate submissions; AbuseIPDB also
      rejects the same IP within 15 minutes.

    **Worked Examples**

    1. *Preview a 24-hour harvest*:
       ``blueteam_abuseipdb_report(from_alerts=True, since="24h")``

    2. *Preview one explicit IP with a custom comment*:
       ``blueteam_abuseipdb_report(srcips=["8.8.8.8"], categories=[18, 22], comment="SSH brute force against a monitored host.")``

    3. *Submit after an explicit user reporting request*:
       ``blueteam_abuseipdb_report(srcips=["8.8.8.8"], categories=[18, 22], comment="Confirmed SSH brute force against a monitored host.", dry_run=False, confirm=True)``

    **Required Permissions**: ``ABUSEIPDB_API_KEY``; the HTTP transport additionally
    requires the ``threatintel:report`` scope (not ``wazuh:write``). Premium
    reference: 50,000 report requests/day; Standard: 1,000. Observed
    ``X-RateLimit-*`` headers are authoritative, and requests are refused below
    the configured quota reserve. One report per IP per 15 minutes still applies.
    Checks are cached for 15 minutes; report submissions are paced at one request
    per second.

    **Limits**: at most 50 candidates per call. ``remaining_candidates`` and
    ``truncated`` are reported; a truncated run never claims complete coverage.
    """
    _audit_log("blueteam_abuseipdb_report", {
        "from_alerts": params.from_alerts,
        "srcip_count": len(params.srcips),
        "dry_run": params.dry_run,
        "confirm": params.confirm,
    })

    if params.from_alerts:
        candidates, meta = await _harvest_candidates(params)
    else:
        candidates = [{
            "ip": ip, "alert_count": 1, "first_seen": "", "last_seen": "",
            "max_level": None, "rule_ids": [], "rule_groups": [],
            "source": "explicit", "role": "srcip", "role_check": "not_applicable",
        } for ip in params.srcips]
        meta = {"source": "explicit", "window": None, "remaining_candidates": 0,
                "truncated": False, "role_check": "not_applicable"}

    try:
        evaluated = await _evaluate(candidates, params)
    except AbuseIPDBError as exc:
        raise ThreatIntelError(
            f"[blueteam_abuseipdb_report] {exc.kind}: {exc.message}") from exc

    if params.dry_run or not params.confirm:
        reason = "dry_run=true" if params.dry_run else "confirm=true is required"
        for row in evaluated:
            if row.get("status") == "eligible":
                row["status"] = "would_report"
        output = _summary(evaluated, meta, params, preview_reason=reason)
        if params.response_format == "json":
            return _truncate_if_needed(json.dumps(output, indent=2, default=str))
        return _truncate_if_needed(_render_report_output(output))

    if not ABUSEIPDB_REPORTING_ENABLED:
        raise ThreatIntelError(
            "[blueteam_abuseipdb_report] reporting is disabled; set "
            "BLUETEAM_ABUSEIPDB_REPORTING_ENABLED=true after analyst approval")

    for row in evaluated:
        if row.get("status") != "eligible":
            continue
        try:
            submitted = await report_ip(
                row["ip"], row["categories"],
                comment=row["comment"],
                timestamp=row.get("timestamp_used"),
                alert_count=int(row.get("alert_count") or 1),
                first_seen=row.get("first_seen") or "",
                last_seen=row.get("last_seen") or "",
                rule_ids=row.get("rule_ids") or [])
            row["status"] = submitted["status"]
            row["verified"] = submitted.get("verified")
            row["abuse_confidence_score"] = submitted.get("abuse_confidence_score")
        except AbuseIPDBError as exc:
            row["status"] = "failed"
            row["error_kind"] = exc.kind
            row["error"] = exc.message
            stop_status = ""
            if exc.kind == "auth_error":
                stop_status = "skipped_auth_error"
            elif exc.kind == "circuit_open":
                stop_status = "skipped_upstream"
            elif exc.kind == "quota_exhausted":
                stop_status = "skipped_quota"
            elif exc.kind == "rate_limited" and (
                    "daily rate limit" in exc.message.lower()
                    or "quota" in exc.message.lower()
                    or "rate limited" in exc.message.lower()):
                stop_status = "skipped_quota"
            if stop_status:
                for pending in evaluated:
                    if pending.get("status") == "eligible":
                        pending["status"] = stop_status
                break

    output = _summary(evaluated, meta, params)
    if params.response_format == "json":
        return _truncate_if_needed(json.dumps(output, indent=2, default=str))
    return _truncate_if_needed(_render_report_output(output))
