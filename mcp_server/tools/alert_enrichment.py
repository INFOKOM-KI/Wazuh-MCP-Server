#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Alert enrichment tools - curated report, threat card, attack chain, beacon detect, summarize, compare
"""
from __future__ import annotations
import json, re, math, asyncio, os
from datetime import datetime, timedelta, timezone
from typing import Optional, Literal, Any
from collections import Counter
from pydantic import BaseModel, ConfigDict, Field, field_validator
from mcp.server.fastmcp import Context
from mcp_server import (mcp, WAZUH_INDEXER_URL, WAZUH_INDEXER_PASSWORD,
                        _WAZUH_INDEXER_MAX_SIZE, _BYPASS_REDACTION_DESC, _REDACTION_POLICY_DESC, _REVEAL_OWNED_DESC, _FORENSIC_TOKEN_DESC,
                        CROWDSEC_API_KEY_ENV, ARGUS_API_KEY_ENV,
                        VIRUSTOTAL_API_KEY,
                        GREYNOISE_COMMUNITY_BASE_URL, ARGUS_BASE_URL,
                        NETRA_MIN_INTERVAL, ARGUS_MIN_INTERVAL, SANGFOR_MIN_INTERVAL)
from mcp_server.core.audit import _audit_log, _truncate_if_needed, _escape_md_table
from mcp_server.core.exceptions import ThreatIntelError
from mcp_server.core.http_client import ValidPublicIp
from mcp_server.core.redact import _redact_alert_data
from mcp_server.core.http_client import _api_call, _handle_api_error
from mcp_server.core.validators import ValidAgentName, ValidKeyword, ValidRuleGroups
from mcp_server.wazuh.indexer import _wazuh_indexer_post, _WAZUH_INDEX_PATTERNS
from mcp_server.wazuh.time_utils import _parse_time_window, _duration_minutes
from mcp_server.threat_intel.crowdsec import _crowdsec_request
from mcp_server.threat_intel._cache import get_limiter
from mcp_server.threat_intel.virustotal import issue_consent
from mcp_server.threat_intel.virustotal_consent import (consent_message,
                                                        request_ioc_sharing)

# Per-provider outbound lookup spacing (Netra/Argus 30s, Sangfor 5s).
# max_concurrent=1 serializes requests so min_interval is strictly enforced.
_netra_limiter = get_limiter("netra", max_concurrent=1, min_interval=NETRA_MIN_INTERVAL)
_argus_limiter = get_limiter("argus", max_concurrent=1, min_interval=ARGUS_MIN_INTERVAL)
_sangfor_limiter = get_limiter("sangfor", max_concurrent=1, min_interval=SANGFOR_MIN_INTERVAL)

# 1: Alert Summarization
# Standalone threat-intel + Sangfor + unified scoring tools (remaining after alert-enrichment modular split)


def _virustotal_fields(data: dict) -> dict:
    keys = ("malicious", "suspicious", "harmless", "undetected", "timeout",
            "stats_complete", "missing_stats", "total_engines",
            "detection_percent", "any_detection", "community_reputation",
            "as_owner", "asn", "network", "country", "total_votes", "tags",
            "last_analysis_date", "http_status", "cached", "retrieved_at",
            "cache_age_seconds", "cache_ttl_seconds", "cache_expired")
    return {key: data.get(key) for key in keys}


def _virustotal_markdown(title: str, value: str, data: dict) -> str:
    from mcp_server.threat_intel.virustotal import markdown_text

    complete = data.get("stats_complete", True)
    total = data.get("total_engines")
    total_label = str(total) if complete and total is not None else "?"
    percent = data.get("detection_percent")
    detection = f"{data.get('malicious', 0)}/{total_label}"
    if complete and percent is not None:
        detection += f" ({percent}%)"
    else:
        detection += " (incomplete)"
    cache_age = data.get("cache_age_seconds")
    cache_age_text = (f"{cache_age}s (TTL {data.get('cache_ttl_seconds', 0)}s)"
                      if cache_age is not None else "-")
    lines = [
        f"# {title} - {markdown_text(value, 253)}",
        "",
        f"- **Malicious**: {data.get('malicious', 0)}",
        f"- **Suspicious**: {data.get('suspicious') if data.get('suspicious') is not None else '-'}",
        f"- **Harmless**: {data.get('harmless') if data.get('harmless') is not None else '-'}",
        f"- **Undetected**: {data.get('undetected') if data.get('undetected') is not None else '-'}",
        f"- **Timeout**: {data.get('timeout') if data.get('timeout') is not None else '-'}",
        f"- **Total engines**: {total_label if total_label != '?' else 'incomplete'}",
        f"- **Detection**: {detection}",
        f"- **Community reputation**: "
        f"{data.get('community_reputation') if data.get('community_reputation') is not None else '-'}",
        f"- **Source**: {'cache' if data.get('cached') else 'live API'}",
        f"- **Retrieved**: {data.get('retrieved_at') or '-'}",
        f"- **Cache age**: {cache_age_text}",
        f"- **Cache expired**: {'yes' if data.get('cache_expired') else 'no'}",
    ]
    for key, label in (("as_owner", "AS owner"), ("asn", "ASN"),
                       ("network", "Network"), ("country", "Country"),
                       ("last_analysis_date", "Last analysis date")):
        if data.get(key) is not None:
            lines.append(f"- **{label}**: {markdown_text(data[key])}")
    if data.get("tags"):
        tags = ", ".join(markdown_text(tag, 64) for tag in data["tags"])
        lines.append(f"- **Tags**: {tags}")
    if data.get("total_votes"):
        votes = ", ".join(f"{key}={value}" for key, value in data["total_votes"].items())
        lines.append(f"- **Community votes**: {votes}")
    return "\n".join(lines)


class VirusTotalHashInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=False, extra="forbid")
    hash: str = Field(..., max_length=64, description="File hash (MD5/SHA1/SHA256)")
    response_format: str = Field(default="markdown", description="'markdown' or 'json'")
    acknowledge_ioc_sharing: bool = Field(
        default=False,
        description=("Request host confirmation before sending the hash to VirusTotal. "
                     "This flag is a request to prompt, not proof of human consent. Default false."),
    )

    @field_validator("hash")
    @classmethod
    def _hash_format(cls, value: str) -> str:
        from mcp_server.threat_intel.virustotal import normalize_hash
        return normalize_hash(value)


# VirusTotal Hash
@mcp.tool(
    name="blueteam_lookup_hash_virustotal",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_lookup_hash_virustotal(params: VirusTotalHashInput,
                                          ctx: Context | None = None) -> str:
    """Check a file hash against VirusTotal's existing report.

    Args:
        params.hash: MD5, SHA-1, or SHA-256 hexadecimal digest.
        params.response_format: 'markdown' (default) or 'json'.
        params.acknowledge_ioc_sharing: requests host confirmation; it is not proof of consent.

    Returns:
        Engine counts, detection percentage, community reputation, and available
        AS/network/tag metadata. No scan is submitted. ``stats_complete=false`` and
        ``missing_stats`` mark a partial ``last_analysis_stats`` object; the tool
        does not compute a percentage or a malicious verdict from that object.
        Zero malicious detections is not a benign confirmation; no report or an
        upstream failure is an unavailable result, not a clean one.

    Examples:
        1. SHA-256 in Markdown:
           ``blueteam_lookup_hash_virustotal(hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
           acknowledge_ioc_sharing=True)``
        2. MD5 in JSON:
           ``blueteam_lookup_hash_virustotal(hash="44d88612fea8a8f36de82e1278abb02f",
           response_format="json", acknowledge_ioc_sharing=True)``
        3. Malformed or path-like value:
           ``blueteam_lookup_hash_virustotal(hash="../../domains/example.com")``
           returns a validation error before any request.

    Permissions: read-only; the default read scope is sufficient. The tool never
    writes to VirusTotal.

    Rate limits: a local operator budget must be armed and the request then obeys
    the configured per-minute and daily provider limits. The default budget is 0 and
    normal startup does not create state, so an uninitialized or zero-budget deployment
    refuses before transport. A cached report is free. A 429
    sets a cooldown. The local budget is persistent and shared across server
    processes; the TTL cache is process-local and does not survive a restart.

    Privacy: the hash leaves the host and VirusTotal adds the queried indicator
    to its community dataset. Send only indicators the organization is authorized
    to share and set ``acknowledge_ioc_sharing=true``.
    """
    _audit_log("blueteam_lookup_hash_virustotal", {"hash": params.hash})
    from mcp_server import VIRUSTOTAL_API_KEY
    if not VIRUSTOTAL_API_KEY:
        raise ThreatIntelError("[virustotal] not_configured: VIRUSTOTAL_API_KEY is not set")
    from mcp_server.threat_intel.virustotal import VirusTotalError, lookup
    if not params.acknowledge_ioc_sharing:
        raise ThreatIntelError(
            "[virustotal] consent_required: set acknowledge_ioc_sharing=true to request host approval")
    if not await request_ioc_sharing(
            ctx, consent_message("files", params.hash)):
        raise ThreatIntelError(
            "[virustotal] consent_required: host approval was not granted")
    try:
        data = await lookup("files", params.hash,
                            consent_token=issue_consent("files", params.hash))
    except VirusTotalError as e:
        raise ThreatIntelError(f"[virustotal] {e.kind}: {e.message}") from e
    if params.response_format == "json":
        return _truncate_if_needed(json.dumps(
            {"hash": params.hash, **_virustotal_fields(data)}, indent=2))
    return _truncate_if_needed(_virustotal_markdown("VirusTotal Hash", params.hash, data))


class VirusTotalDomainInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=False, extra="forbid")
    domain: str = Field(..., max_length=253, description="Domain name")
    response_format: str = Field(default="markdown", description="'markdown' or 'json'")
    acknowledge_ioc_sharing: bool = Field(
        default=False,
        description=("Request host confirmation before sending the domain to VirusTotal. "
                     "This flag is a request to prompt, not proof of human consent. Default false."),
    )

    @field_validator("domain")
    @classmethod
    def _domain_format(cls, value: str) -> str:
        from mcp_server.threat_intel.virustotal import normalize_domain
        return normalize_domain(value)


# VirusTotal Domain
@mcp.tool(
    name="blueteam_lookup_domain_virustotal",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_lookup_domain_virustotal(params: VirusTotalDomainInput,
                                            ctx: Context | None = None) -> str:
    """Check a domain against VirusTotal's existing report.

    Args:
        params.domain: DNS name with at least two labels. IDNA is normalized to
            lowercase ASCII; schemes, paths, queries, fragments, userinfo, ports,
            whitespace, and path traversal are rejected.
        params.response_format: 'markdown' (default) or 'json'.
        params.acknowledge_ioc_sharing: requests host confirmation; it is not proof of consent.

    Returns:
        Engine counts, detection percentage, community reputation, and available
        AS/network/tag metadata. No scan is submitted. ``stats_complete=false`` and
        ``missing_stats`` mark a partial ``last_analysis_stats`` object; the tool
        does not compute a percentage or a malicious verdict from that object.
        Zero malicious detections is not a benign confirmation; no report or an
        upstream failure is an unavailable result, not a clean one.

    Examples:
        1. Apex domain in Markdown:
           ``blueteam_lookup_domain_virustotal(domain="example.com",
           acknowledge_ioc_sharing=True)``
        2. Subdomain in JSON:
           ``blueteam_lookup_domain_virustotal(domain="login.example.com",
           response_format="json", acknowledge_ioc_sharing=True)``
        3. Internationalized domain:
           ``blueteam_lookup_domain_virustotal(domain="münich.example")``
           is sent as its IDNA form.
        4. A path or query is rejected before transport:
           ``blueteam_lookup_domain_virustotal(domain="example.com/../../comments")``

    Permissions: read-only; the default read scope is sufficient. The tool never
    writes to VirusTotal.

    Rate limits: a local operator budget must be armed and the request then obeys
    the configured per-minute and daily provider limits. The default budget is 0 and
    normal startup does not create state, so an uninitialized or zero-budget deployment
    refuses before transport. A cached report is free. A 429
    sets a cooldown. The local budget is persistent and shared across server
    processes; the TTL cache is process-local and does not survive a restart.

    Privacy: the domain leaves the host and VirusTotal adds the queried indicator
    to its community dataset. Send only indicators the organization is authorized
    to share and set ``acknowledge_ioc_sharing=true``.
    """
    _audit_log("blueteam_lookup_domain_virustotal", {"domain": params.domain})
    from mcp_server import VIRUSTOTAL_API_KEY
    if not VIRUSTOTAL_API_KEY:
        raise ThreatIntelError("[virustotal] not_configured: VIRUSTOTAL_API_KEY is not set")
    from mcp_server.threat_intel.virustotal import VirusTotalError, lookup
    if not params.acknowledge_ioc_sharing:
        raise ThreatIntelError(
            "[virustotal] consent_required: set acknowledge_ioc_sharing=true to request host approval")
    if not await request_ioc_sharing(
            ctx, consent_message("domains", params.domain)):
        raise ThreatIntelError(
            "[virustotal] consent_required: host approval was not granted")
    try:
        data = await lookup("domains", params.domain,
                            consent_token=issue_consent("domains", params.domain))
    except VirusTotalError as e:
        raise ThreatIntelError(f"[virustotal] {e.kind}: {e.message}") from e
    if params.response_format == "json":
        return _truncate_if_needed(json.dumps(
            {"domain": params.domain, **_virustotal_fields(data)}, indent=2))
    return _truncate_if_needed(_virustotal_markdown("VirusTotal Domain", params.domain, data))


# Argus response rendering is provider-agnostic: no provider name and no field path is
# hardcoded, so a renamed key, a new provider under "results", or an extra nesting level
# still renders. Long free text values (honeypot comments, ~4 KB each) are reported as
# counts instead of content, which keeps the response small and keeps the victim emails
# and internal IPs inside them out of the LLM context. Use response_format="json" for
# the verbatim payload.
_ARGUS_MAX_DEPTH = 4          # nested objects summarised past this depth
_ARGUS_MAX_DIGEST = 3         # top values printed per low-cardinality field
_ARGUS_VALUE_CHARS = 240      # longest scalar printed verbatim
_ARGUS_FREE_TEXT_CHARS = 120  # longer strings are counted, not printed


def _argus_scalar(value: Any) -> str:
    """One JSON scalar as display text, bounded so a log blob cannot take over."""
    if value is None or isinstance(value, (bool, int, float)):
        return str(value)
    text = str(value)
    return text if len(text) <= _ARGUS_VALUE_CHARS else text[:_ARGUS_VALUE_CHARS] + "..."


def _argus_is_timestamp(value: str) -> bool:
    try:
        datetime.fromisoformat(value)
        return True
    except ValueError:
        return False


def _argus_list_digest(items: list) -> str:
    """Summarise a list of objects: size, time span, and top values per field.
    Field names come from the data, so a renamed or added field flows through.
    Free-text values (whitespace, an @, or over-long) are counted, never printed: report
    comments are where victim emails and internal IPs hide.
    """
    fields: dict[str, str] = {}
    keys = {k for item in items if isinstance(item, dict) for k in item}
    for key in sorted(keys):  # deterministic order across runs
        present = [item.get(key) for item in items if isinstance(item, dict)]
        present = [v for v in present if v not in (None, "", [], {})]
        if not present:
            continue
        if all(isinstance(v, str) and _argus_is_timestamp(v) for v in present):
            fields[key] = f"newest {max(present)}, oldest {min(present)}"
            continue
        counts: Counter = Counter()
        prose = 0
        for value in present:
            for entry in (value if isinstance(value, list) else [value]):
                if isinstance(entry, str) and (" " in entry or "@" in entry
                                               or len(entry) > _ARGUS_FREE_TEXT_CHARS):
                    prose += 1
                elif isinstance(entry, (str, int, bool)):
                    counts[str(entry)] += 1
        bits = [f"{v} ({n})" for v, n in counts.most_common(_ARGUS_MAX_DIGEST)]
        if prose:
            bits.append(f"{prose} text value(s), not expanded")
        if bits:
            fields[key] = ", ".join(bits)
    return " | ".join([f"{len(items)} items", *[f"{k}: {v}" for k, v in fields.items()]])


def _argus_lines(node: Any, path: str = "", depth: int = 0):
    """Yield ``- **path**: value`` bullets for any JSON shape, whatever it holds."""
    if depth > _ARGUS_MAX_DEPTH:
        yield f"- **{path}**: (nested, not expanded)"
    elif isinstance(node, dict):
        if not node:
            yield f"- **{path}**: (empty)"
        for key, value in node.items():
            child = f"{path}.{key}" if path else str(key)
            if isinstance(value, (dict, list)):
                yield from _argus_lines(value, child, depth + 1)
            else:
                yield f"- **{child}**: {_argus_scalar(value)}"
    elif isinstance(node, list):
        if not node:
            yield f"- **{path}**: (empty)"
        elif all(isinstance(i, dict) for i in node):
            yield f"- **{path}**: {_argus_list_digest(node)}"
        else:
            shown = ", ".join(_argus_scalar(i) for i in node[:12])
            more = f" (+{len(node) - 12} more)" if len(node) > 12 else ""
            yield f"- **{path}**: {shown}{more}"
    else:
        yield f"- **{path}**: {_argus_scalar(node)}"


def _format_argus_markdown(raw: Any, ip: str) -> str:
    """Render the Argus envelope, adapting to whatever it currently returns."""
    if not isinstance(raw, dict) or not raw:
        return f"# Argus - {ip}\n\n- (no results in response)"
    envelope = raw.get("results")
    lines = [f"# Argus - {ip}", ""]
    if not isinstance(envelope, dict) or not envelope:
        # No per-provider envelope: render the payload itself, whatever it is.
        body = list(_argus_lines(raw)) or ["- (no data)"]
        return "\n".join([*lines, *body]).strip()
    for name, block in envelope.items():
        success = block.get("success") if isinstance(block, dict) else None
        status = "" if success is None else (" - success" if success else " - failed")
        lines.append(f"## {name}{status}")
        payload = block.get("results", block) if isinstance(block, dict) else block
        lines.extend(list(_argus_lines(payload)) if payload else ["- (no data)"])
        lines.append("")
    return "\n".join(lines).strip()


class ArgusIpLookupInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    ip: ValidPublicIp = Field(..., description="Public IP to query")
    response_format: str = Field(default="markdown", description="'markdown' or 'json'")


# Argus
@mcp.tool(
    name="argus_ip_lookup",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def argus_ip_lookup(params: ArgusIpLookupInput) -> str:
    """Query Argus Threat Intelligence (TangerangKota-CSIRT) aggregating 7 sources.
    Renders every provider the response contains, with no hardcoded provider or field
    names, so a changed response structure still renders instead of showing blanks.
    Args:
        params.ip: Public IP to query
        params.response_format: 'markdown' (summarised, dynamic) or 'json' (verbatim)
    """
    _audit_log("argus_ip_lookup", {"ip": params.ip})
    from mcp_server import ARGUS_API_KEY_ENV, ARGUS_VERIFY_SSL, ARGUS_BASE_URL
    api_key = os.environ.get(ARGUS_API_KEY_ENV, "")
    if not api_key:
        return json.dumps({"error": "ARGUS_API_KEY must be set."})
    try:
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json", "accept": "application/json"}
        async with _argus_limiter:
            resp = await _api_call("post", ARGUS_BASE_URL, client_name="argus", verify=ARGUS_VERIFY_SSL,
                                    headers=headers, json={"observable": params.ip})
        if not resp.content:
            return json.dumps({"error": "Argus API returned empty response"})
        raw = resp.json()
        if params.response_format == "json":
            return _truncate_if_needed(json.dumps(raw, indent=2))
        # Safety net: the renderer already drops prose, but a top level field can still
        # carry a victim email or an internal IP. Benign fields (isp, domain, country,
        # categories) pass through the redaction boundary untouched.
        return _truncate_if_needed(_redact_alert_data(_format_argus_markdown(raw, params.ip)))
    except Exception as e:
        _handle_api_error(e, context="argus")


class NetraIpAnalysisInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    ip: ValidPublicIp = Field(..., description="Public IP to analyze")
    response_format: str = Field(default="markdown", description="'markdown' or 'json'")
    bypass_redaction: bool = Field(default=False, description="When true, skip PII/credential redaction")


# Netra fans out to six upstream sources; a score from fewer is partial.
_NETRA_EXPECTED_SOURCES = 6


@mcp.tool(
    name="netra_ip_analysis",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def netra_ip_analysis(params: NetraIpAnalysisInput) -> str:
    """Query Netra Threat Intelligence for IP analysis.
    Args:
        params.ip: Public IP to analyze
        params.response_format: 'markdown' or 'json'
        params.bypass_redaction: When true, skip PII/credential redaction for audit investigations.
    """
    _audit_log("netra_ip_analysis", {"ip": params.ip})
    from mcp_server import NETRA_API_KEY_ENV, NETRA_VERIFY_SSL, NETRA_BASE_URL
    api_key = os.environ.get(NETRA_API_KEY_ENV, "")
    if not api_key:
        return json.dumps({"error": "NETRA_API_KEY not set."})
    try:
        headers = {"X-API-Key": api_key, "accept": "application/json"}
        async with _netra_limiter:
            # Netra fans out to ~6 sources; 34s measured in production. Give it 90s
            # instead of the global HTTP_TIMEOUT so a 'slow but healthy' lookup does not
            # count as a failure and trip the circuit breaker.
            resp = await _api_call("get", f"{NETRA_BASE_URL}/analysis/{params.ip}",
                                   headers=headers, verify=NETRA_VERIFY_SSL, timeout=90.0)
        raw = resp.json()
        if params.response_format == "json":
            return _truncate_if_needed(json.dumps(raw, indent=2))
        data = raw.get("data", {}).get("results", {})
        ts = data.get("threat_score", {})
        ai = data.get("ai_insight", {})
        ipapi = data.get("ipapi", {}).get("results", {})
        score = ts.get("score")
        level = ts.get("level") or "?"
        sources_ok = ts.get("sources_available") if isinstance(ts.get("sources_available"), list) else []
        sources_fail = ts.get("sources_failed") if isinstance(ts.get("sources_failed"), list) else []
        if not sources_ok:
            coverage = "unavailable"
        elif sources_fail or len(sources_ok) + len(sources_fail) < _NETRA_EXPECTED_SOURCES:
            coverage = "partial"
        else:
            coverage = "complete"
        score_text = f"{score} ({level})" if score is not None and sources_ok else "not available"
        lines = [f"# Netra — {params.ip}", "",
                 f"- **Score**: {score_text}",
                 f"- **Coverage**: {coverage}",
                 f"- **Sources OK**: {', '.join(sources_ok) if sources_ok else 'none'}",
                 f"- **Sources Failed**: {', '.join(sources_fail) if sources_fail else 'none'}",
                 ""]
        if coverage != "complete":
            lines.append(
                f"- **Partial coverage**: {len(sources_ok)} of {_NETRA_EXPECTED_SOURCES} "
                "expected sources succeeded. The score describes only those sources "
                "and is not a clean verdict.")
            lines.append("")
        if ipapi:
            lines.append(f"- **ISP**: {ipapi.get('isp', '?')}")
            lines.append(f"- **Country**: {ipapi.get('country', '?')} ({ipapi.get('city', '?')})")
        if ai.get("success"):
            lines.append(f"- **AI Insight**: {ai.get('insight', '?')[:200]}")
        return _truncate_if_needed("\n".join(lines))
    except Exception as e:
        _handle_api_error(e, context="netra")


# Sangfor Blocklist Lookup
def _format_sangfor_blocklist_markdown(raw: Any) -> str:
    """Render a Sangfor /blocklist response as a markdown table.
    Accepts a raw list of entry objects or a normalized dict with an
    ``entries``/``data`` key. Truncates to the first 50 rows. Fields shown:
    ip_address, isp, location, blockmode, wazuh_score, tip_score, overall_score.
    """
    if isinstance(raw, list):
        items = raw
    else:
        items = raw.get("data") or raw.get("entries") or []
    if not items:
        return ("# Sangfor Blocklist (0 IPs)\n\n_No entries in this window. An empty "
                "result only covers the available records; it is not proof the IP was "
                "never blocked._")
    lines = ["| IP | ISP | Location | Block Mode | Wazuh | TIP | Overall |",
             "|----|-----|----------|------------|-------|-----|---------|"]
    for i in items[:50]:
        lines.append("| `{}` | {} | {} | {} | {} | {} | {} |".format(
            _escape_md_table(str(i.get("ip_address", "?"))),
            _escape_md_table(str(i.get("isp", "?"))),
            _escape_md_table(str(i.get("location", "?"))),
            _escape_md_table(str(i.get("blockmode", "?"))),
            i.get("wazuh_score", "-"),
            i.get("tip_score", "-"),
            i.get("overall_score", "-"),
        ))
    return f"# Sangfor Blocklist ({len(items)} IPs)\n\n" + "\n".join(lines)


class SangforBlocklistCheckInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    ip: ValidPublicIp = Field(..., min_length=3, max_length=45)
    response_format: str = Field(default="markdown")

class SangforBlocklistListInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    limit: int = Field(default=100, ge=1, le=1000000)
    offset: int = Field(default=0, ge=0, le=1000000,
                        description="Pagination offset for the result set.")
    ip: Optional[ValidPublicIp] = Field(default=None, min_length=3, max_length=45,
                                        description="Attacker IP / IoC filter. When provided, only blocklist entries matching this IP are returned.")
    # 32, not 24: an ISO-8601 timestamp with a numeric UTC offset
    # (2026-11-06T00:00:00+07:00) is 25 chars and is passed through as-is.
    date_start: str = Field(default="", max_length=32,
                            description="Start date. ISO 8601 (e.g. 2026-08-18T17:27:00Z or 2026-08-18T17:27:00+07:00) or YYYY-MM-DD HH:MM:SS. Defaults to 30 days ago (UTC, ISO-8601).")
    date_end: str = Field(default="", max_length=32,
                          description="End date. ISO 8601 (e.g. 2026-08-19T17:27:00Z or 2026-08-19T17:27:00+07:00) or YYYY-MM-DD HH:MM:SS. Defaults to now (UTC, ISO-8601).")
    response_format: str = Field(default="markdown")

@mcp.tool(
    name="sangfor_blocklist_check",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def sangfor_blocklist_check(params: SangforBlocklistCheckInput) -> str:
    """Check if an IP is currently blocked by Sangfor firewall."""
    # Sangfor e2e: the /check/{ip} path is UNVERIFIED against the live Sangfor
    # API (URL/token redacted). Documented contract is POST /blocklist with
    # {date_start, date_end, limit, offset, ip} - validate this path, or fold it
    # into sangfor_blocklist_list(ip=...) with limit=1, once live credentials exist.
    _audit_log("sangfor_blocklist_check", {"ip": params.ip})
    from mcp_server import (SANGFOR_BLOCKLIST_URL, SANGFOR_BLOCKLIST_TOKEN,
                            SANGFOR_BLOCKLIST_VERIFY_SSL, SANGFOR_BLOCKLIST_TIMEOUT)
    if not SANGFOR_BLOCKLIST_TOKEN or not SANGFOR_BLOCKLIST_URL:
        return json.dumps({"error": "SANGFOR_BLOCKLIST_TOKEN and SANGFOR_BLOCKLIST_URL must be set."})
    try:
        headers = {"Authorization": f"Bearer {SANGFOR_BLOCKLIST_TOKEN}", "accept": "application/json"}
        async with _sangfor_limiter:
            resp = await _api_call("get", f"{SANGFOR_BLOCKLIST_URL}/check/{params.ip}", headers=headers,
                                   timeout=SANGFOR_BLOCKLIST_TIMEOUT, max_retries=0)
        raw = resp.json()
        if isinstance(raw, list):
            raw = {"blocked": len(raw) > 0, "entries": raw}
        if not isinstance(raw, dict):
            raw = {"entries": []}
        blocked = raw.get("blocked")
        if blocked is True:
            status = "blocked"
        elif blocked is False:
            status = "not_blocked"
        else:
            # The /check contract is unverified, so an absent boolean stays unknown.
            status = "unknown"
        if params.response_format == "json":
            return _truncate_if_needed(json.dumps({
                "ip": params.ip,
                "blocked": blocked,
                "status": status,
                "entries": raw.get("entries") or raw.get("data") or [],
                "note": ("The endpoint did not report an explicit blocked boolean, "
                         "so the status is unknown."
                         if status == "unknown" else None),
            }, indent=2))
        verdict = ("blocked" if blocked is True else
                   "not blocked" if blocked is False else "unknown")
        return _truncate_if_needed(
            f"# Sangfor Blocklist - {params.ip}\n\n- **Blocked**: {verdict}" +
            ("\n- **Note**: the endpoint returned no `blocked` field; this is not "
             "evidence that the IP was never blocked." if status == "unknown" else ""))
    except Exception as e:
        _handle_api_error(e, context="sangfor")

@mcp.tool(
    name="sangfor_blocklist_list",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def sangfor_blocklist_list(params: SangforBlocklistListInput) -> str:
    """List IP blocked by Sangfor firewall, optionally filtered by timestamp and/or attacker IP/IoC.
    Sends a POST to the Sangfor /blocklist endpoint (SANGFOR_BLOCKLIST_URL already
    includes the /blocklist path) with a JSON body {date_start, date_end, limit,
    offset, ip}. The `ip` key is OMITTED from the body when no IP filter is given
    (rather than sending null) so the endpoint sees a pure listing query.
    """
    _audit_log("sangfor_blocklist_list", {"ip": params.ip, "limit": params.limit,
               "offset": params.offset, "date_start": params.date_start,
               "date_end": params.date_end})
    from mcp_server import (SANGFOR_BLOCKLIST_URL, SANGFOR_BLOCKLIST_TOKEN,
                            SANGFOR_BLOCKLIST_VERIFY_SSL, SANGFOR_BLOCKLIST_TIMEOUT)
    if not SANGFOR_BLOCKLIST_TOKEN or not SANGFOR_BLOCKLIST_URL:
        return json.dumps({"error": "SANGFOR_BLOCKLIST_TOKEN and SANGFOR_BLOCKLIST_URL must be set."})
    try:
        headers = {"Authorization": f"Bearer {SANGFOR_BLOCKLIST_TOKEN}",
                   "accept": "application/json", "content-type": "application/json"}
        # Client-side date defaults: 30 days ago -> now, strict ISO-8601 (UTC, Z suffix)
        date_start = params.date_start or (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        date_end = params.date_end or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        body: dict = {"date_start": date_start, "date_end": date_end,
                      "limit": params.limit, "offset": params.offset}
        if params.ip:
            body["ip"] = params.ip
        # POST to SANGFOR_BLOCKLIST_URL directly the URL already ends in /blocklist
        async with _sangfor_limiter:
            # timeout + max_retries=0: a 30s default x 2 attempts exceeded the MCP
            # client's ~60s tool deadline, surfacing as an opaque AbortError.
            resp = await _api_call("post", SANGFOR_BLOCKLIST_URL, json=body,
                                   headers=headers, verify=SANGFOR_BLOCKLIST_VERIFY_SSL,
                                   timeout=SANGFOR_BLOCKLIST_TIMEOUT, max_retries=0)
        raw = resp.json()
        if isinstance(raw, list):
            raw = {"blocked": len(raw) > 0, "count": len(raw), "entries": raw}
        if params.response_format == "json":
            return _truncate_if_needed(json.dumps(raw, indent=2))
        return _truncate_if_needed(_format_sangfor_blocklist_markdown(raw))
    except Exception as e:
        _handle_api_error(e, context="sangfor_list")


# Unified Threat Confidence Scoring
class UnifiedThreatScoreInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    ip: ValidPublicIp = Field(..., min_length=7, max_length=45, description="Public IP to score.")
    response_format: str = Field(default="markdown", description="'markdown' or 'json'.")


@mcp.tool(
    name="blueteam_unified_threat_score",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
)
async def blueteam_unified_threat_score(params: UnifiedThreatScoreInput) -> str:
    """Query multiple threat intel sources and return a unified confidence score.
    Aggregates CrowdSec + ThreatFox + AbuseIPDB into a single weighted verdict
    (0.0 to 1.0) eliminating the need for 3+ sequential LLM tool calls per IP.
    """
    _audit_log("blueteam_unified_threat_score", {"ip": params.ip})

    async def _crowdsec(ip):
        try:
            from mcp_server.threat_intel.crowdsec import _crowdsec_request
            r = await _crowdsec_request(f"/v2/smoke/{ip}"); rep = r.get("reputation","unknown")
            m = {"malicious":1.0,"suspicious":0.5,"known":0.2,"unknown":0.1,"safe":0.0}
            return m.get(rep,0.1), {"reputation":rep,"behaviors":[b.get("name","?") for b in r.get("behaviors",[])[:3]]}
        except Exception: return 0.0, {}

    async def _threatfox(ip):
        try:
            from mcp_server.threat_intel.threatfox import _threatfox_request
            r = await _threatfox_request(ip,False); items = r.get("data",[])
            if not items: return 0.0, {}
            c = max(e.get("confidence_level",0) for e in items)/100.0
            return c, {"malware":items[0].get("malware_printable","?"),"threat_type":items[0].get("threat_type_desc","?"),"confidence":items[0].get("confidence_level",0)}
        except Exception: return 0.0, {}

    async def _abuseipdb(ip):
        from mcp_server.threat_intel.abuseipdb import AbuseIPDBError, check_ip
        try:
            d = await check_ip(ip, max_age_days=90)
            return (d["abuse_confidence_score"] / 100.0,
                    {"confidence": d["abuse_confidence_score"],
                     "total_reports": d["total_reports"]}, "")
        except AbuseIPDBError as exc:
            return 0.0, {}, exc.kind
        except Exception as exc:  # never turn an unexpected failure into a clean vote
            return 0.0, {}, f"upstream_error: {exc}"

    cs_s, cs_d = await _crowdsec(params.ip)
    tf_s, tf_d = await _threatfox(params.ip)
    ab_s, ab_d, ab_status = await _abuseipdb(params.ip)

    w = {"crowdsec":0.35,"threatfox":0.35,"abuseipdb":0.30}
    parts = []
    if cs_d: parts.append((cs_s*w["crowdsec"], w["crowdsec"]))
    if tf_d: parts.append((tf_s*w["threatfox"], w["threatfox"]))
    if ab_d: parts.append((ab_s*w["abuseipdb"], w["abuseipdb"]))
    uw = sum(p[1] for p in parts)
    unified = sum(p[0] for p in parts)/uw if uw>0 else 0.0

    if unified>=0.8: v="CRITICAL - Active threat, escalate immediately"
    elif unified>=0.5: v="HIGH - Likely malicious, investigate"
    elif unified>=0.2: v="MEDIUM - Suspicious, monitor"
    elif parts: v="LOW — Probably benign"
    else: v="UNKNOWN - No threat intel sources available"

    ab_source = ({"score": round(ab_s, 2), **ab_d} if ab_d else
                 {"status": "not_configured" if ab_status == "not_configured"
                  else "unavailable", "error_kind": ab_status})

    if params.response_format=="json":
        return _truncate_if_needed(json.dumps({"ip":params.ip,"unified_score":round(unified,2),"verdict":v,
            "coverage": {"sources_answered": len(parts), "sources_total": 3},
            "sources":{"crowdsec":{"score":round(cs_s,2),**cs_d} if cs_d else None,
                       "threatfox":{"score":round(tf_s,2),**tf_d} if tf_d else None,
                       "abuseipdb": ab_source},
            "scoring_model":{"weights":w,"used_weight":round(uw,2)}},indent=2))

    lines=[f"# Unified Threat Score - `{params.ip}`","",f"**Score**: {unified:.2f} | **Verdict**: {v}",
           f"**Coverage**: {len(parts)}/3 sources answered","","| Source | Score | Details |","|--------|-------|---------|"]
    if cs_d: lines.append(f"| CrowdSec | {cs_s:.2f} | `{cs_d.get('reputation','?')}` - {', '.join(cs_d.get('behaviors',[])[:2])} |")
    else: lines.append("| CrowdSec | - | ⚠️ Not configured |")
    if tf_d: lines.append(f"| ThreatFox | {tf_s:.2f} | `{tf_d.get('malware','?')}` ({tf_d.get('threat_type','?')}, conf={tf_d.get('confidence','?')}) |")
    else: lines.append("| ThreatFox | - | ⚠️ Not configured |")
    if ab_d: lines.append(f"| AbuseIPDB | {ab_s:.2f} | {ab_d.get('confidence',0)}% confidence, {ab_d.get('total_reports',0)} reports |")
    else: lines.append(f"| AbuseIPDB | - | ⚠️ {ab_source['status']} ({ab_status}) |")
    return _truncate_if_needed("\n".join(lines))
