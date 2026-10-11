#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Wazuh focused crawl tool - surgical alert retrieval
"""
from __future__ import annotations
import json, re, ipaddress
from typing import Optional, Literal, Any
import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator
from mcp_server import (mcp, WAZUH_INDEXER_URL, WAZUH_INDEXER_PASSWORD,
                        _WAZUH_INDEXER_MAX_SIZE, _BYPASS_REDACTION_DESC, _REDACTION_POLICY_DESC, _REVEAL_OWNED_DESC, _REVEAL_IDENTITIES_DESC, _FORENSIC_TOKEN_DESC, _FORENSIC_FULL_OUTPUT_DESC, _RESPONSE_FORMAT_DESC,
                        BLUETEAM_ALLOW_UNTRUNCATED, CHARACTER_LIMIT)
from mcp_server.core.audit import (_audit_log, _escape_md_table, _resolve_forensic_full_output,
                                   _fit_document_prefix, _document_stub)
from mcp_server.core.http_client import _handle_api_error
from mcp_server.core.redact import _redact_alert_data
from mcp_server.wazuh.indexer import (_wazuh_indexer_post, _WAZUH_INDEX_PATTERNS, _srcip_should_clauses,
                                      _srcip_from_doc, _SRCIP_FIELD_PATHS,
                                      _KEYWORD_SEARCH_FIELDS, _encode_cursor, _decode_cursor)
from mcp_server.wazuh.time_utils import _parse_time_window
from mcp_server.core.validators import ValidAgentName

class FocusedCrawlInput(BaseModel):
    """Input model for wazuh_alert_focused_crawl - surgical deep dive into specific alert clusters."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    src_ip: Optional[str] = Field(
        default=None,
        max_length=45,
        description="Specific source IP to drill into (e.g. the top abuser from aggregate analysis).",
    )
    rule_id: Optional[str] = Field(
        default=None,
        max_length=32,
        description="Specific rule ID to drill into (e.g. '5763' for authentication failure).",
    )
    agent_name: ValidAgentName = Field(
        default=None,
        max_length=64,
        description="Filter to a specific Wazuh agent.",
    )
    since: Optional[str] = Field(
        default="24h",
        max_length=30,
        description="Start of time window (ISO 8601 or relative expression). Default '24h'.",
    )
    until: Optional[str] = Field(
        default=None,
        max_length=30,
        description="End of time window. Defaults to now.",
    )
    sample_size: int = Field(
        default=50,
        ge=1,
        le=200,
        description="Number of representative alert documents to retrieve (default 50, max 200).",
    )
    cursor: Optional[str] = Field(
        default=None,
        description="Pagination cursor from a previous crawl; resumes after the last returned document.",
    )
    include_full_log: bool = Field(
        default=True,
        description="Include the full_log field in returned documents (PII-redacted per BLUETEAM_REDACT_PII).",
    )
    bypass_redaction: bool = Field(
        default=False,
        description="Bypass PII redaction for audit investigations (requires BLUETEAM_REDACT_PII disabled).",
    )
    redaction_policy: Optional[Literal["full", "protect_victim", "raw"]] = Field(
        default=None,
        description=_REDACTION_POLICY_DESC,
    )
    reveal_owned: bool = Field(default=False, description=_REVEAL_OWNED_DESC)
    reveal_identities: bool = Field(default=False, description=_REVEAL_IDENTITIES_DESC)
    forensic_token: Optional[str] = Field(default=None, max_length=128, description=_FORENSIC_TOKEN_DESC)
    forensic_full_output: bool = Field(default=False, description=_FORENSIC_FULL_OUTPUT_DESC)
    fields: Optional[str] = Field(
        default=None,
        description="Comma-separated additional _source fields to retrieve beyond defaults. "
                    "Example: 'data.url,data.domain,data.user_agent'.",
    )
    keyword: Optional[str] = Field(
        default=None,
        max_length=1024,
        description="Optional keyword/phrase to search in alert full_log and rule description.",
    )
    response_format: Literal["markdown", "json"] = Field(
        default="markdown",
        description="'markdown' (default) for human-readable alert summaries, 'json' for structured data.",
    )

    @field_validator("src_ip")
    @classmethod
    def validate_src_ip(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v = v.strip()
            if not v:
                return None
            try:
                ipaddress.ip_address(v)
            except ValueError as exc:
                raise ValueError(f"Invalid IP address: '{v}'") from exc
        return v

    @field_validator("rule_id")
    @classmethod
    def validate_rule_id(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v = v.strip()
            if not v:
                return None
            if not re.match(r"^\d{1,10}$", v):
                raise ValueError("rule_id must be numeric (e.g. '5763')")
        return v


    @field_validator("fields")
    @classmethod
    def validate_fields(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v = v.strip()
            if not v:
                return None
            parts = [p.strip() for p in v.split(",") if p.strip()]
            for p in parts:
                if not re.match(r"^[a-zA-Z0-9_@.\-]+$", p):
                    raise ValueError(f"Invalid field name: '{p}'. Use only alphanumeric, dots, underscores, @, hyphens.")
        return v


@mcp.tool(
    name="wazuh_alert_focused_crawl",
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def wazuh_alert_focused_crawl(params: FocusedCrawlInput = FocusedCrawlInput()) -> str:
    """Surgical deep-dive into specific Wazuh alert clusters.

    After ``wazuh_alert_aggregate_analysis`` identifies hot spots (top source IPs,
    most-triggered rules, anomalous time windows), use this tool to retrieve
    representative alert samples from those specific slices with full context.

    This is the **drill-through** tool - it returns actual alert documents
    (PII-redacted per ``BLUETEAM_REDACT_PII``). Call it once per identified
    hot spot, not for the entire dataset.

    Args:
        params.src_ip: Specific source IP identified as a hot spot.
        params.rule_id: Specific rule ID (e.g. '5763') identified as a top offender.
        params.agent_name: Filter to a specific agent.
        params.since: Start of time window (default '24h').
        params.until: End of time window (default: now).
        params.sample_size: Alert documents to retrieve (default 50, max 200).
        params.cursor: Pagination cursor from a previous crawl.
        params.include_full_log: Include raw log lines (PII-redacted).
        params.bypass_redaction: Skip PII masking for audit (if BLUETEAM_REDACT_PII allows).
        params.fields: Comma-separated extra _source fields to include.
        params.response_format: 'markdown' (default) or 'json'.
        params.redaction_policy: 'full' (shape-based, default), 'protect_victim' (mask victim-owned indicators only), 'raw' (Layer 1 credential strip only, requires BLUETEAM_ALLOW_FORENSIC_BYPASS).
        params.reveal_owned: When true (forensic), expose emails/subdomains at owned domains (BLUETEAM_OWNED_DOMAINS) unmasked; Layer 1 credentials remain masked.
        params.forensic_token: Operator forensic token (matches BLUETEAM_FORENSIC_TOKEN); required for redaction_policy='raw' / bypass_redaction when that env is set.

    Returns:
        str: Representative alert documents with full context, PII-redacted.
             Includes next_cursor for further pagination into same slice.

    Example usage:
        - "Drill into the top abuser IP from the aggregate analysis"
        - "Show me 50 alerts for rule 5763 on agent HYDRA-DC from the past hour"
        - "Get full alert details for the anomalous 5-minute window at 03:15 UTC"

    Error Handling:
        - "No data found for this target" if the slice has no matching alerts
        - Circuit breaker open -> actionable retry message
        - PII redaction applied automatically (bypass with bypass_redaction=True)
    """
    _audit_log("wazuh_alert_focused_crawl", {"src_ip": params.src_ip, "rule_id": params.rule_id, "sample_size": params.sample_size})
    since_str, until_str = _parse_time_window(params.since, params.until)

    source_fields = [
        "@timestamp",
        "agent.name",
        "rule.id",
        "rule.level",
        "rule.description",
        *_SRCIP_FIELD_PATHS,
        "data.url",
        "predecoder.hostname",
        "location",
        "id",
    ]
    if params.include_full_log:
        source_fields.append("full_log")
    if params.fields:
        extras = [f.strip() for f in params.fields.split(",") if f.strip()]
        for f in extras:
            if f not in source_fields:
                source_fields.append(f)

    try:
        body = {
            "size": params.sample_size,
            "_source": source_fields,
            "query": {"bool": {"filter": [
                {"range": {"@timestamp": {"gte": since_str, "lt": until_str,
                                               "format": "strict_date_optional_time"}}},
            ]}},
            "sort": [{"@timestamp": "asc"}, {"_id": "asc"}],
        }
        if params.cursor:
            decoded = _decode_cursor(params.cursor)
            if decoded and decoded.get("search_after"):
                body["search_after"] = decoded["search_after"]
        if params.agent_name:
            body["query"]["bool"]["filter"].append({"match": {"agent.name": params.agent_name}})
        if params.src_ip:
            body["query"]["bool"]["filter"].append(_srcip_should_clauses(params.src_ip))
        if params.keyword:
            parts = [f'{f}: ({params.keyword})^{b}' if b else f'{f}: ({params.keyword})'
                     for f, b in _KEYWORD_SEARCH_FIELDS]
            body["query"]["bool"]["filter"].append(
                {"query_string": {"query": " OR ".join(parts), "default_operator": "AND", "lenient": True}})
        data = await _wazuh_indexer_post(body, index_pattern=_WAZUH_INDEX_PATTERNS["alerts"])
    except (httpx.HTTPStatusError, httpx.TimeoutException, RuntimeError) as e:
        _handle_api_error(e, context="wazuh_alert_focused_crawl")

    if isinstance(data.get("error"), str):
        return json.dumps(data, indent=2)

    hits = data.get("hits", {})
    total = hits.get("total", {})
    hit_list = hits.get("hits", [])

    hits_state = []
    for h in hit_list:
        doc = h.get("_source", h)
        if h.get("_id") and isinstance(doc, dict):
            doc = {**doc, "_id": h["_id"]}
        hits_state.append({"sort": h.get("sort"), "doc": doc})
    # Apply PII redaction to all document bodies
    docs = [_redact_alert_data(x["doc"], params=params) for x in hits_state]

    # Build next_cursor for further pagination within the same slice
    next_cursor = None
    if hit_list and len(docs) >= params.sample_size:
        last_sort = hit_list[-1].get("sort")
        if last_sort:
            next_cursor = _encode_cursor({"search_after": last_sort})

    # Count unique source IPs and rules in the sample
    unique_ips = set()
    unique_rules = set()
    level_counts: dict[str, int] = {}
    for d in docs:
        src = _srcip_from_doc(d)
        if src:
            unique_ips.add(str(src))
        rid = d.get("rule", {}).get("id") if isinstance(d.get("rule"), dict) else d.get("rule.id")
        if rid:
            unique_rules.add(str(rid))
        lvl = d.get("rule", {}).get("level") if isinstance(d.get("rule"), dict) else d.get("rule.level")
        if lvl is not None:
            band = "high" if lvl >= 10 else ("medium" if lvl >= 5 else "low")
            level_counts[band] = level_counts.get(band, 0) + 1

    def _json_payload(k: int) -> dict:
        omitted = len(docs) - k
        if omitted > 0:
            boundary = (hits_state[k - 1]["sort"] if k > 0
                        else (hits_state[0]["sort"] if hits_state else None))
            cursor = _encode_cursor({"search_after": boundary}) if boundary else next_cursor
        else:
            cursor = next_cursor
        payload = {
            "window": {"since": since_str, "until": until_str},
            "filter": {
                "src_ip": params.src_ip,
                "rule_id": params.rule_id,
                "agent_name": params.agent_name,
            },
            "total": {"value": total.get("value", 0), "relation": total.get("relation", "eq")},
            "count": k if omitted > 0 else len(docs),
            "sample_unique_ips": len(unique_ips),
            "sample_unique_rules": len(unique_rules),
            "severity_bands": level_counts,
            "next_cursor": cursor,
            "alerts": docs[:k],
        }
        if omitted > 0:
            payload["truncated"] = True
            payload["documents_omitted"] = omitted
            if k == 0 and hits_state:
                payload["oversized_documents"] = [_document_stub(hits_state[0]["doc"])]
        return payload

    full_output = _resolve_forensic_full_output(params)
    if params.response_format == "json":
        k = len(docs) if full_output else _fit_document_prefix(
            lambda n: json.dumps(_json_payload(n), indent=2, default=str), len(docs))
        return json.dumps(_json_payload(k), indent=2, default=str)

    # Markdown format
    total_val = total.get("value", 0)
    header = [
        "# Wazuh Alert Focused Crawl",
        "",
        f"**Window**: {since_str} -> {until_str}",
        "",
        "| Filter | Value |",
        "|--------|-------|",
    ]
    if params.src_ip:
        header.append(f"| Source IP | `{params.src_ip}` |")
    if params.rule_id:
        header.append(f"| Rule ID | `{params.rule_id}` |")
    if params.agent_name:
        header.append(f"| Agent | `{params.agent_name}` |")
    header.extend([
        f"| Total matching | {total_val} ({total.get('relation', 'eq')}) |",
        f"| Retrieved | {len(docs)} |",
        f"| Unique IPs in sample | {len(unique_ips)} |",
        f"| Unique rules in sample | {len(unique_rules)} |",
        "",
    ])
    if level_counts:
        header.append(f"**Severity**: L:{level_counts.get('low', 0)} M:{level_counts.get('medium', 0)} H:{level_counts.get('high', 0)}")
        header.append("")
    if not docs:
        header.append("_No alerts matched the filter criteria in this time window._")

    blocks: list[list[str]] = []
    for d in docs[:20]:
        ts = d.get("@timestamp", "?")
        rule = d.get("rule", {}) if isinstance(d.get("rule"), dict) else {}
        rid = rule.get("id", d.get("rule.id", "?"))
        desc = rule.get("description", d.get("rule.description", "?"))
        lvl = rule.get("level", d.get("rule.level", "?"))
        src = _srcip_from_doc(d) or "?"
        agent = d.get("agent", {}).get("name") if isinstance(d.get("agent"), dict) else d.get("agent.name", "?")
        block = [f"**{len(blocks) + 1}.** `{ts}` | Level {lvl} | Rule {rid} - {desc}",
                 f"- Source: `{src}` | Agent: `{agent}`"]
        full = d.get("full_log", "")
        if full:
            block.append(f"- Log: `{full}`")
        block.append("")
        blocks.append(block)

    def _markdown(rendered: int) -> str:
        lines = list(header)
        if docs:
            lines.append(f"## Alert Samples ({len(docs)} of {total_val} total)")
            lines.append("")
            for block in blocks[:rendered]:
                lines.extend(block)
            if len(docs) > 20:
                lines.append(f"_... and {len(docs) - 20} more alerts (use next_cursor for next page)_")
        cursor = next_cursor
        if rendered < len(blocks):
            boundary = (hits_state[rendered - 1]["sort"] if rendered > 0
                        else (hits_state[0]["sort"] if hits_state else None))
            cursor = _encode_cursor({"search_after": boundary}) if boundary else next_cursor
            lines.append("")
            lines.append(f"_... {len(docs) - rendered} more documents omitted to stay under the response limit; continue with next_cursor._")
            if rendered == 0 and hits_state:
                lines.append(f"_oversized document: `{_document_stub(hits_state[0]['doc'])['_id']}` - retrieve it with blueteam_wazuh_forensic_window._")
        if cursor:
            lines.append("")
            lines.append(f"**next_cursor**: `{cursor}` - pass this to the `cursor` parameter of `blueteam_wazuh_indexer_search` to continue paginating this slice.")
        return "\n".join(lines)

    if full_output:
        return _markdown(len(blocks))
    return _markdown(_fit_document_prefix(_markdown, len(blocks)))
