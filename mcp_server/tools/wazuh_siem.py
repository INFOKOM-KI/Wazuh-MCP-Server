#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Wazuh Indexer query tools - Manager API agents/rules/decoders/groups/cluster,
Indexer alerts/search, MITRE resources, and local alerts fallback.

Manager API tools use @blueteam_tool for automatic audit logging, error handling (catching WazuhAuthError / WazuhAPIError),
and response truncation. Agent filtering now passes through Wazuh's native q/sort/select/search/status/distinct parameters.

NOTE: No ``from __future__ import annotations`` — deferred annotation
      evaluation (PEP 563) breaks the @blueteam_tool decorator's type
      resolution because the wrapper's __globals__ is tool_decorator.py.
"""

import json
from pathlib import Path
from typing import Optional, Literal
from pydantic import BaseModel, ConfigDict, Field
from mcp_server import (
    WAZUH_API_URL, WAZUH_API_PASSWORD,
    WAZUH_INDEXER_PASSWORD, WAZUH_INDEXER_URL,
)
from mcp_server.core.constants import (
    _WAZUH_ALERTS_MAX_LINES, MITRE_TACTIC_TO_CATEGORY,
    _WAZUH_LOG_TAG, _WAZUH_ALERTS_PATH,
)
from mcp_server.core.tool_decorator import blueteam_tool

from mcp_server.wazuh.auth import _wazuh_api_get
from mcp_server.wazuh.indexer import (
    _WAZUH_INDEX_PATTERNS, _encode_cursor, _decode_cursor,
)

# Manager API tools - all benefit from @blueteam_tool (audit + error + trunc)
# blueteam_wazuh_get_rules
# Indexer tools (remaining after Manager API split)
from mcp_server.core.audit import _audit_log
from mcp_server.core.redact import _redact_alert_data
from mcp_server.core.subprocess import _run_async


@mcp.tool(
    name="blueteam_wazuh_alerts",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                  "idempotentHint": True, "openWorldHint": False}
)
async def blueteam_wazuh_alerts(
    agent_name: Optional[str] = None,
    srcip: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    limit: int = 500,
    cursor: Optional[str] = None,
    bypass_redaction: bool = False,
    redaction_policy: Optional[str] = None,
) -> str:
    """Read Wazuh security alerts - local alerts.json first, auto-fallback to Indexer."""
    _audit_log("blueteam_wazuh_alerts", {})
    p = Path(_WAZUH_ALERTS_PATH)
    if not p.exists():
        from mcp_server.wazuh.indexer import _wazuh_indexer_post
        from mcp_server.wazuh.time_utils import _parse_time_window
        if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
            return json.dumps({
                "error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set. "
                         "Set these to enable automatic indexer fallback, "
                         "or use blueteam_wazuh_manager_logs."
            }, indent=2)
        search_after = None
        since_iso, until_iso = _parse_time_window(since or "24h", until)
        if cursor:
            decoded = _decode_cursor(cursor)
            if decoded:
                search_after = decoded.get("search_after")
        must = [{"range": {"@timestamp": {"gte": since_iso, "lt": until_iso,
                                           "format": "strict_date_optional_time"}}}]
        if agent_name:
            must.append({"match": {"agent.name": agent_name}})
        if srcip:
            must.append({"bool": {"should": [
                {"match": {"data.srcip": srcip}},
                {"match_phrase": {"full_log": srcip}},
            ], "minimum_should_match": 1}})
        body = {
            "size": min(limit, 2000),
            "sort": [{"@timestamp": {"order": "asc"}}],
            "query": {"bool": {"must": must}},
        }
        if search_after:
            body["search_after"] = search_after
        raw = await _wazuh_indexer_post(body)
        if "error" in raw:
            return json.dumps(raw, indent=2)
        hits = raw.get("hits", {})
        docs = [h.get("_source", h) for h in hits.get("hits", [])]
        next_cursor = None
        hit_list = hits.get("hits", [])
        if hit_list and len(docs) >= limit:
            last_sort = hit_list[-1].get("sort")
            if last_sort:
                next_cursor = _encode_cursor({"search_after": last_sort})
        return _truncate_if_needed(json.dumps({
            "source": "wazuh-indexer",
            "alerts": _redact_alert_data(docs, bypass=bypass_redaction,
                                          policy=redaction_policy),
            "count": len(docs),
            "next_cursor": next_cursor,
        }, indent=2))

    # Local alerts.json path
    skip = 0
    if cursor:
        decoded = _decode_cursor(cursor)
        if decoded:
            skip = decoded.get("scanned", 0)
    page = min((skip + limit) * 3, _WAZUH_ALERTS_MAX_LINES)
    r = await _run_async(["tail", "-n", str(page), _WAZUH_ALERTS_PATH])
    if r.get("returncode", 0) != 0:
        return json.dumps({"error": "Failed to read alerts",
                            "stderr": r.get("stderr", "")})
    alerts = []
    af = (agent_name or "").strip()
    ipf = (srcip or "").strip()
    scanned = 0
    for line in (r.get("stdout") or "").strip().splitlines():
        scanned += 1
        if scanned <= skip:
            continue
        if len(alerts) >= limit:
            break
        line = line.strip()
        if not line:
            continue
        try:
            a = json.loads(line)
            if af:
                ag = a.get("agent") or {}
                n = ag.get("name") or ag.get("id", "") if isinstance(ag, dict) else str(ag)
                if af.lower() not in (n or "").lower():
                    continue
            if ipf:
                ds = str(a.get("data", {}).get("srcip", ""))
                ds2 = str(a.get("data", {}).get("srcip2", ""))
                ts = str(a.get("srcip", ""))
                fl = str(a.get("full_log", ""))
                if ipf not in (ds, ds2, ts) and ipf not in fl:
                    continue
            alerts.append(a)
        except json.JSONDecodeError:
            continue
    next_cursor = _encode_cursor({"scanned": scanned}) if len(alerts) >= limit else None
    return _truncate_if_needed(json.dumps({
        "source": "local",
        "alerts": _redact_alert_data(alerts, bypass=bypass_redaction,
                                      policy=redaction_policy),
        "count": len(alerts),
        "next_cursor": next_cursor,
    }, indent=2))


@mcp.tool(
    name="blueteam_wazuh_indexer_search",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                  "idempotentHint": True, "openWorldHint": False}
)
async def blueteam_wazuh_indexer_search(
    agent_name: Optional[str] = None,
    srcip: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    limit: int = 500,
    max_scanned: int = 0,
    cursor: Optional[str] = None,
    keyword: Optional[str] = None,
    response_format: str = "json",
    redaction_policy: Optional[str] = None,
) -> str:
    """Query Wazuh Indexer (OpenSearch) for alerts/events with cursor pagination.
    Set max_scanned > 0 for auto-pagination (server fetches up to N documents
    across multiple pages in a single call).
    """
    _audit_log("blueteam_wazuh_indexer_search", {})
    from mcp_server.wazuh.indexer import (
        _wazuh_indexer_post, _KEYWORD_SEARCH_FIELDS,
    )
    from mcp_server.wazuh.time_utils import _parse_time_window

    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return json.dumps({
            "error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set."
        }, indent=2)
    since_iso, until_iso = _parse_time_window(since, until)
    must: list[dict] = []
    if agent_name:
        must.append({"match": {"agent.name": agent_name}})
    if srcip:
        must.append({"bool": {"should": [
            {"match": {"data.srcip": srcip}},
            {"match": {"data.srcip2": srcip}},
            {"match": {"srcip": srcip}},
            {"match_phrase": {"full_log": srcip}},
        ], "minimum_should_match": 1}})
    must.append({"range": {"@timestamp": {
        "format": "strict_date_optional_time", "gte": since_iso, "lt": until_iso,
    }}})
    if keyword:
        parts = [
            f"{f}: ({keyword})^{b}" if b else f"{f}: ({keyword})"
            for f, b in _KEYWORD_SEARCH_FIELDS
        ]
        must.append({"query_string": {
            "query": " OR ".join(parts),
            "default_operator": "AND",
            "lenient": True,
        }})

    search_after = None
    if cursor:
        decoded = _decode_cursor(cursor)
        if decoded:
            search_after = decoded.get("search_after")

    all_docs: list[dict] = []
    total_scanned = 0
    total_val = 0
    total_relation = "eq"
    page_size = min(limit, 10000)
    _MAX_AUTO_SCAN = 100000
    effective_max = min(max_scanned, _MAX_AUTO_SCAN) if max_scanned > 0 else page_size

    while total_scanned < effective_max:
        body = {
            "size": min(page_size, effective_max - total_scanned),
            "sort": [{"@timestamp": {"order": "asc"}}, {"_id": "asc"}],
            "query": {"bool": {"must": must}} if must else {"match_all": {}},
        }
        if search_after:
            body["search_after"] = search_after
        raw = await _wazuh_indexer_post(body)
        if "error" in raw:
            if all_docs:
                break
            return json.dumps(raw, indent=2)
        hits = raw.get("hits", {})
        hit_list = hits.get("hits", [])
        docs = [h.get("_source", h) for h in hit_list]
        total = hits.get("total", {})
        total_val = total.get("value", 0) if isinstance(total, dict) else total
        total_relation = total.get("relation", "eq") if isinstance(total, dict) else "eq"
        if not docs:
            break
        all_docs.extend(docs)
        total_scanned += len(docs)
        last_sort = hit_list[-1].get("sort") if hit_list else None
        if len(docs) < page_size or last_sort is None:
            break
        search_after = last_sort

    next_cursor = (
        _encode_cursor({"search_after": search_after})
        if search_after and total_scanned < total_val
        else None
    )
    has_more = next_cursor is not None
    return _truncate_if_needed(json.dumps({
        "total": {"value": total_val, "relation": total_relation},
        "retrieved": total_scanned,
        "has_more": has_more,
        "next_cursor": next_cursor,
        "alerts": _redact_alert_data(all_docs, policy=redaction_policy),
    }, indent=2))


# blueteam_mitre_lookup
@mcp.tool(
    name="blueteam_mitre_lookup",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                  "idempotentHint": True, "openWorldHint": False}
)
async def blueteam_mitre_lookup(tactic_or_technique: str) -> str:
    """Look up a MITRE ATT&CK tactic or technique in the local mapping."""
    _audit_log("blueteam_mitre_lookup", {"query": tactic_or_technique})
    q = tactic_or_technique.strip().upper()
    results: dict[str, str] = {}
    for tactic, category in MITRE_TACTIC_TO_CATEGORY.items():
        if q in tactic.upper() or q in category.upper():
            results[tactic] = category
    if not results:
        return json.dumps({
            "query": tactic_or_technique,
            "result": "not_found",
            "available_tactics": list(MITRE_TACTIC_TO_CATEGORY.keys()),
        }, indent=2)
    return json.dumps({"query": tactic_or_technique, "matches": results}, indent=2)
