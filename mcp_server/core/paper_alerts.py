#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Alert aggregates for the evidence pack.

Reads counts only: total alerts, severity distribution, and the top rule IDs for
a time window. No documents, no source IPs, no payloads, so the result carries no
entity-level cell to suppress. A missing indexer degrades to
``{"available": false, "error_kind": ...}`` instead of failing the pack.
"""
from __future__ import annotations

from typing import Any

from mcp_server.wazuh.indexer import _WAZUH_INDEX_PATTERNS, _wazuh_indexer_post

MAX_WINDOW_MINUTES = 43200
HIGH_SEVERITY_LEVEL = 10

# Only these fields may be aggregated; audit/cloud payloads and full_log return raw values.
# rule.groups is an array, so a top-group share must bucket on rule.id.
SAFE_AGG_FIELDS = frozenset({
    "rule.id", "rule.level", "rule.groups", "rule.mitre.id",
    "rule.mitre.tactic", "rule.mitre.technique", "data.srcip",
})
CANONICAL_SRCIP_FIELD = "data.srcip"


def _agg_field_names(node: object):
    if isinstance(node, dict):
        field = node.get("field")
        if isinstance(field, str):
            yield field
        for value in node.values():
            yield from _agg_field_names(value)
    elif isinstance(node, list):
        for value in node:
            yield from _agg_field_names(value)


def _assert_safe_aggs(node: object, *, per_entity_claims: bool) -> None:
    fields = set(_agg_field_names(node))
    for field in fields:
        if field not in SAFE_AGG_FIELDS:
            raise ValueError(f"aggregation field not allowed: {field}")
    # Extend this alongside SAFE_AGG_FIELDS: a new IP spelling added there
    # needs its own pairing check here, or the flag stops describing the tree.
    has_entity_field = CANONICAL_SRCIP_FIELD in fields
    if has_entity_field != per_entity_claims:
        raise ValueError(
            f"per_entity_claims={per_entity_claims} but {CANONICAL_SRCIP_FIELD} "
            f"{'is' if has_entity_field else 'is not'} in the aggregation tree")


def _error_kind(value: object) -> str:
    """Classify, never echo: a free-text error is pack content and can carry a host."""
    text = str(value).lower()
    if "timed out" in text or "timeout" in text:
        return "timeout"
    if "401" in text or "403" in text or "unauthorized" in text or "forbidden" in text:
        return "auth"
    if any(token in text for token in ("refused", "name or service", "getaddrinfo",
                                       "connect", "unreachable", "no route", "cannot reach")):
        return "unreachable"
    return "unknown"


def _total_hits(data: dict) -> int | None:
    total = (data.get("hits") or {}).get("total")
    if isinstance(total, dict):
        return int(total.get("value") or 0)
    if isinstance(total, int):
        return total
    return None


def _severity(buckets: list[dict]) -> list[dict]:
    rows = []
    for bucket in buckets:
        try:
            level = int(bucket.get("key"))
        except (TypeError, ValueError):
            continue
        rows.append({"level": level, "count": int(bucket.get("doc_count") or 0)})
    return rows


async def alert_summary(window_minutes: int) -> dict:
    minutes = max(1, min(int(window_minutes), MAX_WINDOW_MINUTES))
    body = {
        "size": 0,
        "track_total_hits": True,
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": f"now-{minutes}m", "lt": "now",
                                       "format": "strict_date_optional_time"}}},
            # Archives live under a separate index family; this keeps the count
            # to documents that actually carry an alert level.
            {"exists": {"field": "rule.level"}},
        ]}},
        "aggs": {
            "severity": {"terms": {"field": "rule.level", "size": 20}},
            "rules": {"terms": {"field": "rule.id", "size": 25}},
        },
    }
    per_entity = CANONICAL_SRCIP_FIELD in set(_agg_field_names(body["aggs"]))
    _assert_safe_aggs(body["aggs"], per_entity_claims=per_entity)
    index_pattern = _WAZUH_INDEX_PATTERNS["alerts"]
    base = {"window_minutes": minutes, "index_pattern": index_pattern,
            "filter": "rule.level exists",
            "per_entity_claims": per_entity,
            "canonical_srcip_field": CANONICAL_SRCIP_FIELD}
    try:
        data: Any = await _wazuh_indexer_post(body, index_pattern)
    except Exception as exc:
        return {"available": False, **base, "error_kind": _error_kind(exc)}

    if not isinstance(data, dict) or data.get("error"):
        error = (data or {}).get("error") if isinstance(data, dict) else "unreadable response"
        return {"available": False, **base, "error_kind": _error_kind(error)}

    aggs = data.get("aggregations") or {}
    severity = _severity((aggs.get("severity") or {}).get("buckets") or [])
    rule_buckets = (aggs.get("rules") or {}).get("buckets") or []
    total = _total_hits(data)
    if total is None:
        total = sum(row["count"] for row in severity)

    high = sum(row["count"] for row in severity if row["level"] >= HIGH_SEVERITY_LEVEL)
    top_rules = [{"rule_id": str(bucket.get("key")), "count": int(bucket.get("doc_count") or 0)}
                 for bucket in rule_buckets[:10]]
    top_count = top_rules[0]["count"] if top_rules else 0

    return {
        "available": True,
        "window_minutes": minutes,
        "total": total,
        "severity": severity,
        "high_severity_count": high,
        "top_rules": top_rules,
        "top_rule_share": round(100 * top_count / total, 1) if total else 0.0,
        "truncated": bool((aggs.get("rules") or {}).get("sum_other_doc_count")),
        "partial": bool(data.get("timed_out") or data.get("terminated_early")),
        **base,
    }
