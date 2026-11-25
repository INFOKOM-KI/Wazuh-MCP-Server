#!/usr/bin/env python3
"""Alert aggregate parsing for the evidence pack.

The pack's evaluation claims come from these counts, so the tests pin the
degradation path (indexer down), the high-severity boundary, and the truncation
flag that makes a top-rule share unsafe to cite as complete.
"""
from __future__ import annotations

import asyncio
import os

import pytest

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

from mcp_server.core import paper_alerts

RESPONSE = {
    "hits": {"total": {"value": 120, "relation": "eq"}},
    "aggregations": {
        "severity": {"buckets": [
            {"key": 3, "doc_count": 108},
            {"key": 12, "doc_count": 12},
        ]},
        "rules": {"buckets": [
            {"key": "5710", "doc_count": 48},
            {"key": "550", "doc_count": 24},
        ], "sum_other_doc_count": 0},
    },
}


def _fake(monkeypatch, response):
    seen: dict = {}

    async def call(body, index_pattern=None):
        seen["body"] = body
        seen["index_pattern"] = index_pattern
        return response

    monkeypatch.setattr(paper_alerts, "_wazuh_indexer_post", call)
    return seen


def test_summary_counts_and_high_severity(monkeypatch):
    seen = _fake(monkeypatch, RESPONSE)
    out = asyncio.run(paper_alerts.alert_summary(1440))
    assert out["available"] is True
    assert out["total"] == 120
    assert out["high_severity_count"] == 12
    assert out["top_rule_share"] == 40.0
    assert out["truncated"] is False
    assert out["partial"] is False
    assert out["top_rules"][0] == {"rule_id": "5710", "count": 48}
    assert seen["body"]["query"]["bool"]["filter"][0]["range"]["@timestamp"]["gte"] == "now-1440m"
    assert seen["index_pattern"] == "wazuh-alerts-*"
    assert {"exists": {"field": "rule.level"}} in seen["body"]["query"]["bool"]["filter"]
    assert out["index_pattern"] == "wazuh-alerts-*"
    assert out["per_entity_claims"] is False
    assert out["filter"] == "rule.level exists"


def _agg_fields(node):
    if isinstance(node, dict):
        if isinstance(node.get("field"), str):
            yield node["field"]
        for value in node.values():
            yield from _agg_fields(value)
    elif isinstance(node, list):
        for value in node:
            yield from _agg_fields(value)


def test_aggregation_body_uses_only_safe_fields(monkeypatch):
    seen = _fake(monkeypatch, RESPONSE)
    asyncio.run(paper_alerts.alert_summary(60))
    fields = set(_agg_fields(seen["body"]["aggs"]))
    assert fields <= paper_alerts.SAFE_AGG_FIELDS
    assert "rule.groups" not in fields
    assert "data.srcip" not in fields


def test_unsafe_aggregation_field_is_rejected():
    with pytest.raises(ValueError, match="data.audit.command"):
        paper_alerts._assert_safe_aggs(
            {"x": {"terms": {"field": "data.audit.command"}}}, per_entity_claims=False)
    with pytest.raises(ValueError, match="full_log"):
        paper_alerts._assert_safe_aggs(
            {"x": {"cardinality": {"field": "full_log"}}}, per_entity_claims=False)


@pytest.mark.parametrize("aggs,flag", [
    ({"x": {"terms": {"field": "data.srcip"}}}, False),
    ({"x": {"terms": {"field": "rule.id"}}}, True),
])
def test_entity_flag_and_ip_agg_must_agree(aggs, flag):
    with pytest.raises(ValueError, match="per_entity_claims"):
        paper_alerts._assert_safe_aggs(aggs, per_entity_claims=flag)


def test_matching_entity_pairs_pass():
    paper_alerts._assert_safe_aggs(
        {"x": {"terms": {"field": "data.srcip"}}}, per_entity_claims=True)
    paper_alerts._assert_safe_aggs(
        {"x": {"terms": {"field": "rule.id"}}}, per_entity_claims=False)


def test_indexer_error_degrades_without_raising(monkeypatch):
    _fake(monkeypatch, {"error": "connect failed"})
    out = asyncio.run(paper_alerts.alert_summary(60))
    assert out["available"] is False
    assert out["error_kind"] == "unreachable"
    assert "error" not in out
    assert out["window_minutes"] == 60


def test_other_bucket_count_marks_the_share_truncated(monkeypatch):
    response = {**RESPONSE, "aggregations": {
        **RESPONSE["aggregations"],
        "rules": {**RESPONSE["aggregations"]["rules"], "sum_other_doc_count": 3},
    }}
    _fake(monkeypatch, response)
    out = asyncio.run(paper_alerts.alert_summary(60))
    assert out["truncated"] is True


def test_timed_out_response_is_marked_partial(monkeypatch):
    _fake(monkeypatch, {**RESPONSE, "timed_out": True})
    out = asyncio.run(paper_alerts.alert_summary(60))
    assert out["partial"] is True


def test_error_string_does_not_leak_the_indexer_url(monkeypatch):
    async def boom(body, index_pattern=None):
        raise RuntimeError("cannot reach https://indexer.internal:9200/alerts")
    monkeypatch.setattr(paper_alerts, "_wazuh_indexer_post", boom)
    out = asyncio.run(paper_alerts.alert_summary(60))
    assert out["available"] is False
    assert out["error_kind"] == "unreachable"
    assert "error" not in out
    assert "indexer.internal" not in str(out)


def test_window_is_clamped_to_the_cap(monkeypatch):
    seen = _fake(monkeypatch, RESPONSE)
    out = asyncio.run(paper_alerts.alert_summary(10_000_000))
    assert out["window_minutes"] == paper_alerts.MAX_WINDOW_MINUTES
    assert "now-43200m" in seen["body"]["query"]["bool"]["filter"][0]["range"]["@timestamp"]["gte"]
