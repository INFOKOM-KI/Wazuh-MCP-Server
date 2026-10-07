#!/usr/bin/env python3
"""Behavioral tests for the mapping-resolved curated report (W2/W3).

The report's default group_by used a hardcoded ``.keyword`` path the stock Wazuh
mapping does not carry, so the entity aggregation came back empty. W3 widens the
srcip axis to every mapped source-IP path. These tests mock the indexer boundary,
assert the request targets the resolved field, and assert the mocked buckets
reach the response.
"""
from __future__ import annotations

import json
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import asyncio
import pytest

from mcp_server.tools import alert_curated_report as report


def _run(coro):
    return asyncio.run(coro)


def _tool():
    return getattr(report.blueteam_curated_threat_report, "__wrapped__",
                   report.blueteam_curated_threat_report)


PROPERTIES = {
    "data": {"properties": {"srcip": {"type": "keyword"}, "domain": {"type": "keyword"},
                            "url": {"type": "keyword"}, "user_agent": {"type": "keyword"}}},
    "rule": {"properties": {"id": {"type": "keyword"}, "description": {"type": "keyword"}}},
    "agent": {"properties": {"name": {"type": "keyword"}}},
    "location": {"type": "keyword"},
}


def _entity_aggs(key):
    return {"aggregations": {
        "top_entities": {"buckets": [{"key": key, "doc_count": 3,
            "top_rules": {"buckets": [{"key": "5710", "doc_count": 2}]}}]},
        "total_alerts": {"value": 3},
        "total_with_geo": {"value": 1},
        "top_rules": {"buckets": [{"key": "5710", "doc_count": 2}]},
        "top_agents": {"buckets": [{"key": "web01", "doc_count": 2}]},
        "top_domains": {"buckets": [{"key": "evil.cn", "doc_count": 1}]},
        "severity_bands": {"buckets": [{"key": "low", "doc_count": 3}]},
    }}


def _base_aggs():
    return {"aggregations": {
        "total_alerts": {"value": 3},
        "total_with_geo": {"value": 1},
        "top_rules": {"buckets": [{"key": "5710", "doc_count": 2}]},
        "top_agents": {"buckets": [{"key": "web01", "doc_count": 2}]},
        "top_domains": {"buckets": [{"key": "evil.cn", "doc_count": 1}]},
        "severity_bands": {"buckets": [{"key": "low", "doc_count": 3}]},
    }}


GROUP_CASES = [
    ("srcip", "data.srcip", "203.0.113.7"),
    ("domain", "data.domain", "evil.cn"),
    ("rule.id", "rule.id", "5710"),
    ("agent", "agent.name", "web01"),
]


@pytest.mark.parametrize("group_by,expected_field,key", GROUP_CASES)
def test_group_by_resolves_plain_field_and_returns_buckets(monkeypatch, group_by,
                                                           expected_field, key):
    posted = []

    async def _mapping(index_pattern=None):
        return {"wazuh-alerts-1": {"mappings": {"properties": PROPERTIES}}}

    async def _caps(fields, index_pattern=None):
        return {path: "keyword" for path in
                ("data.srcip", "data.domain", "rule.id", "agent.name")}

    async def _post(body, index_pattern=None):
        posted.append(body)
        if "top_entities" in body.get("aggs", {}):
            return _entity_aggs(key)
        return _base_aggs()

    async def _msearch(bodies, index_pattern=None):
        return [{"hits": {"total": {"value": 3, "relation": "eq"}}} for _ in bodies]

    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_mapping", _mapping)
    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_field_caps", _caps)
    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_post", _post)
    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_msearch", _msearch)
    monkeypatch.setattr(report, "_wazuh_indexer_post", _post)

    out = _run(_tool()(report.CuratedThreatReportInput(
        group_by=group_by, include_threat_intel=False,
        investigation_depth="summary", response_format="json")))

    entity_bodies = [b for b in posted if "top_entities" in b.get("aggs", {})]
    assert entity_bodies, "entity aggregation was not queried"
    agg = entity_bodies[0]["aggs"]["top_entities"]
    assert agg["terms"]["field"] == expected_field
    assert ".keyword" not in json.dumps(entity_bodies[0])
    assert key in out, f"{key} missing from report output"


def test_srcip_group_by_uses_exact_case_c_count(monkeypatch):
    counts = {"data.srcip": 3, "data.office365.ClientIP": 2}

    async def _mapping(index_pattern=None):
        return {"wazuh-alerts-1": {"mappings": {"properties": PROPERTIES}}}

    async def _caps(fields, index_pattern=None):
        return {path: "keyword" for path in ("data.srcip", "data.office365.ClientIP")}

    async def _post(body, index_pattern=None):
        field = body.get("aggs", {}).get("top_entities", {}).get("terms", {}).get("field")
        if field not in counts:
            return _base_aggs()
        return {"aggregations": {"top_entities": {"buckets": [
            {"key": "10.0.0.1", "doc_count": counts[field]}]}}}

    async def _msearch(bodies, index_pattern=None):
        return [{"hits": {"total": {"value": 4, "relation": "eq"}}} for _ in bodies]

    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_mapping", _mapping)
    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_field_caps", _caps)
    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_post", _post)
    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_msearch", _msearch)
    monkeypatch.setattr(report, "_wazuh_indexer_post", _post)

    out = json.loads(_run(_tool()(report.CuratedThreatReportInput(
        group_by="srcip", include_threat_intel=False,
        investigation_depth="summary", response_format="json"))))

    assert out["attackers"][0]["alerts"] == 4
