#!/usr/bin/env python3
"""Executable evidence for the generic MCP handling paths.

Proves the mechanism-level claims the capability model attaches to every leaf:
full-source retrieval, arbitrary-field selection, and pass-through of
query/aggregation bodies (including nested). Mocked at the indexer boundary, so
no cluster is required; these tests verify the MCP request builders, not
OpenSearch semantics.
"""
from __future__ import annotations

import json
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import asyncio
import pytest

import mcp_server.tools.dsl_query as dsl_query
import mcp_server.tools.wazuh_focused as wazuh_focused
import mcp_server.tools.wazuh_siem as wazuh_siem
from mcp_server.tools.dsl_query import DslQueryInput, wazuh_alert_dsl_query
from mcp_server.tools.wazuh_focused import FocusedCrawlInput, wazuh_alert_focused_crawl
from mcp_server.tools.wazuh_siem import (
    WazuhAlertsInput,
    WazuhIndexerSearchInput,
    blueteam_wazuh_alerts,
    blueteam_wazuh_indexer_search,
)

DEEP_DOC = {"@timestamp": "2026-10-06T00:00:00Z", "rule": {"id": "100", "level": 5},
            "data": {"aws": {"eventName": "AssumeRole"},
                     "ms-graph": {"managedDevices": {"id": "dev-1"}}}}
HITS = {"hits": {"total": {"value": 1, "relation": "eq"},
                 "hits": [{"_source": DEEP_DOC, "sort": [1, "id-1"]}]}}


def _tool_fn(decorated):
    return getattr(decorated, "__wrapped__", decorated)


class _CapturingPost:
    """Async stand-in for _wazuh_indexer_post; records every request body."""

    def __init__(self, response):
        self.bodies = []
        self.response = response

    async def __call__(self, body, index_pattern=None):
        self.bodies.append(body)
        return self.response


def test_alerts_fallback_returns_full_source(monkeypatch, tmp_path):
    monkeypatch.setattr(wazuh_siem, "_WAZUH_ALERTS_PATH", str(tmp_path / "absent.json"))
    capture = _CapturingPost(HITS)
    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_post", capture)

    out = asyncio.run(_tool_fn(blueteam_wazuh_alerts)(WazuhAlertsInput()))
    assert capture.bodies, "indexer fallback was not called"
    assert "_source" not in capture.bodies[0], "retrieval must not restrict _source"
    payload = json.loads(out)
    assert payload["alerts"][0]["data"]["aws"]["eventName"] == "AssumeRole"


def test_indexer_search_returns_full_source(monkeypatch):
    capture = _CapturingPost(HITS)
    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_post", capture)

    out = asyncio.run(_tool_fn(blueteam_wazuh_indexer_search)(WazuhIndexerSearchInput(limit=10)))
    assert capture.bodies, "indexer search was not called"
    assert "_source" not in capture.bodies[0], "retrieval must not restrict _source"
    payload = json.loads(out)
    assert payload["alerts"][0]["data"]["ms-graph"]["managedDevices"]["id"] == "dev-1"


def test_dsl_query_forwards_query_and_nested_aggregation(monkeypatch):
    nested_aggs = {"by_device": {"nested": {"path": "data.ms-graph.managedDevices"},
                                 "aggs": {"ids": {"terms": {"field": "data.ms-graph.managedDevices.id"}}}}}
    query = {"bool": {"filter": [{"term": {"rule.level": 10}}]}}
    capture = _CapturingPost({"aggregations": nested_aggs})
    monkeypatch.setattr(dsl_query, "_wazuh_indexer_post", capture)

    out = asyncio.run(_tool_fn(wazuh_alert_dsl_query)(
        DslQueryInput(aggs=nested_aggs, query=query)))
    assert capture.bodies[0]["size"] == 0
    assert capture.bodies[0]["aggs"] == nested_aggs, "nested aggregation must pass through unchanged"
    assert capture.bodies[0]["query"] == query, "filter clause must pass through unchanged"
    assert "by_device" in json.loads(out)["aggregations"]


def test_dsl_query_rejects_document_retrieval():
    with pytest.raises(Exception):
        DslQueryInput(query_json='{"size": 10, "aggs": {"x": {"terms": {"field": "rule.id"}}}}')


def test_focused_crawl_selects_arbitrary_nested_fields(monkeypatch):
    params = FocusedCrawlInput(fields="data.ms-graph.managedDevices.id,syscheck.audit.login_group.name")
    capture = _CapturingPost(HITS)
    monkeypatch.setattr(wazuh_focused, "_wazuh_indexer_post", capture)

    asyncio.run(_tool_fn(wazuh_alert_focused_crawl)(params))
    source = capture.bodies[0]["_source"]
    assert "data.ms-graph.managedDevices.id" in source
    assert "syscheck.audit.login_group.name" in source
