#!/usr/bin/env python3
"""W8 nested MS Graph review: pass-through verification and nested semantics.

The simulator functions model the index behavior locally so the difference
between parent-level and nested evaluation is observable without a cluster.
"""
from __future__ import annotations

import asyncio
import os
from collections import Counter

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

from mcp_server.tools.dsl_query import DslQueryInput, wazuh_alert_dsl_query
from mcp_server.tools.wazuh_focused import FocusedCrawlInput, wazuh_alert_focused_crawl


def _run(coro):
    return asyncio.run(coro)


def _tool(fn):
    return getattr(fn, "__wrapped__", fn)


DOCS = [
    {"@timestamp": "2026-01-01T00:00:00Z", "data": {"ms-graph": {
        "incidentId": "i1",
        "managedDevices": [{"id": "dev-1", "deviceName": "LAPTOP-1"},
                           {"id": "dev-2", "deviceName": "LAPTOP-2"}],
        "evidence": [{"_comment": "phishing"}, {"_comment": "phishing"}],
        "resources": [{"resourceId": "r1", "modifiedProperties": [
            {"displayName": "role", "newValue": "admin"},
            {"displayName": "role", "newValue": "user"}]}]}}},
    {"@timestamp": "2026-01-02T00:00:00Z", "data": {"ms-graph": {
        "incidentId": "i2",
        "managedDevices": [{"id": "dev-1", "deviceName": "LAPTOP-1"}],
        "evidence": [{"_comment": "benign"}],
        "resources": [{"resourceId": "r2", "modifiedProperties": [
            {"displayName": "role", "newValue": "admin"}]}]}}},
]


def _plain_values(docs, path):
    """Parent-level lookup: a nested array is not traversable at the parent."""
    values = []
    for doc in docs:
        node = doc
        for part in path.split("."):
            if isinstance(node, list):
                node = None
                break
            node = node.get(part) if isinstance(node, dict) else None
            if node is None:
                break
        if node is not None:
            values.extend(node if isinstance(node, list) else [node])
    return values


def _nested_values(docs, path):
    """Flatten a leaf across every nested object, as a nested aggregation sees it."""
    def walk(node, parts):
        if not parts:
            return node
        if isinstance(node, list):
            out = []
            for item in node:
                found = walk(item, parts)
                if found is None:
                    continue
                out.extend(found if isinstance(found, list) else [found])
            return out
        if isinstance(node, dict):
            return walk(node.get(parts[0]), parts[1:])
        return None

    values = []
    for doc in docs:
        found = walk(doc, path.split("."))
        if found is None:
            continue
        values.extend(found if isinstance(found, list) else [found])
    return values


def test_plain_aggregation_on_nested_leaf_is_silently_empty():
    assert _plain_values(DOCS, "data.ms-graph.evidence._comment") == []
    assert _nested_values(DOCS, "data.ms-graph.evidence._comment") == [
        "phishing", "phishing", "benign"]


def test_nested_leaf_counts_differ_from_parent_flattening():
    counts = Counter(_nested_values(DOCS, "data.ms-graph.managedDevices.id"))
    assert counts == Counter({"dev-1": 2, "dev-2": 1})
    assert _plain_values(DOCS, "data.ms-graph.managedDevices.id") == []


def test_reverse_nested_counts_parent_alerts_once():
    matched_objects = [v for v in _nested_values(DOCS, "data.ms-graph.evidence._comment")
                       if v == "phishing"]
    parent_alerts = sum(
        1 for doc in DOCS
        if "phishing" in _nested_values([doc], "data.ms-graph.evidence._comment"))
    assert len(matched_objects) == 2     # nested hit count
    assert parent_alerts == 1            # reverse_nested count


def test_depth_two_modified_properties_flattens_through_both_levels():
    values = _nested_values(DOCS, "data.ms-graph.resources.modifiedProperties.newValue")
    assert values == ["admin", "user", "admin"]
    assert _plain_values(DOCS, "data.ms-graph.resources.modifiedProperties.newValue") == []


def _capture_dsl(monkeypatch):
    captured = {}

    async def _post(body, index_pattern=None):
        captured["body"] = body
        return {"aggregations": body.get("aggs", {})}

    monkeypatch.setattr("mcp_server.tools.dsl_query._wazuh_indexer_post", _post)
    return captured


NESTED_AGG = {"nested": {"path": "data.ms-graph.evidence"},
              "aggs": {"comments": {"terms": {"field": "data.ms-graph.evidence._comment",
                                              "size": 10}}}}
NESTED_TERM = {"nested": {"path": "data.ms-graph.managedDevices",
                          "query": {"term": {"data.ms-graph.managedDevices.id": "dev-1"}}}}
REVERSE_AGG = {"nested": {"path": "data.ms-graph.evidence"},
               "aggs": {"comments": {"terms": {"field": "data.ms-graph.evidence._comment"},
                                     "aggs": {"parents": {
                                         "reverse_nested": {},
                                         "aggs": {"alerts": {"value_count": {"field": "_id"}}}}}}}}
DEPTH_TWO_AGG = {
    "nested": {"path": "data.ms-graph.resources"},
    "aggs": {"props": {
        "nested": {"path": "data.ms-graph.resources.modifiedProperties"},
        "aggs": {"values": {"terms": {
            "field": "data.ms-graph.resources.modifiedProperties.newValue",
            "size": 10,
        }}},
    }},
}


def test_dsl_query_forwards_nested_term_query_unchanged(monkeypatch):
    captured = _capture_dsl(monkeypatch)
    _run(_tool(wazuh_alert_dsl_query)(DslQueryInput(query=NESTED_TERM, aggs=NESTED_AGG)))
    assert captured["body"]["size"] == 0
    assert captured["body"]["query"] == NESTED_TERM
    assert captured["body"]["aggs"] == NESTED_AGG


def test_dsl_query_forwards_nested_aggregation_unchanged(monkeypatch):
    captured = _capture_dsl(monkeypatch)
    _run(_tool(wazuh_alert_dsl_query)(DslQueryInput(aggs=NESTED_AGG)))
    assert captured["body"]["aggs"] == NESTED_AGG


def test_dsl_query_forwards_reverse_nested_unchanged(monkeypatch):
    captured = _capture_dsl(monkeypatch)
    _run(_tool(wazuh_alert_dsl_query)(DslQueryInput(aggs=REVERSE_AGG)))
    assert captured["body"]["aggs"] == REVERSE_AGG


def test_dsl_query_forwards_depth_two_nested_aggregation_unchanged(monkeypatch):
    captured = _capture_dsl(monkeypatch)
    _run(_tool(wazuh_alert_dsl_query)(DslQueryInput(aggs=DEPTH_TWO_AGG)))
    assert captured["body"]["aggs"] == DEPTH_TWO_AGG


def test_focused_crawl_selects_depth_two_nested_leaves(monkeypatch):
    captured = {}

    async def _post(body, index_pattern=None):
        captured["body"] = body
        return {"hits": {"total": {"value": 0}, "hits": []}}

    monkeypatch.setattr("mcp_server.tools.wazuh_focused._wazuh_indexer_post", _post)
    params = FocusedCrawlInput(
        fields="data.ms-graph.resources.modifiedProperties.newValue,"
               "data.ms-graph.managedDevices.id")

    _run(_tool(wazuh_alert_focused_crawl)(params))

    assert "data.ms-graph.resources.modifiedProperties.newValue" in captured["body"]["_source"]
    assert "data.ms-graph.managedDevices.id" in captured["body"]["_source"]
