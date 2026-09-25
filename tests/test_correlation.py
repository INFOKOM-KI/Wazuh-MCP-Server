#!/usr/bin/env python3
"""Regression tests for the srcip aggregation in tools/correlation.py.
multi_terms over _SRCIP_FIELD_PATHS dropped every document: an alert populates a
single srcip path and multi_terms requires every key component, so Engine A and
the clustering population both came back empty on real data. These tests pin the
field_caps-driven terms aggregation and the profile fetch that consumes it.
"""
from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import asyncio
from mcp_server.tools import correlation


def _run(coro):
    return asyncio.run(coro)


def _bucket(ip="94.154.46.247", doc_count=334, level_sum=2672.0):
    return {"key": ip, "doc_count": doc_count, "level_sum": {"value": level_sum}}


def _patch(monkeypatch, caps, responses):
    """Stub the field caps probe and record every aggregation body posted."""
    posted = []

    async def _field_caps(fields, index_pattern=None):
        return caps

    async def _post(body, index_pattern=None):
        posted.append(body)
        return responses(body) if callable(responses) else responses

    monkeypatch.setattr(correlation, "_wazuh_indexer_field_caps", _field_caps)
    monkeypatch.setattr(correlation, "_wazuh_indexer_post", _post)
    return posted


def test_terms_on_the_mapped_field_not_multi_terms(monkeypatch):
    """The production mapping has data.srcip and none of the other seven paths."""
    posted = _patch(monkeypatch, {"data.srcip": "keyword"}, lambda body: {
        "aggregations": {"unique_srcips": {"buckets": [_bucket()]}}})

    buckets, warnings, failed = _run(correlation._srcip_buckets(
        {"match_all": {}}, {"level_sum": {"sum": {"field": "rule.level"}}}, "A"))

    assert failed is False
    assert warnings == []
    assert [b["key"] for b in buckets] == ["94.154.46.247"]
    agg = posted[0]["aggs"]["unique_srcips"]
    assert agg["terms"] == {"field": "data.srcip", "size": 10000}
    assert "multi_terms" not in agg


def test_same_ip_on_two_fields_is_not_double_counted(monkeypatch):
    def _response(body):
        field = body["aggs"]["unique_srcips"]["terms"]["field"]
        return {"aggregations": {"unique_srcips": {
            "buckets": [_bucket(doc_count=2 if field == "data.srcip" else 5)]}}}

    posted = _patch(monkeypatch, {"data.srcip": "keyword", "srcip.keyword": "keyword"}, _response)

    buckets, warnings, failed = _run(correlation._srcip_buckets({"match_all": {}}, {}, "A"))

    assert failed is False
    assert len(posted) == 2
    assert [b["doc_count"] for b in buckets] == [5]


def test_probe_failure_assumes_data_srcip_and_warns(monkeypatch):
    posted = _patch(monkeypatch, {}, {"aggregations": {"unique_srcips": {"buckets": [_bucket()]}}})

    buckets, warnings, failed = _run(correlation._srcip_buckets({"match_all": {}}, {}, "B"))

    assert failed is False
    assert len(buckets) == 1
    assert "field_caps probe returned nothing" in warnings[0]
    assert posted[0]["aggs"]["unique_srcips"]["terms"]["field"] == "data.srcip"


def test_no_mapped_srcip_path_warns(monkeypatch):
    _patch(monkeypatch, {"data.other": "keyword"},
           {"aggregations": {"unique_srcips": {"buckets": []}}})

    buckets, warnings, failed = _run(correlation._srcip_buckets({"match_all": {}}, {}, "C"))

    assert buckets == []
    assert failed is False
    assert "no known srcip path is mapped" in warnings[0]


def test_all_queries_failing_is_reported(monkeypatch):
    _patch(monkeypatch, {"data.srcip": "keyword"}, {"error": "Indexer API error: 503"})

    buckets, warnings, failed = _run(correlation._srcip_buckets({"match_all": {}}, {}, "A"))

    assert buckets == []
    assert failed is True
    assert "srcip agg failed" in warnings[0]


def test_fetch_srcip_profiles_populates_entity(monkeypatch):
    """Engine A and clustering share this population; a doc with only data.srcip
    must produce an entity instead of the empty profile that shipped."""
    _patch(monkeypatch, {"data.srcip": "keyword"}, lambda body: {
        "aggregations": {"unique_srcips": {"buckets": [_bucket()]}}})

    result = _run(correlation.fetch_srcip_profiles(
        [("A", "recon", ["web", "attack"])], "2026-09-24T08:00:00Z", "2026-09-25T08:00:00Z",
        use_mitre=False))

    assert result["failures"] == 0
    assert result["warnings"] == []
    profile = result["profiles"]["94.154.46.247"]
    assert profile["alert_count"] == 334
    assert profile["score_a"] > 0
    assert profile["total"] == profile["score_a"]
