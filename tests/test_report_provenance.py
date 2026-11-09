#!/usr/bin/env python3
"""Alert-ID provenance for harvested AbuseIPDB report candidates.

Provenance is sampled by a standalone aggregation, not a ``top_hits`` inside the
harvest tree: ``_merge_bucket_lists`` expects every list element to be a bucket
with a ``key``, and a hit has none. These tests pin the sample, the dedupe, the
truncation flags, and the fail-soft path. Nothing leaves the process.
"""
from __future__ import annotations

import asyncio
import os

import pytest

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

from mcp_server.tools import abuseipdb as tool


def _run(coro):
    return asyncio.run(coro)


def _bucket(key: str, doc_count: int, hits: list[dict]) -> dict:
    return {"key": key, "doc_count": doc_count,
            "sample": {"hits": {"total": {"value": doc_count}, "hits": hits}}}


def _hit(alert_id, rule_id="5710", ts="2026-11-06T01:00:00.000Z"):
    source = {}
    if rule_id is not None:
        source["rule"] = {"id": rule_id}
    if ts is not None:
        source["@timestamp"] = ts
    hit = {"_index": "wazuh-alerts", "_source": source}
    if alert_id is not None:
        hit["_id"] = alert_id
    return hit


FILTERS = [{"range": {"rule.level": {"gte": 7}}}]


# --------------------------------------------------------------------------
# Extraction
# --------------------------------------------------------------------------

def test_sample_is_attached_with_rule_id_and_timestamp(monkeypatch):
    async def fake_post(body, *args, **kwargs):
        assert "_source" in body["aggs"]["refs"]["aggs"]["sample"]["top_hits"]
        assert "full_log" not in str(body)
        return {"aggregations": {"refs": {"buckets": [
            _bucket("198.51.100.7", 12,
                    [_hit("abc123"), _hit("def456", rule_id="5712")])]}}}

    monkeypatch.setattr(tool, "_wazuh_indexer_post", fake_post)
    refs, status = _run(tool._alert_provenance(
        FILTERS, ["198.51.100.7"], ["data.srcip"]))

    assert status == "sampled"
    entry = refs["198.51.100.7"]
    assert [r["alert_id"] for r in entry["refs"]] == ["abc123", "def456"]
    assert entry["refs"][1]["rule_id"] == "5712"
    assert entry["refs"][0]["timestamp"].startswith("2026-11-06")
    assert entry["total"] == 12
    assert entry["truncated"] is True


def test_duplicate_alert_ids_collapse(monkeypatch):
    async def fake_post(body, *args, **kwargs):
        return {"aggregations": {"refs": {"buckets": [
            _bucket("198.51.100.7", 3,
                    [_hit("same-id"), _hit("same-id"), _hit("other")])]}}}

    monkeypatch.setattr(tool, "_wazuh_indexer_post", fake_post)
    refs, _ = _run(tool._alert_provenance(FILTERS, ["198.51.100.7"],
                                          ["data.srcip"]))
    assert [r["alert_id"] for r in refs["198.51.100.7"]["refs"]] == [
        "same-id", "other"]


def test_missing_alert_id_is_never_invented(monkeypatch):
    async def fake_post(body, *args, **kwargs):
        return {"aggregations": {"refs": {"buckets": [
            _bucket("198.51.100.7", 2,
                    [_hit(None), _hit(""), _hit("   "), _hit("real")])]}}}

    monkeypatch.setattr(tool, "_wazuh_indexer_post", fake_post)
    refs, _ = _run(tool._alert_provenance(FILTERS, ["198.51.100.7"],
                                          ["data.srcip"]))
    ids = [r["alert_id"] for r in refs["198.51.100.7"]["refs"]]
    assert ids == ["real"]


def test_missing_rule_id_and_timestamp_stay_none(monkeypatch):
    async def fake_post(body, *args, **kwargs):
        return {"aggregations": {"refs": {"buckets": [
            _bucket("198.51.100.7", 1,
                    [_hit("only-id", rule_id=None, ts=None)])]}}}

    monkeypatch.setattr(tool, "_wazuh_indexer_post", fake_post)
    refs, _ = _run(tool._alert_provenance(FILTERS, ["198.51.100.7"],
                                          ["data.srcip"]))
    ref = refs["198.51.100.7"]["refs"][0]
    assert ref["rule_id"] is None and ref["timestamp"] is None


def test_sample_is_capped_per_ip(monkeypatch):
    async def fake_post(body, *args, **kwargs):
        hits = [_hit(f"id{i}") for i in range(9)]
        return {"aggregations": {"refs": {"buckets": [
            _bucket("198.51.100.7", 40, hits)]}}}

    monkeypatch.setattr(tool, "_wazuh_indexer_post", fake_post)
    refs, _ = _run(tool._alert_provenance(FILTERS, ["198.51.100.7"],
                                          ["data.srcip"]))
    entry = refs["198.51.100.7"]
    assert len(entry["refs"]) == tool.PROVENANCE_SAMPLE_PER_IP
    assert entry["truncated"] is True


def test_failed_query_degrades_to_unavailable(monkeypatch):
    async def fake_post(body, *args, **kwargs):
        return {"error": "index_not_found"}

    monkeypatch.setattr(tool, "_wazuh_indexer_post", fake_post)
    refs, status = _run(tool._alert_provenance(FILTERS, ["198.51.100.7"],
                                               ["data.srcip"]))
    assert refs == {}
    assert status == "unavailable"


def test_no_candidates_short_circuits(monkeypatch):
    called = []

    async def fake_post(body, *args, **kwargs):
        called.append(body)
        return {}

    monkeypatch.setattr(tool, "_wazuh_indexer_post", fake_post)
    refs, status = _run(tool._alert_provenance(FILTERS, [], ["data.srcip"]))
    assert (refs, status) == ({}, "not_requested")
    assert called == []


def test_multiple_paths_merge_and_dedupe(monkeypatch):
    responses = [
        {"aggregations": {"refs": {"buckets": [
            _bucket("198.51.100.7", 5, [_hit("a"), _hit("b")])]}}},
        {"aggregations": {"refs": {"buckets": [
            _bucket("198.51.100.7", 6, [_hit("b"), _hit("c")])]}}},
    ]

    async def fake_post(body, *args, **kwargs):
        return responses.pop(0)

    monkeypatch.setattr(tool, "_wazuh_indexer_post", fake_post)
    refs, status = _run(tool._alert_provenance(
        FILTERS, ["198.51.100.7"], ["data.srcip", "srcip"]))
    entry = refs["198.51.100.7"]
    # "b" appears on both paths and must not be duplicated; the cap is 3.
    assert [r["alert_id"] for r in entry["refs"]] == ["a", "b", "c"]
    assert len(entry["refs"]) == tool.PROVENANCE_SAMPLE_PER_IP
    assert entry["total"] == 6
    assert status == "sampled"


def test_provenance_is_never_in_the_report_comment():
    """The comment is public; an alert id must not reach it."""
    comment = tool.build_comment(4, "2026-11-06T01:00:00Z",
                                 "2026-11-06T01:05:00Z", ["5710"])
    assert "abc123" not in comment
    assert "alert_id" not in comment
    assert "report" not in comment.lower().replace("reported by", "")


# --------------------------------------------------------------------------
# Destination-role fields (Gap 8)
# --------------------------------------------------------------------------

def test_bare_dstip_is_queried():
    assert "dstip" in tool._DSTIP_FIELDS
    assert "data.dstip" in tool._DSTIP_FIELDS


def test_srcip_and_dstip_vocabularies_are_symmetric():
    """Every bare form the harvest reads has a bare destination counterpart."""
    from mcp_server.wazuh.indexer import _SRCIP_FIELD_PATHS

    assert "srcip" in _SRCIP_FIELD_PATHS
    assert "dstip" in tool._DSTIP_FIELDS


def test_collision_still_forces_manual_review():
    status, reason = tool._candidate_status(
        {"ip": "198.51.100.7", "role": "ambiguous"}, [18], None)
    assert status == "manual_review"
    assert "ambiguous" in reason


def test_unavailable_dstip_query_refuses_to_report(monkeypatch):
    async def fake_post(body, *args, **kwargs):
        return {"error": "no mapping for field"}

    monkeypatch.setattr(tool, "_wazuh_indexer_post", fake_post)
    hits, status = _run(tool._dstip_role(FILTERS, ["198.51.100.7"]))
    assert hits == set()
    assert status == "unavailable"
