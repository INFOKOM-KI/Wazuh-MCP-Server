#!/usr/bin/env python3
"""W3 direct-consumer coverage: source-IP families reach the analysis tools.

Count semantics: per-path terms buckets merge to a lower bound (max per key), and
every displayed count is corrected by one server-side document-count query per
candidate IP, batched into a single _msearch. A document is counted once however
many source-IP fields carry the address.
"""
from __future__ import annotations

import asyncio
import json
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import pytest

from mcp_server.tools import (ai_bot_recon, alert_compare, alert_summarize, correlation,
                              threat_hunt, wazuh_velocity)
from mcp_server.wazuh import indexer


def _run(coro):
    return asyncio.run(coro)


def _tool(fn):
    return getattr(fn, "__wrapped__", fn)


def _srcip_field(node):
    """First ``terms`` field in an agg tree that names a source-IP path."""
    found = []

    def walk(current):
        if isinstance(current, dict):
            terms = current.get("terms")
            if isinstance(terms, dict) and terms.get("field") in indexer._SRCIP_FIELD_PATHS:
                found.append(terms["field"])
            for value in current.values():
                walk(value)
        elif isinstance(current, list):
            for value in current:
                walk(value)

    walk(node)
    return found[0] if found else None


def _query_ip(body):
    should = body["query"]["bool"]["filter"][1]["bool"]["should"]
    for clause in should:
        for value in clause["match"].values():
            return value
    return None


def _msearch_fake(exact_by_ip, captured=None):
    async def _msearch(bodies, index_pattern=None):
        if captured is not None:
            captured.extend(bodies)
        return [{"hits": {"total": {"value": exact_by_ip.get(_query_ip(b), 0),
                                    "relation": "eq"}}} for b in bodies]
    return _msearch


def test_should_clause_covers_every_template_path():
    text = json.dumps(indexer._srcip_should_clauses("203.0.113.7"))
    for path in ("data.audit.srcip", "data.aws.sourceIPAddress", "data.office365.ClientIP",
                 "data.ms-graph.actor.ipAddress", "data.ms-graph.ipAddress",
                 "data.win.eventdata.ipAddress", "data.osquery.columns.src_ip", "GeoLocation.ip"):
        assert path in text, path
    assert "full_log" in text
    assert "full_log" not in json.dumps(indexer._srcip_should_clauses("203.0.113.7", full_log=False))
    assert "data.srcip2" in json.dumps(indexer._srcip_should_clauses(
        "203.0.113.7", full_log=False, extra_paths=("data.srcip2",)))


def test_merge_bucket_lists_produces_lower_bound_and_merges_subaggs():
    target = [{"key": "1.2.3.4", "doc_count": 3,
               "paths": {"buckets": [{"key": "/a", "doc_count": 2}]}}]
    incoming = [{"key": "1.2.3.4", "doc_count": 5,
                 "paths": {"buckets": [{"key": "/b", "doc_count": 4}]}},
                {"key": "5.6.7.8", "doc_count": 1}]
    merged = {b["key"]: b for b in indexer._merge_bucket_lists(target, incoming)}
    assert merged["1.2.3.4"]["doc_count"] == 5  # lower bound, corrected later
    assert {b["key"]: b["doc_count"] for b in merged["1.2.3.4"]["paths"]["buckets"]} == {"/a": 2, "/b": 4}
    assert merged["5.6.7.8"]["doc_count"] == 1


def test_srcip_aggs_merged_swaps_field_per_path_and_lower_bounds(monkeypatch):
    posted = []
    counts = {"data.srcip": 3, "data.office365.ClientIP": 2}

    async def _caps(fields, index_pattern=None):
        return {"data.srcip": "keyword", "data.office365.ClientIP": "keyword"}

    async def _post(body, index_pattern=None):
        field = _srcip_field(body)
        posted.append(field)
        return {"aggregations": {"by_srcip": {"buckets": [
            {"key": "203.0.113.7", "doc_count": counts[field]}]}}}

    monkeypatch.setattr(indexer, "_wazuh_indexer_field_caps", _caps)
    monkeypatch.setattr(indexer, "_wazuh_indexer_post", _post)

    merged, live, errors = _run(indexer._srcip_aggs_merged(
        {"match_all": {}}, {"by_srcip": {"terms": {"field": "data.srcip", "size": 20}}}))

    assert sorted(posted) == ["data.office365.ClientIP", "data.srcip"]
    assert errors == []
    assert sorted(live) == ["data.office365.ClientIP", "data.srcip"]
    assert merged["by_srcip"]["buckets"] == [{"key": "203.0.113.7", "doc_count": 3}]


def test_srcip_aggs_merged_never_queries_absent_paths(monkeypatch):
    posted = []

    async def _caps(fields, index_pattern=None):
        return {"data.srcip": "keyword"}

    async def _post(body, index_pattern=None):
        posted.append(_srcip_field(body))
        return {"aggregations": {"by_srcip": {"buckets": []}}}

    monkeypatch.setattr(indexer, "_wazuh_indexer_field_caps", _caps)
    monkeypatch.setattr(indexer, "_wazuh_indexer_post", _post)

    _run(indexer._srcip_aggs_merged(
        {"match_all": {}}, {"by_srcip": {"terms": {"field": "data.srcip", "size": 20}}}))

    assert posted == ["data.srcip"]


def test_exact_srcip_counts_uses_one_document_count_per_candidate(monkeypatch):
    captured = []
    monkeypatch.setattr(indexer, "_wazuh_indexer_msearch",
                        _msearch_fake({"10.0.0.1": 5, "10.0.0.2": 2}, captured))

    counts = _run(indexer._exact_srcip_counts(
        {"match_all": {}}, ["10.0.0.1", "10.0.0.2"]))

    assert counts == {"10.0.0.1": 5, "10.0.0.2": 2}
    assert len(captured) == 2
    body = json.dumps(captured[0])
    assert "data.audit.srcip" in body and "data.office365.ClientIP" in body
    assert "full_log" not in body          # count stays comparable with the terms buckets
    assert '"track_total_hits": true' in body


def test_correct_srcip_counts_resolves_cases_a_b_c(monkeypatch):
    # Case A: one document carries the IP in two fields -> 1.
    # Case B: 3 + 2 independent documents -> 5.
    # Case C: 3 + 2 with one overlapping document -> 4.
    for exact, expected in ((1, 1), (5, 5), (4, 4)):
        buckets = [{"key": "10.0.0.1", "doc_count": 3}]
        monkeypatch.setattr(indexer, "_wazuh_indexer_msearch", _msearch_fake({"10.0.0.1": exact}))
        corrected = _run(indexer._correct_srcip_counts(buckets, {"match_all": {}}))
        assert corrected[0]["doc_count"] == expected, exact


def test_threat_hunt_uses_exact_case_b_count(monkeypatch):
    posted = []
    counts = {"data.srcip": 3, "data.office365.ClientIP": 2}

    async def _caps(fields, index_pattern=None):
        return {"data.srcip": "keyword", "data.office365.ClientIP": "keyword"}

    async def _post(body, index_pattern=None):
        posted.append(body)
        if "by_srcip" in body.get("aggs", {}):
            field = _srcip_field(body)
            return {"aggregations": {"by_srcip": {"buckets": [
                {"key": "203.0.113.7", "doc_count": counts[field]}]}}}
        return {"hits": {"total": {"value": 5}}, "aggregations": {"by_dstip": {"buckets": []}}}

    monkeypatch.setattr(indexer, "_wazuh_indexer_field_caps", _caps)
    monkeypatch.setattr(indexer, "_wazuh_indexer_post", _post)
    monkeypatch.setattr(threat_hunt, "_wazuh_indexer_post", _post)
    monkeypatch.setattr(indexer, "_wazuh_indexer_msearch", _msearch_fake({"203.0.113.7": 5}))

    out = json.loads(_run(_tool(threat_hunt.blueteam_threat_hunt)(
        threat_hunt.ThreatHuntInput(template="lateral_movement", response_format="json"))))

    assert out["aggregations"]["by_srcip"]["buckets"] == [
        {"key": "203.0.113.7", "doc_count": 5}]
    per_path = [b for b in posted if "by_srcip" in b.get("aggs", {})]
    assert sorted(_srcip_field(b) for b in per_path) == ["data.office365.ClientIP", "data.srcip"]


def test_threat_hunt_base_filter_covers_new_paths():
    text = json.dumps(threat_hunt._base_filters(
        "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z", None, "203.0.113.7"))
    assert "data.audit.srcip" in text
    assert "GeoLocation.ip" in text


def test_alert_summarize_filter_covers_new_paths(monkeypatch):
    captured = {}

    async def _post(body, index_pattern=None):
        captured["body"] = body
        return {"hits": {"total": {"value": 0, "relation": "eq"}, "hits": []}}

    monkeypatch.setattr("mcp_server.tools.alert_summarize._wazuh_indexer_post", _post)

    _run(_tool(alert_summarize.blueteam_wazuh_alert_summarize)(
        alert_summarize.AlertSummarizeInput(srcip="203.0.113.7")))

    text = json.dumps(captured["body"])
    for path in ("data.audit.srcip", "data.office365.ClientIP", "GeoLocation.ip"):
        assert path in text, path


def test_ai_bot_recon_uses_exact_case_a_count(monkeypatch):
    posted = []
    counts = {"data.srcip": 1, "data.ms-graph.actor.ipAddress": 1}

    async def _caps(fields, index_pattern=None):
        return {"data.srcip": "keyword", "data.ms-graph.actor.ipAddress": "keyword"}

    async def _post(body, index_pattern=None):
        field = _srcip_field(body)
        posted.append(field)
        return {"aggregations": {"by_srcip": {"buckets": [{
            "key": "10.0.0.1", "doc_count": counts[field],
            "paths": {"buckets": [{"key": f"/{field.split('.')[-1]}", "doc_count": 1}]}}]}}}

    monkeypatch.setattr(indexer, "_wazuh_indexer_field_caps", _caps)
    monkeypatch.setattr(indexer, "_wazuh_indexer_post", _post)
    monkeypatch.setattr(indexer, "_wazuh_indexer_msearch", _msearch_fake({"10.0.0.1": 1}))

    out = _run(_tool(ai_bot_recon.blueteam_ai_bot_recon)(
        ai_bot_recon.AiBotReconInput(response_format="json")))

    assert sorted(posted) == ["data.ms-graph.actor.ipAddress", "data.srcip"]
    assert out["sources"][0]["alerts"] == 1        # one document, not two path hits
    assert out["sources"][0]["unique_paths"] == 2


def test_velocity_uses_exact_case_c_counts(monkeypatch):
    counts = {"data.srcip": 3, "data.win.eventdata.ipAddress": 2}

    async def _caps(fields, index_pattern=None):
        return {"data.srcip": "keyword", "data.win.eventdata.ipAddress": "keyword"}

    async def _post(body, index_pattern=None):
        field = _srcip_field(body)
        return {"aggregations": {"over_time": {"buckets": [{
            "key": 1767225600000, "doc_count": counts[field],
            "top_rules": {"buckets": [{"key": "5710", "doc_count": counts[field]}]},
            "top_srcips": {"buckets": [{"key": "203.0.113.7", "doc_count": counts[field]}]}}]}}}

    monkeypatch.setattr(indexer, "_wazuh_indexer_field_caps", _caps)
    monkeypatch.setattr(indexer, "_wazuh_indexer_post", _post)
    monkeypatch.setattr(indexer, "_wazuh_indexer_msearch", _msearch_fake({"203.0.113.7": 4}))

    out = json.loads(_run(_tool(wazuh_velocity.wazuh_attack_velocity)(
        wazuh_velocity.WazuhAttackVelocityInput(window="1h", response_format="json"))))

    # 4 exact documents per window (3 + 2 with one overlap); the cross-window
    # spread keeps the latest window's value, so the display reports 4 not 8.
    assert out["top_srcips"] == [{"ip": "203.0.113.7", "count": 4}]


def test_aggregate_analysis_uses_exact_case_b_count(monkeypatch):
    counts = {"data.srcip": 3, "data.aws.sourceIPAddress": 2}

    async def _caps(fields, index_pattern=None):
        return {"data.srcip": "keyword", "data.aws.sourceIPAddress": "keyword"}

    async def _post(body, index_pattern=None):
        field = _srcip_field(body)
        return {"aggregations": {"top_srcips": {"buckets": [
            {"key": "203.0.113.7", "doc_count": counts[field]}]}}}

    async def _base_post(body, index_pattern=None):
        return {"hits": {"total": {"value": 5}},
                "aggregations": {"top_rules": {"buckets": []},
                                 "top_agents": {"buckets": []},
                                 "severity_bands": {"buckets": []}}}

    monkeypatch.setattr(indexer, "_wazuh_indexer_field_caps", _caps)
    monkeypatch.setattr(indexer, "_wazuh_indexer_post", _post)
    monkeypatch.setattr(correlation, "_wazuh_indexer_post", _base_post)
    monkeypatch.setattr(indexer, "_wazuh_indexer_msearch", _msearch_fake({"203.0.113.7": 5}))

    out = json.loads(_run(_tool(correlation.wazuh_alert_aggregate_analysis)(
        correlation.AggregateAnalysisInput(response_format="json"))))

    assert out["aggregations"]["top_srcips"]["buckets"] == [
        {"key": "203.0.113.7", "doc_count": 5}]


def test_correlation_buckets_mark_the_lower_bound_basis(monkeypatch):
    async def _caps(fields, index_pattern=None):
        return {"data.srcip": "keyword", "data.audit.srcip": "keyword"}

    async def _post(body, index_pattern=None):
        return {"aggregations": {"unique_srcips": {"buckets": [{"key": "10.0.0.1", "doc_count": 3}]}}}

    monkeypatch.setattr(correlation, "_wazuh_indexer_field_caps", _caps)
    monkeypatch.setattr(correlation, "_wazuh_indexer_post", _post)

    buckets, _warnings, failed, meta = _run(correlation._srcip_buckets(
        {"match_all": {}}, {}, "A"))

    assert failed is False
    assert [b["key"] for b in buckets] == ["10.0.0.1"]
    assert meta["count_basis"] == "per_path_max_lower_bound"


def test_alert_compare_srcip_filters_cover_new_paths():
    clauses = alert_compare._build_curated_query(
        "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z",
        alert_compare.CuratedReportFilters(srcips=["203.0.113.7"],
                                           exclude_srcips=["198.51.100.9"]), {})
    text = json.dumps(clauses)
    for path in ("data.audit.srcip", "GeoLocation.ip"):
        assert path in text, path
    assert "must_not" in text
