#!/usr/bin/env python3
"""W3 source-IP coverage: template families reach the analysis paths."""
from __future__ import annotations

import asyncio
import json
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import pytest

from mcp_server.tools import correlation, forecast, stix_correlation, wazuh_siem
from mcp_server.wazuh import indexer

NEW_PATHS = [
    "data.audit.srcip",
    "data.aws.sourceIPAddress",
    "data.aws.source_ip_address",
    "data.office365.ClientIP",
    "data.ms-graph.actor.ipAddress",
    "data.ms-graph.ipAddress",
    "data.win.eventdata.ipAddress",
    "data.osquery.columns.src_ip",
    "GeoLocation.ip",
]


def _run(coro):
    return asyncio.run(coro)


def _tool(fn):
    return getattr(fn, "__wrapped__", fn)


def test_srcip_paths_cover_every_template_family():
    for path in NEW_PATHS:
        assert path in indexer._SRCIP_FIELD_PATHS, path
    for path in ("data.client_ip", "data.remote_ip", "data.source_ip", "data.ip", "srcip"):
        assert path in indexer._SRCIP_FIELD_PATHS, path
    assert len(indexer._SRCIP_FIELD_PATHS) == len(set(indexer._SRCIP_FIELD_PATHS))


@pytest.mark.parametrize("path", NEW_PATHS)
def test_correlation_queries_and_uses_each_new_srcip_path(monkeypatch, path):
    async def _caps(fields, index_pattern=None):
        return {path: "keyword"}

    async def _post(body, index_pattern=None):
        field = body["aggs"]["unique_srcips"]["terms"]["field"]
        buckets = ([{"key": "203.0.113.7", "doc_count": 4,
                     "level_sum": {"value": 12.0}}] if field == path else [])
        return {"aggregations": {"unique_srcips": {"buckets": buckets}}}

    monkeypatch.setattr(correlation, "_wazuh_indexer_field_caps", _caps)
    monkeypatch.setattr(correlation, "_wazuh_indexer_post", _post)

    buckets, warnings, failed, _meta = _run(correlation._srcip_buckets(
        {"match_all": {}}, {"level_sum": {"sum": {"field": "rule.level"}}}, "A"))

    assert failed is False
    assert warnings == []
    assert [b["key"] for b in buckets] == ["203.0.113.7"]


def test_profile_sees_office365_client_ip_only(monkeypatch):
    async def _caps(fields, index_pattern=None):
        return {"data.office365.ClientIP": "keyword"}

    async def _post(body, index_pattern=None):
        return {"aggregations": {"unique_srcips": {"buckets": [
            {"key": "198.51.100.9", "doc_count": 3, "level_sum": {"value": 6.0}}]}}}

    monkeypatch.setattr(correlation, "_wazuh_indexer_field_caps", _caps)
    monkeypatch.setattr(correlation, "_wazuh_indexer_post", _post)

    result = _run(correlation.fetch_srcip_profiles(
        [("A", "recon", ["web"])], "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z",
        use_mitre=False))

    assert result["failures"] == 0
    assert result["profiles"]["198.51.100.9"]["alert_count"] == 3


def test_absent_new_paths_do_not_error(monkeypatch):
    async def _caps(fields, index_pattern=None):
        return {"data.srcip": "keyword"}

    async def _post(body, index_pattern=None):
        return {"aggregations": {"unique_srcips": {"buckets": [
            {"key": "203.0.113.7", "doc_count": 1}]}}}

    monkeypatch.setattr(correlation, "_wazuh_indexer_field_caps", _caps)
    monkeypatch.setattr(correlation, "_wazuh_indexer_post", _post)

    buckets, warnings, failed, meta = _run(correlation._srcip_buckets(
        {"match_all": {}}, {}, "A"))

    assert failed is False
    assert warnings == []
    assert [b["key"] for b in buckets] == ["203.0.113.7"]
    assert meta["path_errors"] == 0


def test_forecast_reads_office365_client_ip(monkeypatch):
    doc = {"@timestamp": "2026-01-01T00:00:00Z",
           "rule": {"mitre": {"tactic": "Initial Access"}},
           "data": {"office365": {"ClientIP": "198.51.100.9"}}}
    calls = {"n": 0}

    async def _post(body, index_pattern=None):
        calls["n"] += 1
        hits = [{"_id": "1", "_source": doc, "sort": [1, "1"]}] if calls["n"] == 1 else []
        return {"hits": {"total": {"value": 1, "relation": "eq"}, "hits": hits}}

    monkeypatch.setattr(forecast, "_wazuh_indexer_post", _post)

    out = _run(forecast._fetch_tactic_observations(
        None, "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"))

    assert out["rows"]
    assert out["rows"][0]["entity_key"] == "198.51.100.9"
    assert out["rows"][0]["tactic"] == "Initial Access"


def test_stix_killchain_query_covers_new_srcip_paths(monkeypatch):
    captured = {}

    async def _post(body, index_pattern=None):
        captured["body"] = body
        return {"hits": {"total": {"value": 2}},
                "aggregations": {"techniques": {"buckets": [{"key": "T1110"}]}}}

    monkeypatch.setattr(stix_correlation, "_wazuh_indexer_post", _post)

    total, tids = _run(stix_correlation._fetch_techniques_for_srcip(
        "203.0.113.7", None, None))

    text = json.dumps(captured["body"])
    assert "data.audit.srcip" in text
    assert "GeoLocation.ip" in text
    assert "data.srcip2" in text
    assert (total, tids) == (2, ["T1110"])


def test_siem_indexer_search_covers_new_srcip_paths(monkeypatch):
    captured = {}

    async def _post(body, index_pattern=None):
        captured["body"] = body
        return {"hits": {"total": {"value": 1, "relation": "eq"},
                         "hits": [{"_source": {"data": {"audit": {"srcip": "203.0.113.7"}}}}]}}

    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_post", _post)

    _run(_tool(wazuh_siem.blueteam_wazuh_indexer_search)(
        wazuh_siem.WazuhIndexerSearchInput(srcip="203.0.113.7", limit=10)))

    text = json.dumps(captured["body"])
    assert "data.audit.srcip" in text
    assert "data.srcip2" in text


def test_siem_local_reader_matches_new_srcip_path(monkeypatch, tmp_path):
    alerts = tmp_path / "alerts.json"
    alerts.write_text(json.dumps({"data": {"audit": {"srcip": "203.0.113.7"}}, "full_log": ""}) + "\n")
    monkeypatch.setattr(wazuh_siem, "_WAZUH_ALERTS_PATH", str(alerts))

    out = _run(_tool(wazuh_siem.blueteam_wazuh_alerts)(
        wazuh_siem.WazuhAlertsInput(srcip="203.0.113.7")))

    payload = json.loads(out)
    assert payload["count"] == 1
    assert payload["alerts"][0]["data"]["audit"]["srcip"] == "203.0.113.7"
