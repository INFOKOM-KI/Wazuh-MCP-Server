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


def test_private_srcip_is_skipped_before_any_provider_call(monkeypatch):
    posted = []

    async def _mapping(index_pattern=None):
        return {"wazuh-alerts-1": {"mappings": {"properties": PROPERTIES}}}

    async def _caps(fields, index_pattern=None):
        return {path: "keyword" for path in
                ("data.srcip", "data.domain", "rule.id", "agent.name")}

    async def _post(body, index_pattern=None):
        posted.append(body)
        if "top_entities" in body.get("aggs", {}):
            return _entity_aggs("10.0.0.5")
        return _base_aggs()

    async def _msearch(bodies, index_pattern=None):
        return [{"hits": {"total": {"value": 3, "relation": "eq"}}} for _ in bodies]

    async def forbidden(*args, **kwargs):
        raise AssertionError("provider called for a private address")

    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_mapping", _mapping)
    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_field_caps", _caps)
    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_post", _post)
    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_msearch", _msearch)
    monkeypatch.setattr(report, "_wazuh_indexer_post", _post)
    monkeypatch.setattr(report, "VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(report, "ABUSEIPDB_API_KEY", "")
    monkeypatch.setattr(report, "lookup", forbidden)
    monkeypatch.setattr(report, "_crowdsec_request", forbidden)
    monkeypatch.setattr(report, "_api_call", forbidden)
    monkeypatch.delenv(report.CROWDSEC_API_KEY_ENV, raising=False)
    monkeypatch.delenv(report.ARGUS_API_KEY_ENV, raising=False)

    out = _run(_tool()(report.CuratedThreatReportInput(
        group_by="srcip", include_threat_intel=True,
        investigation_depth="summary", response_format="json")))

    assert "non_public_ip" in out
    assert "provider called for a private address" not in out


def test_public_srcip_virustotal_fields_are_in_json(monkeypatch, consent_approval):
    posted = []

    async def _mapping(index_pattern=None):
        return {"wazuh-alerts-1": {"mappings": {"properties": PROPERTIES}}}

    async def _caps(fields, index_pattern=None):
        return {path: "keyword" for path in
                ("data.srcip", "data.domain", "rule.id", "agent.name")}

    async def _post(body, index_pattern=None):
        posted.append(body)
        if "top_entities" in body.get("aggs", {}):
            return _entity_aggs("1.1.1.1")
        return _base_aggs()

    async def _msearch(bodies, index_pattern=None):
        return [{"hits": {"total": {"value": 3, "relation": "eq"}}} for _ in bodies]

    calls = []

    async def fake_lookup(kind, value, **kwargs):
        calls.append((kind, value))
        assert (kind, value) == ("ip_addresses", "1.1.1.1")
        return {
            "malicious": 1, "suspicious": 0, "harmless": 58,
            "undetected": 33, "timeout": 0, "total_engines": 92,
            "stats_complete": True, "missing_stats": [],
            "detection_percent": 1, "community_reputation": 117,
            "as_owner": "Cloudflare, Inc.", "asn": 13335,
            "network": "1.1.1.0/24", "country": "AU",
            "total_votes": {"harmless": 156, "malicious": 39},
            "tags": ["suspicious-udp"], "last_analysis_date": 1794095894,
            "cached": False, "retrieved_at": "2026-11-08T00:00:00+00:00",
        }

    async def forbidden(*args, **kwargs):
        raise AssertionError("unrelated provider called")

    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_mapping", _mapping)
    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_field_caps", _caps)
    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_post", _post)
    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_msearch", _msearch)
    monkeypatch.setattr(report, "_wazuh_indexer_post", _post)
    monkeypatch.setattr(report, "VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(report, "ABUSEIPDB_API_KEY", "")
    monkeypatch.setattr(report, "lookup", fake_lookup)
    monkeypatch.setattr(report, "_crowdsec_request", forbidden)
    monkeypatch.setattr(report, "_api_call", forbidden)
    monkeypatch.delenv(report.CROWDSEC_API_KEY_ENV, raising=False)
    monkeypatch.delenv(report.ARGUS_API_KEY_ENV, raising=False)

    out = _run(_tool()(report.CuratedThreatReportInput(
        group_by="srcip", include_threat_intel=True, include_virustotal=True,
        investigation_depth="summary", response_format="json"), ctx=consent_approval))
    data = json.loads(out)
    attacker = next(a for a in data["attackers"] if a["ip"] == "1.1.1.1")
    vt = attacker["threat_intel"]["virustotal"]
    assert vt["malicious"] == 1
    assert vt["undetected"] == 33
    assert vt["total_engines"] == 92
    assert vt["detection_percent"] == 1
    assert vt["community_reputation"] == 117
    assert vt["as_owner"] == "Cloudflare, Inc."
    assert vt["asn"] == 13335
    assert vt["network"] == "1.1.1.0/24"
    assert vt["country"] == "AU"

    markdown = _run(_tool()(report.CuratedThreatReportInput(
        group_by="srcip", include_threat_intel=True, include_virustotal=True,
        investigation_depth="summary", response_format="markdown"), ctx=consent_approval))
    assert "VT:1/92 (1%) (rep 117)" in markdown
    assert "SKIP:" not in markdown
    assert "VirusTotal:configured" in markdown
    assert "## VirusTotal retrieval" in markdown
    assert "| `1.1.1.1` | live API |" in markdown

    calls_before = len(calls)
    opt_out = _run(_tool()(report.CuratedThreatReportInput(
        group_by="srcip", include_threat_intel=True, include_virustotal=False,
        investigation_depth="summary", response_format="json"), ctx=consent_approval))
    assert len(calls) == calls_before
    assert json.loads(opt_out)["threat_intel_sources"]["VirusTotal"] == "not_requested"
    assert "virustotal" not in json.loads(opt_out)["attackers"][0]["threat_intel"]

    calls_before = len(calls)
    consent_approval.approve = False
    consent_approval.action = "decline"
    declined = _run(_tool()(report.CuratedThreatReportInput(
        group_by="srcip", include_threat_intel=True, include_virustotal=True,
        investigation_depth="summary", response_format="json"), ctx=consent_approval))
    declined_data = json.loads(declined)
    assert len(calls) == calls_before
    assert declined_data["threat_intel_sources"]["VirusTotal"] == "consent_required"
    assert declined_data["attackers"][0]["threat_intel"]["virustotal"]["error"] == "consent_required"


def test_private_srcip_skips_the_crowdsec_prefilter(monkeypatch):
    posted = []

    async def _mapping(index_pattern=None):
        return {"wazuh-alerts-1": {"mappings": {"properties": PROPERTIES}}}

    async def _caps(fields, index_pattern=None):
        return {path: "keyword" for path in
                ("data.srcip", "data.domain", "rule.id", "agent.name")}

    async def _post(body, index_pattern=None):
        posted.append(body)
        if "top_entities" in body.get("aggs", {}):
            return _entity_aggs("10.0.0.5")
        return _base_aggs()

    async def _msearch(bodies, index_pattern=None):
        return [{"hits": {"total": {"value": 3, "relation": "eq"}}} for _ in bodies]

    async def forbidden(*args, **kwargs):
        raise AssertionError("CrowdSec called for a private address")

    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_mapping", _mapping)
    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_field_caps", _caps)
    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_post", _post)
    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_msearch", _msearch)
    monkeypatch.setattr(report, "_wazuh_indexer_post", _post)
    monkeypatch.setattr(report, "_crowdsec_request", forbidden)
    monkeypatch.setenv(report.CROWDSEC_API_KEY_ENV, "test-key")

    out = _run(_tool()(report.CuratedThreatReportInput(
        group_by="srcip", include_threat_intel=False,
        filters={"min_crowdsec_reputation": "malicious"},
        investigation_depth="summary", response_format="json")))

    assert "total_alerts" in out


@pytest.mark.parametrize("value", ["100.64.0.1", "2001:db8::1", "fd00::1"])
def test_non_public_skip_reason_names_the_general_policy(value):
    from mcp_server.tools.alert_curated_report import _enrichment_target

    public, reason = _enrichment_target(value)
    assert public is None
    assert reason == "non-public or non-global IP address"


def test_multiple_srcip_buckets_are_enriched_once(monkeypatch, consent_approval):
    calls = []
    keys = ("1.1.1.1", "8.8.8.8")

    async def _mapping(index_pattern=None):
        return {"wazuh-alerts-1": {"mappings": {"properties": PROPERTIES}}}

    async def _caps(fields, index_pattern=None):
        return {path: "keyword" for path in
                ("data.srcip", "data.domain", "rule.id", "agent.name")}

    async def _post(body, index_pattern=None):
        if "top_entities" in body.get("aggs", {}):
            return {"aggregations": {
                "top_entities": {"buckets": [
                    {"key": key, "doc_count": 3,
                     "top_rules": {"buckets": [{"key": "5710", "doc_count": 2}]}}
                    for key in keys]},
                "total_alerts": {"value": 6},
                "total_with_geo": {"value": 2},
                "top_rules": {"buckets": [{"key": "5710", "doc_count": 4}]},
                "top_agents": {"buckets": [{"key": "web01", "doc_count": 4}]},
                "top_domains": {"buckets": [{"key": "evil.cn", "doc_count": 1}]},
                "severity_bands": {"buckets": [{"key": "low", "doc_count": 6}]},
            }}
        return _base_aggs()

    async def _msearch(bodies, index_pattern=None):
        return [{"hits": {"total": {"value": 3, "relation": "eq"}}} for _ in bodies]

    async def fake_lookup(kind, value, **kwargs):
        calls.append((kind, value))
        return {
            "malicious": 0, "suspicious": 0, "harmless": 10,
            "undetected": 2, "timeout": 0, "total_engines": 12,
            "stats_complete": True, "missing_stats": [],
            "detection_percent": 0, "community_reputation": 7,
            "as_owner": None, "asn": None, "network": None, "country": None,
            "total_votes": None, "tags": None, "last_analysis_date": None,
            "cached": False, "retrieved_at": "2026-11-08T00:00:00+00:00",
        }

    async def forbidden(*args, **kwargs):
        raise AssertionError("unrelated provider called")

    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_mapping", _mapping)
    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_field_caps", _caps)
    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_post", _post)
    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_msearch", _msearch)
    monkeypatch.setattr(report, "_wazuh_indexer_post", _post)
    monkeypatch.setattr(report, "VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(report, "ABUSEIPDB_API_KEY", "")
    monkeypatch.setattr(report, "lookup", fake_lookup)
    monkeypatch.setattr(report, "_crowdsec_request", forbidden)
    monkeypatch.setattr(report, "_api_call", forbidden)
    monkeypatch.delenv(report.CROWDSEC_API_KEY_ENV, raising=False)
    monkeypatch.delenv(report.ARGUS_API_KEY_ENV, raising=False)

    out = _run(_tool()(report.CuratedThreatReportInput(
        group_by="srcip", include_threat_intel=True, include_virustotal=True,
        investigation_depth="summary", response_format="json"), ctx=consent_approval))
    data = json.loads(out)
    assert [a["ip"] for a in data["attackers"]] == list(keys)
    assert calls == [("ip_addresses", "1.1.1.1"), ("ip_addresses", "8.8.8.8")]
    assert all(a["threat_intel"]["virustotal"]["total_engines"] == 12
               for a in data["attackers"])
