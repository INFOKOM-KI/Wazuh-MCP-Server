#!/usr/bin/env python3
"""Regression tests for incomplete-result reporting.

Findings covered here:

* ``blueteam_wazuh_alert_summarize`` reported ``total_alerts`` as the number of
  documents it fetched (bounded by ``limit``), with no indication that the window
  held more. A 200-document sample of a 4,000-alert window read as 200 alerts.
* ``blueteam_curated_threat_report`` presented top-N terms buckets as if they were
  the complete set, ignoring the ``sum_other_doc_count`` the indexer returns. A
  failed dedup query also produced an empty note, implying nothing was deduplicated.
* ``sangfor_blocklist_check`` read a missing ``blocked`` key as ``False`` (clean).
  Absence of a field is not a negative answer.
* ``blueteam_check_webshell`` returned ``CLEAN`` when curl failed or the body was
  never fetched: no evidence was read as evidence of absence.

All indexer and HTTP boundaries are mocked. No Docker, no live Wazuh, no network.
"""
from __future__ import annotations

import asyncio
import json
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import pytest

from mcp_server.tools import alert_summarize
from mcp_server.tools import alert_curated_report as report
from mcp_server.tools import alert_enrichment
from mcp_server.tools import webshell_check


def _run(coro):
    return asyncio.run(coro)


def _tool(module, name):
    fn = getattr(module, name)
    return getattr(fn, "__wrapped__", fn)


# Alert summarize: fetched documents vs the window total

def _summarize_response(total_value: int, docs: int, relation: str = "eq"):
    hits = [{"_source": {
        "@timestamp": f"2026-01-01T00:00:0{i}Z",
        "rule": {"id": "5710", "level": 5, "description": "Synthetic rule"},
        "agent": {"name": "web01"},
        "data": {"srcip": "93.184.216.34"},
    }} for i in range(docs)]
    return {"hits": {"total": {"value": total_value, "relation": relation}, "hits": hits}}


def test_summarize_discloses_fetch_truncation(monkeypatch):
    async def fake_post(body, index_pattern=None):
        assert body.get("track_total_hits") is True
        return _summarize_response(412, 2)

    monkeypatch.setattr(alert_summarize, "_wazuh_indexer_post", fake_post)
    out = _run(_tool(alert_summarize, "blueteam_wazuh_alert_summarize")(
        alert_summarize.AlertSummarizeInput(
            srcip="93.184.216.34", limit=10, response_format="json")))
    data = json.loads(out)

    assert data["total_matching"] == 412
    assert data["alerts_analyzed"] == 2
    assert data["truncated"] is True
    assert data["omitted_alerts"] == 410


def test_summarize_complete_window_is_not_marked_truncated(monkeypatch):
    async def fake_post(body, index_pattern=None):
        return _summarize_response(2, 2)

    monkeypatch.setattr(alert_summarize, "_wazuh_indexer_post", fake_post)
    out = _run(_tool(alert_summarize, "blueteam_wazuh_alert_summarize")(
        alert_summarize.AlertSummarizeInput(
            srcip="93.184.216.34", limit=10, response_format="json")))
    data = json.loads(out)

    assert data["total_matching"] == 2
    assert data["truncated"] is False
    assert data["omitted_alerts"] == 0


# Curated report: sum_other_doc_count and deduplication state

PROPERTIES = {
    "data": {"properties": {"srcip": {"type": "keyword"}, "domain": {"type": "keyword"},
                            "url": {"type": "keyword"}, "user_agent": {"type": "keyword"}}},
    "rule": {"properties": {"id": {"type": "keyword"}, "description": {"type": "keyword"}}},
    "agent": {"properties": {"name": {"type": "keyword"}}},
    "location": {"type": "keyword"},
}

OTHER = 37


def _curated_aggs(total: int = 3):
    return {"aggregations": {
        "top_entities": {
            "sum_other_doc_count": OTHER,
            "buckets": [{"key": "93.184.216.34", "doc_count": 3,
                         "top_rules": {"buckets": [{"key": "5710", "doc_count": 2}]}}],
        },
        "total_alerts": {"value": total},
        "total_with_geo": {"value": 1},
        "top_rules": {"sum_other_doc_count": 5,
                      "buckets": [{"key": "5710", "doc_count": 2}]},
        "top_agents": {"sum_other_doc_count": 2,
                       "buckets": [{"key": "web01", "doc_count": 2}]},
        "top_domains": {"sum_other_doc_count": 4,
                        "buckets": [{"key": "evil.example", "doc_count": 1}]},
        "severity_bands": {"buckets": [{"key": "low", "doc_count": 3}]},
    }}


def _install_curated_mocks(monkeypatch, post):
    async def _mapping(index_pattern=None):
        return {"wazuh-alerts-1": {"mappings": {"properties": PROPERTIES}}}

    async def _caps(fields, index_pattern=None):
        return {path: "keyword" for path in
                ("data.srcip", "data.domain", "rule.id", "agent.name")}

    async def _msearch(bodies, index_pattern=None):
        return [{"hits": {"total": {"value": 3, "relation": "eq"}}} for _ in bodies]

    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_mapping", _mapping)
    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_field_caps", _caps)
    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_msearch", _msearch)
    monkeypatch.setattr("mcp_server.wazuh.indexer._wazuh_indexer_post", post)
    monkeypatch.setattr(report, "_wazuh_indexer_post", post)


def test_curated_report_discloses_truncated_buckets(monkeypatch):
    async def fake_post(body, index_pattern=None):
        return _curated_aggs()

    _install_curated_mocks(monkeypatch, fake_post)
    out = _run(_tool(report, "blueteam_curated_threat_report")(
        report.CuratedThreatReportInput(
            include_threat_intel=False, investigation_depth="summary",
            response_format="json")))
    data = json.loads(out)
    completeness = data["aggregation_completeness"]

    assert completeness["entities"]["truncated"] is True
    assert completeness["entities"]["sum_other_doc_count"] == OTHER
    assert completeness["top_rules"]["sum_other_doc_count"] == 5
    assert completeness["top_agents"]["sum_other_doc_count"] == 2
    assert completeness["top_domains"]["sum_other_doc_count"] == 4


def test_curated_report_marks_wrapper_count_failure_without_implying_inclusion(monkeypatch):
    async def fake_post(body, index_pattern=None):
        query = json.dumps(body.get("query", {}))
        if "must_not" in query:
            return _curated_aggs()
        if "606029" in query:
            raise RuntimeError("indexer unavailable")
        return _curated_aggs()

    _install_curated_mocks(monkeypatch, fake_post)
    out = _run(_tool(report, "blueteam_curated_threat_report")(
        report.CuratedThreatReportInput(
            deduplicate=True, include_threat_intel=False,
            investigation_depth="summary", response_format="json")))
    data = json.loads(out)

    assert data["dedup_applied"] is True
    assert data["active_response"]["excluded"] is True
    assert data["active_response"]["wrapper_count"] is None
    assert "count unavailable" in (data["dedup_note"] or "").lower()
    assert "excluded" in (data["dedup_note"] or "").lower()


# Sangfor: a missing boolean is unknown

class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


def _patch_sangfor(monkeypatch, payload):
    import mcp_server

    monkeypatch.setattr(mcp_server, "SANGFOR_BLOCKLIST_URL", "https://sangfor.example/blocklist")
    monkeypatch.setattr(mcp_server, "SANGFOR_BLOCKLIST_TOKEN", "test-token")
    monkeypatch.setattr(mcp_server, "SANGFOR_BLOCKLIST_VERIFY_SSL", False)

    async def fake_api_call(method, url, **kwargs):
        return _FakeResponse(payload)

    monkeypatch.setattr(alert_enrichment, "_api_call", fake_api_call)


def test_sangfor_missing_blocked_field_is_unknown(monkeypatch):
    _patch_sangfor(monkeypatch, {"entries": [{"ip_address": "93.184.216.34"}]})
    out = _run(_tool(alert_enrichment, "sangfor_blocklist_check")(
        alert_enrichment.SangforBlocklistCheckInput(
            ip="93.184.216.34", response_format="json")))
    data = json.loads(out)

    assert data["blocked"] is None
    assert data["status"] == "unknown"


def test_sangfor_explicit_false_is_not_blocked(monkeypatch):
    _patch_sangfor(monkeypatch, {"blocked": False, "entries": []})
    out = _run(_tool(alert_enrichment, "sangfor_blocklist_check")(
        alert_enrichment.SangforBlocklistCheckInput(
            ip="93.184.216.34", response_format="json")))
    data = json.loads(out)

    assert data["blocked"] is False
    assert data["status"] == "not_blocked"


def test_sangfor_explicit_true_is_blocked(monkeypatch):
    _patch_sangfor(monkeypatch, {"blocked": True, "entries": [{"ip_address": "93.184.216.34"}]})
    out = _run(_tool(alert_enrichment, "sangfor_blocklist_check")(
        alert_enrichment.SangforBlocklistCheckInput(
            ip="93.184.216.34", response_format="json")))
    data = json.loads(out)

    assert data["blocked"] is True
    assert data["status"] == "blocked"


# Webshell: a failed fetch has no verdict

def test_webshell_failed_fetch_is_unknown(monkeypatch):
    async def fake_run(cmd, timeout=10):
        return {"returncode": 7, "stdout": "", "stderr": "Failed to connect"}

    monkeypatch.setattr(webshell_check, "_host_pins",
                        lambda host, allowed: (["93.184.216.34"], None))
    monkeypatch.setattr(webshell_check, "_allowed_internal_domains", lambda: [])
    monkeypatch.setattr(webshell_check, "_pinned_curl_args", lambda url: ([], None))
    monkeypatch.setattr(webshell_check, "_run_async", fake_run)

    out = _run(_tool(webshell_check, "blueteam_check_webshell")(
        webshell_check.WebshellCheckInput(
            url="https://scan.example/shell.php", response_format="json")))
    data = json.loads(out)

    assert data["verdict"] == "UNKNOWN"
    assert data["evidence_sufficient"] is False


def test_webshell_http_error_body_is_not_clean(monkeypatch):
    async def fake_run(cmd, timeout=10):
        return {"returncode": 0,
                "stdout": "HTTP_STATUS:404\nCONTENT_TYPE:text/html\nSIZE:12\nREDIRECT:\n",
                "stderr": ""}

    monkeypatch.setattr(webshell_check, "_host_pins",
                        lambda host, allowed: (["93.184.216.34"], None))
    monkeypatch.setattr(webshell_check, "_allowed_internal_domains", lambda: [])
    monkeypatch.setattr(webshell_check, "_pinned_curl_args", lambda url: ([], None))
    monkeypatch.setattr(webshell_check, "_run_async", fake_run)

    out = _run(_tool(webshell_check, "blueteam_check_webshell")(
        webshell_check.WebshellCheckInput(
            url="https://scan.example/shell.php", response_format="json")))
    data = json.loads(out)

    assert data["http_status"] == 404
    assert data["verdict"] == "UNKNOWN"
    assert data["evidence_sufficient"] is False


def test_curated_report_reports_successful_dedup(monkeypatch):
    async def fake_post(body, index_pattern=None):
        query = json.dumps(body.get("query", {}))
        if "must_not" in query:
            return _curated_aggs(total=1)
        if "606029" in query:
            return {"aggregations": {"total_children": {"value": 2}}}
        return _curated_aggs()

    _install_curated_mocks(monkeypatch, fake_post)
    out = _run(_tool(report, "blueteam_curated_threat_report")(
        report.CuratedThreatReportInput(
            deduplicate=True, include_threat_intel=False,
            investigation_depth="summary", response_format="json")))
    data = json.loads(out)

    assert data["dedup_applied"] is True
    assert data["total_alerts"] == 1
    assert data["document_population"] == "deduplicated"
    assert data["active_response"] == {
        "excluded": True, "wrapper_count": 2, "rule_ids": ["606029", "651"]}


def test_curated_report_names_the_document_population(monkeypatch):
    bodies: list[dict] = []

    async def fake_post(body, index_pattern=None):
        bodies.append(body)
        query = json.dumps(body.get("query", {}))
        if "must_not" in query:
            return _curated_aggs(total=10)
        if "606029" in query:
            return {"aggregations": {"total_children": {"value": 4}}}
        return _curated_aggs(total=14)

    _install_curated_mocks(monkeypatch, fake_post)

    all_out = _run(_tool(report, "blueteam_curated_threat_report")(
        report.CuratedThreatReportInput(
            group_by="rule.id", include_threat_intel=False,
            investigation_depth="summary", response_format="json")))
    all_data = json.loads(all_out)
    assert all_data["total_alerts"] == 14
    assert all_data["document_population"] == "all_documents"
    assert all_data["active_response"]["excluded"] is False
    assert "must_not" not in json.dumps(bodies[0].get("query", {}))

    bodies.clear()
    dedup_out = _run(_tool(report, "blueteam_curated_threat_report")(
        report.CuratedThreatReportInput(
            group_by="rule.id", deduplicate=True, include_threat_intel=False,
            investigation_depth="summary", response_format="json")))
    dedup_data = json.loads(dedup_out)
    assert dedup_data["total_alerts"] == 10
    assert dedup_data["document_population"] == "deduplicated"
    assert dedup_data["active_response"]["excluded"] is True
    assert dedup_data["active_response"]["wrapper_count"] == 4
    main_query = json.dumps(bodies[0].get("query", {}))
    assert "must_not" in main_query
    assert "606029" in main_query and "651" in main_query


# full_log query contract: phrase matching, no wildcard, never a count axis

def test_full_log_srcip_clause_is_a_phrase_and_not_a_wildcard():
    from mcp_server.wazuh.indexer import _srcip_should_clauses

    with_log = _srcip_should_clauses("203.0.113.9")["bool"]["should"]
    assert {"match_phrase": {"full_log": "203.0.113.9"}} in with_log
    assert all("wildcard" not in clause for clause in with_log)

    without_log = _srcip_should_clauses("203.0.113.9", full_log=False)["bool"]["should"]
    assert all("full_log" not in json.dumps(clause) for clause in without_log)


def test_exact_srcip_counts_never_query_full_log(monkeypatch):
    from mcp_server.wazuh import indexer

    bodies: list[dict] = []

    async def fake_msearch(batch, index_pattern=None):
        bodies.extend(batch)
        return [{"hits": {"total": {"value": 3}}} for _ in batch]

    monkeypatch.setattr(indexer, "_wazuh_indexer_msearch", fake_msearch)
    counts = _run(indexer._exact_srcip_counts({"match_all": {}}, ["203.0.113.9"]))

    assert counts == {"203.0.113.9": 3}
    assert bodies
    assert all("full_log" not in json.dumps(body) for body in bodies)


def test_summarize_counts_active_response_wrappers_in_the_sample(monkeypatch):
    async def fake_post(body, index_pattern=None):
        docs = [
            {"_source": {"@timestamp": "2026-01-01T00:00:00Z",
                         "rule": {"id": "5710", "level": 5, "description": "Original"},
                         "agent": {"name": "web01"},
                         "data": {"srcip": "93.184.216.34"}}},
            {"_source": {"@timestamp": "2026-01-01T00:00:01Z",
                         "rule": {"id": "606029", "level": 5, "description": "Active Response"},
                         "agent": {"name": "web01"},
                         "data": {"srcip": "93.184.216.34"}}},
            {"_source": {"@timestamp": "2026-01-01T00:00:02Z",
                         "rule": {"id": "651", "level": 5, "description": "Agent-spawned"},
                         "agent": {"name": "web01"},
                         "data": {"srcip": "93.184.216.34"}}},
        ]
        return {"hits": {"total": {"value": 3, "relation": "eq"}, "hits": docs}}

    monkeypatch.setattr(alert_summarize, "_wazuh_indexer_post", fake_post)
    out = _run(_tool(alert_summarize, "blueteam_wazuh_alert_summarize")(
        alert_summarize.AlertSummarizeInput(
            srcip="93.184.216.34", limit=10, response_format="json")))
    data = json.loads(out)

    assert data["alerts_analyzed"] == 3
    assert data["active_response_wrappers_in_sample"] == 2


def test_summarize_positive_total_with_no_docs_is_not_a_clean_window(monkeypatch):
    async def fake_post(body, index_pattern=None):
        return {"hits": {"total": {"value": 12, "relation": "eq"}, "hits": []}}

    monkeypatch.setattr(alert_summarize, "_wazuh_indexer_post", fake_post)
    out = _run(_tool(alert_summarize, "blueteam_wazuh_alert_summarize")(
        alert_summarize.AlertSummarizeInput(
            srcip="93.184.216.34", limit=10, response_format="json")))
    data = json.loads(out)

    assert data["total_matching"] == 12
    assert data["alerts_analyzed"] == 0
    assert data["truncated"] is True
    assert data["omitted_alerts"] == 12


def _patch_netra(monkeypatch, payload):
    import mcp_server

    monkeypatch.setenv("NETRA_API_KEY", "test-key")
    monkeypatch.setattr(mcp_server, "NETRA_BASE_URL", "https://netra.example/api")
    monkeypatch.setattr(mcp_server, "NETRA_VERIFY_SSL", False)
    monkeypatch.setattr(alert_enrichment._netra_limiter, "min_interval", 0.0)

    async def fake_api_call(method, url, **kwargs):
        return _FakeResponse(payload)

    monkeypatch.setattr(alert_enrichment, "_api_call", fake_api_call)


def _netra_payload(ok, failed, score=0):
    return {"data": {"results": {
        "threat_score": {"score": score, "level": "low",
                         "sources_available": ok, "sources_failed": failed},
        "ipapi": {"results": {"isp": "Example ISP", "country": "ID", "city": "Tangerang"}},
        "ai_insight": {"success": False},
    }}}


def test_netra_partial_sources_are_not_a_clean_verdict(monkeypatch):
    _patch_netra(monkeypatch, _netra_payload(
        ["source_a", "source_b"],
        ["source_c", "source_d", "source_e", "source_f"]))
    out = _run(_tool(alert_enrichment, "netra_ip_analysis")(
        alert_enrichment.NetraIpAnalysisInput(
            ip="93.184.216.34", response_format="markdown")))

    assert "**Coverage**: partial" in out
    assert "2 of 6" in out
    assert "not a clean verdict" in out


def test_netra_complete_sources_are_not_marked_partial(monkeypatch):
    _patch_netra(monkeypatch, _netra_payload(
        ["a", "b", "c", "d", "e", "f"], [], score=0))
    out = _run(_tool(alert_enrichment, "netra_ip_analysis")(
        alert_enrichment.NetraIpAnalysisInput(
            ip="93.184.216.34", response_format="markdown")))

    assert "**Coverage**: complete" in out
    assert "not a clean verdict" not in out


def test_netra_no_sources_is_unavailable(monkeypatch):
    _patch_netra(monkeypatch, _netra_payload([], ["a", "b", "c", "d", "e", "f"], score=0))
    out = _run(_tool(alert_enrichment, "netra_ip_analysis")(
        alert_enrichment.NetraIpAnalysisInput(
            ip="93.184.216.34", response_format="markdown")))

    assert "**Coverage**: unavailable" in out
    assert "**Score**: not available" in out


def test_active_response_wrapper_ids_are_shared():
    from mcp_server.core.constants import ACTIVE_RESPONSE_WRAPPER_RULES
    from mcp_server.correlation.three_sum_core import _DEDUP_WRAPPER_RULES
    from mcp_server.tools.alert_compare import _DEDUP_PATTERNS

    assert set(_DEDUP_WRAPPER_RULES) == set(ACTIVE_RESPONSE_WRAPPER_RULES)
    assert _DEDUP_PATTERNS == list(ACTIVE_RESPONSE_WRAPPER_RULES.items())
