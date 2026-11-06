#!/usr/bin/env python3
"""Regression tests for provider response normalization and partial results.

These reproduce defects found during source inspection:

* OTX returns ``attack_ids`` / ``malware_families`` as lists of dicts in some
  responses. A set comprehension over them raised ``unhashable type: 'dict'``,
  which downgraded the whole OTX provider to an upstream error (and could hide a
  real pulse).
* A response with the expected 200 status but a body that is not the documented
  shape (a JSON string, a missing ``pulse_info``/``data`` object) was read as a
  clean verdict (``risk_level="none"``) instead of an unavailable provider.
* ThreatFox's bulk path called ``.get`` on a non-object JSON body and crashed
  the whole batch instead of recording that one provider as unavailable.

All HTTP calls are replaced at the module boundary. No request leaves the host.
"""
from __future__ import annotations

import asyncio
import os
from unittest.mock import patch

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import pytest

from mcp_server.core.exceptions import ThreatIntelError
from mcp_server.threat_intel import otx, threatfox
from mcp_server.tools import threat_intel_aggregate as agg
from mcp_server.threat_intel import abuseipdb


def _run(coro):
    return asyncio.run(coro)


def _otx_pulse() -> dict:
    """One pulse in the shape OTX actually returns for attack_ids."""
    return {
        "name": "Synthetic pulse",
        "author": {"username": "analyst"},
        "created": "2026-01-01T00:00:00",
        "modified": "2026-01-02T00:00:00",
        "tags": ["c2", "malware"],
        "malware_families": ["ExampleLoader"],
        "adversary": {"name": "APT-Example"},
        "industries": ["Government"],
        "attack_ids": [
            {"id": "T1190", "name": "Exploit Public-Facing Application",
             "display_name": "Exploit Public-Facing Application"},
            {"id": "T1499.003", "name": "Application Exhaustion Flood"},
        ],
        "targeted_countries": ["ID"],
        "indicator_count": 4,
    }


def test_extract_pulse_summary_normalizes_dict_attack_ids():
    summary = otx._extract_pulse_summary([_otx_pulse()])
    assert summary[0]["attack_ids"] == ["T1190", "T1499.003"]
    assert summary[0]["adversary"] == "APT-Example"
    assert summary[0]["malware_families"] == ["ExampleLoader"]


def test_otx_provider_keeps_pulses_with_dict_attack_ids(monkeypatch):
    monkeypatch.setenv("OTX_API_KEY", "test-key")

    async def fake_request(indicator, section="general"):
        if section == "malware":
            return {"data": []}
        return {"pulse_info": {"count": 1, "pulses": [_otx_pulse()]}}

    with patch("mcp_server.threat_intel.otx._otx_request", fake_request):
        result = _run(agg._otx_provider("evil.example.com", "domain"))

    assert result.error is None, result.error
    assert result.is_malicious is True
    assert result.attack_techniques == ["T1190", "T1499.003"]
    assert result.malware_families == ["ExampleLoader"]
    assert result.adversaries == ["APT-Example"]


def test_otx_provider_malformed_body_is_unavailable_not_clean(monkeypatch):
    monkeypatch.setenv("OTX_API_KEY", "test-key")

    async def fake_request(indicator, section="general"):
        return {"unexpected": "not an OTX response"}

    with patch("mcp_server.threat_intel.otx._otx_request", fake_request):
        result = _run(agg._otx_provider("evil.example.com", "domain"))

    assert result.error is not None
    assert result.error_kind == "upstream_error"
    assert result.risk_level is None
    assert result.is_malicious is None


def test_otx_markdown_renders_dict_attack_ids_as_ids():
    rendered = otx._format_otx_markdown("evil.example.com", "domain",
                                        {"pulse_info": {"count": 1}},
                                        [_otx_pulse()])
    assert "T1190" in rendered
    assert "T1499.003" in rendered
    assert "{'id'" not in rendered


def test_threatfox_request_rejects_non_object_body():
    class _Response:
        def json(self):
            return "ok"

    async def fake_api_call(method, url, **kwargs):
        return _Response()

    with patch.object(threatfox, "_api_call", fake_api_call), \
            patch.object(threatfox, "_get_threatfox_api_key", lambda: "test-key"):
        with pytest.raises(ThreatIntelError):
            _run(threatfox._threatfox_request("evil.example.com"))


def test_threatfox_provider_bad_status_is_error(monkeypatch):
    monkeypatch.setenv("THREATFOX_API_KEY", "test-key")

    async def fake_request(indicator, exact_match=False):
        return {"query_status": "illegal_search_term", "data": []}

    with patch("mcp_server.threat_intel.threatfox._threatfox_request", fake_request):
        result = _run(agg._threatfox_provider("evil.example.com", "domain"))

    assert result.error is not None
    assert result.error_kind == "upstream_error"
    assert result.risk_level is None
    assert result.is_malicious is None


def test_virustotal_missing_data_is_error(monkeypatch):
    class _Response:
        def json(self):
            return {"error": {"code": "NotFoundError"}}

    async def fake_api_call(method, url, **kwargs):
        return _Response()

    monkeypatch.setattr(agg, "VIRUSTOTAL_API_KEY", "test-key")
    with patch.object(agg, "_api_call", fake_api_call):
        result = _run(agg._virustotal_provider("140.82.0.86", "IPv4"))

    assert result.error is not None
    assert result.error_kind == "upstream_error"
    assert result.risk_level is None
    assert result.is_malicious is None


def test_abuseipdb_missing_data_is_error(monkeypatch):
    class _Response:
        def json(self):
            return {"errors": [{"detail": "quota"}]}

    async def fake_api_call(method, url, **kwargs):
        return _Response()

    monkeypatch.setattr(abuseipdb, "ABUSEIPDB_API_KEY", "test-key")
    with patch.object(abuseipdb, "_api_call", fake_api_call):
        result = _run(agg._abuseipdb_provider("140.82.0.86", "IPv4"))

    assert result.error is not None
    assert result.error_kind == "upstream_error"
    assert result.risk_level is None
    assert result.is_malicious is None


def _http_status_error(status: int):
    import httpx
    request = httpx.Request("GET", "https://upstream.example/api")
    return httpx.HTTPStatusError(f"status {status}", request=request,
                                 response=httpx.Response(status, request=request))


def test_rate_limited_provider_is_attempted_but_not_clean(monkeypatch):
    monkeypatch.setenv("CROWDSEC_API_KEY", "test-key")

    async def fake_request(path):
        raise _http_status_error(429)

    with patch("mcp_server.threat_intel.crowdsec._crowdsec_request", fake_request):
        result = _run(agg._crowdsec_provider("140.82.0.86", "IPv4"))

    assert result.error_kind == "rate_limited"
    assert result.risk_level is None
    assert result.is_malicious is None

    output = agg._aggregate([result])
    assert output.providers_total == 1
    assert output.providers_ok == 0
    assert output.aggregated_risk_level is None


def test_timeout_is_reported_as_timeout_not_clean(monkeypatch):
    import httpx

    async def fake_api_call(method, url, **kwargs):
        raise httpx.ReadTimeout("slow upstream")

    monkeypatch.setattr(abuseipdb, "ABUSEIPDB_API_KEY", "test-key")
    with patch.object(abuseipdb, "_api_call", fake_api_call):
        result = _run(agg._abuseipdb_provider("140.82.0.86", "IPv4"))

    assert result.error_kind == "timeout"
    assert result.risk_level is None
    assert result.is_malicious is None


def test_partial_provider_availability_keeps_the_valid_result():
    results = [
        agg.TIProviderResult(provider="otx", indicator="evil.example.com",
                             indicator_type="domain", risk_level="medium",
                             is_malicious=True, reputation_score=60),
        agg.TIProviderResult(provider="threatfox", indicator="evil.example.com",
                             indicator_type="domain", error="timed out",
                             error_kind="timeout"),
    ]
    output = agg._aggregate(results)

    assert output.providers_total == 2
    assert output.providers_ok == 1
    assert output.consensus_malicious == 1
    assert output.aggregated_risk_level == "medium"
    assert any("threatfox" in error for error in output.errors)


def test_otx_pulse_count_without_pulses_is_not_clean(monkeypatch):
    monkeypatch.setenv("OTX_API_KEY", "test-key")

    async def fake_request(indicator, section="general"):
        return {"pulse_info": {"count": 4, "pulses": []}}

    with patch("mcp_server.threat_intel.otx._otx_request", fake_request):
        result = _run(agg._otx_provider("evil.example.com", "domain"))

    assert result.error is not None
    assert result.risk_level is None
    assert result.is_malicious is None


def test_threatfox_ok_without_data_is_malformed(monkeypatch):
    monkeypatch.setenv("THREATFOX_API_KEY", "test-key")

    async def fake_request(indicator, exact_match=False):
        return {"query_status": "ok"}

    with patch("mcp_server.threat_intel.threatfox._threatfox_request", fake_request):
        result = _run(agg._threatfox_provider("evil.example.com", "domain"))

    assert result.error is not None
    assert result.risk_level is None
    assert result.is_malicious is None


def test_virustotal_without_stats_is_malformed(monkeypatch):
    class _Response:
        def json(self):
            return {"data": {"attributes": {"reputation": 0}}}

    async def fake_api_call(method, url, **kwargs):
        return _Response()

    monkeypatch.setattr(agg, "VIRUSTOTAL_API_KEY", "test-key")
    with patch.object(agg, "_api_call", fake_api_call):
        result = _run(agg._virustotal_provider("140.82.0.86", "IPv4"))

    assert result.error is not None
    assert result.risk_level is None
    assert result.is_malicious is None


def test_abuseipdb_without_confidence_is_malformed(monkeypatch):
    class _Response:
        def json(self):
            return {"data": {"totalReports": 0}}

    async def fake_api_call(method, url, **kwargs):
        return _Response()

    monkeypatch.setattr(abuseipdb, "ABUSEIPDB_API_KEY", "test-key")
    with patch.object(abuseipdb, "_api_call", fake_api_call):
        result = _run(agg._abuseipdb_provider("140.82.0.86", "IPv4"))

    assert result.error is not None
    assert result.risk_level is None
    assert result.is_malicious is None


def test_threatfox_no_results_is_unknown_not_clean(monkeypatch):
    monkeypatch.setenv("THREATFOX_API_KEY", "test-key")

    async def fake_request(indicator, exact_match=False):
        return {"query_status": "no_results", "data": []}

    with patch("mcp_server.threat_intel.threatfox._threatfox_request", fake_request):
        result = _run(agg._threatfox_provider("evil.example.com", "domain"))

    assert result.error is None
    assert result.risk_level is None
    assert result.is_malicious is None
    assert "no_results" in result.tags
    assert result.detail["match_count"] == 0


def test_unknown_vote_is_not_rendered_as_negative():
    assert agg._malicious_mark(None) == "?"
    assert agg._malicious_mark(True) == "✅"
    assert agg._malicious_mark(False) == "❌"
