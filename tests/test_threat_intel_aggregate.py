#!/usr/bin/env python3
"""Tests for unified threat intel aggregator."""
from __future__ import annotations

import os

# mcp_server/__init__.py calls init_config() at import and hard-fails without
# WAZUH_INDEXER_* (ConfigurationError). Seed them at module level so this file
# passes in isolation, not only when a peer module happens to import first.
os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")


def test_ti_provider_result_model():
    from mcp_server.tools.threat_intel_aggregate import TIProviderResult
    r = TIProviderResult(provider="crowdsec", indicator="1.2.3.4",
                         indicator_type="IPv4", risk_level="high",
                         reputation_score=100, is_malicious=True,
                         malware_families=["Emotet"], attack_techniques=["T1190"])
    assert r.provider == "crowdsec"
    assert r.is_malicious is True
    assert "Emotet" in r.malware_families
    assert "T1190" in r.attack_techniques


def test_ti_query_output_model():
    from mcp_server.tools.threat_intel_aggregate import TIQueryOutput, TIProviderResult
    r1 = TIProviderResult(provider="crowdsec", indicator="1.2.3.4",
                          indicator_type="IPv4", risk_level="high",
                          is_malicious=True)
    r2 = TIProviderResult(provider="otx", indicator="1.2.3.4",
                          indicator_type="IPv4", risk_level="medium",
                          is_malicious=True)
    out = TIQueryOutput(indicator="1.2.3.4", indicator_type="IPv4",
                        results=[r1, r2], aggregated_risk_level="high",
                        consensus_malicious=2)
    assert out.consensus_malicious == 2
    assert out.aggregated_risk_level == "high"


def test_aggregate_consensus():
    from mcp_server.tools.threat_intel_aggregate import _aggregate, TIProviderResult
    results = [
        TIProviderResult(provider="crowdsec", indicator="1.2.3.4",
                         indicator_type="IPv4", risk_level="high",
                         is_malicious=True, reputation_score=90),
        TIProviderResult(provider="otx", indicator="1.2.3.4",
                         indicator_type="IPv4", risk_level="medium",
                         is_malicious=True, reputation_score=60),
        TIProviderResult(provider="greynoise", indicator="1.2.3.4",
                         indicator_type="IPv4", risk_level="none",
                         is_malicious=False, reputation_score=0),
        TIProviderResult(provider="virustotal", indicator="1.2.3.4",
                         indicator_type="IPv4", error="not configured"),
    ]
    out = _aggregate(results)
    assert out.consensus_malicious == 2  # crowdsec + otx
    assert out.aggregated_risk_level == "high"  # highest risk wins
    assert len(out.errors) == 1  # virustotal skipped


def test_aggregate_all_errors():
    from mcp_server.tools.threat_intel_aggregate import _aggregate, TIProviderResult
    results = [
        TIProviderResult(provider="crowdsec", indicator="1.2.3.4",
                         indicator_type="IPv4", error="not configured"),
        TIProviderResult(provider="otx", indicator="1.2.3.4",
                         indicator_type="IPv4", error="not configured"),
    ]
    out = _aggregate(results)
    assert out.consensus_malicious == 0
    assert out.aggregated_risk_level is None
    assert len(out.errors) == 2


def test_input_validation_rejects_private_ip():
    from mcp_server.tools.threat_intel_aggregate import ThreatIntelAggregateInput
    from pydantic import ValidationError
    try:
        ThreatIntelAggregateInput(indicator="192.168.1.1")
        assert False, "Should have raised"
    except ValidationError:
        pass


def test_input_validation_accepts_public():
    from mcp_server.tools.threat_intel_aggregate import ThreatIntelAggregateInput
    inp = ThreatIntelAggregateInput(indicator="140.82.0.86")
    assert inp.indicator == "140.82.0.86"


class _FakeResponse:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def json(self) -> dict:
        return self._payload


_VT_STATS = {"data": {"attributes": {
    "last_analysis_stats": {"malicious": 6, "suspicious": 0, "harmless": 60, "undetected": 4},
    "reputation": 12,
}}}


def test_virustotal_provider_routes_indicator_types():
    import asyncio
    from unittest.mock import patch
    from mcp_server.tools import threat_intel_aggregate as agg

    seen: list[str] = []

    async def fake_api_call(method, url, **kw):
        seen.append(url)
        return _FakeResponse(_VT_STATS)

    async def lookup(indicator, ind_type):
        with patch.object(agg, "_api_call", fake_api_call), \
                patch.object(agg, "VIRUSTOTAL_API_KEY", "test-key"):
            return await agg._virustotal_provider(indicator, ind_type)

    cases = [("140.82.0.86", "IPv4", "ip_addresses"),
             ("evil.example.com", "domain", "domains"),
             ("a" * 64, "file", "files")]
    for indicator, ind_type, segment in cases:
        result = asyncio.run(lookup(indicator, ind_type))
        assert result.error is None, result.error
        assert seen[-1].endswith(f"/{segment}/{indicator}"), seen[-1]
        assert result.risk_level == "low"  # 6/70 = 8%
        assert result.reputation_score == 8
        assert result.is_malicious is True
        assert result.detail["detections"] == "6/70"


def test_virustotal_provider_without_key_reports_not_configured():
    import asyncio
    from unittest.mock import patch
    from mcp_server.tools import threat_intel_aggregate as agg

    async def lookup():
        with patch.object(agg, "VIRUSTOTAL_API_KEY", ""):
            return await agg._virustotal_provider("140.82.0.86", "IPv4")

    result = asyncio.run(lookup())
    assert result.error == "not configured"
    assert result.error_kind == "not_configured"


def _http_status_error(status: int):
    import httpx
    req = httpx.Request("GET", "https://upstream.example/api")
    return httpx.HTTPStatusError(f"status {status}", request=req,
                                 response=httpx.Response(status, request=req))


def test_classifier_maps_every_error_kind():
    import httpx
    from typing import get_args
    from mcp_server.core.http_client import _classify_api_error, CircuitOpenError
    from mcp_server.tools.threat_intel_aggregate import ErrorKind

    cases = [
        (_http_status_error(429), "rate_limited"),
        (_http_status_error(401), "auth_error"),
        (_http_status_error(403), "auth_error"),
        (_http_status_error(404), "not_found"),
        (_http_status_error(400), "bad_request"),
        (_http_status_error(500), "upstream_error"),
        (_http_status_error(503), "upstream_error"),
        (httpx.ReadTimeout("slow"), "timeout"),
        (CircuitOpenError("open"), "circuit_open"),
        (RuntimeError("THREATFOX_API_KEY not set"), "not_configured"),
    ]
    for exc, expected in cases:
        kind = _classify_api_error(exc)
        assert kind == expected, (exc, kind)
        assert kind in get_args(ErrorKind)


def test_crowdsec_provider_marks_rate_limited():
    import asyncio
    from unittest.mock import patch
    from mcp_server.tools import threat_intel_aggregate as agg

    async def boom(path):
        raise _http_status_error(429)

    async def lookup():
        with patch.dict(os.environ, {"CROWDSEC_API_KEY": "test-key"}), \
                patch("mcp_server.threat_intel.crowdsec._crowdsec_request", boom):
            return await agg._crowdsec_provider("140.82.0.86", "IPv4")

    result = asyncio.run(lookup())
    assert result.error_kind == "rate_limited"
    assert "429" in result.error


def test_threatfox_provider_marks_upstream_error():
    import asyncio
    from unittest.mock import patch
    from mcp_server.tools import threat_intel_aggregate as agg

    async def boom(search_term, exact_match=False):
        raise _http_status_error(503)

    async def lookup():
        with patch.dict(os.environ, {"THREATFOX_API_KEY": "test-key"}), \
                patch("mcp_server.threat_intel.threatfox._threatfox_request", boom):
            return await agg._threatfox_provider("evil-c2.example.com", "domain")

    result = asyncio.run(lookup())
    assert result.error_kind == "upstream_error"


def test_provider_guards_report_not_configured_and_unsupported_type():
    import asyncio
    from unittest.mock import patch
    from mcp_server.tools import threat_intel_aggregate as agg

    async def lookup():
        with patch.dict(os.environ, {"CROWDSEC_API_KEY": ""}):
            unconfigured = await agg._crowdsec_provider("140.82.0.86", "IPv4")
        unsupported = await agg._greynoise_provider("evil.example.com", "domain")
        return unconfigured, unsupported

    unconfigured, unsupported = asyncio.run(lookup())
    assert unconfigured.error_kind == "not_configured"
    assert unconfigured.error == "not configured"
    assert unsupported.error_kind == "unsupported_type"
    assert unsupported.error == "unsupported type"


def test_json_output_carries_error_kind_without_losing_error():
    from mcp_server.tools.threat_intel_aggregate import TIQueryOutput, TIProviderResult
    out = TIQueryOutput(indicator="1.2.3.4", indicator_type="IPv4", results=[
        TIProviderResult(provider="otx", indicator="1.2.3.4", indicator_type="IPv4",
                         error="not configured", error_kind="not_configured"),
        TIProviderResult(provider="crowdsec", indicator="1.2.3.4", indicator_type="IPv4"),
    ])
    payload = out.model_dump()
    assert payload["results"][0]["error"] == "not configured"
    assert payload["results"][0]["error_kind"] == "not_configured"
    assert payload["results"][1]["error"] is None
    assert payload["results"][1]["error_kind"] is None


def test_aggregate_coverage_counts_only_attempted_providers():
    from mcp_server.tools.threat_intel_aggregate import _aggregate, TIProviderResult
    results = [
        TIProviderResult(provider="crowdsec", indicator="1.2.3.4",
                         indicator_type="IPv4", risk_level="high", is_malicious=True),
        TIProviderResult(provider="otx", indicator="1.2.3.4",
                         indicator_type="IPv4", error="boom", error_kind="upstream_error"),
        TIProviderResult(provider="virustotal", indicator="1.2.3.4",
                         indicator_type="IPv4", error="not configured",
                         error_kind="not_configured"),
        TIProviderResult(provider="greynoise", indicator="1.2.3.4",
                         indicator_type="IPv4", error="unsupported type",
                         error_kind="unsupported_type"),
    ]
    out = _aggregate(results)
    assert out.providers_total == 2  # crowdsec + otx only
    assert out.providers_ok == 1
    assert len(out.errors) == 3


def test_aggregate_all_attempted_providers_fail():
    from mcp_server.tools.threat_intel_aggregate import _aggregate, TIProviderResult
    results = [
        TIProviderResult(provider="crowdsec", indicator="1.2.3.4",
                         indicator_type="IPv4", error="429", error_kind="rate_limited"),
        TIProviderResult(provider="otx", indicator="1.2.3.4",
                         indicator_type="IPv4", error="timeout", error_kind="timeout"),
    ]
    out = _aggregate(results)
    assert out.providers_total == 2
    assert out.providers_ok == 0
    assert out.aggregated_risk_level is None


def test_aggregate_zero_eligible_providers():
    from mcp_server.tools.threat_intel_aggregate import _aggregate, TIProviderResult
    results = [
        TIProviderResult(provider="crowdsec", indicator="evil.example.com",
                         indicator_type="domain", error="unsupported type",
                         error_kind="unsupported_type"),
        TIProviderResult(provider="virustotal", indicator="evil.example.com",
                         indicator_type="domain", error="not configured",
                         error_kind="not_configured"),
    ]
    out = _aggregate(results)
    assert out.providers_total == 0
    assert out.providers_ok == 0
    assert out.aggregated_risk_level is None
    assert len(out.errors) == 2


def test_aggregate_full_success_coverage():
    from mcp_server.tools.threat_intel_aggregate import _aggregate, TIProviderResult
    results = [
        TIProviderResult(provider="crowdsec", indicator="1.2.3.4",
                         indicator_type="IPv4", risk_level="low", is_malicious=False),
        TIProviderResult(provider="otx", indicator="1.2.3.4",
                         indicator_type="IPv4", risk_level="none", is_malicious=False),
    ]
    out = _aggregate(results)
    assert out.providers_total == 2
    assert out.providers_ok == 2


if __name__ == "__main__":
    import sys, traceback
    tests = [f for f in dir() if f.startswith("test_")]
    passed = 0
    for t in tests:
        try:
            globals()[t]()
            print(f"PASS {t}")
            passed += 1
        except Exception:
            print(f"FAIL {t}")
            traceback.print_exc()
    print(f"\n{passed}/{len(tests)} passed")
    sys.exit(0 if passed == len(tests) else 1)
