#!/usr/bin/env python3
"""GreyNoise shared lookup: cache reuse, no blind retries, honest provider errors."""
from __future__ import annotations

import asyncio
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

_GN_URL = "https://api.greynoise.io/v3/community"


def _run(coro):
    return asyncio.run(coro)


def _response(ip: str, payload: dict, status: int = 200):
    import httpx
    req = httpx.Request("GET", f"{_GN_URL}/{ip}")
    return httpx.Response(status_code=status, json=payload, request=req)


def _status_error(ip: str, status: int, headers: dict | None = None):
    import httpx
    req = httpx.Request("GET", f"{_GN_URL}/{ip}")
    resp = httpx.Response(status_code=status, request=req, headers=headers or {})
    return httpx.HTTPStatusError(f"HTTP {status}", request=req, response=resp)


def _no_pacing(monkeypatch, gn):
    monkeypatch.setattr(gn._greynoise_limiter, "min_interval", 0)


def test_lookup_reuses_cache_within_ttl(monkeypatch):
    from mcp_server.threat_intel import greynoise as gn

    _no_pacing(monkeypatch, gn)
    calls = {"n": 0}

    async def _api(method, url, **kw):
        calls["n"] += 1
        return _response("198.51.100.7", {"ip": "198.51.100.7", "noise": False,
                                          "riot": False, "classification": "benign"})

    monkeypatch.setattr(gn, "_api_call", _api)

    first = _run(gn._greynoise_lookup("198.51.100.7"))
    second = _run(gn._greynoise_lookup("198.51.100.7"))

    assert calls["n"] == 1
    assert first == second


def test_lookup_turns_404_into_cached_no_data(monkeypatch):
    from mcp_server.threat_intel import greynoise as gn

    _no_pacing(monkeypatch, gn)
    calls = {"n": 0}

    async def _api(method, url, **kw):
        calls["n"] += 1
        raise _status_error("198.51.100.8", 404)

    monkeypatch.setattr(gn, "_api_call", _api)

    raw = _run(gn._greynoise_lookup("198.51.100.8"))
    again = _run(gn._greynoise_lookup("198.51.100.8"))

    assert raw["message"] == "No data in GreyNoise Community dataset"
    assert raw["noise"] is False and raw["riot"] is False
    assert calls["n"] == 1
    assert again == raw


def test_lookup_propagates_429_without_retry_or_cache(monkeypatch):
    import httpx
    from mcp_server.threat_intel import greynoise as gn

    _no_pacing(monkeypatch, gn)
    calls = {"n": 0}
    failures = {"left": 1}

    async def _api(method, url, **kw):
        calls["n"] += 1
        if failures["left"]:
            failures["left"] = 0
            raise _status_error("198.51.100.9", 429, headers={"x-ratelimit-remaining": "0"})
        return _response("198.51.100.9", {"ip": "198.51.100.9", "noise": True,
                                          "riot": False, "classification": "malicious"})

    monkeypatch.setattr(gn, "_api_call", _api)

    try:
        _run(gn._greynoise_lookup("198.51.100.9"))
    except httpx.HTTPStatusError as e:
        assert e.response.status_code == 429
    else:
        raise AssertionError("429 must propagate")

    assert calls["n"] == 1  # the shared layer adds no blind retry

    raw = _run(gn._greynoise_lookup("198.51.100.9"))  # the error was not cached
    assert calls["n"] == 2
    assert raw["classification"] == "malicious"


def test_tool_and_lookup_share_one_cache(monkeypatch):
    from mcp_server.threat_intel import greynoise as gn

    _no_pacing(monkeypatch, gn)
    calls = {"n": 0}

    async def _api(method, url, **kw):
        calls["n"] += 1
        return _response("1.1.1.1", {"ip": "1.1.1.1", "noise": False,
                                     "riot": True, "classification": "benign"})

    monkeypatch.setattr(gn, "_api_call", _api)

    first = _run(gn.greynoise_ip_context(gn.GreyNoiseContextInput(ip="1.1.1.1")))
    second = _run(gn.greynoise_ip_context(gn.GreyNoiseContextInput(ip="1.1.1.1")))

    assert "GreyNoise Community" in first
    assert first == second
    assert calls["n"] == 1


def test_aggregate_maps_no_data_to_unknown_not_low(monkeypatch):
    from mcp_server.tools import threat_intel_aggregate as agg

    async def _lookup(ip):
        return {"ip": ip, "noise": False, "riot": False, "classification": "unknown",
                "message": "No data in GreyNoise Community dataset"}

    monkeypatch.setattr(agg, "_greynoise_lookup", _lookup)

    result = _run(agg._greynoise_provider("198.51.100.11", "IPv4"))

    assert result.error is None
    assert result.risk_level is None
    assert result.is_malicious is None
    assert "no_data" in result.tags


def test_aggregate_keeps_rate_limited_provider_out_of_the_verdict(monkeypatch):
    from mcp_server.tools import threat_intel_aggregate as agg

    async def _lookup(ip):
        raise _status_error(ip, 429)

    monkeypatch.setattr(agg, "_greynoise_lookup", _lookup)

    result = _run(agg._greynoise_provider("198.51.100.12", "IPv4"))
    assert result.risk_level is None
    assert result.is_malicious is None
    assert result.error_kind == "rate_limited"

    out = agg._aggregate([
        result,
        agg.TIProviderResult(provider="otx", indicator="198.51.100.12",
                             indicator_type="IPv4", risk_level="medium",
                             is_malicious=False),
    ])
    assert out.aggregated_risk_level == "medium"
    assert out.providers_ok == 1
    assert out.providers_total == 2
    assert any("greynoise" in e for e in out.errors)


def test_aggregate_keeps_success_body_with_message_field(monkeypatch):
    from mcp_server.tools import threat_intel_aggregate as agg
    from mcp_server.threat_intel import greynoise as gn

    _no_pacing(monkeypatch, gn)

    async def _api(method, url, **kw):
        # GreyNoise puts message="Success" in every 200 body; only the synthetic
        # 404 record marks no-data.
        return _response("9.9.9.9", {"ip": "9.9.9.9", "noise": False, "riot": True,
                                     "classification": "benign", "name": "Quad9",
                                     "last_seen": "2026-01-01", "message": "Success"})

    monkeypatch.setattr(gn, "_api_call", _api)

    result = _run(agg._greynoise_provider("9.9.9.9", "IPv4"))

    assert result.error is None
    assert result.risk_level == "none"
    assert result.is_malicious is False
    assert "no_data" not in result.tags
    assert result.detail["name"] == "Quad9"


def test_provider_errors_keep_their_classifications(monkeypatch):
    import httpx
    from mcp_server.tools import threat_intel_aggregate as agg

    async def _lookup_timeout(ip):
        raise httpx.TimeoutException("read timeout")

    async def _lookup_malformed(ip):
        raise ValueError("Expecting value: line 1 column 1 (char 0)")

    monkeypatch.setattr(agg, "_greynoise_lookup", _lookup_timeout)
    timeout_result = _run(agg._greynoise_provider("9.9.9.9", "IPv4"))
    assert timeout_result.error_kind == "timeout"
    assert timeout_result.risk_level is None

    monkeypatch.setattr(agg, "_greynoise_lookup", _lookup_malformed)
    malformed_result = _run(agg._greynoise_provider("9.9.9.9", "IPv4"))
    assert malformed_result.error_kind == "upstream_error"
    assert malformed_result.risk_level is None
