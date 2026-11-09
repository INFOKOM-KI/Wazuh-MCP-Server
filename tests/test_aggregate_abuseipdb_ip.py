#!/usr/bin/env python3
"""AbuseIPDB inside ``blueteam_threat_intel_aggregate`` must work for IPv4 and IPv6.

The standalone ``blueteam_abuseipdb_check`` tool always accepted both, but the
aggregate's AbuseIPDB adapter answered ``unsupported_type`` for IPv6, so an
analyst investigating an IPv6 alert silently lost one of six providers. The
adapter now routes both versions to the same ``/check`` endpoint.

These tests drive the aggregate adapter with a real ``httpx.AsyncClient`` over a
``MockTransport``, so they assert the request that would actually be sent rather
than the kwargs some fake received. Nothing leaves the process.
"""
from __future__ import annotations

import asyncio
import json
import os

import httpx
import pytest

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

from mcp_server.core import http_client
from mcp_server.threat_intel._cache import AsyncRateLimiter, cache_delete_prefix
from mcp_server.tools import threat_intel_aggregate as agg

QUOTA_HEADERS = {
    "x-ratelimit-limit": "1000",
    "x-ratelimit-remaining": "900",
    "x-ratelimit-reset": "2026-11-06T02:00:00+00:00",
}


def _run(coro):
    return asyncio.run(coro)


def _check_payload(ip: str, ip_version: int, score: int) -> dict:
    return {"data": {
        "ipAddress": ip, "isPublic": True, "ipVersion": ip_version,
        "abuseConfidenceScore": score, "totalReports": 7,
        "lastReportedAt": "2026-11-05T12:00:00+00:00",
        "countryCode": "NL", "isp": "Example Hosting", "usageType": "Data Center",
    }}


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    from mcp_server.threat_intel import abuseipdb

    monkeypatch.setattr(abuseipdb, "CHECK_LIMITER",
                        AsyncRateLimiter(max_concurrent=1, min_interval=0))
    monkeypatch.setattr(abuseipdb, "ABUSEIPDB_API_KEY", "test-key")
    abuseipdb.reset_quota_state()
    cache_delete_prefix("abuseipdb", "")


@pytest.fixture
def real_client(monkeypatch):
    """Real client over a mock transport. ``seen`` holds the built requests."""
    seen: list[httpx.Request] = []
    payloads = {
        "8.8.8.8": _check_payload("8.8.8.8", 4, 80),
        "2001:4860:4860::8888": _check_payload("2001:4860:4860::8888", 6, 30),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        ip = request.url.params.get("ipAddress", "")
        return httpx.Response(200, headers=QUOTA_HEADERS,
                              content=json.dumps(payloads[ip]).encode())

    transport = httpx.MockTransport(handler)

    async def fake_get_client(name, verify=True):
        return httpx.AsyncClient(transport=transport)

    monkeypatch.setattr(http_client, "_get_client", fake_get_client)
    monkeypatch.setattr(http_client, "_get_breaker",
                        lambda name: http_client.CircuitBreaker())
    return seen


def test_aggregate_abuseipdb_provider_queries_ipv4(real_client):
    result = _run(agg._abuseipdb_provider("8.8.8.8", "IPv4"))

    assert result.error is None, result.error
    assert result.provider == "abuseipdb"
    assert result.indicator_type == "IPv4"
    assert result.risk_level == "high"
    assert result.reputation_score == 80
    assert result.is_malicious is True

    request = real_client[0]
    assert request.method == "GET"
    assert request.url.path == "/api/v2/check"
    assert request.url.params["ipAddress"] == "8.8.8.8"
    assert request.headers["key"] == "test-key"


def test_aggregate_abuseipdb_provider_queries_ipv6(real_client):
    """Regression: this returned error_kind='unsupported_type' before the fix."""
    result = _run(agg._abuseipdb_provider("2001:4860:4860::8888", "IPv6"))

    assert result.error is None, result.error
    assert result.error_kind is None
    assert result.indicator_type == "IPv6"
    assert result.risk_level == "low"
    assert result.reputation_score == 30
    assert result.is_malicious is False

    request = real_client[0]
    assert request.method == "GET"
    assert request.url.path == "/api/v2/check"
    assert request.url.params["ipAddress"] == "2001:4860:4860::8888"
    assert request.headers["key"] == "test-key"


@pytest.mark.parametrize("ind_type", ["domain", "file", "unknown"])
def test_aggregate_abuseipdb_provider_still_refuses_non_ip_types(ind_type):
    """The IPv6 widening must not turn the adapter into a catch-all."""
    result = _run(agg._abuseipdb_provider("example.com", ind_type))
    assert result.error_kind == "unsupported_type"
    assert result.error is not None


def test_schema_still_rejects_non_public_ipv6():
    """Widening the adapter must not widen input validation."""
    from pydantic import ValidationError

    for bad in ("::1", "fe80::1", "fd00::1", "ff02::1", "::ffff:10.0.0.1"):
        with pytest.raises(ValidationError):
            agg.ThreatIntelAggregateInput(indicator=bad)
