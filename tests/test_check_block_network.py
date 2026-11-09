#!/usr/bin/env python3
"""AbuseIPDB ``/check-block`` for IPv4 and IPv6, over a real httpx client.

The endpoint is a GET with ``network`` and ``maxAgeInDays`` query parameters. These
tests build the real request through the shared transport so the method, path,
headers, and encoding are inspected rather than inferred. Nothing leaves the
process.
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
from mcp_server.threat_intel import abuseipdb
from mcp_server.threat_intel._cache import AsyncRateLimiter, cache_delete_prefix

QUOTA_HEADERS = {
    "x-ratelimit-limit": "5000",
    "x-ratelimit-remaining": "4990",
    "x-ratelimit-reset": "2026-11-06T02:00:00+00:00",
}


def _block_payload(**overrides) -> dict:
    data = {
        "networkAddress": "8.8.8.0",
        "netmask": "255.255.255.0",
        "minAddress": "8.8.8.1",
        "maxAddress": "8.8.8.254",
        "numPossibleHosts": 254,
        "addressSpaceDesc": "Level 3 Communications",
        "reportedAddress": [
            {"ipAddress": "8.8.8.8", "numReports": 12,
             "mostRecentReport": "2026-11-05T12:00:00+00:00",
             "abuseConfidenceScore": 100, "countryCode": "US"},
            {"ipAddress": "8.8.4.4", "numReports": 3,
             "mostRecentReport": "2026-11-04T09:30:00+00:00",
             "abuseConfidenceScore": 0, "countryCode": None},
        ],
    }
    data.update(overrides)
    return {"data": data}


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    monkeypatch.setattr(abuseipdb, "CHECK_LIMITER",
                        AsyncRateLimiter(max_concurrent=1, min_interval=0))
    monkeypatch.setattr(abuseipdb, "ABUSEIPDB_API_KEY", "test-key")
    abuseipdb.reset_quota_state()
    cache_delete_prefix("abuseipdb", "")


@pytest.fixture
def real_client(monkeypatch):
    seen: list[httpx.Request] = []
    payload = _block_payload()

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, headers=QUOTA_HEADERS,
                              content=json.dumps(payload).encode())

    transport = httpx.MockTransport(handler)

    async def fake_get_client(name, verify=True):
        return httpx.AsyncClient(transport=transport)

    monkeypatch.setattr(http_client, "_get_client", fake_get_client)
    monkeypatch.setattr(http_client, "_get_breaker",
                        lambda name: http_client.CircuitBreaker())
    return seen


def test_ipv4_cidr_request_construction(real_client):
    result = _run(abuseipdb.check_block("8.8.8.0/24", max_age_days=15))

    request = real_client[0]
    assert request.method == "GET"
    assert request.url.path == "/api/v2/check-block"
    assert request.url.params["network"] == "8.8.8.0/24"
    assert request.url.params["maxAgeInDays"] == "15"
    assert request.headers["key"] == "test-key"
    assert request.headers["accept"] == "application/json"
    assert not request.content, "check-block must not send a form body"

    assert result["network"] == "8.8.8.0/24"
    assert result["returned_count"] == 2


def test_ipv6_cidr_request_construction(real_client):
    result = _run(abuseipdb.check_block("2001:4860:4860::/120", max_age_days=30))

    request = real_client[0]
    assert request.method == "GET"
    assert request.url.path == "/api/v2/check-block"
    # The colon-bearing address is percent-encoded on the wire and decodes back.
    assert request.url.params["network"] == "2001:4860:4860::/120"
    assert "%3A" in str(request.url)
    assert result["network"] == "2001:4860:4860::/120"


@pytest.mark.parametrize("response_field,expected", [
    ("networkAddress", "network_address"),
    ("netmask", "netmask"),
    ("minAddress", "min_address"),
    ("maxAddress", "max_address"),
    ("numPossibleHosts", "num_possible_hosts"),
    ("addressSpaceDesc", "address_space"),
])
def test_block_metadata_is_normalized(real_client, response_field, expected):
    result = _run(abuseipdb.check_block("8.8.8.0/24"))
    assert result[expected] == _block_payload()["data"][response_field]


def test_reported_address_rows_keep_every_published_field(real_client):
    result = _run(abuseipdb.check_block("8.8.8.0/24"))
    row = result["reported_addresses"][0]
    assert row == {
        "ip": "8.8.8.8",
        "num_reports": 12,
        "last_reported_at": "2026-11-05T12:00:00+00:00",
        "abuse_confidence_score": 100,
        "country_code": "US",
    }
    # A null countryCode stays null; it is not turned into a guessed value.
    assert result["reported_addresses"][1]["country_code"] is None


def test_large_reported_list_truncates_explicitly(real_client, monkeypatch):
    monkeypatch.setattr(abuseipdb, "CHECK_BLOCK_MAX_RESULTS", 1)
    result = _run(abuseipdb.check_block("8.8.8.0/24"))
    assert result["returned_count"] == 1
    assert result["truncated"] is True


def test_ipv6_prefix_wider_than_the_local_bound_is_rejected():
    with pytest.raises(abuseipdb.AbuseIPDBError) as exc:
        _run(abuseipdb.check_block("2001:4860::/64"))
    assert exc.value.kind == "bad_request"
    assert "IPv6" in exc.value.message


@pytest.mark.parametrize("network", [
    "2001:db8::/120",    # documentation range, not global
    "fe80::/120",        # link-local
    "fd00::/120",        # ULA
    "::1/128",           # loopback
])
def test_non_public_ipv6_networks_are_never_queried(network):
    with pytest.raises(abuseipdb.AbuseIPDBError) as exc:
        _run(abuseipdb.check_block(network))
    assert exc.value.kind == "bad_request"


def test_plan_limit_error_keeps_its_classification(real_client, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(402, headers=QUOTA_HEADERS,
                              content=json.dumps(
                                  {"errors": [{"detail": "prefix too wide",
                                               "status": 402}]}).encode())

    transport = httpx.MockTransport(handler)

    async def fake_get_client(name, verify=True):
        return httpx.AsyncClient(transport=transport)

    monkeypatch.setattr(http_client, "_get_client", fake_get_client)
    with pytest.raises(abuseipdb.AbuseIPDBError) as exc:
        _run(abuseipdb.check_block("8.8.0.0/16"))
    assert exc.value.kind == "plan_limit"
    assert exc.value.status == 402


def test_malformed_block_body_is_a_failure_not_a_clean_result():
    async def fake_api_call(method, url, **kwargs):
        class R:
            status_code = 200

            def json(self):
                return {"data": {"networkAddress": "8.8.8.0"}}
        return R()

    import unittest.mock as mock
    with mock.patch.object(abuseipdb, "_api_call", fake_api_call):
        result = _run(abuseipdb.check_block("8.8.8.0/24"))
    # No reportedAddress key at all: an empty list, and the call still normalizes.
    assert result["reported_addresses"] == []
    assert result["truncated"] is False


# --------------------------------------------------------------------------
# Tool surface: one tool, two input shapes
# --------------------------------------------------------------------------

def test_schema_accepts_ipv6_network():
    from mcp_server.tools.abuseipdb import AbuseIPDBCheckInput

    params = AbuseIPDBCheckInput(network="2001:4860:4860::/120")
    assert params.network == "2001:4860:4860::/120"
    assert params.ip is None


def test_schema_still_rejects_an_unbounded_ipv6_prefix():
    import pydantic
    from mcp_server.tools.abuseipdb import AbuseIPDBCheckInput

    with pytest.raises(pydantic.ValidationError):
        AbuseIPDBCheckInput(network="2001:4860::/48")


def test_schema_still_requires_exactly_one_target():
    import pydantic
    from mcp_server.tools.abuseipdb import AbuseIPDBCheckInput

    with pytest.raises(pydantic.ValidationError):
        AbuseIPDBCheckInput()
    with pytest.raises(pydantic.ValidationError):
        AbuseIPDBCheckInput(ip="8.8.8.8", network="8.8.8.0/24")
