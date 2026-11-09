#!/usr/bin/env python3
"""AbuseIPDB requests must survive a real ``httpx.AsyncClient``.

Every other abuseipdb test replaces ``http_client._get_client`` with a fake that
accepts ``**kwargs``. That fake hid a production defect: ``abuseipdb._request``
forwarded ``data=None`` on a GET, and the real ``AsyncClient.get()`` rejects
``data`` outright with ``TypeError``. The provider was 100% dead and the suite
stayed green.

This module builds the real client (transport mocked, client class untouched) so
a request body kwarg on a verb that takes no body fails here instead of on the
server. Nothing leaves the process.
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

# Hardcoded on purpose: the requirement is this literal, so the test must not
# inherit a changed constant from the implementation.
REQUIRED_SIGNATURE = "Reported by TangerangKota-CSIRT."

CHECK_PAYLOAD = {
    "data": {
        "ipAddress": "8.8.8.8",
        "isPublic": True,
        "abuseConfidenceScore": 12,
        "countryCode": "US",
        "totalReports": 3,
    }
}
QUOTA_HEADERS = {
    "x-ratelimit-limit": "1000",
    "x-ratelimit-remaining": "900",
    "x-ratelimit-reset": "2026-11-06T02:00:00+00:00",
}


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    monkeypatch.setattr(abuseipdb, "CHECK_LIMITER",
                        AsyncRateLimiter(max_concurrent=1, min_interval=0))
    monkeypatch.setattr(abuseipdb, "REPORT_LIMITER",
                        AsyncRateLimiter(max_concurrent=1, min_interval=0))
    monkeypatch.setattr(abuseipdb, "ABUSEIPDB_API_KEY", "test-key")
    abuseipdb.reset_quota_state()
    cache_delete_prefix("abuseipdb", "")
    with abuseipdb._LAST_REPORT_LOCK:
        abuseipdb._LAST_REPORT.clear()
    yield
    cache_delete_prefix("abuseipdb", "")


@pytest.fixture
def real_client(monkeypatch):
    """Real ``httpx.AsyncClient`` over a mock transport. Returns the request log."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path.endswith("/report"):
            return httpx.Response(
                200, headers=QUOTA_HEADERS,
                content=json.dumps({"data": {"ipAddress": "8.8.8.8",
                                             "abuseConfidenceScore": 12}}).encode())
        return httpx.Response(200, headers=QUOTA_HEADERS,
                              content=json.dumps(CHECK_PAYLOAD).encode())

    transport = httpx.MockTransport(handler)

    async def fake_get_client(name, verify=True):
        return httpx.AsyncClient(transport=transport)

    monkeypatch.setattr(http_client, "_get_client", fake_get_client)
    monkeypatch.setattr(http_client, "_get_breaker",
                        lambda name: http_client.CircuitBreaker())
    return seen


def test_get_check_builds_a_real_request(real_client):
    """Regression: ``data=None`` on a GET raised TypeError, killing the provider."""
    result = _run(abuseipdb.check_ip("8.8.8.8", max_age_days=30))

    assert result["abuse_confidence_score"] == 12
    assert len(real_client) == 1
    request = real_client[0]
    assert request.method == "GET"
    assert request.url.params["ipAddress"] == "8.8.8.8"
    assert not request.content, "a GET must not carry a body"


def test_get_check_builds_a_real_ipv6_request(real_client):
    """IPv6 must reach the wire unmodified, not be rejected or mangled."""
    result = _run(abuseipdb.check_ip("2001:4860:4860::8888", max_age_days=30))

    assert result["abuse_confidence_score"] == 12
    request = real_client[0]
    assert request.method == "GET"
    assert request.url.params["ipAddress"] == "2001:4860:4860::8888"
    assert not request.content


def test_get_check_block_builds_a_real_request(real_client):
    result = _run(abuseipdb.check_block("8.8.8.0/24", max_age_days=30))

    request = real_client[0]
    assert request.method == "GET"
    assert request.url.params["network"] == "8.8.8.0/24"
    assert "reported_addresses" in result


def test_post_report_keeps_its_form_body(real_client):
    _run(abuseipdb._request(
        "post", "/report", limiter=abuseipdb.REPORT_LIMITER, max_retries=0,
        data={"ip": "8.8.8.8", "categories": "18",
              "comment": "SSH brute force against a monitored host.",
              "timestamp": "2026-11-06T01:00:00+00:00"}))

    request = real_client[0]
    assert request.method == "POST"
    assert request.headers["content-type"] == "application/x-www-form-urlencoded"
    assert b"ip=8.8.8.8" in request.content


def test_report_form_payload_carries_the_exact_signature(real_client):
    """The signature is checked in the encoded body, not in a return value."""
    _run(abuseipdb.report_ip(
        "8.8.8.8", [18, 22], alert_count=4,
        first_seen="2026-11-06T01:00:00Z",
        last_seen="2026-11-06T01:10:00Z", rule_ids=["5710"]))

    request = real_client[0]
    assert request.method == "POST"
    form = dict(httpx.QueryParams(request.content.decode()))
    comment = form["comment"]
    assert comment.endswith(REQUIRED_SIGNATURE), repr(comment[-60:])
    assert comment.count(REQUIRED_SIGNATURE) == 1
    assert "5710" in comment
    assert form["ip"] == "8.8.8.8"
    assert form["categories"] == "18,22"
