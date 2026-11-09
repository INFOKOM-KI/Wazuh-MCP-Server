#!/usr/bin/env python3
"""Premium-aware AbuseIPDB quota accounting, check-block limits, and pacing.

Every test mocks the HTTP transport. No request reaches AbuseIPDB or Wazuh.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from datetime import datetime, timedelta, timezone

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import httpx
import pytest
from pydantic import ValidationError

from mcp_server.core import http_client
from mcp_server.threat_intel import abuseipdb
from mcp_server.threat_intel._cache import AsyncRateLimiter, cache_delete_prefix
from mcp_server.threat_intel.abuseipdb import AbuseIPDBError
from mcp_server.tools import abuseipdb as report_tool
from mcp_server.tools.abuseipdb import (AbuseIPDBCheckInput, AbuseIPDBReportInput,
                                        blueteam_abuseipdb_check,
                                        blueteam_abuseipdb_report)

BASE = "https://api.abuseipdb.com/api/v2"


def _run(coro):
    return asyncio.run(coro)


def _future_epoch() -> int:
    return int(time.time()) + 3600


class _Response:
    def __init__(self, payload, headers=None):
        self._payload = payload
        self.headers = headers or {}

    def json(self):
        return self._payload


def _check_payload(ip="8.8.8.8", score=50):
    return {"data": {"ipAddress": ip, "abuseConfidenceScore": score,
                     "isPublic": True, "totalReports": 10}}


def _quota_headers(limit=50_000, remaining=49_900, reset=None):
    return {"X-RateLimit-Limit": str(limit),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(reset if reset is not None else _future_epoch())}


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    abuseipdb.reset_quota_state()
    monkeypatch.setattr(abuseipdb, "ABUSEIPDB_API_KEY", "test-key")
    monkeypatch.setattr(abuseipdb, "CHECK_LIMITER",
                        AsyncRateLimiter(max_concurrent=1, min_interval=0))
    monkeypatch.setattr(abuseipdb, "REPORT_LIMITER",
                        AsyncRateLimiter(max_concurrent=1, min_interval=0))
    cache_delete_prefix("abuseipdb", "")
    with abuseipdb._LAST_REPORT_LOCK:
        abuseipdb._LAST_REPORT.clear()
    yield
    abuseipdb.reset_quota_state()
    cache_delete_prefix("abuseipdb", "")
    with abuseipdb._LAST_REPORT_LOCK:
        abuseipdb._LAST_REPORT.clear()


class _FakeClient:
    def __init__(self, calls, queue):
        self.calls = calls
        self.queue = queue

    async def _do(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        item = self.queue.pop(0) if self.queue else _Response(_check_payload())
        if isinstance(item, BaseException):
            raise item
        if isinstance(item, _Response):
            return httpx.Response(
                200, json=item._payload, headers=item.headers,
                request=httpx.Request(method.upper(), url))
        return item

    async def get(self, url, **kwargs):
        return await self._do("get", url, **kwargs)

    async def post(self, url, **kwargs):
        return await self._do("post", url, **kwargs)


@pytest.fixture
def transport(monkeypatch):
    """Patch the pooled client and breaker; ``queue`` is consumed in call order."""
    calls: list[dict] = []
    queue: list = []

    async def fake_get_client(name, verify=True):
        return _FakeClient(calls, queue)

    monkeypatch.setattr(http_client, "_get_client", fake_get_client)
    monkeypatch.setattr(http_client, "_get_breaker",
                        lambda name: http_client.CircuitBreaker())
    return calls, queue


# Configured reference and header parsing

def test_premium_limits_are_per_endpoint():
    limits = abuseipdb.PREMIUM_DAILY_LIMITS
    assert limits["check"] == 50_000
    assert limits["reports"] == 25_000
    assert limits["blacklist"] == 500
    assert limits["report"] == 50_000
    assert limits["check-block"] == 5_000
    assert limits["bulk-report"] == 500
    assert limits["clear-address"] == 500
    assert abuseipdb.CONFIGURED_DAILY_LIMITS["check"] == 50_000


def test_headers_update_each_endpoint_independently(transport):
    calls, queue = transport
    queue.extend([
        _Response(_check_payload(), _quota_headers(50_000, 49_000)),
        _Response({"data": {"abuseConfidenceScore": 50}},
                  _quota_headers(50_000, 48_000)),
        _Response({"data": {}}, _quota_headers(5_000, 4_000)),
    ])
    _run(abuseipdb._api_call("get", f"{BASE}/check"))
    _run(abuseipdb._api_call("post", f"{BASE}/report", data={
        "ip": "8.8.8.8", "categories": "18", "comment": "SSH brute force."}))
    _run(abuseipdb._api_call("get", f"{BASE}/check-block"))
    snapshots = {name: abuseipdb.quota_snapshot(name)
                 for name in ("check", "report", "check-block")}
    assert snapshots["check"]["remaining"] == 49_000
    assert snapshots["report"]["remaining"] == 48_000
    assert snapshots["check-block"]["remaining"] == 4_000
    assert len(calls) == 3


def test_unsupported_endpoint_fails_closed(transport):
    calls, _ = transport
    with pytest.raises(AbuseIPDBError, match="unsupported"):
        _run(abuseipdb._api_call("get", f"{BASE}/reports"))
    assert calls == []


def test_header_names_are_case_insensitive(transport):
    _, queue = transport
    queue.append(_Response(_check_payload(), {
        "x-ratelimit-limit": "50000",
        "x-ratelimit-remaining": "49950",
        "x-ratelimit-reset": str(_future_epoch()),
    }))
    _run(abuseipdb._api_call("get", f"{BASE}/check"))
    snapshot = abuseipdb.quota_snapshot("check")
    assert snapshot["available"] is True
    assert snapshot["remaining"] == 49_950
    assert snapshot["limit_source"] == "response"


def test_missing_headers_do_not_invent_remaining(transport):
    _, queue = transport
    queue.append(_Response(_check_payload(), {}))
    _run(abuseipdb._api_call("get", f"{BASE}/check"))
    snapshot = abuseipdb.quota_snapshot("check")
    assert snapshot["available"] is False
    assert snapshot["remaining"] is None
    assert snapshot["limit"] == 50_000
    assert snapshot["limit_source"] == "configured"


@pytest.mark.parametrize("headers", [
    {"X-RateLimit-Remaining": "abc"},
    {"X-RateLimit-Remaining": "-1"},
    {"X-RateLimit-Limit": "", "X-RateLimit-Reset": "not-a-date"},
])
def test_malformed_headers_are_ignored(transport, headers):
    _, queue = transport
    queue.append(_Response(_check_payload(), headers))
    _run(abuseipdb._api_call("get", f"{BASE}/check"))
    snapshot = abuseipdb.quota_snapshot("check")
    assert snapshot["available"] is False
    assert snapshot["remaining"] is None
    assert "test-key" not in json.dumps(snapshot)


def test_reset_epoch_is_stored_as_utc(transport):
    _, queue = transport
    epoch = _future_epoch()
    queue.append(_Response(_check_payload(), _quota_headers(reset=epoch)))
    _run(abuseipdb._api_call("get", f"{BASE}/check"))
    reset = abuseipdb.quota_snapshot("check")["reset_at"]
    parsed = datetime.fromisoformat(reset)
    assert parsed.tzinfo is not None
    assert parsed.utcoffset().total_seconds() == 0
    assert int(parsed.timestamp()) == epoch


# Quota guard

def test_quota_guard_stops_before_transport_at_the_reserve(transport, monkeypatch):
    calls, queue = transport
    queue.append(_Response(_check_payload(),
                           _quota_headers(50_000, 100)))
    _run(abuseipdb._api_call("get", f"{BASE}/check"))
    assert len(calls) == 1

    monkeypatch.setattr(abuseipdb, "ABUSEIPDB_QUOTA_RESERVE", 100)
    with pytest.raises(AbuseIPDBError, match="quota reserve") as exc:
        _run(abuseipdb._api_call("get", f"{BASE}/check"))
    assert exc.value.kind == "quota_exhausted"
    assert len(calls) == 1  # no second transport call


def test_request_quota_guard_runs_before_key_and_limiter(transport, monkeypatch):
    calls, queue = transport
    queue.append(_Response(_check_payload(), _quota_headers(50_000, 10)))
    _run(abuseipdb._api_call("get", f"{BASE}/check"))

    def forbidden_key():
        raise AssertionError("API key was looked up")

    class _NoEnter:
        async def __aenter__(self):
            raise AssertionError("rate limiter was entered")

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr(abuseipdb, "ABUSEIPDB_QUOTA_RESERVE", 100)
    monkeypatch.setattr(abuseipdb, "_api_key", forbidden_key)
    with pytest.raises(AbuseIPDBError, match="quota reserve"):
        _run(abuseipdb._request("get", "/check", limiter=_NoEnter()))
    assert len(calls) == 1


def test_quota_guard_keeps_other_endpoints_available(transport, monkeypatch):
    calls, queue = transport
    queue.extend([
        _Response(_check_payload(), _quota_headers(50_000, 0)),
        _Response({"data": {}}, _quota_headers(5_000, 4_000)),
    ])
    _run(abuseipdb._api_call("get", f"{BASE}/check"))
    monkeypatch.setattr(abuseipdb, "ABUSEIPDB_QUOTA_RESERVE", 100)
    with pytest.raises(AbuseIPDBError, match="quota reserve"):
        _run(abuseipdb._api_call("get", f"{BASE}/check"))
    _run(abuseipdb._api_call("get", f"{BASE}/check-block"))
    assert len(calls) == 2


def test_quota_guard_lifts_after_reset(transport, monkeypatch):
    calls, queue = transport
    past = int(time.time()) - 60
    queue.extend([
        _Response(_check_payload(), _quota_headers(50_000, 0, past)),
        _Response(_check_payload(), _quota_headers(50_000, 49_000)),
    ])
    _run(abuseipdb._api_call("get", f"{BASE}/check"))
    monkeypatch.setattr(abuseipdb, "ABUSEIPDB_QUOTA_RESERVE", 100)
    _run(abuseipdb._api_call("get", f"{BASE}/check"))
    assert len(calls) == 2


def test_headerless_observation_expires_after_a_daily_window(transport):
    calls, queue = transport
    old = datetime.now(timezone.utc) - timedelta(hours=25)
    abuseipdb._QUOTA_STATE["check"] = {"remaining": 0,
                                       "observed_at": old.isoformat()}
    queue.append(_Response(_check_payload(), _quota_headers()))
    _run(abuseipdb._api_call("get", f"{BASE}/check"))
    assert len(calls) == 1


def test_fresh_headerless_observation_still_blocks(transport):
    calls, _ = transport
    abuseipdb._QUOTA_STATE["check"] = {
        "remaining": 0,
        "observed_at": datetime.now(timezone.utc).isoformat()}
    with pytest.raises(AbuseIPDBError, match="quota reserve"):
        _run(abuseipdb._api_call("get", f"{BASE}/check"))
    assert calls == []


def test_429_retry_after_is_recorded(transport):
    calls, queue = transport
    request = httpx.Request("GET", f"{BASE}/check")
    response = httpx.Response(
        429, request=request,
        headers={"Retry-After": "120", "X-RateLimit-Remaining": "0",
                 "X-RateLimit-Limit": "50000",
                 "X-RateLimit-Reset": str(_future_epoch())},
        json={"errors": [{"detail": "rate limited"}]})
    queue.append(httpx.HTTPStatusError("429", request=request, response=response))
    with pytest.raises(AbuseIPDBError):
        _run(abuseipdb._api_call("get", f"{BASE}/check", max_retries=0))
    snapshot = abuseipdb.quota_snapshot("check")
    assert snapshot["remaining"] == 0
    assert snapshot["retry_after_seconds"] == 120
    assert len(calls) == 1


# Check-block Premium capability

def _block_payload(rows=2):
    return {"data": {
        "networkAddress": "8.8.0.0", "numPossibleHosts": 65534,
        "addressSpaceDesc": "Example",
        "reportedAddress": [
            {"ipAddress": f"8.8.0.{i}", "numReports": 3,
             "mostRecentReport": "2026-11-01T00:00:00+00:00",
             "abuseConfidenceScore": 60, "countryCode": "US"}
            for i in range(1, rows + 1)
        ],
    }}


def test_premium_check_block_accepts_slash_16(transport):
    calls, queue = transport
    queue.append(_Response(_block_payload(), _quota_headers(5_000, 4_999)))
    assert AbuseIPDBCheckInput(network="8.8.0.0/16").network == "8.8.0.0/16"
    result = _run(abuseipdb.check_block("8.8.0.0/16", 365))
    assert result["network"] == "8.8.0.0/16"
    assert result["returned_count"] == 2
    assert result["truncated"] is False
    assert result["quota"]["endpoint"] == "check-block"
    assert calls[0]["params"]["maxAgeInDays"] == 365


def test_check_block_rejects_slash_15(transport):
    calls, _ = transport
    with pytest.raises(AbuseIPDBError, match="/16"):
        _run(abuseipdb.check_block("8.8.0.0/15"))
    assert calls == []


def test_standard_plan_rejects_slash_16(transport, monkeypatch):
    calls, _ = transport
    monkeypatch.setattr(abuseipdb, "ABUSEIPDB_CHECK_BLOCK_MAX_PREFIX", 24)
    monkeypatch.setattr(report_tool, "ABUSEIPDB_CHECK_BLOCK_MAX_PREFIX", 24)
    with pytest.raises(AbuseIPDBError, match="/24"):
        _run(abuseipdb.check_block("8.8.0.0/16"))
    with pytest.raises(ValidationError):
        AbuseIPDBCheckInput(network="8.8.0.0/16")
    assert calls == []


def test_check_block_rejects_more_than_365_days(transport):
    calls, _ = transport
    with pytest.raises(AbuseIPDBError, match="1 and 365"):
        _run(abuseipdb.check_block("8.8.0.0/24", 366))
    assert calls == []


def test_check_block_rejects_an_ipv6_prefix_wider_than_the_local_bound(transport):
    """IPv6 is accepted, but not an unbounded sweep. The /32 is a local bound."""
    calls, _ = transport
    with pytest.raises(AbuseIPDBError, match="IPv6"):
        _run(abuseipdb.check_block("2001:4860::/32"))
    assert calls == []


def test_check_block_caps_the_returned_list(transport, monkeypatch):
    calls, queue = transport
    monkeypatch.setattr(abuseipdb, "CHECK_BLOCK_MAX_RESULTS", 2)
    queue.append(_Response(_block_payload(rows=3)))
    result = _run(abuseipdb.check_block("8.8.0.0/24"))
    assert result["returned_count"] == 2
    assert result["truncated"] is True
    assert len(calls) == 1


# Check caching and report pacing

def test_cached_check_does_not_spend_transport(transport):
    calls, queue = transport
    queue.append(_Response(_check_payload(), _quota_headers()))
    first = _run(abuseipdb.check_ip("8.8.8.8"))
    second = _run(abuseipdb.check_ip("8.8.8.8"))
    assert first["cached"] is False
    assert second["cached"] is True
    assert second["quota"]["remaining"] == 49_900
    assert len(calls) == 1


def test_cache_key_separates_age_and_verbose(transport):
    calls, queue = transport
    queue.extend([_Response(_check_payload()), _Response(_check_payload()),
                  _Response(_check_payload())])
    _run(abuseipdb.check_ip("8.8.8.8", 30))
    _run(abuseipdb.check_ip("8.8.8.8", 90))
    _run(abuseipdb.check_ip("8.8.8.8", 30, verbose=True))
    assert len(calls) == 3


def test_report_post_is_not_retried(transport, monkeypatch):
    calls, queue = transport
    monkeypatch.setattr(abuseipdb, "ABUSEIPDB_QUOTA_RESERVE", 0)
    queue.append(httpx.Response(
        500, request=httpx.Request("POST", f"{BASE}/report"),
        json={"errors": [{"detail": "upstream"}]}))
    with pytest.raises(AbuseIPDBError):
        _run(abuseipdb.report_ip("8.8.8.8", [18]))
    posts = [c for c in calls if c["method"] == "post"]
    assert len(posts) == 1


def test_report_quota_exhaustion_is_not_marked_reported(transport, monkeypatch):
    calls, queue = transport
    monkeypatch.setattr(abuseipdb, "ABUSEIPDB_QUOTA_RESERVE", 100)
    queue.append(_Response({"data": {"abuseConfidenceScore": 50}},
                           _quota_headers(50_000, 50)))
    _run(abuseipdb.report_ip("8.8.8.8", [18]))
    with pytest.raises(AbuseIPDBError) as exc:
        _run(abuseipdb.report_ip("8.8.4.4", [18]))
    assert exc.value.kind == "quota_exhausted"
    assert len(calls) == 1


def test_reporting_tool_surfaces_quota_exhaustion(transport, monkeypatch):
    calls, queue = transport
    monkeypatch.setattr(report_tool, "ABUSEIPDB_REPORTING_ENABLED", True)
    monkeypatch.setattr(abuseipdb, "ABUSEIPDB_QUOTA_RESERVE", 100)
    # First response seeds the report bucket at the reserve.
    queue.append(_Response({"data": {"abuseConfidenceScore": 50}},
                           _quota_headers(50_000, 10)))
    _run(abuseipdb.report_ip("8.8.8.8", [18]))
    output = json.loads(_run(blueteam_abuseipdb_report(AbuseIPDBReportInput(
        srcips=["8.8.4.4"], categories=[18],
        comment="SSH brute force against a monitored host.",
        dry_run=False, confirm=True, response_format="json"))))
    assert output["reported"] == 0
    assert output["failed"] == 1
    assert output["results"][0]["error_kind"] == "quota_exhausted"
    posts = [c for c in calls if c["method"] == "post"]
    assert len(posts) == 1  # only the seeding report, no new POST


# Observability

def test_check_tool_json_reports_quota(transport):
    _, queue = transport
    reset = _future_epoch()
    queue.append(_Response(_check_payload(), _quota_headers(reset=reset)))
    output = json.loads(_run(blueteam_abuseipdb_check(
        AbuseIPDBCheckInput(ip="8.8.8.8", response_format="json"))))
    assert output["quota"]["endpoint"] == "check"
    assert output["quota"]["remaining"] == 49_900
    assert output["quota"]["reset_at"].startswith("20")
    assert "test-key" not in json.dumps(output)
