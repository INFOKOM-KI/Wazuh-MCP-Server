#!/usr/bin/env python3
"""Transport policy, unified reservation, reset windows, and bootstrap tests.

Every test replaces the pooled httpx client. No request leaves the process.
"""
from __future__ import annotations

import asyncio
import io
import os
import time
from datetime import datetime, timedelta, timezone

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import httpx
import pytest

import mcp_server
from mcp_server.core import http_client
from mcp_server.core.config import _plan
from mcp_server.core.http_client import CircuitOpenError
from mcp_server.threat_intel import abuseipdb
from mcp_server.threat_intel._cache import AsyncRateLimiter, cache_delete_prefix
from mcp_server.threat_intel.abuseipdb import AbuseIPDBError

BASE = "https://api.abuseipdb.com/api/v2"
CHECK = f"{BASE}/check"
BLOCK = f"{BASE}/check-block"
REPORT = f"{BASE}/report"


def _run(coro):
    return asyncio.run(coro)


class _Response:
    def __init__(self, payload, headers=None):
        self._payload = payload
        self.headers = headers or {}

    def json(self):
        return self._payload


def _check_payload():
    return {"data": {"ipAddress": "8.8.8.8", "abuseConfidenceScore": 50,
                     "isPublic": True}}


def _quota(remaining=101, limit=50_000, reset=None, include_reset=True):
    headers = {"X-RateLimit-Limit": str(limit),
               "X-RateLimit-Remaining": str(remaining)}
    if include_reset:
        headers["X-RateLimit-Reset"] = str(
            reset if reset is not None else int(time.time()) + 3600)
    return headers


def _response(method, url, payload=None, headers=None):
    return httpx.Response(
        200, json=payload if payload is not None else _check_payload(),
        headers=headers or {},
        request=httpx.Request(method.upper(), url))


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
            return _response(method, url, item._payload, item.headers)
        return item

    async def get(self, url, **kwargs):
        return await self._do("get", url, **kwargs)

    async def post(self, url, **kwargs):
        return await self._do("post", url, **kwargs)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    abuseipdb.reset_quota_state()
    monkeypatch.setattr(abuseipdb, "ABUSEIPDB_API_KEY", "test-key")
    monkeypatch.setattr(abuseipdb, "ABUSEIPDB_QUOTA_RESERVE", 100)
    monkeypatch.setattr(abuseipdb, "ABUSEIPDB_BOOTSTRAP_CONCURRENCY", 1)
    monkeypatch.setattr(abuseipdb, "ABUSEIPDB_BOOTSTRAP_BUDGET", 5)
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


@pytest.fixture
def transport(monkeypatch):
    calls: list[dict] = []
    queue: list = []

    async def fake_get_client(name, verify=True):
        return _FakeClient(calls, queue)

    monkeypatch.setattr(http_client, "_get_client", fake_get_client)
    monkeypatch.setattr(http_client, "_get_breaker",
                        lambda name: http_client.CircuitBreaker())
    return calls, queue


def _seed(remaining=101, endpoint="check", reset=None, include_reset=True):
    abuseipdb.finish_quota_reservation(
        None,
        _Response({}, _quota(remaining=remaining, reset=reset,
                             include_reset=include_reset)),
        endpoint=endpoint)


# ---------------------------------------------------------------------------
# Unified transport and provider isolation
# ---------------------------------------------------------------------------

def test_wrapper_rejects_http_downgrade(transport):
    calls, _ = transport
    with pytest.raises(AbuseIPDBError, match="HTTPS"):
        _run(abuseipdb._api_call("get", "http://api.abuseipdb.com/api/v2/check"))
    assert calls == []


@pytest.mark.parametrize("url", [
    "https://1.2.3.4/api/v2/check",
    "https://[2001:4860::1]/api/v2/check",
])
def test_wrapper_rejects_ip_literal_hosts(transport, url):
    calls, _ = transport
    with pytest.raises(AbuseIPDBError, match="IP literal"):
        _run(abuseipdb._api_call("get", url))
    assert calls == []


def test_wrapper_rejects_verify_false(transport):
    calls, _ = transport
    with pytest.raises(AbuseIPDBError, match="verification"):
        _run(abuseipdb._api_call("get", CHECK, verify=False))
    assert calls == []


def test_wrapper_rejects_foreign_dns_host(transport):
    calls, _ = transport
    with pytest.raises(AbuseIPDBError, match="configured hostname"):
        _run(abuseipdb._api_call("get", "https://evil.example/api/v2/check",
                                 headers={"Key": "test-key"}))
    assert calls == []


def test_wrapper_rejects_ip_literal_on_unknown_path(transport):
    calls, _ = transport
    with pytest.raises(AbuseIPDBError, match="IP literal"):
        _run(abuseipdb._api_call("get", "https://1.2.3.4/anything"))
    assert calls == []


def test_wrapper_accepts_normalized_host(transport):
    calls, _ = transport
    _run(abuseipdb._api_call("get", "https://API.ABUSEIPDB.COM./api/v2/check"))
    assert len(calls) == 1


def test_core_rejects_http_downgrade(transport):
    calls, _ = transport
    with pytest.raises(AbuseIPDBError, match="HTTPS"):
        _run(http_client._api_call("get", "http://api.abuseipdb.com/api/v2/check",
                                   client_name="hardening-core"))
    assert calls == []


def test_core_rejects_verify_false(transport):
    calls, _ = transport
    with pytest.raises(AbuseIPDBError, match="verification"):
        _run(http_client._api_call("get", CHECK, client_name="hardening-core",
                                   verify=False))
    assert calls == []


@pytest.mark.parametrize("url", [
    "https://1.2.3.4/api/v2/check",
    "https://[2001:4860::1]/api/v2/check",
])
def test_core_rejects_ip_literal_with_key(transport, url):
    calls, _ = transport
    with pytest.raises(AbuseIPDBError, match="credential"):
        _run(http_client._api_call("get", url, client_name="hardening-core",
                                   headers={"Key": "test-key"}))
    assert calls == []


@pytest.mark.parametrize("method,url", [
    ("get", f"{BASE}/reports"),
    ("post", CHECK),
    ("get", f"{BASE}/unknown"),
])
def test_core_rejects_unsupported_or_wrong_method(transport, method, url):
    calls, _ = transport
    with pytest.raises(AbuseIPDBError, match="unsupported"):
        _run(http_client._api_call(method, url, client_name="hardening-core"))
    assert calls == []


def test_core_accepts_normalized_host(transport):
    calls, _ = transport
    _run(http_client._api_call("get", "https://API.ABUSEIPDB.COM./api/v2/check",
                               client_name="hardening-core"))
    assert len(calls) == 1


def test_core_leaves_other_providers_alone(transport):
    calls, _ = transport
    _run(http_client._api_call("get", "https://example.com/api/v2/check",
                               client_name="hardening-core",
                               headers={"Authorization": "Bearer x"}))
    assert len(calls) == 1
    assert abuseipdb.quota_snapshot("check")["observed_at"] is None


def test_configured_base_host_is_explicitly_trusted(transport, monkeypatch):
    calls, queue = transport
    monkeypatch.setattr(mcp_server, "ABUSEIPDB_BASE_URL",
                        "https://proxy.example/api/v2")
    monkeypatch.setattr(abuseipdb, "ABUSEIPDB_BASE_URL",
                        "https://proxy.example/api/v2")
    queue.append(_Response(_check_payload(), _quota(remaining=700)))
    _run(http_client._api_call("get", "https://proxy.example/api/v2/check",
                               client_name="hardening-proxy"))
    assert len(calls) == 1
    assert abuseipdb.quota_snapshot("check")["remaining"] == 700


def test_invalid_plan_falls_back_to_standard():
    assert _plan("") == "premium"
    assert _plan("premium") == "premium"
    assert _plan("standard") == "standard"
    assert _plan("bogus") == "standard"


# ---------------------------------------------------------------------------
# Credential isolation at the shared transport
# ---------------------------------------------------------------------------

def test_configured_key_to_approved_host_is_allowed(transport):
    calls, _ = transport
    _run(http_client._api_call("get", CHECK, client_name="hardening-key",
                               headers={"Key": "test-key"}))
    assert len(calls) == 1


def test_configured_key_to_foreign_host_is_rejected(transport, caplog):
    caplog.set_level("DEBUG")
    calls, _ = transport
    with pytest.raises(AbuseIPDBError, match="credential") as exc:
        _run(http_client._api_call("get", "https://evil.example/api/v2/check",
                                   client_name="hardening-key",
                                   headers={"Key": "test-key"}))
    assert calls == []
    assert "test-key" not in str(exc.value)
    assert "test-key" not in caplog.text


def test_configured_key_to_ip_literal_is_rejected(transport):
    calls, _ = transport
    with pytest.raises(AbuseIPDBError, match="credential"):
        _run(http_client._api_call("get", "https://1.2.3.4/api/v2/check",
                                   client_name="hardening-key",
                                   headers={"Key": "test-key"}))
    assert calls == []


def test_authorization_header_to_foreign_host_is_unaffected(transport):
    calls, _ = transport
    _run(http_client._api_call("get", "https://evil.example/api/v2/check",
                               client_name="hardening-key",
                               headers={"Authorization": "Bearer x"}))
    assert len(calls) == 1


def test_nonmatching_key_header_to_foreign_host_is_unaffected(transport):
    calls, _ = transport
    _run(http_client._api_call("get", "https://evil.example/api/v2/check",
                               client_name="hardening-key",
                               headers={"Key": "other-key"}))
    assert len(calls) == 1


def test_mixed_case_key_to_foreign_host_is_rejected(transport):
    calls, _ = transport
    with pytest.raises(AbuseIPDBError, match="credential"):
        _run(http_client._api_call("get", "https://evil.example/api/v2/check",
                                   client_name="hardening-key",
                                   headers={"kEy": "test-key"}))
    assert calls == []


def test_duplicate_key_header_to_foreign_host_is_rejected(transport):
    calls, _ = transport
    headers = httpx.Headers([("Key", "other-key"), ("Key", "test-key")])
    with pytest.raises(AbuseIPDBError, match="credential"):
        _run(http_client._api_call("get", "https://evil.example/api/v2/check",
                                   client_name="hardening-key", headers=headers))
    assert calls == []


def test_combined_key_header_to_foreign_host_is_rejected(transport):
    calls, _ = transport
    with pytest.raises(AbuseIPDBError, match="credential"):
        _run(http_client._api_call("get", "https://evil.example/api/v2/check",
                                   client_name="hardening-key",
                                   headers={"Key": "other-key, test-key"}))
    assert calls == []


def test_list_of_pairs_key_to_foreign_host_is_rejected(transport):
    calls, _ = transport
    with pytest.raises(AbuseIPDBError, match="credential"):
        _run(http_client._api_call(
            "get", "https://evil.example/api/v2/check",
            client_name="hardening-key",
            headers=[("Key", "other-key"), ("Key", "test-key")]))
    assert calls == []


def test_whitespace_padded_key_to_foreign_host_is_rejected(transport):
    calls, _ = transport
    with pytest.raises(AbuseIPDBError, match="credential"):
        _run(http_client._api_call(
            "get", "https://evil.example/api/v2/check",
            client_name="hardening-key",
            headers={"Key": " test-key "}))
    assert calls == []


def test_query_key_to_foreign_host_is_rejected(transport):
    calls, _ = transport
    with pytest.raises(AbuseIPDBError, match="credential"):
        _run(http_client._api_call("get", "https://evil.example/api/v2/check",
                                   client_name="hardening-key",
                                   params={"key": "test-key"}))
    assert calls == []


@pytest.mark.parametrize("headers", [
    {"Authorization": "Bearer test-key"},
    {"X-Api-Key": "test-key"},
    {"X-Custom": "prefix test-key suffix"},
])
def test_configured_key_in_any_header_is_rejected(transport, headers):
    calls, _ = transport
    with pytest.raises(AbuseIPDBError, match="credential"):
        _run(http_client._api_call("get", "https://evil.example/api/v2/check",
                                   client_name="hardening-key", headers=headers))
    assert calls == []


@pytest.mark.parametrize("params", [
    {"anything": "test-key"},
    {"x": ["safe", "test-key"]},
    "x=test-key",
])
def test_configured_key_in_params_is_rejected(transport, params):
    calls, _ = transport
    with pytest.raises(AbuseIPDBError, match="credential"):
        _run(http_client._api_call("get", "https://evil.example/api/v2/check",
                                   client_name="hardening-key", params=params))
    assert calls == []


@pytest.mark.parametrize("kwargs", [
    {"data": {"comment": "test-key"}},
    {"data": "comment=test-key"},
    {"json": {"note": "test-key"}},
    {"json": {"a": [{"b": "test-key"}]}},
    {"content": b"test-key"},
    {"content": "test-key"},
    {"cookies": {"session": "test-key"}},
    {"files": {"f": ("name", b"test-key")}},
    {"auth": ("user", "test-key")},
    {"auth": httpx.BasicAuth("user", "test-key")},
    {"extensions": {"trace": b"test-key"}},
])
def test_configured_key_in_body_components_is_rejected(transport, kwargs):
    calls, _ = transport
    with pytest.raises(AbuseIPDBError, match="credential"):
        _run(http_client._api_call("get", "https://evil.example/api/v2/check",
                                   client_name="hardening-key", **kwargs))
    assert calls == []


@pytest.mark.parametrize("url", [
    "https://evil.example/test-key",
    "https://evil.example/%74est-key",
    "https://evil.example/api/v2/check?x=test-key",
])
def test_configured_key_in_url_is_rejected(transport, url):
    calls, _ = transport
    with pytest.raises(AbuseIPDBError, match="credential"):
        _run(http_client._api_call("get", url, client_name="hardening-key"))
    assert calls == []


@pytest.mark.parametrize("kwargs", [
    {"headers": {"Authorization": "Bearer other-key"}},
    {"headers": {"X-Api-Key": "other-key"}},
    {"params": {"api_key": "other-key"}},
    {"json": {"key": "other-key"}},
    {"data": {"key": "other-key"}},
    {"auth": ("user", "other-key")},
])
def test_other_provider_credentials_are_unaffected(transport, kwargs):
    calls, _ = transport
    _run(http_client._api_call("get", "https://evil.example/api/v2/check",
                               client_name="hardening-key", **kwargs))
    assert len(calls) == 1


def test_approved_host_accepts_key_in_authorization(transport):
    calls, _ = transport
    _run(http_client._api_call("get", CHECK, client_name="hardening-key",
                               headers={"Authorization": "Bearer test-key"}))
    assert len(calls) == 1


def test_custom_base_host_accepts_key_in_custom_header(transport, monkeypatch):
    calls, _ = transport
    monkeypatch.setattr(mcp_server, "ABUSEIPDB_BASE_URL",
                        "https://proxy.example/api/v2")
    monkeypatch.setattr(abuseipdb, "ABUSEIPDB_BASE_URL",
                        "https://proxy.example/api/v2")
    _run(http_client._api_call("get", "https://proxy.example/api/v2/check",
                               client_name="hardening-key",
                               headers={"X-Custom": "test-key"}))
    assert len(calls) == 1


def test_custom_base_host_accepts_the_configured_key(transport, monkeypatch):
    calls, _ = transport
    monkeypatch.setattr(mcp_server, "ABUSEIPDB_BASE_URL",
                        "https://proxy.example/api/v2")
    monkeypatch.setattr(abuseipdb, "ABUSEIPDB_BASE_URL",
                        "https://proxy.example/api/v2")
    _run(http_client._api_call("get", "https://proxy.example/api/v2/check",
                               client_name="hardening-key",
                               headers={"Key": "test-key"}))
    assert len(calls) == 1


# ---------------------------------------------------------------------------
# Opaque-object boundary (documented limitations)
# ---------------------------------------------------------------------------

class _KeyAuth(httpx.Auth):
    def auth_flow(self, request):
        request.headers["X-Auth"] = "test-key"
        yield request


class _OtherAuth(httpx.Auth):
    def auth_flow(self, request):
        request.headers["X-Auth"] = "other-key"
        yield request


class _SlottedAuth(httpx.Auth):
    __slots__ = ()

    def auth_flow(self, request):
        request.headers["X-Auth"] = "other-key"
        yield request


def test_custom_auth_object_is_outside_the_scan(transport):
    calls, _ = transport
    auth = _KeyAuth()
    _run(http_client._api_call("get", "https://evil.example/api/v2/check",
                               client_name="hardening-opaque", auth=auth))
    assert len(calls) == 1
    assert calls[0]["auth"] is auth
    request = httpx.Request("GET", "https://evil.example/api/v2/check")
    applied = next(iter(auth.auth_flow(request)))
    assert applied.headers["X-Auth"] == "test-key"


def test_custom_auth_with_unrelated_credential_is_allowed(transport):
    calls, _ = transport
    _run(http_client._api_call("get", "https://evil.example/api/v2/check",
                               client_name="hardening-opaque", auth=_OtherAuth()))
    assert len(calls) == 1


def test_slotted_custom_auth_does_not_crash_the_scanner(transport):
    calls, _ = transport
    _run(http_client._api_call("get", "https://evil.example/api/v2/check",
                               client_name="hardening-opaque", auth=_SlottedAuth()))
    assert len(calls) == 1


def test_seekable_file_like_content_is_outside_the_scan(transport):
    calls, _ = transport
    stream = io.BytesIO(b"test-key")
    try:
        _run(http_client._api_call("get", "https://evil.example/api/v2/check",
                                   client_name="hardening-opaque", content=stream))
        assert len(calls) == 1
        assert calls[0]["content"] is stream
        assert stream.tell() == 0  # the scanner did not consume it
        stream.seek(0)
        assert stream.read() == b"test-key"
    finally:
        stream.close()


def test_streaming_content_is_not_consumed_by_the_scan(transport):
    calls, _ = transport

    def body():
        yield b"test-"
        yield b"key"

    stream = body()
    _run(http_client._api_call("get", "https://evil.example/api/v2/check",
                               client_name="hardening-opaque", content=stream))
    assert len(calls) == 1
    assert calls[0]["content"] is stream


def test_streaming_content_with_unrelated_data_is_allowed(transport):
    calls, _ = transport
    stream = (chunk for chunk in [b"ordinary", b"data"])
    _run(http_client._api_call("get", "https://evil.example/api/v2/check",
                               client_name="hardening-opaque", content=stream))
    assert len(calls) == 1
    assert calls[0]["content"] is stream


# ---------------------------------------------------------------------------
# Unified reservation lifecycle
# ---------------------------------------------------------------------------

def test_snapshot_separates_observed_remaining_from_inflight():
    _seed(101)
    reservation = abuseipdb.begin_quota_reservation("check")
    snapshot = abuseipdb.quota_snapshot("check")
    assert snapshot["remaining"] == 101
    assert snapshot["inflight"] == 1
    assert snapshot["local_available"] == 100
    abuseipdb.finish_quota_reservation(
        reservation, _Response({}, _quota(remaining=100)))
    snapshot = abuseipdb.quota_snapshot("check")
    assert snapshot["remaining"] == 100
    assert snapshot["inflight"] == 0


def test_single_reservation_boundary(transport, monkeypatch):
    calls, _ = transport
    original = abuseipdb.begin_quota_reservation
    seen = []

    def counted(endpoint):
        seen.append(endpoint)
        return original(endpoint)

    monkeypatch.setattr(abuseipdb, "begin_quota_reservation", counted)
    _run(http_client._api_call("get", CHECK, client_name="hardening-single"))
    _run(abuseipdb._api_call("get", CHECK))
    _run(abuseipdb._request("get", "/check", limiter=abuseipdb.CHECK_LIMITER))
    assert seen == ["check", "check", "check"]
    assert len(calls) == 3


def test_reservation_release_is_idempotent():
    _seed(101)
    reservation = abuseipdb.begin_quota_reservation("check")
    abuseipdb.finish_quota_reservation(
        reservation, _Response({}, _quota(remaining=90)))
    abuseipdb.finish_quota_reservation(
        reservation, _Response({}, _quota(remaining=80)))
    snapshot = abuseipdb.quota_snapshot("check")
    assert snapshot["remaining"] == 90
    assert snapshot["inflight"] == 0


def test_reservation_cannot_be_transferred_between_endpoints():
    _seed(101, "check")
    reservation = abuseipdb.begin_quota_reservation("check")
    abuseipdb.finish_quota_reservation(
        reservation, _Response({}, _quota(remaining=90)),
        endpoint="check-block")
    assert abuseipdb.quota_snapshot("check")["remaining"] == 90
    assert abuseipdb.quota_snapshot("check")["inflight"] == 0
    assert abuseipdb.quota_snapshot("check-block")["remaining"] is None


def test_core_call_reserves_and_reconciles(transport):
    calls, queue = transport
    queue.append(_Response(_check_payload(), _quota(remaining=900)))
    _run(http_client._api_call("get", CHECK, client_name="hardening-core"))
    assert len(calls) == 1
    snapshot = abuseipdb.quota_snapshot("check")
    assert snapshot["remaining"] == 900
    assert snapshot["inflight"] == 0


def test_concurrent_requests_cannot_both_consume_the_last_unit(transport, monkeypatch):
    _seed(101)

    async def scenario():
        started = asyncio.Event()
        release = asyncio.Event()
        calls = []

        class Blocking:
            async def get(self, url, **kwargs):
                calls.append(url)
                started.set()
                await release.wait()
                return _response("get", url, _check_payload(),
                                 _quota(remaining=100))

        async def fake_get_client(name, verify=True):
            return Blocking()

        monkeypatch.setattr(http_client, "_get_client", fake_get_client)
        first = asyncio.create_task(
            http_client._api_call("get", CHECK, client_name="hardening-concurrent"))
        await started.wait()
        with pytest.raises(AbuseIPDBError, match="quota reserve"):
            await http_client._api_call("get", CHECK,
                                        client_name="hardening-concurrent")
        release.set()
        await first
        return calls

    assert asyncio.run(scenario()) == [CHECK]
    snapshot = abuseipdb.quota_snapshot("check")
    assert snapshot["remaining"] == 100
    assert snapshot["inflight"] == 0


def test_concurrent_requests_to_different_endpoints_do_not_block(transport, monkeypatch):
    _seed(101, "check")
    _seed(101, "check-block")

    async def scenario():
        started = asyncio.Event()
        release = asyncio.Event()
        calls = []

        class Blocking:
            async def get(self, url, **kwargs):
                calls.append(url)
                if url == CHECK:
                    started.set()
                    await release.wait()
                return _response("get", url, _check_payload(),
                                 _quota(remaining=100))

        async def fake_get_client(name, verify=True):
            return Blocking()

        monkeypatch.setattr(http_client, "_get_client", fake_get_client)
        first = asyncio.create_task(
            http_client._api_call("get", CHECK, client_name="hardening-different"))
        await started.wait()
        await http_client._api_call("get", BLOCK,
                                    client_name="hardening-different")
        release.set()
        await first
        return calls

    assert asyncio.run(scenario()) == [CHECK, BLOCK]


def test_429_during_concurrent_request_updates_state(transport, monkeypatch):
    _seed(101)

    async def scenario():
        started = asyncio.Event()
        release = asyncio.Event()
        request = httpx.Request("GET", CHECK)
        response = httpx.Response(
            429, request=request, headers=_quota(remaining=0),
            json={"errors": [{"detail": "Daily rate limit exceeded"}]})

        class Failing:
            async def get(self, url, **kwargs):
                started.set()
                await release.wait()
                raise httpx.HTTPStatusError("429", request=request,
                                            response=response)

        async def fake_get_client(name, verify=True):
            return Failing()

        monkeypatch.setattr(http_client, "_get_client", fake_get_client)
        task = asyncio.create_task(
            http_client._api_call("get", CHECK, client_name="hardening-429",
                                  max_retries=0))
        await started.wait()
        release.set()
        with pytest.raises(httpx.HTTPStatusError):
            await task

    asyncio.run(scenario())
    snapshot = abuseipdb.quota_snapshot("check")
    assert snapshot["remaining"] == 0
    assert snapshot["inflight"] == 0
    with pytest.raises(AbuseIPDBError, match="quota reserve"):
        _run(abuseipdb._api_call("get", CHECK))


# ---------------------------------------------------------------------------
# Reset-window reconciliation
# ---------------------------------------------------------------------------

def _epoch(hour: int) -> int:
    base = datetime(2030, 1, 1, tzinfo=timezone.utc)
    return int((base + timedelta(hours=hour)).timestamp())


def test_older_reset_window_cannot_overwrite_newer():
    _seed(500, reset=_epoch(13))
    abuseipdb.finish_quota_reservation(
        None, _Response({}, _quota(remaining=90, reset=_epoch(12))),
        endpoint="check")
    snapshot = abuseipdb.quota_snapshot("check")
    assert snapshot["remaining"] == 500
    assert snapshot["reset_at"].startswith("2030-01-01T13")


def test_equal_reset_window_keeps_the_lower_remaining():
    _seed(500, reset=_epoch(13))
    abuseipdb.finish_quota_reservation(
        None, _Response({}, _quota(remaining=400, reset=_epoch(13))),
        endpoint="check")
    abuseipdb.finish_quota_reservation(
        None, _Response({}, _quota(remaining=450, reset=_epoch(13))),
        endpoint="check")
    assert abuseipdb.quota_snapshot("check")["remaining"] == 400


def test_missing_reset_header_never_raises_remaining():
    _seed(500, reset=_epoch(13))
    abuseipdb.finish_quota_reservation(
        None, _Response({}, _quota(remaining=600, include_reset=False)),
        endpoint="check")
    snapshot = abuseipdb.quota_snapshot("check")
    assert snapshot["remaining"] == 500
    assert snapshot["reset_at"].startswith("2030-01-01T13")


def test_malformed_reset_is_treated_as_missing():
    _seed(500, reset=_epoch(13))
    headers = _quota(remaining=600)
    headers["X-RateLimit-Reset"] = "not-a-date"
    abuseipdb.finish_quota_reservation(
        None, _Response({}, headers), endpoint="check")
    assert abuseipdb.quota_snapshot("check")["remaining"] == 500


def test_reset_milliseconds_and_iso_are_normalized():
    ms = (_epoch(14)) * 1000
    _seed(500, reset=ms)
    assert abuseipdb.quota_snapshot("check")["reset_at"].startswith("2030-01-01T14")
    iso = datetime(2030, 1, 1, 15, tzinfo=timezone.utc).isoformat()
    abuseipdb.finish_quota_reservation(
        None, _Response({}, _quota(remaining=400, reset=iso)),
        endpoint="check")
    assert abuseipdb.quota_snapshot("check")["remaining"] == 400
    assert abuseipdb.quota_snapshot("check")["reset_at"].startswith("2030-01-01T15")


def test_429_same_window_records_retry_after():
    headers = _quota(remaining=400, reset=_epoch(13))
    headers["Retry-After"] = "120"
    _seed(500, reset=_epoch(13))
    abuseipdb.finish_quota_reservation(
        None, _Response({}, headers), endpoint="check")
    snapshot = abuseipdb.quota_snapshot("check")
    assert snapshot["remaining"] == 400
    assert snapshot["retry_after_seconds"] == 120
    with pytest.raises(AbuseIPDBError, match="rate limited"):
        abuseipdb.begin_quota_reservation("check")


def test_429_from_older_window_is_ignored():
    headers = _quota(remaining=0, reset=_epoch(12))
    headers["Retry-After"] = "120"
    _seed(500, reset=_epoch(13))
    abuseipdb.finish_quota_reservation(
        None, _Response({}, headers), endpoint="check")
    snapshot = abuseipdb.quota_snapshot("check")
    assert snapshot["remaining"] == 500
    assert snapshot["retry_after_seconds"] is None
    assert abuseipdb.begin_quota_reservation("check") is not None


def test_out_of_order_headers_keep_the_lower_remaining():
    _seed(103)
    first = abuseipdb.begin_quota_reservation("check")
    second = abuseipdb.begin_quota_reservation("check")
    abuseipdb.finish_quota_reservation(
        second, _Response({}, _quota(remaining=91)))
    abuseipdb.finish_quota_reservation(
        first, _Response({}, _quota(remaining=90)))
    snapshot = abuseipdb.quota_snapshot("check")
    assert snapshot["remaining"] == 90
    assert snapshot["inflight"] == 0


def test_past_reset_allows_recovery(transport):
    _seed(0, reset=int(time.time()) - 60)
    calls, queue = transport
    queue.append(_Response(_check_payload(), _quota(remaining=500)))
    _run(http_client._api_call("get", CHECK, client_name="hardening-reset"))
    assert abuseipdb.quota_snapshot("check")["remaining"] == 500


# ---------------------------------------------------------------------------
# Bootstrap and ambiguous failures
# ---------------------------------------------------------------------------

def test_bootstrap_limits_first_concurrent_requests(transport, monkeypatch):
    async def scenario():
        started = asyncio.Event()
        release = asyncio.Event()
        calls = []

        class Blocking:
            async def get(self, url, **kwargs):
                calls.append(url)
                started.set()
                await release.wait()
                return _response("get", url, _check_payload(),
                                 _quota(remaining=500))

        async def fake_get_client(name, verify=True):
            return Blocking()

        monkeypatch.setattr(http_client, "_get_client", fake_get_client)
        first = asyncio.create_task(
            http_client._api_call("get", CHECK, client_name="hardening-bootstrap"))
        await started.wait()
        with pytest.raises(AbuseIPDBError, match="bootstrap"):
            await http_client._api_call("get", CHECK,
                                        client_name="hardening-bootstrap")
        release.set()
        await first
        return calls

    assert asyncio.run(scenario()) == [CHECK]
    snapshot = abuseipdb.quota_snapshot("check")
    assert snapshot["remaining"] == 500
    assert snapshot["bootstrap"] is False


def test_headerless_first_response_keeps_bootstrap(transport):
    calls, queue = transport
    queue.append(_Response(_check_payload(), {}))
    _run(abuseipdb._api_call("get", CHECK))
    snapshot = abuseipdb.quota_snapshot("check")
    assert snapshot["remaining"] is None
    assert snapshot["bootstrap"] is True
    assert snapshot["bootstrap_limit"] == 1
    assert snapshot["inflight"] == 0


def test_bootstrap_recovers_with_header(transport):
    calls, queue = transport
    queue.extend([
        _Response(_check_payload(), {}),
        _Response(_check_payload(), _quota(remaining=500)),
    ])
    _run(abuseipdb._api_call("get", CHECK))
    _run(abuseipdb._api_call("get", CHECK))
    snapshot = abuseipdb.quota_snapshot("check")
    assert snapshot["remaining"] == 500
    assert snapshot["bootstrap"] is False


def test_sequential_headerless_requests_are_bounded(transport, monkeypatch):
    calls, queue = transport
    monkeypatch.setattr(abuseipdb, "ABUSEIPDB_BOOTSTRAP_BUDGET", 3)
    queue.extend([_Response(_check_payload(), {}) for _ in range(3)])
    for _ in range(3):
        _run(abuseipdb._api_call("get", CHECK))
    with pytest.raises(AbuseIPDBError, match="bootstrap budget"):
        _run(abuseipdb._api_call("get", CHECK))
    assert len(calls) == 3
    snapshot = abuseipdb.quota_snapshot("check")
    assert snapshot["bootstrap_used"] == 3
    assert snapshot["bootstrap_remaining"] == 0


def test_bootstrap_budget_is_per_endpoint(transport, monkeypatch):
    calls, queue = transport
    monkeypatch.setattr(abuseipdb, "ABUSEIPDB_BOOTSTRAP_BUDGET", 1)
    queue.extend([_Response(_check_payload(), {}), _Response({"data": {}}, {})])
    _run(abuseipdb._api_call("get", CHECK))
    with pytest.raises(AbuseIPDBError, match="bootstrap budget"):
        _run(abuseipdb._api_call("get", CHECK))
    _run(abuseipdb._api_call("get", BLOCK))
    assert len(calls) == 2
    assert abuseipdb.quota_snapshot("check")["bootstrap_used"] == 1
    assert abuseipdb.quota_snapshot("check-block")["bootstrap_used"] == 1


def test_authoritative_header_clears_bootstrap_budget(transport, monkeypatch):
    calls, queue = transport
    monkeypatch.setattr(abuseipdb, "ABUSEIPDB_BOOTSTRAP_BUDGET", 2)
    queue.extend([
        _Response(_check_payload(), {}),
        _Response(_check_payload(), _quota(remaining=500)),
    ])
    _run(abuseipdb._api_call("get", CHECK))
    _run(abuseipdb._api_call("get", CHECK))
    snapshot = abuseipdb.quota_snapshot("check")
    assert snapshot["bootstrap"] is False
    assert snapshot["bootstrap_used"] >= 0
    assert snapshot["remaining"] == 500
    _run(abuseipdb._api_call("get", CHECK))
    assert len(calls) == 3


def test_headerless_response_does_not_fabricate_reset(transport):
    calls, queue = transport
    queue.append(_Response(_check_payload(), {}))
    _run(abuseipdb._api_call("get", CHECK))
    snapshot = abuseipdb.quota_snapshot("check")
    assert snapshot["bootstrap"] is True
    assert snapshot["reset_at"] is None
    assert snapshot["bootstrap_used"] == 1


@pytest.mark.parametrize("exc,decrements", [
    (httpx.ConnectError("dns"), False),
    (httpx.ConnectTimeout("connect"), False),
    (httpx.PoolTimeout("pool"), False),
    (CircuitOpenError("open"), False),
    (httpx.ReadTimeout("read"), True),
    (httpx.WriteTimeout("write"), True),
    (httpx.RemoteProtocolError("reset"), True),
    (httpx.ReadError("read"), True),
    (httpx.WriteError("write"), True),
    (RuntimeError("unknown"), False),
])
def test_ambiguous_failure_accounting(transport, monkeypatch, exc, decrements):
    _seed(101)

    class Failing:
        async def get(self, url, **kwargs):
            raise exc

    async def fake_get_client(name, verify=True):
        return Failing()

    monkeypatch.setattr(http_client, "_get_client", fake_get_client)
    with pytest.raises(type(exc)):
        _run(http_client._api_call("get", CHECK, client_name="hardening-fail",
                                   max_retries=0))
    snapshot = abuseipdb.quota_snapshot("check")
    assert snapshot["inflight"] == 0
    assert snapshot["remaining"] == (100 if decrements else 101)


def test_cancellation_is_conservative(transport, monkeypatch):
    _seed(101)

    class Cancelling:
        async def get(self, url, **kwargs):
            raise asyncio.CancelledError()

    async def fake_get_client(name, verify=True):
        return Cancelling()

    monkeypatch.setattr(http_client, "_get_client", fake_get_client)
    with pytest.raises(asyncio.CancelledError):
        _run(http_client._api_call("get", CHECK, client_name="hardening-cancel"))
    assert abuseipdb.quota_snapshot("check")["remaining"] == 100
