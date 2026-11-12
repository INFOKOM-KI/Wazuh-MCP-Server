#!/usr/bin/env python3
"""The shared transport must reject arguments the selected httpx helper rejects.

Measured against httpx 0.28.1: ``get``/``head``/``options``/``delete`` take no
body arguments, ``post``/``put``/``patch`` do. The streaming branch uses
``build_request()``, which accepts body kwargs on every verb, so the guard has to
run before either branch or the two paths disagree.
"""
from __future__ import annotations

import asyncio
import os

import httpx
import pytest

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

from mcp_server.core import http_client
from mcp_server.core.exceptions import ThreatIntelError

BODY_VERBS = ("post", "put", "patch")
NO_BODY_VERBS = ("get", "head", "options", "delete")


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def transport(monkeypatch):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"ok": True})

    mock = httpx.MockTransport(handler)

    async def fake_get_client(name, verify=True):
        return httpx.AsyncClient(transport=mock)

    monkeypatch.setattr(http_client, "_get_client", fake_get_client)
    monkeypatch.setattr(http_client, "_get_breaker",
                        lambda name: http_client.CircuitBreaker())
    return seen


@pytest.mark.parametrize("verb", NO_BODY_VERBS)
@pytest.mark.parametrize("kwarg", ["data", "json", "content", "files"])
def test_bodiless_verbs_reject_body_arguments(verb, kwarg):
    with pytest.raises(ThreatIntelError) as exc:
        _run(http_client._api_call(verb, "https://example.test/x",
                                   **{kwarg: {"a": 1}}))
    assert verb.upper() in str(exc.value)
    assert kwarg in str(exc.value)


@pytest.mark.parametrize("verb", NO_BODY_VERBS)
def test_bodiless_verbs_still_accept_params(transport, verb):
    _run(http_client._api_call(verb, "https://example.test/x",
                               params={"a": "1"}))
    assert transport[0].method == verb.upper()
    assert transport[0].url.params["a"] == "1"
    assert not transport[0].content


@pytest.mark.parametrize("verb", BODY_VERBS)
def test_body_verbs_keep_their_payload(transport, verb):
    _run(http_client._api_call(verb, "https://example.test/x",
                               data={"ip": "8.8.8.8"}))
    assert transport[0].method == verb.upper()
    assert transport[0].content == b"ip=8.8.8.8"


@pytest.mark.parametrize("verb", BODY_VERBS)
def test_body_verbs_accept_json(transport, verb):
    _run(http_client._api_call(verb, "https://example.test/x", json={"a": 1}))
    assert transport[0].method == verb.upper()
    assert transport[0].headers["content-type"] == "application/json"


@pytest.mark.parametrize("kwarg", ["data", "json"])
def test_streaming_path_applies_the_same_policy(kwarg):
    """max_response_bytes switches to build_request, which accepts any kwarg."""
    with pytest.raises(ThreatIntelError):
        _run(http_client._api_call("get", "https://example.test/x",
                                   max_response_bytes=1024,
                                   **{kwarg: {"a": 1}}))


def test_streaming_path_still_works_for_a_legal_request(transport):
    resp = _run(http_client._api_call("get", "https://example.test/x",
                                      max_response_bytes=1024,
                                      params={"a": "1"}))
    assert resp.status_code == 200
    assert transport[0].url.params["a"] == "1"


@pytest.mark.parametrize("verb", ["trace", "connect", "foo", "", None])
def test_unknown_methods_are_rejected(verb):
    with pytest.raises(ThreatIntelError) as exc:
        _run(http_client._api_call(verb, "https://example.test/x"))
    assert "unsupported HTTP method" in str(exc.value)


def test_none_body_value_is_rejected_not_passed_through():
    """data=None is exactly how the original AbuseIPDB defect reached httpx."""
    with pytest.raises(ThreatIntelError) as exc:
        _run(http_client._api_call("get", "https://example.test/x", data=None))
    assert "data" in str(exc.value)


def test_method_case_is_irrelevant(transport):
    _run(http_client._api_call("GET", "https://example.test/x"))
    assert transport[0].method == "GET"


def test_credential_guard_runs_before_the_shape_check(monkeypatch):
    """A leaked key must be reported as a credential violation, not a shape error."""
    called = []

    def spy(method, url, verify, kw):
        called.append(method)
        return kw, None, None

    monkeypatch.setattr(http_client, "_guard_abuseipdb_request", spy)
    with pytest.raises(ThreatIntelError):
        _run(http_client._api_call("get", "https://example.test/x",
                                   data={"a": 1}))
    assert called == ["get"]


# Reservation safety on a shape rejection

def test_shape_rejection_releases_the_abuseipdb_reservation(monkeypatch):
    """The guard reserves before the shape check; a raise there must not leak it."""
    from mcp_server.threat_intel import abuseipdb

    reserved = []

    def fake_begin(endpoint):
        reserved.append(endpoint)
        state = abuseipdb._QUOTA_STATE.setdefault(endpoint, {})
        state["inflight"] = int(state.get("inflight", 0)) + 1
        return abuseipdb._QuotaReservation(endpoint)

    monkeypatch.setattr(abuseipdb, "begin_quota_reservation", fake_begin)
    monkeypatch.setattr(abuseipdb, "ABUSEIPDB_API_KEY", "test-key")
    abuseipdb.reset_quota_state()

    with pytest.raises(ThreatIntelError):
        _run(http_client._api_call(
            "get", "https://api.abuseipdb.com/api/v2/check", data={"a": 1}))

    assert reserved == ["check"]
    assert abuseipdb.quota_snapshot("check")["inflight"] == 0
