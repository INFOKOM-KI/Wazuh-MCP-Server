#!/usr/bin/env python3
"""RFC 1918 is a hard egress invariant for AbuseIPDB ``/report``.

``10.0.0.0/8``, ``172.16.0.0/12`` and ``192.168.0.0/16`` must never reach the
report endpoint, whatever the caller, severity, attack type, or exclusion
configuration. Every test mocks the HTTP boundary; none contacts AbuseIPDB or
Wazuh.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os

import httpx

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import pytest
from pydantic import ValidationError

from mcp_server.core import http_client
from mcp_server.core.exceptions import ThreatIntelError
from mcp_server.threat_intel import abuseipdb
from mcp_server.threat_intel._cache import AsyncRateLimiter, cache_delete_prefix
from mcp_server.threat_intel.abuseipdb import AbuseIPDBError
from mcp_server.tools import abuseipdb as report_tool
from mcp_server.tools.abuseipdb import (AbuseIPDBCheckInput, AbuseIPDBReportInput,
                                        blueteam_abuseipdb_report)

RFC1918_SAMPLES = [
    "10.0.0.0", "10.0.0.1", "10.255.255.255",
    "172.16.0.0", "172.16.0.1", "172.31.255.255",
    "192.168.0.0", "192.168.0.1", "192.168.255.255",
]
OUTSIDE_SAMPLES = [
    "9.255.255.255", "11.0.0.0", "172.15.255.255",
    "172.32.0.0", "192.167.255.255", "192.169.0.0",
]


def _run(coro):
    return asyncio.run(coro)


class _Response:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    """No pacing, no ledger or cache bleed, a key that never reaches a network."""
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
    with abuseipdb._LAST_REPORT_LOCK:
        abuseipdb._LAST_REPORT.clear()


@pytest.fixture
def outbound(monkeypatch):
    """Record every call that would leave the process."""
    calls = []

    async def fake_api_call(method, url, **kwargs):
        body = kwargs.get("data") or {}
        calls.append({"method": method, "url": url, "data": kwargs.get("data"),
                      "params": kwargs.get("params")})
        return _Response({"data": {"ipAddress": body.get("ip"),
                                   "abuseConfidenceScore": 50}})

    monkeypatch.setattr(abuseipdb, "_api_call_raw", fake_api_call)
    return calls


def _report_boundary(**overrides):
    body = {
        "ip": "8.8.8.8",
        "categories": "18,22",
        "comment": "SSH brute force against a monitored host.",
        "timestamp": "2026-11-06T01:00:00+00:00",
    }
    body.update(overrides)
    return abuseipdb._request("post", "/report",
                              limiter=abuseipdb.REPORT_LIMITER, data=body)


# Predicate and normalizer

@pytest.mark.parametrize("value", RFC1918_SAMPLES)
def test_rfc1918_predicate_and_normalizer_reject_every_range(value):
    assert abuseipdb.is_rfc1918(ipaddress.ip_address(value))
    with pytest.raises(ValueError, match="RFC 1918"):
        abuseipdb.normalize_public_ip(value)


@pytest.mark.parametrize("value", OUTSIDE_SAMPLES)
def test_addresses_immediately_outside_rfc1918_stay_public(value):
    assert not abuseipdb.is_rfc1918(ipaddress.ip_address(value))
    assert abuseipdb.normalize_public_ip(value) == value


@pytest.mark.parametrize("value", [
    "::ffff:10.0.0.1", "::ffff:172.16.0.1", "::ffff:192.168.1.1",
])
def test_ipv4_mapped_rfc1918_is_rejected(value):
    with pytest.raises(ValueError, match="RFC 1918"):
        abuseipdb.normalize_public_ip(value)


def test_ipv4_mapped_public_keeps_normalized_behavior():
    assert abuseipdb.normalize_public_ip("::ffff:8.8.8.8") == "8.8.8.8"


@pytest.mark.parametrize("value", [
    "", "  ", None, "010.0.0.1", "0x0a000001", "167772161",
    "10.0.0.1/8", "10.0.0.1.", "fe80::1%eth0", "not-an-ip",
])
def test_malformed_or_missing_values_fail_closed(value):
    with pytest.raises(ValueError):
        abuseipdb.normalize_public_ip(value)


@pytest.mark.parametrize("value", ["224.0.0.1", "239.1.1.1", "ff02::1", "ff05::2"])
def test_multicast_is_rejected(value):
    with pytest.raises(ValueError, match="multicast"):
        abuseipdb.normalize_public_ip(value)


# Outbound /report boundary

@pytest.mark.parametrize("value", RFC1918_SAMPLES)
def test_egress_boundary_rejects_rfc1918_before_http(outbound, value):
    with pytest.raises(AbuseIPDBError) as exc:
        _run(_report_boundary(ip=value))
    assert exc.value.kind == "bad_request"
    assert outbound == []


@pytest.mark.parametrize("payload", [
    None, {}, {"ip": None}, {"ip": 167772161}, {"ip": ""}, {"ip": "not-an-ip"},
])
def test_egress_boundary_rejects_missing_or_malformed_payload(outbound, payload):
    with pytest.raises(AbuseIPDBError):
        _run(abuseipdb._request("post", "/report",
                                limiter=abuseipdb.REPORT_LIMITER, data=payload))
    assert outbound == []


def test_egress_boundary_does_not_accept_ip_only_in_query_params(outbound):
    with pytest.raises(AbuseIPDBError, match="payload is missing"):
        _run(abuseipdb._request("post", "/report",
                                limiter=abuseipdb.REPORT_LIMITER,
                                params={"ip": "8.8.8.8"}, data=None))
    assert outbound == []


def test_egress_rejection_happens_before_key_and_limiter(monkeypatch):
    def forbidden_key():
        raise AssertionError("API key was looked up")

    class _NoEnter:
        async def __aenter__(self):
            raise AssertionError("rate limiter was entered")

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr(abuseipdb, "_api_key", forbidden_key)
    with pytest.raises(AbuseIPDBError, match="RFC 1918"):
        _run(abuseipdb._request("post", "/report", limiter=_NoEnter(),
                                data={"ip": "10.0.0.1"}))


@pytest.mark.parametrize("method,path", [
    ("POST", "/report"), ("post", "/report/"), ("Post", "/REPORT"),
    ("post", "/report?x=1"), ("post", "/report#frag"),
    ("post", "/v2/report"), ("post", "/./report"),
    ("post", "/report%2F"), ("post", "/%72eport"),
    ("post", "/report;x=1"), ("post", "/report\\"),
    ("post", "/report%00"),
])
def test_report_endpoint_is_detected_across_spellings(outbound, method, path):
    with pytest.raises(AbuseIPDBError, match="RFC 1918"):
        _run(abuseipdb._request(method, path,
                                limiter=abuseipdb.REPORT_LIMITER,
                                data={"ip": "192.168.1.1"}))
    assert outbound == []


def test_egress_boundary_submits_the_normalized_ip(outbound):
    _run(_report_boundary(ip="::ffff:8.8.8.8"))
    assert [c["data"]["ip"] for c in outbound] == ["8.8.8.8"]


@pytest.mark.parametrize("comment", [
    "attack from 10.0.0.5", "attack from 172.16.0.5", "attack from 192.168.0.5",
])
def test_egress_boundary_rejects_rfc1918_in_comment(outbound, comment):
    with pytest.raises(AbuseIPDBError, match="different IP address"):
        _run(_report_boundary(comment=comment))
    assert outbound == []


def test_egress_boundary_allows_the_reported_public_ip_in_comment(outbound):
    _run(_report_boundary(
        comment="SSH brute force from 8.8.8.8 against a monitored host."))
    assert len(outbound) == 1
    assert outbound[0]["data"]["comment"].count(abuseipdb.SIGNATURE) == 1


@pytest.mark.parametrize("comment", [
    "attack from 10\uff0e0\uff0e0\uff0e5",
    "attack from 172\uff0e16\uff0e0\uff0e5",
    "attack from 1\u200b0.0.0.5",
])
def test_comment_unicode_forms_cannot_hide_a_private_ip(outbound, comment):
    with pytest.raises(AbuseIPDBError, match="different IP address"):
        _run(_report_boundary(comment=comment))
    assert outbound == []


@pytest.mark.parametrize("comment", [
    "contact ｕｓｅｒ＠ｅｘａｍｐｌｅ.ｃｏｍ",
    "see ｈｔｔｐ：／／ｅｘａｍｐｌｅ.ｃｏｍ",
])
def test_comment_unicode_forms_cannot_hide_email_or_url(outbound, comment):
    with pytest.raises(AbuseIPDBError, match="email|URL"):
        _run(_report_boundary(comment=comment))
    assert outbound == []


# Direct transport boundary (_api_call), bypassing _request entirely

REPORT_URL = "https://api.abuseipdb.com/api/v2/report"


def _report_body(**overrides):
    body = {
        "ip": "8.8.8.8",
        "categories": "18",
        "comment": "SSH brute force against a monitored host.",
        "timestamp": "2026-11-06T01:00:00+00:00",
    }
    body.update(overrides)
    return body


@pytest.mark.parametrize("value", [
    "10.0.0.1", "172.16.0.1", "192.168.1.1",
    "::ffff:10.0.0.1", "::ffff:172.16.0.1", "::ffff:192.168.1.1",
])
def test_direct_transport_rejects_rfc1918(outbound, value):
    with pytest.raises(AbuseIPDBError) as exc:
        _run(abuseipdb._api_call("post", REPORT_URL,
                                 data=_report_body(ip=value)))
    assert exc.value.kind == "bad_request"
    assert outbound == []


@pytest.mark.parametrize("payload", [
    None, {}, {"ip": None}, {"ip": 167772161}, {"ip": ""}, {"ip": "not-an-ip"},
])
def test_direct_transport_rejects_missing_or_malformed_payload(outbound, payload):
    with pytest.raises(AbuseIPDBError):
        _run(abuseipdb._api_call("post", REPORT_URL, data=payload))
    assert outbound == []


@pytest.mark.parametrize("url", [
    REPORT_URL, REPORT_URL + "/", REPORT_URL.replace("/report", "/REPORT"),
    REPORT_URL + "?x=1", "/report", "/api/v2/./report",
])
def test_direct_transport_detects_the_report_endpoint(outbound, url):
    with pytest.raises(AbuseIPDBError, match="RFC 1918"):
        _run(abuseipdb._api_call("POST", url, data={"ip": "10.0.0.1"}))
    assert outbound == []


def test_direct_transport_rejects_rfc1918_in_comment(outbound):
    with pytest.raises(AbuseIPDBError, match="different IP address"):
        _run(abuseipdb._api_call("post", REPORT_URL,
                                 data=_report_body(comment="attack from 10.0.0.5")))
    assert outbound == []


def test_direct_transport_submits_the_normalized_public_ip(outbound):
    _run(abuseipdb._api_call("post", REPORT_URL,
                             data=_report_body(ip="::ffff:8.8.8.8")))
    assert len(outbound) == 1
    assert outbound[0]["data"]["ip"] == "8.8.8.8"
    assert outbound[0]["data"]["comment"].count(abuseipdb.SIGNATURE) == 1


def test_direct_transport_leaves_the_check_endpoint_unchanged(outbound):
    _run(abuseipdb._api_call("get", "https://api.abuseipdb.com/api/v2/check",
                             params={"ipAddress": "10.0.0.1"}))
    assert len(outbound) == 1
    assert outbound[0]["method"] == "get"
    assert outbound[0]["params"] == {"ipAddress": "10.0.0.1"}


# Shared raw transport (core.http_client._api_call); no module wrapper.

@pytest.fixture
def raw_core_transport(monkeypatch):
    calls = []

    class _FakeClient:
        async def post(self, url, **kw):
            calls.append((url, kw))
            return httpx.Response(200, json={"ok": True},
                                  request=httpx.Request("POST", url))

        async def get(self, url, **kw):
            calls.append((url, kw))
            return httpx.Response(200, json={"ok": True},
                                  request=httpx.Request("GET", url))

    async def fake_get_client(name, verify=True):
        return _FakeClient()

    monkeypatch.setattr(http_client, "_get_client", fake_get_client)
    return calls


@pytest.mark.parametrize("value", [
    "10.0.0.1", "172.16.0.1", "192.168.1.1", "224.0.0.1",
    "::ffff:10.0.0.1",
])
def test_raw_core_transport_blocks_non_public_report(raw_core_transport, value):
    with pytest.raises(AbuseIPDBError):
        _run(http_client._api_call(
            "post", REPORT_URL, client_name="abuseipdb-raw-guard",
            data={"ip": value, "categories": "18", "comment": "x"}))
    assert raw_core_transport == []


def test_raw_core_transport_normalizes_public_report(raw_core_transport):
    _run(http_client._api_call(
        "post", REPORT_URL, client_name="abuseipdb-raw-guard",
        data={"ip": "::ffff:8.8.8.8", "categories": "18", "comment": "x"}))
    assert len(raw_core_transport) == 1
    assert raw_core_transport[0][1]["data"]["ip"] == "8.8.8.8"


@pytest.mark.parametrize("url", [
    "https://api.abuseipdb.com/api/v2/%72eport",
    "https://api.abuseipdb.com/api/v2/report%2F",
    "https://api.abuseipdb.com/api/v2/report;x=1",
])
def test_raw_core_transport_blocks_encoded_report_url(raw_core_transport, url):
    with pytest.raises(AbuseIPDBError):
        _run(http_client._api_call(
            "post", url, client_name="abuseipdb-raw-guard",
            data={"ip": "10.0.0.1", "categories": "18", "comment": "x"}))
    assert raw_core_transport == []


def test_raw_core_transport_blocks_json_only_report(raw_core_transport):
    with pytest.raises(AbuseIPDBError, match="payload is missing"):
        _run(http_client._api_call(
            "post", REPORT_URL, client_name="abuseipdb-raw-guard",
            json={"ip": "10.0.0.1"}))
    assert raw_core_transport == []


def test_raw_core_transport_blocks_trailing_dot_host(raw_core_transport):
    with pytest.raises(AbuseIPDBError, match="RFC 1918"):
        _run(http_client._api_call(
            "post", "https://api.abuseipdb.com./api/v2/report",
            client_name="abuseipdb-raw-guard",
            data={"ip": "10.0.0.1", "categories": "18", "comment": "x"}))
    assert raw_core_transport == []


def test_raw_core_transport_leaves_check_endpoint_unchanged(raw_core_transport):
    _run(http_client._api_call(
        "get", "https://api.abuseipdb.com/api/v2/check",
        client_name="abuseipdb-raw-guard",
        params={"ipAddress": "10.0.0.1"}))
    assert len(raw_core_transport) == 1
    assert raw_core_transport[0][1]["params"] == {"ipAddress": "10.0.0.1"}


# report_ip and the input schemas

@pytest.mark.parametrize("value", RFC1918_SAMPLES)
def test_report_ip_rejects_rfc1918_before_http(outbound, value):
    with pytest.raises(AbuseIPDBError) as exc:
        _run(abuseipdb.report_ip(value, [18]))
    assert exc.value.kind == "bad_request"
    assert outbound == []


@pytest.mark.parametrize("value", RFC1918_SAMPLES)
def test_explicit_srcips_schema_rejects_rfc1918(value):
    with pytest.raises(ValidationError):
        AbuseIPDBReportInput(srcips=[value], comment="SSH brute force.")


@pytest.mark.parametrize("value", ["10.0.0.1", "172.16.0.1", "192.168.1.1"])
def test_check_schema_rejects_rfc1918(value):
    with pytest.raises(ValidationError):
        AbuseIPDBCheckInput(ip=value)


def test_check_schema_rejects_rfc1918_network():
    with pytest.raises(ValidationError):
        AbuseIPDBCheckInput(network="192.168.0.0/24")


# Harvest path

def _bucket(ip: str) -> dict:
    return {
        "key": ip, "doc_count": 5,
        "first_seen": {"value_as_string": "2026-11-06T01:00:00.000Z"},
        "last_seen": {"value_as_string": "2026-11-06T02:00:00.000Z"},
        "max_level": {"value": 10},
        "rule_ids": {"buckets": [{"key": "5710"}]},
        "rule_groups": {"buckets": [{"key": "sshd"}]},
    }


@pytest.fixture
def harvest(monkeypatch):
    ips = {"value": []}

    async def fake_merged(query, aggs):
        return ({"srcips": {"buckets": [_bucket(ip) for ip in ips["value"]],
                            "sum_other_doc_count": 0}},
                ["data.srcip.keyword"], [])

    async def fake_correct(buckets, query, index_pattern=None):
        observed = len([b for b in buckets if b.get("key") is not None])
        return buckets, observed

    async def fake_role(filters, candidate_ips):
        return set(), "checked"

    async def fake_check(ip, max_age_days=30, **kwargs):
        return {"ip": ip, "abuse_confidence_score": 50, "risk_band": "medium",
                "is_malicious": True, "total_reports": 10,
                "num_distinct_users": 3, "last_reported_at": None,
                "is_whitelisted": False, "is_public": True, "cached": False,
                "reports": []}

    monkeypatch.setattr(report_tool, "WAZUH_INDEXER_URL", "https://indexer:9200")
    monkeypatch.setattr(report_tool, "WAZUH_INDEXER_PASSWORD", "test")
    monkeypatch.setattr(report_tool, "_srcip_aggs_merged", fake_merged)
    monkeypatch.setattr(report_tool, "_correct_srcip_counts_with_status", fake_correct)
    monkeypatch.setattr(report_tool, "_dstip_role", fake_role)
    monkeypatch.setattr(report_tool, "check_ip", fake_check)
    monkeypatch.setattr(report_tool, "report_retry_after", lambda ip: 0)
    monkeypatch.setattr(report_tool, "ABUSEIPDB_EXCLUDE", "")
    monkeypatch.setattr(report_tool, "ABUSEIPDB_REPORTING_ENABLED", True)
    return ips


def test_empty_exclude_list_never_allows_rfc1918(harvest, outbound):
    harvest["value"] = ["10.0.0.1", "172.16.0.1", "192.168.1.1"]
    assert report_tool.ABUSEIPDB_EXCLUDE == ""
    output = json.loads(_run(blueteam_abuseipdb_report(AbuseIPDBReportInput(
        from_alerts=True, min_alerts=1, min_level=0,
        dry_run=False, confirm=True, response_format="json"))))
    assert output["reported"] == 0
    assert output["candidates_processed"] == 0
    assert output["excluded"]["private_or_reserved"] == 3
    assert outbound == []


def test_harvest_reports_only_the_public_source(harvest, outbound):
    harvest["value"] = ["10.0.0.1", "172.16.0.1", "192.168.1.1", "8.8.8.8"]
    output = json.loads(_run(blueteam_abuseipdb_report(AbuseIPDBReportInput(
        from_alerts=True, min_alerts=1, min_level=0,
        dry_run=False, confirm=True, response_format="json"))))
    assert output["reported"] == 1
    assert output["excluded"]["private_or_reserved"] == 3
    assert [c["data"]["ip"] for c in outbound] == ["8.8.8.8"]


@pytest.mark.parametrize("comment", [
    "SSH brute force from 10.0.0.5.",
    "SSH brute force from 172.16.0.5.",
    "SSH brute force from 192.168.0.5.",
])
def test_tool_rejects_rfc1918_in_explicit_comment(outbound, comment):
    with pytest.raises(ThreatIntelError, match="different IP address"):
        _run(blueteam_abuseipdb_report(AbuseIPDBReportInput(
            srcips=["8.8.8.8"], categories=[18], comment=comment,
            dry_run=False, confirm=True)))
    assert [c for c in outbound if c["method"] == "post"] == []


# Public reporting is unchanged

def test_public_report_ip_body_is_unchanged(outbound):
    result = _run(abuseipdb.report_ip(
        "8.8.8.8", [18], alert_count=4,
        first_seen="2026-11-06T01:00:00Z",
        last_seen="2026-11-06T01:10:00Z", rule_ids=["5710"]))
    assert result["status"] == "reported"
    assert [c["data"]["ip"] for c in outbound] == ["8.8.8.8"]
    assert outbound[0]["data"]["categories"] == "18"
    assert outbound[0]["data"]["comment"].count(abuseipdb.SIGNATURE) == 1


def test_public_explicit_report_still_posts(outbound, monkeypatch):
    monkeypatch.setattr(report_tool, "ABUSEIPDB_REPORTING_ENABLED", True)
    result = json.loads(_run(blueteam_abuseipdb_report(AbuseIPDBReportInput(
        srcips=["8.8.8.8"], categories=[18, 22],
        comment="SSH brute force against a monitored host.",
        dry_run=False, confirm=True, response_format="json"))))
    posts = [c for c in outbound if c["method"] == "post"]
    assert result["reported"] == 1
    assert len(posts) == 1
    assert posts[0]["data"]["ip"] == "8.8.8.8"
    assert posts[0]["data"]["categories"] == "18,22"
    assert posts[0]["data"]["comment"].count(abuseipdb.SIGNATURE) == 1
