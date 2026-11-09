#!/usr/bin/env python3
"""Offline tests for the shared AbuseIPDB client and the check tool.

No test performs network I/O. ``_api_call`` is replaced at the module boundary;
the repository-wide conftest fixture also blocks non-loopback sockets.
"""
from __future__ import annotations

import asyncio
import os
from unittest.mock import patch

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import httpx
import pytest

from mcp_server.threat_intel import abuseipdb
from mcp_server.threat_intel._cache import (AsyncRateLimiter, cache_delete_prefix)

# Hardcoded, not imported from the implementation. A test that compares the
# constant to itself cannot catch a changed signature; this literal is the
# requirement, and the assertion below pins the constant to it.
REQUIRED_SIGNATURE = "Reported by TangerangKota-CSIRT."


class _Response:
    def __init__(self, payload, status: int = 200):
        self._payload = payload
        self.status_code = status

    def json(self):
        return self._payload


def _status_error(status: int, detail: str) -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "https://api.abuseipdb.com/api/v2/check")
    response = httpx.Response(
        status, request=request,
        json={"errors": [{"detail": detail, "status": status}]})
    return httpx.HTTPStatusError(f"status {status}", request=request, response=response)


@pytest.fixture(autouse=True)
def _fast_abuseipdb(monkeypatch):
    """No waiting between upstream calls and no state leaking across tests."""
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


def _run(coro):
    return asyncio.run(coro)


# Input validation
@pytest.mark.parametrize("value", [
    "not-an-ip", "999.1.1.1", "1.2.3", "", "  ", "127.0.0.1",
    "192.168.1.1", "100.64.0.1", "169.254.1.1", "::1", "fc00::1",
    "224.0.0.1", "ff02::1",
])
def test_public_ip_rejects_invalid_private_and_cgnat(value):
    with pytest.raises(ValueError):
        abuseipdb.normalize_public_ip(value)


@pytest.mark.parametrize("value,expected", [
    ("8.8.8.8", "8.8.8.8"),
    ("2001:4860:4860::8888", "2001:4860:4860::8888"),
    ("::ffff:8.8.8.8", "8.8.8.8"),
])
def test_public_ip_accepts_public_v4_and_v6(value, expected):
    assert abuseipdb.normalize_public_ip(value) == expected


def test_shared_validator_now_rejects_malformed_ip():
    from mcp_server.core.http_client import _validate_public_ip
    for value in ("not-an-ip", "999.1.1.1"):
        with pytest.raises(ValueError, match="not a valid IP"):
            _validate_public_ip(value)


# Category table and mapping
def test_category_table_matches_official_ids():
    assert abuseipdb.CATEGORY_NAMES[14] == "Port Scan"
    assert abuseipdb.CATEGORY_NAMES[15] == "Hacking"
    assert abuseipdb.CATEGORY_NAMES[18] == "Brute-Force"
    assert abuseipdb.CATEGORY_NAMES[20] == "Exploited Host"
    assert abuseipdb.CATEGORY_NAMES[21] == "Web App Attack"
    assert abuseipdb.CATEGORY_NAMES[22] == "SSH"
    assert set(abuseipdb.CATEGORY_NAMES) == set(range(1, 24))


def test_categories_for_ssh_evidence():
    cats, reason = abuseipdb.categories_for_evidence(["sshd", "authentication_failed"])
    assert cats == [18, 22]
    assert reason == "ssh_bruteforce"


def test_authentication_failure_without_ssh_is_brute_force_only():
    cats, reason = abuseipdb.categories_for_evidence(["authentication_failed"])
    assert cats == [18]
    assert reason == "brute_force"


def test_categories_for_scan_and_web_and_malware():
    assert abuseipdb.categories_for_evidence(["scan"])[0] == [14]
    assert abuseipdb.categories_for_evidence(["web_attack", "accesslog"])[0] == [21]
    assert abuseipdb.categories_for_evidence(["sql_injection"])[0] == [16, 21]
    assert abuseipdb.categories_for_evidence(["malware"])[0] == [20]


def test_unknown_category_is_manual_review_not_hacking():
    cats, reason = abuseipdb.categories_for_evidence(["syslog", "custom"])
    assert cats == []
    assert reason == "manual_review"
    assert 15 not in cats


# Comment construction and the CIRT signature
def test_signature_constant_is_the_mandated_literal():
    assert abuseipdb.SIGNATURE == REQUIRED_SIGNATURE


def test_build_comment_has_exactly_one_signature_and_no_pii():
    text = abuseipdb.build_comment(
        7, "2026-11-06T01:00:00Z", "2026-11-06T02:00:00Z", ["5710", "5712"])
    assert text.count(REQUIRED_SIGNATURE) == 1
    assert text.endswith(REQUIRED_SIGNATURE)
    assert "5710" in text and "5712" in text
    assert "@" not in text and "http" not in text
    assert "agent" not in text.lower()


def test_signature_is_not_duplicated():
    custom = f"SSH brute force. {abuseipdb.SIGNATURE} {abuseipdb.SIGNATURE}"
    text = abuseipdb.sanitize_comment(custom)
    assert text.count(abuseipdb.SIGNATURE) == 1
    assert text.endswith(abuseipdb.SIGNATURE)
    assert text.startswith("SSH brute force.")


def test_signature_appended_to_custom_comment():
    text = abuseipdb.sanitize_comment("Port scan against a monitored host.")
    assert text == f"Port scan against a monitored host. {abuseipdb.SIGNATURE}"


@pytest.mark.parametrize("comment", [
    "Contact analyst@example.com",
    "Payload at https://victim.example/go",
])
def test_comment_rejects_pii_and_urls(comment):
    with pytest.raises(abuseipdb.AbuseIPDBError) as exc:
        abuseipdb.sanitize_comment(comment)
    assert exc.value.kind == "bad_request"


def test_long_comment_keeps_signature_and_cap():
    text = abuseipdb.sanitize_comment("A" * 900)
    assert len(text) <= abuseipdb.MAX_COMMENT_LENGTH
    assert text.count(REQUIRED_SIGNATURE) == 1
    assert text.endswith(REQUIRED_SIGNATURE)
    assert text[-len(REQUIRED_SIGNATURE):] == REQUIRED_SIGNATURE


def test_category_validation():
    assert abuseipdb.validate_categories([22, 18, 18]) == [18, 22]
    for value in ([], [0], [24], ["18"], [True]):
        with pytest.raises(abuseipdb.AbuseIPDBError):
            abuseipdb.validate_categories(value)


# check_ip
def test_check_ip_normalizes_and_caches():
    seen = {"calls": 0, "params": None}

    async def fake_api_call(method, url, **kwargs):
        seen["calls"] += 1
        seen["params"] = kwargs.get("params")
        return _Response({"data": {
            "ipAddress": "8.8.8.8", "isPublic": True, "ipVersion": 4,
            "isWhitelisted": False, "abuseConfidenceScore": 100,
            "totalReports": 12, "numDistinctUsers": 5,
            "lastReportedAt": "2026-11-01T00:00:00+00:00",
            "countryCode": "US", "isp": "Example", "usageType": "Data Center",
            "isTor": False,
        }})

    with patch.object(abuseipdb, "_api_call", fake_api_call):
        first = _run(abuseipdb.check_ip("8.8.8.8", 30))
        second = _run(abuseipdb.check_ip("8.8.8.8", 30))

    assert seen["calls"] == 1
    assert seen["params"]["ipAddress"] == "8.8.8.8"
    assert seen["params"]["maxAgeInDays"] == 30
    assert first["abuse_confidence_score"] == 100
    assert first["cached"] is False
    assert second["cached"] is True


def test_check_ip_invalid_age_is_rejected_without_request():
    async def fake_api_call(*args, **kwargs):
        raise AssertionError("no request expected")

    with patch.object(abuseipdb, "_api_call", fake_api_call):
        with pytest.raises(abuseipdb.AbuseIPDBError) as exc:
            _run(abuseipdb.check_ip("8.8.8.8", 0))
    assert exc.value.kind == "bad_request"


@pytest.mark.parametrize("payload", [
    {"errors": [{"detail": "quota"}]},
    {"data": {}},
    {"data": {"abuseConfidenceScore": "high"}},
    {"data": {"totalReports": 1}},
])
def test_check_ip_malformed_body_is_unavailable_not_clean(payload):
    async def fake_api_call(*args, **kwargs):
        return _Response(payload)

    with patch.object(abuseipdb, "_api_call", fake_api_call):
        with pytest.raises(abuseipdb.AbuseIPDBError):
            _run(abuseipdb.check_ip("8.8.8.8"))


def test_check_ip_timeout_is_timeout():
    async def fake_api_call(*args, **kwargs):
        raise httpx.ReadTimeout("slow")

    with patch.object(abuseipdb, "_api_call", fake_api_call):
        with pytest.raises(abuseipdb.AbuseIPDBError) as exc:
            _run(abuseipdb.check_ip("8.8.8.8"))
    assert exc.value.kind == "timeout"


@pytest.mark.parametrize("status,kind", [(401, "auth_error"), (403, "auth_error"),
                                         (429, "rate_limited"), (422, "bad_request")])
def test_check_ip_status_errors_keep_kind(status, kind):
    async def fake_api_call(*args, **kwargs):
        raise _status_error(status, "upstream says no")

    with patch.object(abuseipdb, "_api_call", fake_api_call):
        with pytest.raises(abuseipdb.AbuseIPDBError) as exc:
            _run(abuseipdb.check_ip("8.8.8.8"))
    assert exc.value.kind == kind


# check_block
def test_check_block_rejects_broad_or_private_network():
    for network in ("8.8.0.0/15", "192.168.1.0/24", "2001:db8::/64"):
        with pytest.raises(abuseipdb.AbuseIPDBError):
            _run(abuseipdb.check_block(network))


def test_check_block_normalizes_reported_addresses():
    async def fake_api_call(method, url, **kwargs):
        assert kwargs["params"]["network"] == "8.8.8.0/24"
        return _Response({"data": {
            "networkAddress": "8.8.8.0", "netmask": "255.255.255.0",
            "numPossibleHosts": 254, "addressSpaceDesc": "Example",
            "reportedAddress": [{
                "ipAddress": "8.8.8.9", "numReports": 4,
                "mostRecentReport": "2026-11-01T00:00:00+00:00",
                "abuseConfidenceScore": 75, "countryCode": None,
            }],
        }})

    with patch.object(abuseipdb, "_api_call", fake_api_call):
        result = _run(abuseipdb.check_block("8.8.8.9/24"))
    assert result["network"] == "8.8.8.0/24"
    assert result["reported_addresses"][0]["ip"] == "8.8.8.9"
    assert result["reported_addresses"][0]["num_reports"] == 4


# report_ip (the submission safety boundary is tested again in Phase 2)
def test_report_ip_uses_form_body_and_signature():
    seen = {}

    async def fake_api_call(method, url, **kwargs):
        seen["method"] = method
        seen["url"] = url
        seen["data"] = kwargs.get("data")
        seen["params"] = kwargs.get("params")
        seen["max_retries"] = kwargs.get("max_retries")
        return _Response({"data": {"ipAddress": "8.8.8.8",
                                   "abuseConfidenceScore": 52}})

    with patch.object(abuseipdb, "_api_call", fake_api_call):
        result = _run(abuseipdb.report_ip(
            "8.8.8.8", [18, 22], alert_count=4,
            first_seen="2026-11-06T01:00:00Z",
            last_seen="2026-11-06T01:10:00Z", rule_ids=["5710"]))

    assert seen["method"] == "post"
    assert seen["url"].endswith("/report")
    assert seen["params"] is None
    assert seen["max_retries"] == 0
    assert seen["data"]["ip"] == "8.8.8.8"
    assert seen["data"]["categories"] == "18,22"
    assert "5710" in seen["data"]["comment"]
    assert seen["data"]["comment"].count(REQUIRED_SIGNATURE) == 1
    assert seen["data"]["comment"].endswith(REQUIRED_SIGNATURE)
    assert result["status"] == "reported"
    assert result["verified"] is True


def test_report_ip_duplicate_is_local_and_does_not_spend_quota():
    calls = {"n": 0}

    async def fake_api_call(*args, **kwargs):
        calls["n"] += 1
        return _Response({"data": {"ipAddress": "8.8.8.8",
                                   "abuseConfidenceScore": 52}})

    with patch.object(abuseipdb, "_api_call", fake_api_call):
        first = _run(abuseipdb.report_ip("8.8.8.8", [18]))
        second = _run(abuseipdb.report_ip("8.8.8.8", [18]))

    assert calls["n"] == 1
    assert first["status"] == "reported"
    assert second["status"] == "duplicate_local"
    assert second["retry_after_seconds"] > 0
    assert second["comment"].count(abuseipdb.SIGNATURE) == 1


def test_report_ip_200_without_score_is_reported_but_unverified():
    async def fake_api_call(*args, **kwargs):
        return _Response({"data": {"ipAddress": "8.8.8.8"}})

    with patch.object(abuseipdb, "_api_call", fake_api_call):
        result = _run(abuseipdb.report_ip("8.8.8.8", [18]))
    assert result["status"] == "reported"
    assert result["verified"] is False
    assert result["abuse_confidence_score"] is None


def test_report_ip_duplicate_429_keeps_upstream_detail():
    async def fake_api_call(*args, **kwargs):
        raise _status_error(429, "You can only report the same IP address once in 15 minutes.")

    with patch.object(abuseipdb, "_api_call", fake_api_call):
        with pytest.raises(abuseipdb.AbuseIPDBError) as exc:
            _run(abuseipdb.report_ip("8.8.8.8", [18]))
    assert exc.value.kind == "rate_limited"
    assert "15 minutes" in exc.value.message


# Auth scope
def test_report_scope_is_separate_from_wazuh_write():
    from mcp_server.core.server_auth import (REPORT_SCOPE, TOOL_SCOPE_OVERRIDES,
                                             WRITE_SCOPE)
    assert REPORT_SCOPE == "threatintel:report"
    assert TOOL_SCOPE_OVERRIDES["blueteam_abuseipdb_report"] == REPORT_SCOPE
    assert REPORT_SCOPE != WRITE_SCOPE


def test_middleware_requires_report_scope_for_report_tool():
    from mcp_server.core.server_auth import APIAuthMiddleware, REPORT_SCOPE, WRITE_SCOPE
    mw = APIAuthMiddleware.__new__(APIAuthMiddleware)
    mw._write_tools = frozenset({"blueteam_abuseipdb_report",
                                 "blueteam_fail2ban_unban"})
    assert mw._required_scope("blueteam_abuseipdb_report") == REPORT_SCOPE
    assert mw._required_scope("blueteam_fail2ban_unban") == WRITE_SCOPE
    assert mw._required_scope("blueteam_abuseipdb_check") is None


# Report tool: input shape, safety gates, evidence, provenance

from pydantic import ValidationError  # noqa: E402

from mcp_server.tools import abuseipdb as report_tool  # noqa: E402
from mcp_server.tools.abuseipdb import AbuseIPDBReportInput  # noqa: E402


def _checked(score: int = 50, whitelisted: bool = False) -> dict:
    return {"ip": "8.8.8.8", "abuse_confidence_score": score,
            "risk_band": "medium", "is_malicious": score >= 50,
            "total_reports": 10, "num_distinct_users": 3,
            "last_reported_at": "2026-11-01T00:00:00+00:00",
            "is_whitelisted": whitelisted, "is_public": True,
            "cached": False, "reports": []}


def _bucket(ip: str, count: int, groups: list[str], rules: list[str]) -> dict:
    return {
        "key": ip, "doc_count": count,
        "first_seen": {"value_as_string": "2026-11-06T01:00:00.000Z"},
        "last_seen": {"value_as_string": "2026-11-06T02:00:00.000Z"},
        "max_level": {"value": 10},
        "rule_ids": {"buckets": [{"key": r} for r in rules]},
        "rule_groups": {"buckets": [{"key": g} for g in groups]},
    }


@pytest.fixture
def harvest_patches(monkeypatch):
    async def fake_merged(query, aggs):
        return ({"srcips": {"buckets": [
                    _bucket("8.8.8.8", 5, ["sshd"], ["5710", "5712"]),
                    _bucket("8.8.4.4", 1, ["sshd"], ["5710"]),
                    _bucket("192.168.1.1", 9, ["sshd"], ["5710"]),
                ], "sum_other_doc_count": 0}},
                ["data.srcip.keyword"], [])

    async def fake_correct(buckets, query):
        return buckets

    async def fake_role(filters, ips):
        return set(), "checked"

    async def fake_check(ip, max_age_days=30, **kwargs):
        return _checked()

    monkeypatch.setattr(report_tool, "WAZUH_INDEXER_URL", "https://indexer:9200")
    monkeypatch.setattr(report_tool, "WAZUH_INDEXER_PASSWORD", "test")
    monkeypatch.setattr(report_tool, "_srcip_aggs_merged", fake_merged)
    monkeypatch.setattr(report_tool, "_correct_srcip_counts", fake_correct)
    monkeypatch.setattr(report_tool, "_dstip_role", fake_role)
    monkeypatch.setattr(report_tool, "check_ip", fake_check)
    monkeypatch.setattr(report_tool, "report_retry_after", lambda ip: 0)
    return monkeypatch


def test_report_input_requires_exactly_one_source():
    with pytest.raises(ValidationError):
        AbuseIPDBReportInput()
    with pytest.raises(ValidationError):
        AbuseIPDBReportInput(srcips=["8.8.8.8"], from_alerts=True)
    with pytest.raises(ValidationError):
        AbuseIPDBReportInput(srcips=["192.168.1.1"])
    with pytest.raises(ValidationError):
        AbuseIPDBReportInput(srcips=["8.8.8.8", "8.8.4.4"], comment="x")


def test_report_input_rejects_unknown_category():
    with pytest.raises(ValidationError):
        AbuseIPDBReportInput(srcips=["8.8.8.8"], categories=[99])


def test_explicit_preview_shows_final_comment_and_does_not_submit():
    calls = {"n": 0}

    async def fake_report(*args, **kwargs):
        calls["n"] += 1
        return {"status": "reported"}

    with patch.object(report_tool, "report_ip", fake_report), \
            patch.object(report_tool, "check_ip",
                         lambda *a, **k: asyncio.sleep(0, result=_checked())):
        output = _run(report_tool.blueteam_abuseipdb_report(
            AbuseIPDBReportInput(
                srcips=["8.8.8.8"], categories=[18, 22],
                comment="SSH brute force against a monitored host.")))

    assert calls["n"] == 0
    assert "would_report" in output
    final = output.split("## Final comments", 1)[1]
    assert final.count(abuseipdb.SIGNATURE) == 1
    assert "SSH brute force" in output


def test_explicit_auto_without_evidence_is_manual_review():
    async def fake_check(ip, max_age_days=30, **kwargs):
        return _checked()

    with patch.object(report_tool, "check_ip", fake_check):
        output = _run(report_tool.blueteam_abuseipdb_report(
            AbuseIPDBReportInput(srcips=["8.8.8.8"],
                                 comment="Analyst observed repeated SSH failures.")))
    assert "manual_review" in output
    assert "would_report" not in output


def test_confirm_required_returns_preview_only():
    called = {"n": 0}

    async def fake_report(*args, **kwargs):
        called["n"] += 1

    with patch.object(report_tool, "report_ip", fake_report), \
            patch.object(report_tool, "check_ip",
                         lambda *a, **k: asyncio.sleep(0, result=_checked())):
        output = _run(report_tool.blueteam_abuseipdb_report(
            AbuseIPDBReportInput(
                srcips=["8.8.8.8"], categories=[18],
                comment="Analyst observed repeated SSH failures.",
                dry_run=False, confirm=False)))
    assert called["n"] == 0
    assert "confirm=true is required" in output


def test_reporting_disabled_raises_instead_of_fake_success(monkeypatch):
    async def fake_check(ip, max_age_days=30, **kwargs):
        return _checked()

    monkeypatch.setattr(report_tool, "ABUSEIPDB_REPORTING_ENABLED", False)
    with patch.object(report_tool, "check_ip", fake_check):
        with pytest.raises(Exception, match="reporting is disabled"):
            _run(report_tool.blueteam_abuseipdb_report(
                AbuseIPDBReportInput(
                    srcips=["8.8.8.8"], categories=[18],
                    comment="Analyst observed repeated SSH failures.",
                    dry_run=False, confirm=True)))


def test_confirmed_submission_calls_report_once(monkeypatch):
    seen = []

    async def fake_check(ip, max_age_days=30, **kwargs):
        return _checked()

    async def fake_report(ip, categories, **kwargs):
        seen.append((ip, categories, kwargs["comment"]))
        return {"status": "reported", "verified": True,
                "abuse_confidence_score": 52}

    monkeypatch.setattr(report_tool, "ABUSEIPDB_REPORTING_ENABLED", True)
    with patch.object(report_tool, "check_ip", fake_check), \
            patch.object(report_tool, "report_ip", fake_report):
        output = _run(report_tool.blueteam_abuseipdb_report(
            AbuseIPDBReportInput(
                srcips=["8.8.8.8"], categories=[18, 22],
                comment="Analyst observed repeated SSH failures.",
                dry_run=False, confirm=True)))

    assert len(seen) == 1
    assert seen[0][0] == "8.8.8.8"
    assert seen[0][1] == [18, 22]
    assert seen[0][2].count(abuseipdb.SIGNATURE) == 1
    assert "reported" in output
    assert "AbuseIPDB Report - submission" in output
    assert "Submission blocked" not in output


def test_harvest_filters_private_and_low_volume(harvest_patches):
    output = _run(report_tool.blueteam_abuseipdb_report(
        AbuseIPDBReportInput(from_alerts=True, min_alerts=3)))
    assert "8.8.8.8" in output
    assert "8.8.4.4" not in output
    assert "192.168.1.1" not in output
    assert "5710" in output
    final = output.split("## Final comments", 1)[1]
    assert final.count(abuseipdb.SIGNATURE) == 1


def test_harvest_ambiguous_destination_is_manual_review(harvest_patches):
    async def fake_role(filters, ips):
        return {"8.8.8.8"}, "checked"

    harvest_patches.setattr(report_tool, "_dstip_role", fake_role)
    output = _run(report_tool.blueteam_abuseipdb_report(
        AbuseIPDBReportInput(from_alerts=True, min_alerts=3)))
    assert "manual_review" in output
    assert "source/destination role is ambiguous" in output


def test_harvest_unverifiable_role_refuses_to_report(harvest_patches):
    async def fake_role(filters, ips):
        return set(), "unavailable"

    harvest_patches.setattr(report_tool, "_dstip_role", fake_role)
    with pytest.raises(Exception, match="cannot verify srcip/dstip role"):
        _run(report_tool.blueteam_abuseipdb_report(
            AbuseIPDBReportInput(from_alerts=True, min_alerts=3)))


def test_harvest_requires_indexer_configuration(monkeypatch):
    monkeypatch.setattr(report_tool, "WAZUH_INDEXER_URL", "")
    monkeypatch.setattr(report_tool, "WAZUH_INDEXER_PASSWORD", "")
    with pytest.raises(Exception, match="WAZUH_INDEXER_URL"):
        _run(report_tool.blueteam_abuseipdb_report(
            AbuseIPDBReportInput(from_alerts=True)))


def test_quota_failure_is_failed_not_reported(monkeypatch, harvest_patches):
    async def fake_report(*args, **kwargs):
        raise abuseipdb.AbuseIPDBError("Request quota exhausted", "rate_limited")

    monkeypatch.setattr(report_tool, "ABUSEIPDB_REPORTING_ENABLED", True)
    harvest_patches.setattr(report_tool, "report_ip", fake_report)
    output = _run(report_tool.blueteam_abuseipdb_report(
        AbuseIPDBReportInput(from_alerts=True, min_alerts=3,
                             dry_run=False, confirm=True)))
    assert "failed" in output
    assert "Partial**: True" in output


def test_auth_error_stops_the_batch(monkeypatch, harvest_patches):
    calls = {"n": 0}

    async def fake_report(*args, **kwargs):
        calls["n"] += 1
        raise abuseipdb.AbuseIPDBError("bad key", "auth_error")

    monkeypatch.setattr(report_tool, "ABUSEIPDB_REPORTING_ENABLED", True)
    harvest_patches.setattr(report_tool, "report_ip", fake_report)
    output = _run(report_tool.blueteam_abuseipdb_report(
        AbuseIPDBReportInput(from_alerts=True, min_alerts=3,
                             dry_run=False, confirm=True)))
    assert calls["n"] == 1
    assert "failed" in output


def test_harvest_reports_truncation_and_remaining(harvest_patches):
    async def fake_merged(query, aggs):
        return ({"srcips": {"buckets": [
                    _bucket("8.8.8.8", 5, ["sshd"], ["5710"]),
                ], "sum_other_doc_count": 7}},
                ["data.srcip.keyword"], [])
    harvest_patches.setattr(report_tool, "_srcip_aggs_merged", fake_merged)
    output = _run(report_tool.blueteam_abuseipdb_report(
        AbuseIPDBReportInput(from_alerts=True, min_alerts=3)))
    assert "Remaining candidates**: at least 7" in output
    assert "Truncated**: True" in output
    assert "Partial**: True" in output


def test_harvest_provenance_is_preserved(harvest_patches):
    output = _run(report_tool.blueteam_abuseipdb_report(
        AbuseIPDBReportInput(from_alerts=True, min_alerts=3)))
    assert "## Provenance" in output
    assert "5710, 5712" in output
    assert "sshd" in output
    assert "2026-11-06T01:00:00.000Z" in output


def test_custom_comment_keeps_one_signature_in_preview():
    async def fake_check(ip, max_age_days=30, **kwargs):
        return _checked()

    with patch.object(report_tool, "check_ip", fake_check):
        output = _run(report_tool.blueteam_abuseipdb_report(
            AbuseIPDBReportInput(
                srcips=["8.8.8.8"], categories=[18],
                comment=f"SSH brute force. {abuseipdb.SIGNATURE}")))
    final = output.split("## Final comments", 1)[1]
    assert final.count(abuseipdb.SIGNATURE) == 1


def test_comment_with_pii_is_rejected_before_check():
    with pytest.raises(ValidationError):
        AbuseIPDBReportInput(
            srcips=["8.8.8.8"], categories=[18],
            comment="Contact analyst@example.com")


def test_unified_score_rejects_cgnat_and_reserved():
    from mcp_server.tools.alert_enrichment import UnifiedThreatScoreInput
    for value in ("100.64.0.1", "192.0.2.10", "not-an-ip"):
        with pytest.raises(ValidationError):
            UnifiedThreatScoreInput(ip=value)


def test_unified_score_marks_abuseipdb_unavailable(monkeypatch):
    from mcp_server.tools import alert_enrichment
    from mcp_server.threat_intel import crowdsec as cs
    from mcp_server.threat_intel import threatfox as tf

    async def fake_cs(path):
        return {"reputation": "unknown", "behaviors": []}

    async def fake_tf(ip, exact_match=False):
        return {"data": []}

    async def fake_check(*args, **kwargs):
        raise abuseipdb.AbuseIPDBError("timed out", "timeout")

    monkeypatch.setattr(cs, "_crowdsec_request", fake_cs)
    monkeypatch.setattr(tf, "_threatfox_request", fake_tf)
    monkeypatch.setattr(abuseipdb, "check_ip", fake_check)
    out = _run(alert_enrichment.blueteam_unified_threat_score(
        alert_enrichment.UnifiedThreatScoreInput(ip="8.8.8.8")))
    assert "unavailable" in out
    assert "timeout" in out
    assert "AbuseIPDB | - | ⚠️ unavailable (timeout)" in out


def test_verbose_check_strips_third_party_comment_text():
    async def fake_api_call(*args, **kwargs):
        return _Response({"data": {
            "ipAddress": "8.8.8.8", "abuseConfidenceScore": 90,
            "totalReports": 1, "reports": [{
                "reportedAt": "2026-11-01T00:00:00+00:00",
                "categories": [18, 22],
                "comment": "root login from victim@example.com",
            }],
        }})

    with patch.object(abuseipdb, "_api_call", fake_api_call):
        result = _run(abuseipdb.check_ip("8.8.8.8", 30, verbose=True))
    assert result["reports"][0]["categories"] == [18, 22]
    assert result["reports"][0]["comment"] == "[third-party comment omitted]"
    assert "victim@example.com" not in str(result)


def test_signature_deduplicates_case_insensitively():
    text = abuseipdb.sanitize_comment(
        f"SSH brute force. {abuseipdb.SIGNATURE.lower()} {abuseipdb.SIGNATURE}")
    assert text.count(abuseipdb.SIGNATURE) == 1
    assert text.endswith(abuseipdb.SIGNATURE)


def test_daily_quota_stops_the_batch(monkeypatch, harvest_patches):
    async def fake_merged(query, aggs):
        return ({"srcips": {"buckets": [
                    _bucket("8.8.8.8", 5, ["sshd"], ["5710"]),
                    _bucket("8.8.4.4", 5, ["sshd"], ["5710"]),
                ], "sum_other_doc_count": 0}},
                ["data.srcip.keyword"], [])

    calls = {"n": 0}

    async def fake_report(*args, **kwargs):
        calls["n"] += 1
        raise abuseipdb.AbuseIPDBError(
            "Daily rate limit of 1000 requests exceeded for this endpoint.",
            "rate_limited")

    monkeypatch.setattr(report_tool, "ABUSEIPDB_REPORTING_ENABLED", True)
    harvest_patches.setattr(report_tool, "_srcip_aggs_merged", fake_merged)
    harvest_patches.setattr(report_tool, "report_ip", fake_report)
    output = _run(report_tool.blueteam_abuseipdb_report(
        AbuseIPDBReportInput(from_alerts=True, min_alerts=1,
                             dry_run=False, confirm=True)))
    assert calls["n"] == 1
    assert "skipped_quota" in output


def test_explicit_srcip_requires_evidence_comment():
    with pytest.raises(ValidationError):
        AbuseIPDBReportInput(srcips=["8.8.8.8"], categories=[18])


def test_report_scope_is_accepted_by_the_key_loader(monkeypatch):
    from mcp_server.core.server_auth import (REPORT_SCOPE, ServerAuthManager,
                                             WRITE_SCOPE)
    key = "btm_" + "a" * 43
    monkeypatch.setenv("MCP_API_KEY", key)
    monkeypatch.setenv("MCP_API_KEY_SCOPES", REPORT_SCOPE)
    manager = ServerAuthManager()
    parsed = manager.validate_api_key(key)
    assert parsed is not None
    assert parsed.has_scope(REPORT_SCOPE)
    assert not parsed.has_scope(WRITE_SCOPE)


def test_check_ip_accepts_ipv6_and_passes_it_as_a_parameter():
    seen = {}

    async def fake_api_call(method, url, **kwargs):
        seen["params"] = kwargs.get("params")
        return _Response({"data": {
            "ipAddress": "2001:4860:4860::8888", "abuseConfidenceScore": 0,
            "totalReports": 0, "isPublic": True, "ipVersion": 6,
        }})

    with patch.object(abuseipdb, "_api_call", fake_api_call):
        result = _run(abuseipdb.check_ip("2001:4860:4860::8888"))
    assert seen["params"]["ipAddress"] == "2001:4860:4860::8888"
    assert result["ip_version"] == 6


@pytest.mark.parametrize("comment", [
    "SSH login attempts with user root.",
    "Invalid user admin from the internet.",
    "Agent web-01 saw repeated failures.",
    "Failed password for root from the attacker.",
])
def test_comment_rejects_identities_and_raw_logs(comment):
    with pytest.raises(abuseipdb.AbuseIPDBError) as exc:
        abuseipdb.sanitize_comment(comment)
    assert exc.value.kind == "bad_request"


def test_comment_allows_generic_user_enumeration_wording():
    text = abuseipdb.sanitize_comment("User enumeration and login attempts observed.")
    assert text.endswith(abuseipdb.SIGNATURE)


def test_comment_rejects_a_third_party_ip():
    with pytest.raises(abuseipdb.AbuseIPDBError) as exc:
        abuseipdb.sanitize_comment(
            "SSH brute force from 8.8.8.8 against 10.0.0.5.",
            allowed_ip="8.8.8.8")
    assert "different IP" in exc.value.message


def test_comment_allows_the_reported_ip():
    text = abuseipdb.sanitize_comment(
        "SSH brute force from 8.8.8.8.", allowed_ip="8.8.8.8")
    assert "8.8.8.8" in text
    assert text.endswith(abuseipdb.SIGNATURE)


def test_explicit_comment_with_third_party_ip_is_rejected_at_evaluation():
    async def fake_check(ip, max_age_days=30, **kwargs):
        return _checked()

    with patch.object(report_tool, "check_ip", fake_check):
        with pytest.raises(Exception, match="different IP"):
            _run(report_tool.blueteam_abuseipdb_report(
                AbuseIPDBReportInput(
                    srcips=["8.8.8.8"], categories=[18],
                    comment="SSH brute force from 8.8.8.8 against 10.0.0.5.")))


def test_harvest_reports_exclusion_counts_and_coverage(harvest_patches):
    output = _run(report_tool.blueteam_abuseipdb_report(
        AbuseIPDBReportInput(from_alerts=True, min_alerts=3)))
    assert "Alerts examined**: 15" in output
    assert "Unique srcip buckets**: 3" in output
    assert "Excluded**: 2" in output
    assert "private_or_reserved=1" in output
    assert "below_min_alerts=1" in output
    assert "Checks**: 1 live" in output
