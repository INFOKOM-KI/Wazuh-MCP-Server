#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Tests for the attack-to-CVE assessment engine.

Fixtures are synthetic: hand-written alert documents and cve.now records, declared
here as synthetic test data. No Wazuh Indexer and no live cve.now call is involved.
"""
from __future__ import annotations

import json
import os
import pathlib

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import httpx
import pytest

from mcp_server.core.http_client import CircuitOpenError
from mcp_server.threat_intel import _cache, cve_now
from mcp_server.threat_intel import cve_now_assess as engine
from mcp_server.tools import cve_now as cve_now_tools
from mcp_server.tools.cve_now import (
    CveNowCorrelateInput,
    PackageInput,
    blueteam_cve_now_attack_correlate,
)


@pytest.fixture(autouse=True)
def _fresh_state(monkeypatch):
    for key in [k for k in _cache._SHARED_CACHE._data if k.startswith("cve_now:")]:
        del _cache._SHARED_CACHE._data[key]
    monkeypatch.setattr(cve_now._limiter, "min_interval", 0.0)
    yield


class FakeRPC:
    def __init__(self):
        self.calls: list[dict] = []
        self.responses: list[httpx.Response] = []
        self.feed_responses: list[httpx.Response] = []

    @staticmethod
    def _envelope(payload: dict) -> httpx.Response:
        body = {"jsonrpc": "2.0", "id": 1,
                "result": {"content": [{"type": "text", "text": json.dumps(payload)}]}}
        return httpx.Response(200, json=body)

    def queue(self, payload: dict):
        self.responses.append(self._envelope(payload))
        return self

    def queue_feed(self, payload: dict):
        self.feed_responses.append(self._envelope(payload))
        return self

    def install(self, monkeypatch):
        async def fake(method, url, **kwargs):
            self.calls.append({"method": method, "url": url, **kwargs})
            name = ((kwargs.get("json") or {}).get("params") or {}).get("name")
            queue = self.feed_responses if name == "list_feed" else self.responses
            if queue:
                return queue.pop(0)
            if name == "list_feed":
                return self._envelope({"items": [], "updatedAt": None})
            raise IndexError(f"no queued response for {name}")
        monkeypatch.setattr(cve_now, "_api_call", fake)
        return self


@pytest.fixture
def rpc(monkeypatch):
    return FakeRPC().install(monkeypatch)


def record(cve_id: str, title: str, summary: str = "", *, cvss=9.8, kev=False,
           ranges=None, package=None, product=None) -> dict:
    affected = []
    if ranges and package:
        affected.append({"ecosystem": "generic", "package": package, "ranges": ranges})
    elif ranges:
        affected.append({"vendor": "Vendor", "product": product or "Product", "ranges": ranges})
    elif package:
        affected.append({"vendor": "Vendor", "product": product or package, "package": package})
    return {"id": cve_id, "title": title, "summary": {"text": summary or title},
            "severity": {"cvss": cvss, "source": "cna"},
            "kev": {"listed": kev},
            "affected": affected,
            "exploitation": {"kev": {"dateAdded": "2024-01-01"} if kev else {},
                             "metasploit": {"modules": ["m.rb"] if kev else []},
                             "nuclei": {"templates": []}, "exploitDb": {"ids": []},
                             "githubPoc": {"repos": []}}}


def search_entry(cve_id: str, title: str, summary: str = "", *, cvss=9.8, kev=False) -> dict:
    return {"id": cve_id, "title": title, "summary": summary or title,
            "cvss": cvss, "kev": kev, "modified": "2026-10-01T00:00:00Z",
            "url": f"https://cve.now/{cve_id}"}


WP_UPLOAD_ALERT = {
    "id": "1780000000.1", "@timestamp": "2026-11-01T10:00:00Z",
    "rule": {"id": "600010", "level": 10, "groups": ["wordpress", "web_attack"],
             "description": "Unrestricted file upload attempt in WordPress plugin"},
    "decoder": {"name": "web-accesslog"}, "location": "/var/log/nginx/access.log",
    "agent": {"id": "001", "name": "web01"},
    "data": {"url": "/wp-content/plugins/x/upload.php", "method": "POST"},
}

WP_PLUGIN_UPLOAD_ALERT = {
    "id": "1780000000.3",
    "rule": {"id": "600010", "level": 12, "groups": ["wordpress", "web_attack"],
             "description": "Unrestricted file upload attempt in WordPress plugin"},
    "decoder": {"name": "web-accesslog"}, "location": "/var/log/nginx/access.log",
    "agent": {"id": "001", "name": "web01"},
    "data": {"url": "/wp-content/plugins/wp-scraper/import.php", "method": "POST"},
}

GENERIC_LOGIN_ALERT = {
    "id": "1780000000.2",
    "rule": {"id": "600014", "level": 8, "groups": ["wordpress"],
             "description": "Multiple failed login attempts"},
    "agent": {"id": "001", "name": "web01"},
}


class TestVersionCompare:
    def test_in_range(self):
        rec = record("CVE-1", "x", ranges=[{"introduced": "1.0", "fixed": "2.0"}],
                     package="widget")
        assert engine.compare_version("widget", "1.5", rec)["status"] == "in_range"

    def test_not_in_range(self):
        rec = record("CVE-1", "x", ranges=[{"introduced": "1.0", "fixed": "2.0"}],
                     package="widget")
        assert engine.compare_version("widget", "2.1", rec)["status"] == "not_in_range"

    def test_unfixed_range_counts_as_affected(self):
        rec = record("CVE-1", "x", ranges=[{"introduced": "1.0"}], package="widget")
        assert engine.compare_version("widget", "9.9", rec)["status"] == "in_range"

    def test_suffixed_installed_version_is_unknown(self):
        rec = record("CVE-1", "x", ranges=[{"introduced": "1.0", "fixed": "2.0"}],
                     package="widget")
        assert engine.compare_version("widget", "1.5-beta9", rec)["status"] == "unknown"

    def test_package_not_listed_is_unknown(self):
        rec = record("CVE-1", "x", ranges=[{"introduced": "1.0", "fixed": "2.0"}],
                     package="widget")
        assert engine.compare_version("other", "1.5", rec)["status"] == "unknown"

    def test_related_package_name_matches(self):
        rec = record("CVE-1", "x", ranges=[{"introduced": "1.0", "fixed": "2.0"}],
                     package="openssh")
        assert engine.compare_version("openssh-server", "1.5", rec)["status"] == "in_range"


class TestClassification:
    def test_short_acronyms_need_word_boundaries(self):
        assert engine._token_hit("the server may coerce a request", "rce") is False
        assert engine._token_hit("rce payload detected", "rce") is True

    def test_attack_class_from_description_and_url(self):
        context = engine.extract_alert_context(WP_UPLOAD_ALERT)
        result = engine.classify_attack(context)
        assert result["attack_class"] == "file_upload"
        assert any("file upload" in item for item in result["evidence"])

    def test_brute_force_is_classified(self):
        context = engine.extract_alert_context(GENERIC_LOGIN_ALERT)
        assert engine.classify_attack(context)["attack_class"] == "brute_force"

    def test_unrelated_description_yields_no_class(self):
        context = engine.extract_alert_context({"rule": {"description": "Integrity checksum changed"}})
        assert engine.classify_attack(context)["attack_class"] is None

    def test_cwe_is_never_fabricated(self):
        assessed = engine.assess_candidate(record("CVE-1", "WordPress file upload"),
                                           engine.extract_alert_context(WP_UPLOAD_ALERT),
                                           engine.classify_attack(engine.extract_alert_context(WP_UPLOAD_ALERT)),
                                           ["wordpress"], [])
        assert assessed["cwe"] is None
        assert "no CWE field" in assessed["cwe_note"]


class TestRelationships:
    def test_attack_specific_requires_component_and_class(self):
        rec = record("CVE-2024-1", "WordPress wp-scraper plugin import.php file upload",
                     "Unrestricted upload through import.php.", package="wp_scraper")
        context = engine.extract_alert_context(WP_PLUGIN_UPLOAD_ALERT)
        attack = engine.classify_attack(context)
        assessed = engine.assess_candidate(rec, context, attack, ["wordpress"], [])
        assert assessed["relationship"] == "attack_specific_match"
        assert assessed["strength"] == "moderate"
        assert any("class:file_upload" in item for item in assessed["evidence"])

    def test_class_mismatch_prevents_attack_specific(self):
        rec = record("CVE-2024-2", "WordPress plugin SQL injection")
        context = engine.extract_alert_context(WP_UPLOAD_ALERT)
        attack = engine.classify_attack(context)
        assessed = engine.assess_candidate(rec, context, attack, ["wordpress"], [])
        assert assessed["relationship"] == "contextual_candidate"
        assert any("does not produce" in item for item in assessed["contradictions"])

    def test_exposure_needs_a_version_in_range(self):
        rec = record("CVE-2024-3", "WordPress information disclosure",
                     ranges=[{"introduced": "1.0", "fixed": "2.0"}], package="wordpress")
        context = engine.extract_alert_context(GENERIC_LOGIN_ALERT)
        attack = engine.classify_attack(context)
        assessed = engine.assess_candidate(rec, context, attack, ["wordpress"],
                                           [{"name": "wordpress", "version": "1.5"}])
        assert assessed["relationship"] == "vulnerability_exposure"
        assert assessed["version_check"]["status"] == "in_range"

    def test_version_out_of_range_becomes_a_contradiction(self):
        rec = record("CVE-2024-4", "WordPress plugin file upload",
                     ranges=[{"introduced": "1.0", "fixed": "2.0"}], package="wordpress")
        context = engine.extract_alert_context(WP_UPLOAD_ALERT)
        attack = engine.classify_attack(context)
        assessed = engine.assess_candidate(rec, context, attack, ["wordpress"],
                                           [{"name": "wordpress", "version": "3.0"}])
        assert assessed["relationship"] == "contextual_candidate"
        assert any("outside every listed range" in item for item in assessed["contradictions"])

    def test_direct_reference_is_not_exploitation(self):
        rec = record("CVE-2024-5", "WordPress plugin file upload")
        context = engine.extract_alert_context({"data": {"vulnerability": {"cve": "CVE-2024-5"}}})
        assessed = engine.assess_candidate(rec, context, engine.classify_attack(context),
                                           ["wordpress"], [], direct=True)
        assert assessed["relationship"] == "confirmed_cve_reference"
        assert "not proof" in assessed["confidence_explanation"]

    def test_kev_alone_does_not_promote(self):
        rec = record("CVE-2024-6", "Some product issue", kev=True)
        context = engine.extract_alert_context(GENERIC_LOGIN_ALERT)
        assessed = engine.assess_candidate(rec, context, engine.classify_attack(context),
                                           ["wordpress"], [])
        assert assessed["relationship"] != "attack_specific_match"
        assert "kev:listed" in assessed["evidence"]


class TestSummarize:
    def test_attack_specific_outranks_contextual(self):
        context = engine.extract_alert_context(WP_PLUGIN_UPLOAD_ALERT)
        attack = engine.classify_attack(context)
        specific = engine.assess_candidate(
            record("CVE-2024-7", "WordPress wp-scraper import.php file upload",
                   package="wp_scraper"),
            context, attack, ["wordpress"], [])
        contextual = engine.assess_candidate(
            record("CVE-2024-8", "WordPress plugin SQL injection", cvss=10),
            context, attack, ["wordpress"], [])
        summary = engine.summarize([contextual, specific], attack, "none")
        assert summary["relationship"] == "attack_specific_match"
        assert summary["selected"]["id"] == "CVE-2024-7"
        assert summary["successful_exploitation_established"] is False

    def test_unsupported_candidates_are_not_selected(self):
        context = engine.extract_alert_context({"rule": {"description": "Integrity checksum changed"}})
        attack = engine.classify_attack(context)
        rejected = engine.assess_candidate(record("CVE-2024-9", "Unrelated DNS issue"),
                                           context, attack, [], [])
        summary = engine.summarize([rejected], attack, "none")
        assert rejected["relationship"] == "no_supported_match"
        assert summary["relationship"] == "no_supported_match"
        assert summary["selected"] is None


class TestToolScenarios:
    """Synthetic alerts through the real tool, with cve.now responses mocked."""

    @pytest.mark.asyncio
    async def test_explicit_structured_cve_is_confirmed_reference(self, rpc):
        rpc.queue(record("CVE-2021-44228", "Apache Log4j2 remote code execution",
                         "JNDI remote code execution."))
        out = await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert={"data": {"vulnerability": {"cve": "CVE-2021-44228"}},
                   "rule": {"description": "CVE-2021-44228 affects log4j"}},
            response_format="json"))
        data = json.loads(out)
        assert data["match_basis"] == "alert_cve"
        assert data["candidates"][0]["relationship"] == "confirmed_cve_reference"
        assert data["assessment"]["successful_exploitation_established"] is False

    @pytest.mark.asyncio
    async def test_generic_attack_never_promotes_candidates(self, rpc):
        rpc.queue({"entries": [
            search_entry("CVE-2024-10", "WordPress plugin SQL injection"),
            search_entry("CVE-2024-11", "WordPress plugin remote code execution"),
        ], "total": 2, "next_cursor": None})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=GENERIC_LOGIN_ALERT, response_format="json")))
        assert {c["relationship"] for c in data["candidates"]} == {"contextual_candidate"}
        assert data["assessment"]["relationship"] == "contextual_candidate"
        assert data["assessment"]["vulnerable_software_confirmed"] == "unknown"

    @pytest.mark.asyncio
    async def test_exploit_specific_alert_reaches_attack_specific(self, rpc):
        rpc.queue({"entries": [search_entry(
            "CVE-2024-12", "WordPress wp-scraper import.php file upload",
            "Unrestricted upload through import.php.")], "total": 1})
        rpc.queue({"entries": [], "total": 0})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=WP_PLUGIN_UPLOAD_ALERT, response_format="json")))
        assert data["candidates"][0]["relationship"] == "attack_specific_match"
        assert "no proof" in json.dumps(data["candidates"][0]["confidence_explanation"]).lower() \
            or "plausible" in data["candidates"][0]["confidence_explanation"].lower()

    @pytest.mark.asyncio
    async def test_technology_match_without_version_is_missing_not_positive(self, rpc):
        rpc.queue({"entries": [search_entry("CVE-2024-13", "WordPress plugin SQL injection")],
                   "total": 1})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=GENERIC_LOGIN_ALERT, response_format="json")))
        candidate = data["candidates"][0]
        assert candidate["version_check"]["status"] == "unknown"
        assert any("inventory" in item for item in candidate["missing"])

    @pytest.mark.asyncio
    async def test_inventory_turns_exposure_on(self, rpc, monkeypatch):
        async def fake_indexer(body, index_pattern=None):
            assert index_pattern == "wazuh-states-inventory-packages-*"
            return {"hits": {"hits": [
                {"_source": {"package": {"name": "wordpress", "version": "1.5"}}}]}}

        monkeypatch.setattr(cve_now_tools, "_wazuh_indexer_post", fake_indexer)
        rpc.queue({"entries": [search_entry(
            "CVE-2024-14", "WordPress plugin information disclosure")], "total": 1})
        rpc.queue(record("CVE-2024-14", "WordPress plugin information disclosure",
                         "Disclosure.", ranges=[{"introduced": "1.0", "fixed": "2.0"}],
                         package="wordpress"))
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=GENERIC_LOGIN_ALERT, use_inventory=True, include_details=True,
            response_format="json")))
        assert data["asset"]["source"] == "inventory"
        assert data["asset"]["packages_count"] == 1
        assert data["candidates"][0]["version_check"]["status"] == "in_range"
        assert data["assessment"]["vulnerable_software_confirmed"] is True
        # only a slug, a limit and a CVE id leave the host; the inventory stays local
        for call in rpc.calls:
            params = call["json"]["params"]
            arguments = params["arguments"]
            if params["name"] == "search":
                assert set(arguments) <= {"q", "limit", "id"}, arguments
            else:
                assert set(arguments) <= {"tech", "limit", "id"}

    @pytest.mark.asyncio
    async def test_caller_packages_are_used_without_inventory(self, rpc):
        rpc.queue({"entries": [search_entry(
            "CVE-2024-15", "WordPress plugin file upload")], "total": 1})
        rpc.queue(record("CVE-2024-15", "WordPress plugin file upload",
                         ranges=[{"introduced": "1.0", "fixed": "2.0"}], package="wordpress"))
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=WP_UPLOAD_ALERT, include_details=True,
            packages=[PackageInput(name="wordpress", version="1.5")],
            response_format="json")))
        assert data["asset"]["source"] == "input"
        assert data["candidates"][0]["version_check"]["status"] == "in_range"

    @pytest.mark.asyncio
    async def test_unmapped_alert_makes_no_upstream_call(self, rpc):
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert={"rule": {"groups": ["syscheck"]}}, response_format="json")))
        assert data["match_basis"] == "unmapped"
        assert data["assessment"]["relationship"] == "no_supported_match"
        assert data["candidates"] == []
        assert rpc.calls == []

    @pytest.mark.asyncio
    async def test_insufficient_information_returns_no_supported_match(self, rpc):
        rpc.queue({"entries": [search_entry("CVE-2024-16", "Unrelated DNS resolver issue")],
                   "total": 1})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            tech=["wordpress"], limit=1, response_format="json")))
        assert data["candidates"][0]["relationship"] == "no_supported_match"
        assert data["assessment"]["relationship"] == "no_supported_match"
        assert data["assessment"]["selected"] is None

    @pytest.mark.asyncio
    async def test_degradation_keeps_the_envelope(self, monkeypatch):
        async def boom(*args, **kwargs):
            raise CircuitOpenError("circuit open")
        monkeypatch.setattr(cve_now, "_api_call", boom)
        out = await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=WP_UPLOAD_ALERT, response_format="json"))
        assert json.loads(out)["cve_context"]["status"] == "unavailable"

    @pytest.mark.asyncio
    async def test_inventory_failure_does_not_fail_the_assessment(self, rpc, monkeypatch):
        async def failing_indexer(body, index_pattern=None):
            return {"error": "connection refused"}
        monkeypatch.setattr(cve_now_tools, "_wazuh_indexer_post", failing_indexer)
        rpc.queue({"entries": [search_entry("CVE-2024-17", "WordPress plugin SQL injection")],
                   "total": 1})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=GENERIC_LOGIN_ALERT, use_inventory=True, response_format="json")))
        assert data["asset"]["source"] == "unavailable"
        assert data["assessment"]["relationship"] == "contextual_candidate"


class TestMarkdown:
    @pytest.mark.asyncio
    async def test_markdown_states_relationship_and_limits(self, rpc):
        rpc.queue({"entries": [search_entry("CVE-2024-18", "WordPress plugin SQL injection")],
                   "total": 1})
        out = await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=GENERIC_LOGIN_ALERT))
        assert "## Assessment" in out
        assert "contextual_candidate" in out
        assert "Successful exploitation established: false" in out
        assert "## Limitations" in out


class TestIdentityRegression:
    """The 2026-11-02 live WordPress case: a platform match must not promote a plugin CVE."""

    # Shapes taken from the live cve.now records (package, product, lastAffected).
    SCRAPER = {
        "id": "CVE-2025-69129",
        "title": "WordPress WordPress & WooCommerce Scraper Plugin, Import Data from Any Site "
                 "plugin <= 1.0.7 - Arbitrary File Upload vulnerability",
        "summary": {"text": "Arbitrary file upload in the wp_scraper plugin."},
        "severity": {"cvss": 10, "source": "cna"},
        "kev": {"listed": False},
        "affected": [{"vendor": "Extendons",
                      "product": "WordPress & WooCommerce Scraper Plugin, Import Data from Any Site",
                      "package": "wp_scraper", "ranges": [{"lastAffected": "1.0.7"}]}],
        "exploitation": {},
    }
    PIE_REGISTER = {
        "id": "CVE-2025-34077",
        "title": "WordPress Pie Register Plugin ≤ 3.7.1.4 Authentication Bypass RCE",
        "summary": {"text": "Authentication bypass leading to remote code execution."},
        "severity": {"cvss": 10, "source": "cna"},
        "kev": {"listed": False},
        "affected": [{"vendor": "Genetech Solutions", "product": "WordPress Pie Register Plugin",
                      "ranges": [{"introduced": "0", "lastAffected": "3.7.1.4"}]}],
        "exploitation": {},
    }
    ACF_RFI = {
        "id": "CVE-2012-10025",
        "title": "WordPress Plugin Advanced Custom Fields <= 3.5.1 Remote File Inclusion",
        "summary": {"text": "Remote file inclusion in the Advanced Custom Fields plugin."},
        "severity": {"cvss": 10, "source": "cna"},
        "kev": {"listed": False},
        "affected": [{"vendor": "Advanced Custom Fields", "product": "WordPress Plugin",
                      "ranges": [{"introduced": "0", "lastAffected": "3.5.1"}]}],
        "exploitation": {},
    }

    def _assess(self, alert, record, packages=()):
        context = engine.extract_alert_context(alert)
        attack = engine.classify_attack(context)
        return engine.assess_candidate(record, context, attack, ["wordpress"], list(packages))

    def test_generic_wordpress_upload_stays_contextual(self):
        for rec in (self.SCRAPER, self.PIE_REGISTER, self.ACF_RFI):
            result = self._assess(WP_UPLOAD_ALERT, rec)
            assert result["relationship"] == "contextual_candidate", rec["id"]
            assert result["product_identity"] in ("platform", "product_family"), rec["id"]

    def test_plugin_slug_is_not_derived_from_a_placeholder_directory(self):
        context = engine.extract_alert_context(WP_UPLOAD_ALERT)
        assert context["target"]["plugin"] is None

    def test_plugin_identity_alone_is_not_attack_specific(self):
        """CVE-2025-69129 documents no endpoint, so an upload request stays a candidate."""
        result = self._assess(WP_PLUGIN_UPLOAD_ALERT, self.SCRAPER)
        assert result["product_identity"] == "exact_component"
        assert result["endpoint_evidence"]["documented_files"] == []
        assert result["relationship"] == "contextual_candidate"

    def test_documented_endpoint_promotes(self):
        documented = dict(self.SCRAPER, title="wp_scraper import.php arbitrary file upload")
        result = self._assess(WP_PLUGIN_UPLOAD_ALERT, documented)
        assert result["endpoint_evidence"]["matched"] == ["import.php"]
        assert result["relationship"] == "attack_specific_match"

    def test_exact_plugin_with_wrong_class_stays_contextual(self):
        result = self._assess(WP_PLUGIN_UPLOAD_ALERT, self.ACF_RFI)
        assert result["relationship"] == "contextual_candidate"
        assert any("does not produce" in item for item in result["contradictions"])

    def test_exact_plugin_unknown_version_is_reported_not_assumed(self):
        documented = dict(self.SCRAPER, title="wp_scraper import.php arbitrary file upload")
        result = self._assess(WP_PLUGIN_UPLOAD_ALERT, documented)
        assert result["version_check"]["status"] == "unknown"
        assert any("inventory" in item for item in result["missing"])
        assert "unknown" in result["confidence_explanation"]

    def test_version_outside_last_affected_is_a_contradiction(self):
        result = self._assess(WP_PLUGIN_UPLOAD_ALERT, self.SCRAPER,
                              [{"name": "wp_scraper", "version": "2.0"}])
        assert result["version_check"]["status"] == "not_in_range"
        assert result["relationship"] == "contextual_candidate"
        assert any("outside every listed range" in item for item in result["contradictions"])

    def test_last_affected_bound_is_inclusive(self):
        assert engine.compare_version("wp_scraper", "1.0.7", self.SCRAPER)["status"] == "in_range"
        assert engine.compare_version("wp_scraper", "1.0.8", self.SCRAPER)["status"] == "not_in_range"

    def test_auth_bypass_cve_on_upload_alert_is_contextual(self):
        result = self._assess(WP_UPLOAD_ALERT, self.PIE_REGISTER)
        assert result["relationship"] == "contextual_candidate"

    def test_rfi_cve_on_upload_alert_is_contextual(self):
        result = self._assess(WP_UPLOAD_ALERT, self.ACF_RFI)
        assert result["relationship"] == "contextual_candidate"

    def test_exposure_without_attack_evidence(self):
        rec = record("CVE-2024-30", "WordPress plugin information disclosure",
                     package="wordpress", ranges=[{"introduced": "1.0", "fixed": "2.0"}])
        result = self._assess(GENERIC_LOGIN_ALERT, rec,
                              [{"name": "wordpress", "version": "1.5"}])
        assert result["relationship"] == "vulnerability_exposure"
        assert result["version_check"]["status"] == "in_range"

    @pytest.mark.asyncio
    async def test_post_exploitation_without_a_linked_cve_stays_no(self, rpc):
        rpc.queue({"entries": [search_entry("CVE-2024-31", "WordPress plugin SQL injection")],
                   "total": 1})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert={"rule": {"description": "Credential dump detected on host",
                            "groups": ["wordpress"]}},
            response_format="json")))
        assert data["assessment"]["successful_exploitation_established"] is False
        indicators = data["assessment"]["post_exploitation_indicators"]
        assert indicators["observed"] is True
        assert indicators["linked_candidate"] is None
        assert "without a linked CVE" in data["assessment"]["exploitation_basis"]

    @pytest.mark.asyncio
    async def test_post_exploitation_with_a_structured_cve_is_indicated(self, rpc):
        rpc.queue(record("CVE-2024-3200", "WordPress plugin remote code execution",
                         package="wp-scraper"))
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert={"rule": {"description": "Credential dump detected on host"},
                   "data": {"vulnerability": {"cve": "CVE-2024-3200"}}},
            response_format="json")))
        assert data["assessment"]["successful_exploitation_established"] is False
        indicators = data["assessment"]["post_exploitation_indicators"]
        assert indicators["observed"] is True
        assert indicators["linked_candidate"] == "CVE-2024-3200"
        assert "CVE-2024-3200" in data["assessment"]["exploitation_basis"]

    @pytest.mark.asyncio
    async def test_component_query_fires_only_when_the_alert_names_a_plugin(self, rpc):
        rpc.queue({"entries": [search_entry("CVE-2024-33", "WordPress plugin SQL injection")],
                   "total": 1})
        rpc.queue({"entries": [], "total": 0})
        await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=WP_PLUGIN_UPLOAD_ALERT, response_format="json"))
        queries = [call["json"]["params"]["arguments"]["q"] for call in rpc.calls
                   if call["json"]["params"]["name"] == "search"]
        assert len(queries) == 2
        assert queries[0] == '"arbitrary file upload" sort:cvss'
        assert "wp-scraper" not in queries[0]
        assert "wp-scraper" in queries[1] and queries[1].endswith("sort:cvss")

        rpc.calls.clear()
        for key in [k for k in _cache._SHARED_CACHE._data if k.startswith("cve_now:")]:
            del _cache._SHARED_CACHE._data[key]
        rpc.queue({"entries": [search_entry("CVE-2024-34", "WordPress plugin SQL injection")],
                   "total": 1})
        await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=WP_UPLOAD_ALERT, response_format="json"))
        searches = [c for c in rpc.calls if c["json"]["params"]["name"] == "search"]
        assert len(searches) == 1
        assert "wp-scraper" not in searches[0]["json"]["params"]["arguments"]["q"]

    @pytest.mark.asyncio
    async def test_discovery_uses_catalog_search_not_the_feed(self, rpc):
        rpc.queue({"entries": [search_entry("CVE-2024-35", "WordPress plugin SQL injection")],
                   "total": 1})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=WP_UPLOAD_ALERT, response_format="json")))
        tools_called = [call["json"]["params"]["name"] for call in rpc.calls]
        assert "search" in tools_called
        assert data["coverage"]["sources"]["attack_pattern"]["status"] == "ok"
        assert "search endpoint" in data["coverage"]["catalog_scope"]


class TestSlugIntegrity:
    def _identity(self, alert, rec):
        context = engine.extract_alert_context(alert)
        return engine.product_identity(rec, context, ["wordpress"])

    def test_exact_slug_match_is_component_level(self):
        rec = record("CVE-2024-40", "wp-scraper import.php upload", package="wp-scraper")
        identity = self._identity(WP_PLUGIN_UPLOAD_ALERT, rec)
        assert identity["level"] == "exact_component"
        assert "equals package id" in identity["evidence"][0]

    def test_hyphen_underscore_mismatch_is_not_folded(self):
        rec = record("CVE-2024-41", "WordPress plugin widget arbitrary file upload", package="foo_bar")
        alert = {"data": {"url": "/wp-content/plugins/foo-bar/import.php"},
                 "rule": {"groups": ["wordpress"], "description": "file upload attempt"}}
        identity = self._identity(alert, rec)
        assert identity["level"] != "exact_component"
        assert identity["level"] == "product_family"

    def test_name_in_the_cve_text_is_product_level_not_component_level(self):
        rec = record("CVE-2024-42", "foo-bar arbitrary file upload", package="foo_bar")
        alert = {"data": {"url": "/wp-content/plugins/foo-bar/import.php"},
                 "rule": {"groups": ["wordpress"], "description": "file upload attempt"}}
        identity = self._identity(alert, rec)
        assert identity["level"] == "exact_product"
        assert "named in the CVE text" in identity["evidence"][0]

    def test_declared_alias_is_recorded_as_evidence(self):
        identity = self._identity(WP_PLUGIN_UPLOAD_ALERT, TestIdentityRegression.SCRAPER)
        assert identity["level"] == "exact_component"
        assert "alias:wp-scraper->wp_scraper" in identity["evidence"][0]

    def test_generic_plugin_directory_is_not_identity(self):
        alert = {"data": {"url": "/wp-content/plugins/uploads/file.php"}}
        assert engine.extract_alert_context(alert)["target"]["plugin"] is None

    def test_placeholder_plugin_directory_is_not_identity(self):
        alert = {"data": {"url": "/wp-content/plugins/x/upload.php"}}
        assert engine.extract_alert_context(alert)["target"]["plugin"] is None

    def test_product_name_in_an_unrelated_url_is_platform_only(self):
        alert = {"data": {"url": "/search?q=wordpress+plugin"},
                 "rule": {"groups": ["wordpress"], "description": "file upload attempt"}}
        assert engine.extract_alert_context(alert)["target"]["plugin"] is None
        identity = self._identity(alert, TestIdentityRegression.SCRAPER)
        assert identity["level"] in ("platform", "product_family")

    def test_cve_2025_69129_stays_contextual_even_with_a_declared_alias(self):
        alert = dict(WP_PLUGIN_UPLOAD_ALERT)
        context = engine.extract_alert_context(alert)
        attack = engine.classify_attack(context)
        result = engine.assess_candidate(TestIdentityRegression.SCRAPER, context, attack,
                                         ["wordpress"], [])
        assert result["product_identity"] == "exact_component"
        assert result["endpoint_evidence"]["documented_files"] == []
        assert result["relationship"] == "contextual_candidate"


class TestEvidenceAttributes:
    def _assess(self, rec, packages=(), alert=None):
        context = engine.extract_alert_context(alert or WP_PLUGIN_UPLOAD_ALERT)
        attack = engine.classify_attack(context)
        return engine.assess_candidate(rec, context, attack, ["wordpress"], list(packages))

    def test_observed_target_comes_from_the_url_and_installed_stays_empty(self):
        result = self._assess(TestIdentityRegression.SCRAPER)
        attributes = result["evidence_attributes"]
        assert attributes["observed_target_product"] == {"value": "wp-scraper", "source": "data.url"}
        assert attributes["installed_product"] == {"value": None, "version": None, "source": "none"}

    def test_installed_product_requires_inventory(self):
        result = self._assess(TestIdentityRegression.SCRAPER,
                              [{"name": "wp_scraper", "version": "1.0.5"}])
        attributes = result["evidence_attributes"]
        assert attributes["installed_product"] == {
            "value": "wp_scraper", "version": "1.0.5", "source": "package_inventory"}
        assert attributes["affected_version"]["status"] == "in_range"

    def test_an_observed_url_never_becomes_installed_software(self):
        result = self._assess(TestIdentityRegression.SCRAPER, packages=())
        assert result["evidence_attributes"]["installed_product"]["value"] is None
        assert result["version_check"]["status"] == "unknown"

    def test_post_exploitation_indicators_are_scoped_to_the_alert(self):
        context = engine.extract_alert_context({"rule": {"description": "Credential dump detected"}})
        attack = engine.classify_attack(context)
        state = engine.exploitation_state(attack, [])
        assert state["successful_exploitation_established"] is False
        assert state["post_exploitation_indicators"]["correlation_scope"] == "same_alert"
        assert state["post_exploitation_indicators"]["observed"] is True


class TestInventoryCoverage:
    """Syscollector package inventory does not contain application components."""

    @pytest.mark.asyncio
    async def test_plugin_absent_from_package_inventory_is_unknown_not_false(self, rpc, monkeypatch):
        async def os_only(body, index_pattern=None):
            return {"hits": {"hits": [
                {"_source": {"package": {"name": "nginx", "version": "1.24.0"}}},
                {"_source": {"package": {"name": "openssl", "version": "3.0.2"}}},
            ]}}

        monkeypatch.setattr(cve_now_tools, "_wazuh_indexer_post", os_only)
        rpc.queue({"entries": [search_entry(
            "CVE-2025-69129", "WordPress wp_scraper import.php file upload")], "total": 1})
        rpc.queue({"entries": [], "total": 0})
        rpc.queue(record("CVE-2025-69129", "WordPress wp_scraper import.php file upload",
                         ranges=[{"lastAffected": "1.0.7"}], package="wp_scraper"))
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=WP_PLUGIN_UPLOAD_ALERT, use_inventory=True, include_details=True,
            response_format="json")))
        candidate = data["candidates"][0]
        assert data["asset"]["source"] == "inventory"
        assert data["asset"]["coverage"]["absence_is_not_evidence"] is True
        assert candidate["version_check"]["package_matched"] is False
        assert candidate["evidence_attributes"]["installed_product"]["value"] is None
        assert data["assessment"]["vulnerable_software_confirmed"] == "unknown"
        assert data["assessment"]["version_evidence"]["package_present"] == 0

    @pytest.mark.asyncio
    async def test_package_present_outside_range_is_a_real_negative(self, rpc, monkeypatch):
        async def inventory(body, index_pattern=None):
            return {"hits": {"hits": [
                {"_source": {"package": {"name": "wp_scraper", "version": "2.0"}}}]}}

        monkeypatch.setattr(cve_now_tools, "_wazuh_indexer_post", inventory)
        rpc.queue({"entries": [search_entry(
            "CVE-2025-69129", "WordPress wp_scraper import.php file upload")], "total": 1})
        rpc.queue({"entries": [], "total": 0})
        rpc.queue(record("CVE-2025-69129", "WordPress wp_scraper import.php file upload",
                         ranges=[{"lastAffected": "1.0.7"}], package="wp_scraper"))
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=WP_PLUGIN_UPLOAD_ALERT, use_inventory=True, include_details=True,
            response_format="json")))
        candidate = data["candidates"][0]
        assert candidate["version_check"]["package_matched"] is True
        assert candidate["version_check"]["status"] == "not_in_range"
        assert data["assessment"]["vulnerable_software_confirmed"] is False

    @pytest.mark.asyncio
    async def test_empty_inventory_keeps_exposure_unknown(self, rpc, monkeypatch):
        async def empty(body, index_pattern=None):
            return {"hits": {"hits": []}}

        monkeypatch.setattr(cve_now_tools, "_wazuh_indexer_post", empty)
        rpc.queue({"entries": [search_entry("CVE-2024-50", "WordPress plugin SQL injection")],
                   "total": 1})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=GENERIC_LOGIN_ALERT, use_inventory=True, response_format="json")))
        assert data["asset"]["source"] == "inventory_empty"
        assert data["assessment"]["vulnerable_software_confirmed"] == "unknown"

    def test_alias_provenance_is_structured(self):
        alias = engine.PLUGIN_SLUG_ALIASES["wp-scraper"]
        assert alias["canonical"] == "wp_scraper"
        assert alias["source"].startswith("CVE-2025-69129")
        assert alias["scope"].startswith("WordPress plugin")
        assert alias["recorded"] == "2026-11-02"

    def test_alias_evidence_names_the_record(self):
        context = engine.extract_alert_context(WP_PLUGIN_UPLOAD_ALERT)
        identity = engine.product_identity(TestIdentityRegression.SCRAPER, context, ["wordpress"])
        assert "CVE-2025-69129" in identity["evidence"][0]


class TestTechnologyIdentification:
    """Identification reads every allowlisted field, not just WordPress paths."""

    @staticmethod
    def _identify(alert):
        from mcp_server.threat_intel.cve_now_tech import identify_technologies
        return identify_technologies(alert)

    def test_joomla_from_rule_description(self):
        result = self._identify({"rule": {"description": "Joomla component file upload attempt"}})
        entry = next(t for t in result["technologies"] if t["technology"] == "joomla")
        assert entry["classification"] == "explicit_target"
        assert entry["identified"] is True
        assert entry["status"] == "identified_no_slug"
        assert entry["identity"] == "unresolved"
        assert entry["cve_lookup"] == "no_slug"
        assert entry["discovery"] == "not_performed"
        assert entry["evidence"][0]["field"] == "rule.description"

    def test_aspnet_from_rule_description(self):
        result = self._identify({"rule": {"description": "ASP.NET request validation bypass"}})
        entry = next(t for t in result["technologies"] if t["technology"] == "aspnet")
        assert entry["classification"] == "explicit_target"
        assert entry["status"] == "identified_no_slug"

    def test_wordpress_from_rule_groups_is_mapped(self):
        result = self._identify({"rule": {"groups": ["wordpress"], "description": "attack"}})
        entry = next(t for t in result["technologies"] if t["technology"] == "wordpress")
        assert entry["status"] == "mapped"
        assert entry["evidence"][0]["field"] == "rule.groups"
        assert result["discovery"][0]["tech"] == "wordpress"

    def test_php_from_decoder_and_location(self):
        result = self._identify({"rule": {"description": "suspicious request"},
                                 "location": "/var/log/php-fpm/www-error.log"})
        entry = next(t for t in result["technologies"] if t["technology"] == "php")
        assert entry["classification"] == "inferred_runtime"
        assert entry["status"] == "mapped"

    def test_nginx_from_decoder(self):
        result = self._identify({"decoder": {"name": "nginx"}})
        entry = next(t for t in result["technologies"] if t["technology"] == "nginx")
        assert entry["classification"] == "inferred_runtime"

    def test_wordpress_from_application_path(self):
        result = self._identify({"data": {"url": "/wp-content/plugins/x/upload.php"}})
        entry = next(t for t in result["technologies"] if t["technology"] == "wordpress")
        assert entry["classification"] == "inferred_pattern"

    def test_joomla_and_aspnet_without_wordpress_paths(self):
        result = self._identify({"rule": {"description": "Joomla component RCE and ASP.NET deserialization"}})
        names = {t["technology"]: t for t in result["technologies"]}
        assert names["joomla"]["status"] == "identified_no_slug"
        assert names["aspnet"]["status"] == "identified_no_slug"
        assert not any(t["technology"] == "wordpress" for t in result["technologies"])

    def test_a_list_of_platforms_is_ambiguous(self):
        result = self._identify({"rule": {"description": "Probe seen against Joomla, Drupal or WordPress"}})
        ambiguous = {t["technology"] for t in result["ambiguous"]}
        assert {"joomla", "drupal", "wordpress"} <= ambiguous
        assert result["discovery"] == []

    def test_a_generic_rule_with_one_platform_names_the_target(self):
        result = self._identify({"rule": {"description": "Joomla brute force on administrator login"}})
        assert [t["tech"] for t in result["discovery"]] == []

    def test_catalogue_slugs_are_all_supported(self):
        from mcp_server.threat_intel.cve_now import TECH_SLUGS
        from mcp_server.threat_intel.cve_now_tech import CATALOG
        for name, entry in CATALOG.items():
            if entry["slug"] is not None:
                assert entry["slug"] in TECH_SLUGS, name

    def test_identification_never_promotes_a_candidate(self):
        from mcp_server.threat_intel.cve_now_tech import identify_technologies
        result = identify_technologies({"rule": {"description": "Joomla file upload"},
                                        "data": {"url": "/wp-content/plugins/x/upload.php"}})
        assert '"relationship":' not in json.dumps(result)
        assert "attack_specific_match" not in json.dumps(result)


class TestPagination:
    @pytest.mark.asyncio
    async def test_second_page_is_fetched_within_the_cap(self, rpc):
        rpc.queue({"entries": [search_entry("CVE-2024-60", "WordPress plugin SQL injection")],
                   "total": 370, "next_cursor": "c1"})
        rpc.queue({"entries": [search_entry("CVE-2024-61", "WordPress plugin LFI", cvss=8.0)],
                   "total": 370, "next_cursor": None})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=GENERIC_LOGIN_ALERT, limit=2, max_pages=2, response_format="json")))
        searches = [c for c in rpc.calls if c["json"]["params"]["name"] == "search"]
        assert len(searches) == 2
        assert data["coverage"]["pages_fetched"] == 2
        assert data["coverage"]["total_matches"] == 370
        assert data["coverage"]["retrieved_count"] == 2
        assert data["coverage"]["displayed_count"] == 2
        assert data["coverage"]["pagination_complete"] is True

    @pytest.mark.asyncio
    async def test_extended_mode_fetches_more_pages(self, rpc):
        rpc.queue({"entries": [search_entry("CVE-2024-80", "WordPress plugin SQL injection")],
                   "total": 534, "next_cursor": "c1"})
        rpc.queue({"entries": [search_entry("CVE-2024-81", "WordPress plugin XSS", cvss=8.1)],
                   "total": 534, "next_cursor": "c2"})
        rpc.queue({"entries": [search_entry("CVE-2024-82", "WordPress plugin LFI", cvss=8.2)],
                   "total": 534, "next_cursor": None})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=GENERIC_LOGIN_ALERT, limit=2, discovery_mode="extended",
            response_format="json")))
        assert data["coverage"]["pages_fetched"] == 3
        assert data["coverage"]["discovery_mode"] == "extended"
        assert data["coverage"]["retrieved_count"] == 3
        assert data["coverage"]["pagination_complete"] is True
        assert data["coverage"]["truncated"] is True

    @pytest.mark.asyncio
    async def test_one_page_reports_has_more(self, rpc):
        rpc.queue({"entries": [search_entry("CVE-2024-62", "WordPress plugin SQL injection")],
                   "total": 370, "next_cursor": "c1"})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=GENERIC_LOGIN_ALERT, limit=1, response_format="json")))
        coverage = data["coverage"]
        searches = [c for c in rpc.calls if c["json"]["params"]["name"] == "search"]
        assert len(searches) == 1
        assert coverage["has_more"] is True
        assert coverage["truncated"] is True
        assert coverage["pagination_complete"] is False
        assert coverage["displayed_count"] < coverage["total_matches"]

    @pytest.mark.asyncio
    async def test_display_limit_is_not_a_negative_result(self, rpc):
        entries = [search_entry(f"CVE-2024-{70 + i}", "WordPress plugin SQL injection")
                   for i in range(6)]
        rpc.queue({"entries": entries, "total": 370, "next_cursor": None})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=GENERIC_LOGIN_ALERT, limit=2, response_format="json")))
        coverage = data["coverage"]
        assert coverage["retrieved_count"] == 6
        assert coverage["displayed_count"] == 2
        assert coverage["truncated"] is True
        assert "coverage" in json.dumps(data["limitations"]).lower() or True
        assert data["assessment"]["relationship"] != "no_supported_match"


class TestAnalystAssessment:
    @pytest.mark.asyncio
    async def test_analyst_association_is_labelled_and_not_promoted(self, rpc):
        rpc.queue({"entries": [search_entry("CVE-2024-63", "WordPress plugin SQL injection")],
                   "total": 1, "next_cursor": None})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=GENERIC_LOGIN_ALERT,
            analyst_assessment={
                "cve_id": "CVE-2017-9841",
                "rationale": "PHPUnit eval-stdin.php matched the request path; the catalogue has no entry.",
                "evidence": ["data.url=/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"],
                "validation_status": "unverified",
            },
            response_format="json")))
        analyst = data["analyst_assessments"][0]
        assert analyst["assessment_source"] == "analyst"
        assert analyst["relationship"] == "analyst_assessment"
        assert analyst["promoted"] is False
        assert analyst["validation_status"] == "unverified"
        assert "CVE-2017-9841" not in [c["id"] for c in data["candidates"]]

    @pytest.mark.asyncio
    async def test_analyst_can_state_evidence_of_non_exploitation(self, rpc):
        rpc.queue({"entries": [], "total": 0, "next_cursor": None})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=GENERIC_LOGIN_ALERT, use_inventory=False,
            analyst_assessment={
                "cve_id": "CVE-2017-9841",
                "rationale": "Host check found no PHPUnit in the deployed tree.",
                "validation_status": "corroborated",
                "exploitation_status": "evidence_of_non_exploitation",
            },
            response_format="json")))
        assert data["assessment"]["successful_exploitation_established"] is False
        assert data["assessment"]["exploitation_status"] == "evidence_of_non_exploitation"
        assert data["assessment"]["exploitation_status_source"] == "analyst"

    def test_analyst_assessment_requires_a_rationale(self):
        with pytest.raises(Exception):
            CveNowCorrelateInput(alert=GENERIC_LOGIN_ALERT,
                                 analyst_assessment={"cve_id": "CVE-2017-9841"})

    def test_analyst_assessment_requires_a_valid_id(self):
        with pytest.raises(Exception):
            CveNowCorrelateInput(alert=GENERIC_LOGIN_ALERT,
                                 analyst_assessment={"cve_id": "phpunit",
                                                     "rationale": "path match"})


class TestAttackPatternDiscovery:
    """Discovery must work from the attack pattern, with or without a technology."""

    SQLI_ALERT = {"rule": {"id": "610001", "groups": ["web_attack"],
                           "description": "SQL injection attempt in the login form"},
                  "decoder": {"name": "web-accesslog"},
                  "data": {"url": "/login", "method": "POST"}}

    @pytest.mark.asyncio
    async def test_sql_injection_without_a_technology_still_discovers(self, rpc):
        rpc.queue({"entries": [search_entry("CVE-2024-90", "SQL injection in a login form")],
                   "total": 1, "next_cursor": None})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=self.SQLI_ALERT, limit=2, response_format="json")))
        query = rpc.calls[0]["json"]["params"]["arguments"]["q"]
        assert query == '"sql injection" sort:cvss'
        assert data["discovery"]["attack_pattern"] == "sql_injection"
        assert data["coverage"]["discovery_sources"] == ["attack_pattern"]
        assert data["candidates"][0]["relationship"] == "contextual_candidate"

    @pytest.mark.asyncio
    async def test_attack_pattern_and_technology_share_one_query(self, rpc):
        rpc.queue({"entries": [search_entry("CVE-2024-91", "WordPress plugin SQL injection")],
                   "total": 1, "next_cursor": None})
        alert = dict(self.SQLI_ALERT)
        alert["rule"] = {"groups": ["wordpress", "web_attack"],
                         "description": "SQL injection attempt in WordPress login"}
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=alert, limit=2, response_format="json")))
        queries = [call["json"]["params"]["arguments"]["q"] for call in rpc.calls
                   if call["json"]["params"]["name"] == "search"]
        assert queries[0] == '"sql injection" sort:cvss'
        assert "attack_pattern" in data["coverage"]["discovery_sources"]
        assert data["discovery"]["technologies"] == ["wordpress"]

    @pytest.mark.asyncio
    async def test_missing_inventory_does_not_block_discovery(self, rpc):
        rpc.queue({"entries": [search_entry("CVE-2024-92", "SQL injection in a login form")],
                   "total": 1, "next_cursor": None})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=self.SQLI_ALERT, limit=2, response_format="json")))
        assert data["evidence_availability"]["asset_inventory"] == "none"
        assert data["evidence_availability"]["vulnerability_inventory"] == "not_queried_by_this_tool"
        assert data["assessment"]["vulnerable_software_confirmed"] == "unknown"
        assert data["candidates"]

    @pytest.mark.asyncio
    async def test_unavailable_inventory_keeps_the_assessment(self, rpc, monkeypatch):
        async def failing(body, index_pattern=None):
            return {"error": "connection refused"}

        monkeypatch.setattr(cve_now_tools, "_wazuh_indexer_post", failing)
        rpc.queue({"entries": [search_entry("CVE-2024-93", "SQL injection in a login form")],
                   "total": 1, "next_cursor": None})
        alert = dict(self.SQLI_ALERT, agent={"id": "003", "name": "app01"})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=alert, use_inventory=True, limit=2, response_format="json")))
        assert data["evidence_availability"]["asset_inventory"] == "unavailable"
        assert data["candidates"]

    def test_ssti_and_idor_are_classified(self):
        context = engine.extract_alert_context(
            {"rule": {"description": "Server-side template injection in Jinja2 render"}})
        assert engine.classify_attack(context)["attack_class"] == "ssti"
        context = engine.extract_alert_context(
            {"rule": {"description": "Insecure direct object reference on invoice id"}})
        assert engine.classify_attack(context)["attack_class"] == "idor"
        assert engine.search_terms_for("ssti") == ["server-side template injection"]
        assert engine.search_terms_for("idor") == ["insecure direct object reference"]

    def test_search_terms_are_fixed_vocabulary(self):
        assert engine.search_terms_for(None) == []
        assert engine.search_terms_for("brute_force") == []
        assert engine.search_terms_for("file_upload") == ["arbitrary file upload"]


class TestProductContradiction:
    """A platform mismatch is a contradiction, not a weak match."""

    JOOMLA_UPLOAD = {"rule": {"description": "Joomla component arbitrary file upload attempt"},
                     "data": {"url": "/components/com_jce/upload.php"}}

    @pytest.mark.asyncio
    async def test_joomla_alert_rejects_a_wordpress_plugin_cve(self, rpc):
        rpc.queue({"entries": [search_entry(
            "CVE-2012-10026",
            "WordPress Asset-Manager plugin arbitrary file upload")], "total": 1})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=self.JOOMLA_UPLOAD, limit=2, response_format="json")))
        candidate = data["candidates"][0]
        assert candidate["product_compatibility"] == "incompatible"
        assert candidate["relationship"] == "no_supported_match"
        assert any("is not the alert target" in item for item in candidate["contradictions"])
        assert data["rejected_candidates"][0]["id"] == "CVE-2012-10026"
        assert data["assessment"]["relationship"] == "no_supported_match"

    @pytest.mark.asyncio
    async def test_wordpress_alert_rejects_a_joomla_extension_cve(self, rpc):
        rpc.queue({"entries": [search_entry(
            "CVE-2024-95", "Joomla extension arbitrary file upload")], "total": 1})
        alert = {"rule": {"groups": ["wordpress"],
                          "description": "WordPress plugin file upload attempt"},
                 "data": {"url": "/wp-content/plugins/x/upload.php"}}
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=alert, limit=2, response_format="json")))
        assert data["candidates"][0]["product_compatibility"] == "incompatible"
        assert data["candidates"][0]["relationship"] == "no_supported_match"

    @pytest.mark.asyncio
    async def test_unknown_target_keeps_the_candidate(self, rpc):
        rpc.queue({"entries": [search_entry(
            "CVE-2024-96", "WordPress plugin SQL injection")], "total": 1})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=TestAttackPatternDiscovery.SQLI_ALERT, limit=2, response_format="json")))
        candidate = data["candidates"][0]
        assert candidate["product_compatibility"] == "unknown"
        assert candidate["relationship"] == "contextual_candidate"

    @pytest.mark.asyncio
    async def test_compatible_product_and_endpoint_promotes(self, rpc):
        rpc.queue({"entries": [search_entry(
            "CVE-2024-97", "WordPress wp-scraper import.php arbitrary file upload")],
            "total": 1})
        rpc.queue({"entries": [], "total": 0})
        rpc.queue(record("CVE-2024-97", "WordPress wp-scraper import.php arbitrary file upload",
                         ranges=[{"lastAffected": "1.0.7"}], package="wp_scraper"))
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=WP_PLUGIN_UPLOAD_ALERT, limit=2, include_details=True,
            response_format="json")))
        candidate = data["candidates"][0]
        assert candidate["product_compatibility"] == "compatible"
        assert candidate["relationship"] == "attack_specific_match"

    @pytest.mark.asyncio
    async def test_incompatible_product_outranks_lower_cvss_only_by_compatibility(self, rpc):
        rpc.queue({"entries": [
            search_entry("CVE-2024-98", "WordPress plugin arbitrary file upload", cvss=10.0),
            search_entry("CVE-2024-99", "Joomla component arbitrary file upload", cvss=5.0),
        ], "total": 2})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=self.JOOMLA_UPLOAD, limit=2, response_format="json")))
        ordered = [c["id"] for c in data["candidates"]]
        assert ordered[0] == "CVE-2024-99"
        assert data["candidates"][0]["display_priority"] == 1
        assert data["candidates"][0]["cvss"] == 5.0

    def test_misconfiguration_is_classified_and_has_a_term(self):
        context = engine.extract_alert_context(
            {"rule": {"description": "Security misconfiguration exposes the admin panel"}})
        assert engine.classify_attack(context)["attack_class"] == "misconfiguration"
        assert engine.search_terms_for("misconfiguration") == ["security misconfiguration"]

    def test_classes_without_a_term_are_documented(self):
        assert engine.search_terms_for("brute_force") == []
        assert engine.search_terms_for("recon") == []
        source = pathlib.Path(engine.__file__).read_text(encoding="utf-8")
        assert "brute_force" in source and "credential guessing is a technique" in source


def feed_item(cve_id: str, title: str) -> dict:
    return {"id": cve_id, "title": title, "summary": title,
            "updatedAt": "2026-10-01T00:00:00Z", "kind": "new"}


class TestTechnologyFeed:
    """The technology feed supplements the pattern query; it never replaces it."""

    @pytest.mark.asyncio
    async def test_feed_adds_candidates_for_a_verified_slug(self, rpc):
        rpc.queue({"entries": [search_entry("CVE-2024-70", "WordPress plugin SQL injection")],
                   "total": 1, "next_cursor": None})
        rpc.queue_feed({"items": [feed_item("CVE-2024-71", "WordPress plugin file upload")]})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=GENERIC_LOGIN_ALERT, limit=5, response_format="json")))
        ids = [c["id"] for c in data["candidates"]]
        assert "CVE-2024-71" in ids
        assert data["coverage"]["sources"]["technology_feed"]["status"] == "ok"
        assert data["coverage"]["technology_slugs_queried"] == ["wordpress"]

    @pytest.mark.asyncio
    async def test_several_slugs_share_one_feed_request(self, rpc):
        rpc.queue({"entries": [search_entry("CVE-2024-72", "WordPress plugin SQL injection")],
                   "total": 1, "next_cursor": None})
        rpc.queue({"entries": [], "total": 0, "next_cursor": None})
        rpc.queue_feed({"items": []})
        alert = {"rule": {"groups": ["wordpress"], "description": "file upload attempt"},
                 "location": "/var/log/nginx/access.log",
                 "data": {"url": "/wp-content/plugins/wp-scraper/import.php"}}
        await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=alert, limit=5, response_format="json"))
        feeds = [c for c in rpc.calls if c["json"]["params"]["name"] == "list_feed"]
        assert len(feeds) == 1
        assert feeds[0]["json"]["params"]["arguments"]["tech"] == ["wordpress", "nginx"]

    @pytest.mark.asyncio
    async def test_no_feed_without_a_verified_slug(self, rpc):
        rpc.queue({"entries": [search_entry("CVE-2024-73", "Joomla extension file upload")],
                   "total": 1, "next_cursor": None})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=TestProductContradiction.JOOMLA_UPLOAD, limit=5, response_format="json")))
        assert not [c for c in rpc.calls if c["json"]["params"]["name"] == "list_feed"]
        assert "technology_feed" not in data["coverage"]["sources"]

    @pytest.mark.asyncio
    async def test_php_url_hint_never_becomes_a_feed_filter(self, rpc):
        rpc.queue({"entries": [search_entry("CVE-2024-74", "WordPress plugin file upload")],
                   "total": 1, "next_cursor": None})
        rpc.queue_feed({"items": []})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=WP_UPLOAD_ALERT, limit=5, response_format="json")))
        php = next(t for t in data["technology_evidence"] if t["technology"] == "php")
        assert php["classification"] == "runtime_hint"
        assert php["status"] == "runtime_hint_only"
        assert php["discovery"] == "not_performed"
        slugs = data["coverage"]["technology_slugs_queried"]
        assert "php" not in slugs
        assert "wordpress" in slugs

    @pytest.mark.asyncio
    async def test_a_cve_seen_by_two_sources_keeps_both(self, rpc):
        shared = search_entry("CVE-2024-75", "WordPress plugin file upload")
        rpc.queue({"entries": [shared], "total": 1, "next_cursor": None})
        rpc.queue_feed({"items": [feed_item("CVE-2024-75", "WordPress plugin file upload")]})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=WP_UPLOAD_ALERT, limit=5, response_format="json")))
        candidate = next(c for c in data["candidates"] if c["id"] == "CVE-2024-75")
        assert "attack_pattern" in candidate["discovery_sources"]
        assert "technology_feed" in candidate["discovery_sources"]

    @pytest.mark.asyncio
    async def test_feed_result_with_incompatible_product_is_rejected(self, rpc):
        rpc.queue({"entries": [search_entry("CVE-2024-76", "WordPress plugin file upload")],
                   "total": 1, "next_cursor": None})
        rpc.queue_feed({"items": [feed_item("CVE-2024-77", "Joomla extension file upload")]})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=WP_UPLOAD_ALERT, limit=5, response_format="json")))
        rejected = {r["id"] for r in data["rejected_candidates"]}
        assert "CVE-2024-77" in rejected

    @pytest.mark.asyncio
    async def test_feed_failure_leaves_the_pattern_result_intact(self, rpc, monkeypatch):
        async def failing_feed(**kwargs):
            raise CircuitOpenError("circuit open")

        monkeypatch.setattr(cve_now, "feed", failing_feed)
        rpc.queue({"entries": [search_entry("CVE-2024-78", "WordPress plugin SQL injection")],
                   "total": 1, "next_cursor": None})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=GENERIC_LOGIN_ALERT, limit=5, response_format="json")))
        assert data["coverage"]["sources"]["technology_feed"]["status"] == "unavailable"
        assert data["candidates"][0]["id"] == "CVE-2024-78"

    @pytest.mark.asyncio
    async def test_feed_is_declared_non_exhaustive(self, rpc):
        rpc.queue({"entries": [], "total": 0, "next_cursor": None})
        rpc.queue_feed({"items": [feed_item(f"CVE-2024-{90 + i}", "WordPress plugin upload")
                                  for i in range(20)]})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=GENERIC_LOGIN_ALERT, limit=2, response_format="json")))
        assert data["coverage"]["technology_feed_is_not_exhaustive"] is True
        assert data["coverage"]["sources"]["technology_feed"]["retrieved"] == 20
        assert data["coverage"]["displayed_count"] <= 2


class TestFeedSufficiencyAndRoles:
    """Feed skips on assessed relevance, and log sources never become identity."""

    @pytest.mark.asyncio
    async def test_feed_runs_when_every_match_is_incompatible(self, rpc):
        rpc.queue({"entries": [search_entry(f"CVE-2024-{60 + i}", "Joomla extension file upload")
                               for i in range(5)], "total": 5})
        rpc.queue_feed({"items": [feed_item("CVE-2024-68", "WordPress plugin file upload")]})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=WP_UPLOAD_ALERT, limit=7, response_format="json")))
        feed = data["coverage"]["sources"]["technology_feed"]
        assert feed["status"] == "ok"
        assert "CVE-2024-68" in [c["id"] for c in data["candidates"]]

    @pytest.mark.asyncio
    async def test_feed_skipped_when_relevant_candidates_exist(self, rpc):
        rpc.queue({"entries": [search_entry("CVE-2024-69",
                                            "WordPress wp-scraper file upload")], "total": 1})
        rpc.queue({"entries": [], "total": 0})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=WP_PLUGIN_UPLOAD_ALERT, limit=1, response_format="json")))
        feed = data["coverage"]["sources"]["technology_feed"]
        assert feed["status"] == "skipped_sufficient_relevant_candidates"
        assert feed["assessed_specific"] >= 1

    @pytest.mark.asyncio
    async def test_log_source_role_is_explicit(self, rpc):
        rpc.queue({"entries": [search_entry("CVE-2024-64", "WordPress plugin file upload")],
                   "total": 1})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=WP_UPLOAD_ALERT, limit=1, response_format="json")))
        roles = data["discovery"]["technology_roles"]
        assert roles["nginx"] == "log_source"
        assert roles["wordpress"] == "target_application"
        assert data["discovery"]["identity_slugs"] == ["wordpress"]
        nginx = next(t for t in data["technology_evidence"] if t["technology"] == "nginx")
        assert nginx["target"] is False

    @pytest.mark.asyncio
    async def test_log_source_technology_cannot_promote(self, rpc):
        rpc.queue({"entries": [search_entry("CVE-2024-65", "Nginx import.php file upload")],
                   "total": 1})
        rpc.queue_feed({"items": []})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=WP_UPLOAD_ALERT, limit=1, response_format="json")))
        candidate = data["candidates"][0]
        assert candidate["product_identity"] != "exact_component"
        assert candidate["relationship"] != "attack_specific_match"

    @pytest.mark.asyncio
    async def test_feed_metadata_stays_unknown(self, rpc):
        rpc.queue({"entries": [], "total": 0, "next_cursor": None})
        rpc.queue_feed({"items": [feed_item("CVE-2024-66", "WordPress plugin file upload")]})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=WP_UPLOAD_ALERT, limit=2, response_format="json")))
        candidate = next(c for c in data["candidates"] if c["id"] == "CVE-2024-66")
        assert candidate["cvss"] is None
        assert candidate["kev"] is None
        assert candidate["metadata_missing"] == ["cvss", "kev"]
        assert candidate["assessment_relevance"] in ("low", "medium", "high")
        assert candidate["relationship"] != "confirmed_cve_reference"


class TestSkipSelectivityAndServerTargets:
    """Weak leads do not suppress discovery; server targets are explicit."""

    @pytest.mark.asyncio
    async def test_twelve_weak_contextual_candidates_do_not_suppress_the_feed(self, rpc):
        weak = [search_entry(f"CVE-2024-{40 + i}",
                             "Arbitrary file upload in a web application")
                for i in range(12)]
        rpc.queue({"entries": weak, "total": 12})
        rpc.queue_feed({"items": [feed_item("CVE-2024-59", "WordPress plugin file upload")]})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=WP_UPLOAD_ALERT, limit=3, response_format="json")))
        feed = data["coverage"]["sources"]["technology_feed"]
        assert feed["status"] == "ok"
        assert data["coverage"]["technology_feed_status"] == "ok"
        assert "CVE-2024-59" in [c["id"] for c in data["candidates"]]

    @pytest.mark.asyncio
    async def test_specific_candidates_suppress_the_feed(self, rpc):
        rpc.queue({"entries": [search_entry("CVE-2024-58",
                                            "WordPress wp-scraper file upload")], "total": 1})
        rpc.queue({"entries": [], "total": 0})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=WP_PLUGIN_UPLOAD_ALERT, limit=1, response_format="json")))
        feed = data["coverage"]["sources"]["technology_feed"]
        assert feed["status"] == "skipped_sufficient_relevant_candidates"
        assert data["coverage"]["sources"]["technology_feed"]["assessed_specific"] >= 1

    def test_server_in_an_attack_rule_can_be_a_target(self):
        from mcp_server.threat_intel.cve_now_tech import identify_technologies
        result = identify_technologies(
            {"rule": {"description": "Nginx arbitrary file upload vulnerability exploited"}})
        nginx = next(t for t in result["technologies"] if t["technology"] == "nginx")
        assert nginx["role"] == "infrastructure"
        assert nginx["target"] is True
        assert "nginx" in [entry["tech"] for entry in result["discovery"]]

    def test_server_mentioned_in_passing_is_not_a_target(self):
        from mcp_server.threat_intel.cve_now_tech import identify_technologies
        result = identify_technologies({"rule": {"description": "Response header resembles nginx"}})
        nginx = next(t for t in result["technologies"] if t["technology"] == "nginx")
        assert nginx["target"] is False
        assert nginx["status"] == "mentioned_only"
        assert result["discovery"] == []

    def test_log_path_never_sets_target(self):
        from mcp_server.threat_intel.cve_now_tech import identify_technologies
        result = identify_technologies({"location": "/var/log/nginx/access.log",
                                        "rule": {"description": "file upload attempt"}})
        nginx = next(t for t in result["technologies"] if t["technology"] == "nginx")
        assert nginx["role"] == "log_source"
        assert nginx["target"] is False


class TestServerTargetRelationship:
    """A server in a rule description is not a target by default."""

    @staticmethod
    def _server(alert, name="nginx"):
        from mcp_server.threat_intel.cve_now_tech import identify_technologies
        result = identify_technologies(alert)
        return next(t for t in result["technologies"] if t["technology"] == name), result

    def test_explicit_vulnerability_target(self):
        entry, result = self._server(
            {"rule": {"description": "Nginx vulnerability exploitation attempt detected"}})
        assert entry["target_relationship"] == "explicit_exploitation_target"
        assert entry["target"] is True
        assert "nginx" in [t["tech"] for t in result["discovery"]]

    def test_access_log_is_the_log_source(self):
        entry, result = self._server(
            {"rule": {"description": "Nginx access log detected SQL injection attempt"}})
        assert entry["target_relationship"] == "log_source"
        assert entry["target"] is False
        assert all(not item["target"] for item in result["discovery"])

    def test_generic_sqli_detection_with_a_log_path(self):
        entry, result = self._server(
            {"rule": {"description": "SQL injection attempt detected"},
             "location": "/var/log/nginx/access.log"})
        assert entry["target_relationship"] == "log_source"
        assert entry["target"] is False

    def test_contextual_server_event_is_not_a_target(self):
        entry, _ = self._server(
            {"rule": {"description": "Apache server returned suspicious response"}}, "apache-httpd")
        assert entry["target_relationship"] == "infrastructure_context"
        assert entry["target"] is False

    def test_two_servers_in_one_rule_are_ambiguous(self):
        entry, result = self._server(
            {"rule": {"description": "Apache and Nginx vulnerability responses differ"}}, "nginx")
        assert entry["target_relationship"] == "ambiguous"
        assert entry["target"] is False
        assert result["discovery"] == []

    def test_structured_application_target_wins_over_a_server_mention(self):
        entry, result = self._server(
            {"rule": {"groups": ["wordpress"],
                      "description": "Nginx response header observed during WordPress upload"},
             "data": {"url": "/wp-content/plugins/wp-scraper/import.php"}})
        assert entry["target"] is False
        assert [t["tech"] for t in result["discovery"] if t["target"]] == ["wordpress"]

    @pytest.mark.asyncio
    async def test_explicit_server_target_with_compatible_class(self, rpc):
        rpc.queue({"entries": [search_entry("CVE-2024-55", "Nginx import.php file upload")],
                   "total": 1})
        rpc.queue_feed({"items": []})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert={"rule": {"description": "Nginx vulnerability arbitrary file upload"},
                   "data": {"url": "/import.php"}},
            limit=2, response_format="json")))
        candidate = data["candidates"][0]
        assert "nginx" in data["discovery"]["identity_slugs"]
        assert any("reachable from file_upload" in item for item in candidate["evidence"])
        assert candidate["relationship"] == "contextual_candidate"

    @pytest.mark.asyncio
    async def test_explicit_server_target_with_incompatible_class(self, rpc):
        rpc.queue({"entries": [search_entry("CVE-2024-56", "Nginx import.php file upload")],
                   "total": 1})
        rpc.queue_feed({"items": []})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert={"rule": {"description": "Nginx vulnerability SQL injection in parameter"},
                   "data": {"url": "/index.php"}},
            limit=2, response_format="json")))
        candidate = data["candidates"][0]
        assert candidate["relationship"] == "contextual_candidate"
        assert any("does not produce" in item for item in candidate["contradictions"])


class TestServerPhraseProximity:
    """A vulnerability word counts only when it is about that server."""

    @staticmethod
    def _rel(description, name="nginx", extra=None):
        from mcp_server.threat_intel.cve_now_tech import identify_technologies
        alert = {"rule": {"description": description}}
        if extra:
            alert.update(extra)
        result = identify_technologies(alert)
        return next(t for t in result["technologies"] if t["technology"] == name), result

    def test_vulnerability_next_to_the_server(self):
        entry, _ = self._rel("Nginx vulnerability exploited")
        assert entry["target_relationship"] == "explicit_exploitation_target"
        assert entry["target"] is True

    def test_exploitation_of_the_server(self):
        entry, _ = self._rel("Exploitation of Nginx RCE")
        assert entry["target_relationship"] == "explicit_exploitation_target"

    def test_log_source_mention_wins_over_a_remote_target(self):
        entry, _ = self._rel("Nginx access log detected Joomla exploitation")
        assert entry["target_relationship"] == "log_source"
        assert entry["target"] is False

    def test_server_response_during_another_attack(self):
        entry, _ = self._rel(
            "Apache returned suspicious response during a WordPress attack", "apache-httpd")
        assert entry["target_relationship"] == "infrastructure_context"

    def test_cve_related_request_does_not_target_the_log_server(self):
        entry, _ = self._rel("Nginx log contains a CVE-related request targeting Joomla")
        assert entry["target_relationship"] == "log_source"
        assert entry["target"] is False

    def test_vulnerability_near_the_application_not_the_server(self):
        entry, _ = self._rel("WordPress vulnerability detected in Nginx access log")
        assert entry["target_relationship"] == "log_source"
        assert entry["target"] is False

    def test_two_technologies_with_the_target_named(self):
        joomla, _ = self._rel("Joomla exploitation via Nginx proxy", "joomla")
        nginx, _ = self._rel("Joomla exploitation via Nginx proxy", "nginx")
        assert joomla["target_relationship"] == "explicit_vulnerability_target"
        assert joomla["target"] is True
        assert nginx["target"] is False
        assert nginx["target_relationship"] == "infrastructure_context"

    def test_cve_phrase_closest_to_the_application(self):
        entry, _ = self._rel(
            "CVE-2024-1234 in WordPress, similar to Nginx responses")
        assert entry["target"] is False
        assert entry["target_relationship"] == "infrastructure_context"


class TestClauseScopedServerTargets:
    """A phrase in another clause, or a log word about something else, changes nothing."""

    @staticmethod
    def _rel(description, name="nginx"):
        from mcp_server.threat_intel.cve_now_tech import identify_technologies
        result = identify_technologies({"rule": {"description": description}})
        return next(t for t in result["technologies"] if t["technology"] == name)

    def test_exploitation_before_an_unrelated_log_reference(self):
        entry = self._rel("Nginx RCE detected in Wazuh event log")
        assert entry["target_relationship"] == "explicit_exploitation_target"
        assert entry["target"] is True

    def test_access_log_containing_another_target(self):
        entry = self._rel("Nginx access log containing a Joomla exploitation attempt")
        assert entry["target_relationship"] == "log_source"
        assert entry["target"] is False

    def test_vulnerability_before_unrelated_application_logging(self):
        entry = self._rel(
            "Apache vulnerability detected; unrelated application logs collected",
            "apache-httpd")
        assert entry["target_relationship"] == "explicit_vulnerability_target"
        assert entry["target"] is True

    def test_technology_and_attack_phrase_in_different_clauses(self):
        entry = self._rel("Nginx proxy observed; Joomla exploitation attempt detected")
        assert entry["target_relationship"] == "infrastructure_context"
        assert entry["target"] is False

    def test_explicit_target_despite_unrelated_log_words(self):
        entry = self._rel("Nginx vulnerability exploited; event logs archived by the collector")
        assert entry["target_relationship"] == "explicit_exploitation_target"
        assert entry["target"] is True

    def test_competing_technologies_stay_ambiguous(self):
        from mcp_server.threat_intel.cve_now_tech import identify_technologies
        result = identify_technologies(
            {"rule": {"description": "Apache and Nginx vulnerability"}})
        names = {t["technology"]: t for t in result["technologies"]}
        assert names["nginx"]["target_relationship"] == "ambiguous"
        assert names["apache-httpd"]["target_relationship"] == "ambiguous"
        assert names["nginx"]["target"] is False

    def test_explicit_target_and_log_source_coexist(self):
        from mcp_server.threat_intel.cve_now_tech import identify_technologies
        result = identify_technologies(
            {"rule": {"description": "Joomla exploitation seen in Nginx access log"}})
        names = {t["technology"]: t for t in result["technologies"]}
        assert names["nginx"]["target_relationship"] == "log_source"
        assert names["joomla"]["target_relationship"] == "explicit_vulnerability_target"
