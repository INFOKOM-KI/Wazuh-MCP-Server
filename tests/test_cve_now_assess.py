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

    def queue(self, payload: dict):
        body = {"jsonrpc": "2.0", "id": 1,
                "result": {"content": [{"type": "text", "text": json.dumps(payload)}]}}
        self.responses.append(httpx.Response(200, json=body))
        return self

    def install(self, monkeypatch):
        async def fake(method, url, **kwargs):
            self.calls.append({"method": method, "url": url, **kwargs})
            return self.responses.pop(0)
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
            arguments = call["json"]["params"]["arguments"]
            assert set(arguments) <= {"q", "limit", "id"}, arguments
            assert arguments.get("q") in (None, "tech:wordpress sort:cvss")

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
        queries = [call["json"]["params"]["arguments"]["q"] for call in rpc.calls]
        assert len(queries) == 2
        assert queries[0].startswith("tech:") and "wp-scraper" not in queries[0]
        assert "wp-scraper" in queries[1] and queries[1].endswith("sort:cvss")

        rpc.calls.clear()
        for key in [k for k in _cache._SHARED_CACHE._data if k.startswith("cve_now:")]:
            del _cache._SHARED_CACHE._data[key]
        rpc.queue({"entries": [search_entry("CVE-2024-34", "WordPress plugin SQL injection")],
                   "total": 1})
        await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=WP_UPLOAD_ALERT, response_format="json"))
        assert len(rpc.calls) == 1
        assert "wp-scraper" not in rpc.calls[0]["json"]["params"]["arguments"]["q"]

    @pytest.mark.asyncio
    async def test_discovery_uses_catalog_search_not_the_feed(self, rpc):
        rpc.queue({"entries": [search_entry("CVE-2024-35", "WordPress plugin SQL injection")],
                   "total": 1})
        data = json.loads(await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert=WP_UPLOAD_ALERT, response_format="json")))
        tools_called = [call["json"]["params"]["name"] for call in rpc.calls]
        assert tools_called == ["search"]
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
