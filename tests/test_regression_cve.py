#!/usr/bin/env python3
"""Regression tests for CVE assessment, correlation completeness, and technology identification.

Covered issues:

* ``compare_version`` documented "unknown rather than guessing when a range bound
  is not numeric", but a record whose only ranges carried a non-numeric ``fixed``
  bound fell through to ``not_in_range`` - a negative claim built on a range it
  never evaluated.
* ``correlate_alert`` referenced the local ``result`` in its coverage block even
  when neither technologies nor search terms produced a catalog query, raising
  ``UnboundLocalError`` instead of returning an empty candidate set.
* The no-query path reported ``pagination_complete=true`` for a search that never
  ran. Search state is now explicit: completed, incomplete, or not_performed.
* Laravel and PHPUnit were not recognized locally even though alert paths and
  descriptions identify them. Identification no longer depends on a cve.now slug.

No network: the correlation tests replace ``search_tech`` or stop at the
``unmapped`` path before ``_rpc``.
"""
from __future__ import annotations

import asyncio
import json
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

from mcp_server.threat_intel.cve_now import correlate_alert
from mcp_server.threat_intel.cve_now_assess import compare_version


def test_non_numeric_range_bound_is_unknown_not_out_of_range():
    record = {"affected": [{"package": "php",
                            "ranges": [{"introduced": "0", "fixed": "not-a-version"}]}]}
    result = compare_version("php", "8.1.0", record)
    assert result["status"] == "unknown"
    assert result["package_matched"] is True
    assert "not-a-version" not in result.get("evidence", [])


def test_all_ranges_unusable_is_unknown_not_out_of_range():
    record = {"affected": [{"package": "php",
                            "ranges": [{"introduced": "zero", "fixed": "1.2.3"},
                                       {"introduced": "1.0", "lastAffected": "latest"}]}]}
    result = compare_version("php", "8.1.0", record)
    assert result["status"] == "unknown"


def test_one_valid_range_after_an_invalid_one_is_evaluated():
    record = {"affected": [{"package": "php",
                            "ranges": [{"introduced": "0", "fixed": "bad"},
                                       {"introduced": "8.0", "fixed": "8.2"}]}]}
    result = compare_version("php", "8.1.0", record)
    assert result["status"] == "in_range"


def test_missing_inventory_does_not_produce_a_negative():
    record = {"affected": [{"package": "php",
                            "ranges": [{"introduced": "8.0", "fixed": "8.2"}]}]}
    result = compare_version("", "", record)
    assert result["status"] == "unknown"
    assert result["package_matched"] is False


def test_correlate_alert_without_tech_or_terms_reports_not_performed():
    payload = asyncio.run(correlate_alert({}, [], limit=3, terms=[]))
    coverage = payload["coverage"]

    assert payload["candidates"] == []
    assert coverage["catalog_matches"] is None
    assert coverage["total_matches"] == 0
    assert coverage["search_performed"] is False
    assert coverage["search_status"] == "not_performed"
    assert coverage["pagination_complete"] is None
    assert coverage["has_more"] is None
    assert coverage["truncated"] is None


def _entry(cve_id: str = "CVE-2024-1") -> dict:
    return {"id": cve_id, "title": "Synthetic", "cvss": 5.0, "kev": False,
            "modified": "2026-01-01", "url": "https://cve.now/" + cve_id}


def test_correlate_alert_reports_a_completed_search(monkeypatch):
    from mcp_server.threat_intel import cve_now

    async def fake_search(tech, limit, component=None, cursor=None, terms=None):
        return {"entries": [_entry()], "total": 1, "next_cursor": None}

    async def fake_feed(tech=None, limit=20, **kwargs):
        return {"items": []}

    monkeypatch.setattr(cve_now, "search_tech", fake_search)
    monkeypatch.setattr(cve_now, "feed", fake_feed)
    payload = asyncio.run(cve_now.correlate_alert(
        {}, [{"tech": "nginx", "evidence": []}], limit=1, terms=[]))
    coverage = payload["coverage"]

    assert coverage["search_performed"] is True
    assert coverage["search_status"] == "completed"
    assert coverage["pagination_complete"] is True
    assert coverage["has_more"] is False
    assert coverage["truncated"] is False


def test_correlate_alert_reports_an_incomplete_search(monkeypatch):
    from mcp_server.threat_intel import cve_now

    async def fake_search(tech, limit, component=None, cursor=None, terms=None):
        return {"entries": [_entry()], "total": 10, "next_cursor": "next-page"}

    monkeypatch.setattr(cve_now, "search_tech", fake_search)
    payload = asyncio.run(cve_now.correlate_alert(
        {}, [{"tech": "nginx", "evidence": []}], limit=1, max_pages=1, terms=[]))
    coverage = payload["coverage"]

    assert coverage["search_performed"] is True
    assert coverage["search_status"] == "incomplete"
    assert coverage["pagination_complete"] is False
    assert coverage["has_more"] is True
    assert coverage["truncated"] is True


def test_laravel_is_identified_without_a_catalog_slug():
    from mcp_server.threat_intel.cve_now_tech import identify_technologies

    result = identify_technologies({
        "data": {"url": "/vendor/laravel/framework/src/Illuminate/Foundation/Application.php"},
    })
    entry = next(t for t in result["technologies"] if t["technology"] == "laravel")

    assert entry["identified"] is True
    assert entry["status"] == "identified_no_slug"
    assert entry["identity"] == "unresolved"
    assert entry["cve_lookup"] == "no_slug"
    assert entry["discovery"] == "not_performed"
    assert entry["evidence"][0]["field"] == "data.url"
    assert all(item["tech"] != "laravel" for item in result["discovery"])


def test_phpunit_is_identified_without_a_catalog_slug():
    from mcp_server.threat_intel.cve_now_tech import identify_technologies

    result = identify_technologies({
        "rule": {"description": "PHPUnit eval-stdin.php remote code execution attempt"},
    })
    entry = next(t for t in result["technologies"] if t["technology"] == "phpunit")

    assert entry["identified"] is True
    assert entry["status"] == "identified_no_slug"
    assert entry["identity"] == "unresolved"
    assert entry["cve_lookup"] == "no_slug"
    assert entry["discovery"] == "not_performed"
    assert entry["evidence"][0]["field"] == "rule.description"
    assert all(item["tech"] != "phpunit" for item in result["discovery"])


def test_insufficient_evidence_does_not_assign_laravel_or_phpunit():
    from mcp_server.threat_intel.cve_now_tech import identify_technologies

    result = identify_technologies({
        "rule": {"description": "Generic file upload attempt"},
        "data": {"url": "/uploads/shell.php"},
    })
    names = {t["technology"] for t in result["technologies"]}
    assert "laravel" not in names
    assert "phpunit" not in names


def test_component_search_is_reported_as_a_completed_search(monkeypatch):
    from mcp_server.threat_intel import cve_now

    async def fake_search(tech, limit, component=None, cursor=None, terms=None):
        return {"entries": [_entry()], "total": 1, "next_cursor": None}

    monkeypatch.setattr(cve_now, "search_tech", fake_search)
    payload = asyncio.run(cve_now.correlate_alert(
        {}, [], limit=1, terms=[], component="revslider"))
    coverage = payload["coverage"]

    assert coverage["search_performed"] is True
    assert coverage["search_status"] == "completed"
    assert coverage["pagination_complete"] is True
    assert coverage["pages_fetched"] == 1
    assert coverage["sources"]["component_search"]["pages_fetched"] == 1


def test_laravel_is_identified_but_not_sent_to_the_catalog():
    from mcp_server.tools.cve_now import (CveNowCorrelateInput,
                                          blueteam_cve_now_attack_correlate)

    out = asyncio.run(blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
        alert={"data": {"url": "/vendor/laravel/framework/src/Illuminate/Foundation/Application.php"}},
        response_format="json")))
    data = json.loads(out)

    assert data["match_basis"] == "unmapped"
    assert data["coverage"]["search_status"] == "not_performed"
    assert "laravel" in data["discovery"]["identified_without_catalog_mapping"]
    assert data["discovery"]["technologies"] == []


PHP2SHELL_ALERT = {
    "id": "1780000000.9",
    "rule": {"id": "600100", "level": 12,
             "groups": ["web", "attack", "webshell", "php2shell"],
             "description": "PHP2Shell webshell upload attempt"},
    "decoder": {"name": "web-accesslog"},
    "location": "/var/log/nginx/access.log",
    "agent": {"id": "001", "name": "web01"},
    "data": {"url": "/uploads/shell.php", "method": "POST", "status": 200},
}


def _assessment(record: dict) -> dict:
    from mcp_server.threat_intel.cve_now_assess import (assess_candidate,
                                                        classify_attack,
                                                        extract_alert_context)
    context = extract_alert_context(PHP2SHELL_ALERT)
    return assess_candidate(record, context, classify_attack(context), [], [])


def test_smbv3_rce_is_not_a_php2shell_candidate():
    record = {
        "id": "CVE-2020-0796", "cvss": 10.0,
        "title": "SMBv3 remote code execution vulnerability",
        "summary": {"text": "A remote code execution vulnerability exists in Microsoft SMBv3."},
        "affected": [],
    }
    assessed = _assessment(record)

    assert assessed["relationship"] == "no_supported_match"
    assert any("product:" in item for item in assessed["contradictions"])


def test_windows_dns_rce_is_not_a_php2shell_candidate():
    record = {
        "id": "CVE-2020-1350", "cvss": 10.0,
        "title": "Windows DNS Server remote code execution vulnerability",
        "summary": {"text": "A remote code execution vulnerability exists in Windows DNS Server."},
        "affected": [{"vendor": "Microsoft", "product": "Windows DNS Server",
                      "package": "dns-server"}],
    }
    assessed = _assessment(record)

    assert assessed["relationship"] == "no_supported_match"
    assert any("product:" in item for item in assessed["contradictions"])


def test_relevant_php_upload_cve_survives_product_filtering():
    record = {
        "id": "CVE-2024-9999", "cvss": 8.0,
        "title": "PHP file upload vulnerability",
        "summary": {"text": "Unrestricted upload of shell.php allows code execution."},
        "affected": [{"vendor": "PHP", "product": "PHP", "package": "php-app"}],
    }
    assessed = _assessment(record)

    assert assessed["relationship"] == "contextual_candidate"
    assert assessed["endpoint_evidence"]["matched"] == ["shell.php"]
    assert not any("names no token" in item for item in assessed["contradictions"])


def test_request_pattern_is_not_installed_product_evidence():
    from mcp_server.threat_intel.cve_now_tech import identify_technologies

    result = identify_technologies({
        "rule": {"description": "PHPUnit eval-stdin.php exploit attempt",
                 "groups": ["web", "attack"]},
        "decoder": {"name": "web-accesslog"},
        "data": {"url": "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                 "method": "POST"},
    })
    entry = next(t for t in result["technologies"] if t["technology"] == "phpunit")

    assert entry["status"] == "identified_no_slug"
    assert entry["observation"] == "description"
    assert entry["installed_confirmation"] == "not_established"
    assert entry["identity"] == "unresolved"


def test_phpunit_request_pattern_alone_is_not_vulnerability_exposure():
    from mcp_server.threat_intel.cve_now_assess import (assess_candidate,
                                                        classify_attack,
                                                        extract_alert_context)
    alert = {
        "rule": {"description": "PHPUnit eval-stdin.php exploit attempt",
                 "groups": ["web", "attack"]},
        "decoder": {"name": "web-accesslog"},
        "data": {"url": "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                 "method": "POST"},
    }
    record = {
        "id": "CVE-2017-9841", "cvss": 9.8,
        "title": "PHPUnit eval-stdin.php remote code execution",
        "summary": {"text": "PHPUnit eval-stdin.php allows remote code execution."},
        "affected": [{"package": "phpunit",
                      "ranges": [{"introduced": "0", "fixed": "4.8.28"}]}],
    }
    context = extract_alert_context(alert)
    assessed = assess_candidate(record, context, classify_attack(context), [],
                                [], target_families=["phpunit"])

    assert assessed["relationship"] == "contextual_candidate"
    assert assessed["version_check"]["status"] == "unknown"
    assert assessed["product_identity"] == "none"


def test_phpunit_version_exposure_needs_package_inventory():
    from mcp_server.threat_intel.cve_now_assess import (assess_candidate,
                                                        classify_attack,
                                                        extract_alert_context)
    alert = {
        "rule": {"description": "PHPUnit eval-stdin.php exploit attempt",
                 "groups": ["web", "attack"]},
        "data": {"url": "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"},
    }
    record = {
        "id": "CVE-2017-9841", "cvss": 9.8,
        "title": "PHPUnit eval-stdin.php remote code execution",
        "summary": {"text": "PHPUnit eval-stdin.php allows remote code execution."},
        "affected": [{"package": "phpunit",
                      "ranges": [{"introduced": "0", "fixed": "4.8.28"}]}],
    }
    context = extract_alert_context(alert)
    assessed = assess_candidate(
        record, context, classify_attack(context), [],
        [{"name": "phpunit", "version": "4.8.0"}],
        target_families=["phpunit"])

    assert assessed["relationship"] == "vulnerability_exposure"
    assert assessed["version_check"]["status"] == "in_range"
    assert assessed["version_check"]["package_matched"] is True


def test_generic_wazuh_groups_stay_unmapped():
    from mcp_server.threat_intel.cve_now import map_alert_tech
    from mcp_server.threat_intel.cve_now_tech import identify_technologies

    for token in ("web", "attack", "webshell", "recon", "rce", "brute_force"):
        technologies, unmapped = map_alert_tech({"rule": {"groups": [token]}})
        assert technologies == []
        assert unmapped == [token]

        identified = identify_technologies({
            "rule": {"groups": [token], "description": "Generic activity"},
        })
        assert identified["technologies"] == []
        assert token in identified["unmapped_groups"]


def test_cve_coverage_declares_no_time_window_filter(monkeypatch):
    from mcp_server.threat_intel import cve_now

    async def fake_search(tech, limit, component=None, cursor=None, terms=None):
        return {"entries": [], "total": 0, "next_cursor": None}

    async def fake_feed(tech=None, limit=20, **kwargs):
        return {"items": []}

    monkeypatch.setattr(cve_now, "search_tech", fake_search)
    monkeypatch.setattr(cve_now, "feed", fake_feed)
    payload = asyncio.run(cve_now.correlate_alert(
        {}, [{"tech": "nginx", "evidence": []}], limit=1, terms=[]))

    assert payload["coverage"]["time_window"].startswith("none")
    assert "not filtered" in payload["coverage"]["time_window"]
