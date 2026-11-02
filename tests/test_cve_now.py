#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Tests for the cve.now integration: transport, envelope, projections, mapping,
correlation honesty, caching, and graceful degradation.

No network: every test replaces ``cve_now._api_call``. The one live test is marked
and skipped unless CVE_NOW_LIVE=1.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import httpx
import pytest
from pydantic import ValidationError

from mcp_server.core.http_client import CircuitOpenError
from mcp_server.threat_intel import _cache
from mcp_server.threat_intel import cve_now
from mcp_server.threat_intel.cve_now import (
    CANDIDATE_DISCLAIMER,
    CveNowError,
    CveNowNotFound,
    _rank_key,
    alert_cve_ids,
    map_alert_tech,
    normalize_id,
    project_vulnerability,
)
from mcp_server.tools.cve_now import (
    CveNowCorrelateInput,
    CveNowFeedInput,
    CveNowLookupInput,
    blueteam_cve_now_attack_correlate,
    blueteam_cve_now_feed,
    blueteam_cve_now_lookup,
)

PROMO = ("Source: cve.now, built and run by Sazabi (AI-native observability and security): "
         "https://sazabi.com/?utm_source=cve-now&utm_medium=mcp&utm_content=get_vulnerability")


@pytest.fixture(autouse=True)
def _fresh_state(monkeypatch):
    """Drop cached cve.now entries and the inter-request delay, restore afterwards."""
    for key in [k for k in _cache._SHARED_CACHE._data if k.startswith("cve_now:")]:
        del _cache._SHARED_CACHE._data[key]
    monkeypatch.setattr(cve_now._limiter, "min_interval", 0.0)
    yield


class FakeRPC:
    """Records requests and returns a queued JSON-RPC envelope."""

    def __init__(self):
        self.calls: list[dict] = []
        self.responses: list[httpx.Response] = []

    def queue(self, text: str, *, is_error: bool = False, promo: bool = True,
              extra_block: str | None = None, status: int = 200):
        blocks = [{"type": "text", "text": text}]
        if extra_block is not None:
            blocks = [{"type": "text", "text": extra_block}, {"type": "text", "text": text}]
        if promo:
            blocks.append({"type": "text", "text": PROMO})
        payload = {"jsonrpc": "2.0", "id": 1, "result": {"content": blocks}}
        if is_error:
            payload["result"]["isError"] = True
        self.responses.append(httpx.Response(status, json=payload))
        return self

    def queue_raw(self, payload: dict | bytes):
        if isinstance(payload, bytes):
            self.responses.append(httpx.Response(200, content=payload))
        else:
            self.responses.append(httpx.Response(200, json=payload))
        return self

    def install(self, monkeypatch) -> "FakeRPC":
        async def fake(method, url, **kwargs):
            self.calls.append({"method": method, "url": url, **kwargs})
            name = ((kwargs.get("json") or {}).get("params") or {}).get("name")
            if name == "list_feed":
                if self.responses:
                    head = self.responses[0].json()["result"]["content"][0]["text"]
                    if "items" in json.loads(head):
                        return self.responses.pop(0)
                body = {"jsonrpc": "2.0", "id": 1, "result": {"content": [
                    {"type": "text", "text": json.dumps({"items": [], "updatedAt": None})}]}}
                return httpx.Response(200, json=body)
            return self.responses.pop(0)
        monkeypatch.setattr(cve_now, "_api_call", fake)
        return self


@pytest.fixture
def rpc(monkeypatch):
    return FakeRPC().install(monkeypatch)


def vuln_record(**overrides) -> dict:
    record = {
        "id": "CVE-2021-44228",
        "aliases": ["GHSA-JFH8-C2JP-5V3Q"],
        "title": "Apache Log4j2 JNDI",
        "summary": {"text": "Remote code execution through JNDI lookups."},
        "originalDescription": "long NVD text",
        "severity": {"cvss": 10, "vector": "CVSS:3.1/AV:N", "source": "cisa-adp"},
        "exploitation": {
            "kev": {"dateAdded": "2021-12-10", "dueDate": "2021-12-24"},
            "epssReached": {"date": "2026-10-22"},
            "exploitDb": {"ids": [str(i) for i in range(12)]},
            "metasploit": {"modules": [f"m{i}.rb" for i in range(9)]},
            "nuclei": {"templates": ["t.yaml"]},
            "githubPoc": {"repos": ["a/b", "c/d"], "exploits": [], "exploitsSeen": True},
        },
        "affected": ([{"vendor": "Apache", "product": "Log4j2",
                       "ranges": [{"introduced": "2.0", "fixed": "2.15.0"}]}] * 9),
        "context": {
            "sentence": "JNDI lookups reach attacker-controlled servers.",
            "conditions": [{"text": f"condition {i}"} for i in range(9)],
            "attacker": {"access": "network"},
            "fix": {"versions": ["2.15.0"], "workaround": None, "partial": False,
                    "sourceUrl": "https://example.test/advisory"},
            "faq": [{"key": "meaning", "answer": "..."}],
        },
        "ssvc": {"exploitation": "active", "automatable": "yes",
                 "technicalImpact": "total", "source": "cisa-adp"},
        "exposure": "Actively exploited",
        "references": [{"url": f"https://ref.test/{i}"} for i in range(20)],
        "sources": [{"name": "cvelistV5"}],
        "publishedAt": "2021-12-10T00:00:00Z",
        "modifiedAt": "2025-10-21T00:00:00Z",
        "firstSeenAt": "2026-10-22T00:00:00Z",
    }
    record.update(overrides)
    return record


def search_payload(entries=None) -> str:
    rows = entries if entries is not None else [
        {"id": "CVE-2024-0002", "title": "second", "cvss": 7.5, "kev": False,
         "modified": "2024-01-02T00:00:00Z", "url": "https://cve.now/CVE-2024-0002"},
        {"id": "CVE-2024-0001", "title": "first", "cvss": 9.8, "kev": True,
         "modified": "2024-01-01T00:00:00Z", "url": "https://cve.now/CVE-2024-0001"},
        {"id": "CVE-2024-0003", "title": "third", "cvss": 5.0, "kev": False,
         "modified": "2024-01-03T00:00:00Z", "url": "https://cve.now/CVE-2024-0003"},
    ]
    return json.dumps({"entries": rows, "total": len(rows), "next_cursor": None})


class TestTransport:
    @pytest.mark.asyncio
    async def test_request_is_stateless_jsonrpc(self, rpc):
        rpc.queue(json.dumps(vuln_record()))
        await cve_now.lookup("CVE-2021-44228")

        call = rpc.calls[0]
        assert call["method"] == "post"
        assert call["url"] == cve_now.CVE_NOW_MCP_URL
        body = call["json"]
        assert body["jsonrpc"] == "2.0"
        assert body["method"] == "tools/call"
        assert body["params"] == {"name": "get_vulnerability",
                                  "arguments": {"id": "CVE-2021-44228"}}
        assert "mcp-session-id" not in {k.lower() for k in (call.get("headers") or {})}

    @pytest.mark.asyncio
    async def test_first_json_block_wins_and_promo_is_dropped(self, rpc):
        rpc.queue(json.dumps(vuln_record(title="https://sazabi.com/?utm_source=cve-now")))
        record = await cve_now.lookup("CVE-2021-44228")
        assert record["title"] == ""
        assert "sazabi" not in json.dumps(record).lower()

    @pytest.mark.asyncio
    async def test_non_json_first_block_is_skipped(self, rpc):
        rpc.queue(json.dumps(vuln_record()), extra_block="Welcome to cve.now", promo=False)
        assert (await cve_now.lookup("CVE-2021-44228"))["id"] == "CVE-2021-44228"

    @pytest.mark.asyncio
    async def test_jsonrpc_error_raises(self, rpc):
        rpc.queue_raw({"jsonrpc": "2.0", "id": 1,
                       "error": {"code": -32601, "message": "Method not found"}})
        with pytest.raises(CveNowError, match="Method not found"):
            await cve_now.lookup("CVE-2021-44228")

    @pytest.mark.asyncio
    async def test_unknown_id_maps_to_not_found(self, rpc):
        rpc.queue("No entry found for CVE-2026-999999", is_error=True)
        assert await cve_now.lookup("CVE-2026-999999") is None

    @pytest.mark.asyncio
    async def test_unexpected_upstream_error_is_not_a_negative(self, rpc):
        rpc.queue("upstream database unavailable", is_error=True)
        with pytest.raises(CveNowError):
            await cve_now.lookup("CVE-2021-44228")

    @pytest.mark.asyncio
    async def test_oversize_response_rejected_before_parsing(self, rpc):
        rpc.queue_raw(b"x" * (cve_now.MAX_RESPONSE_BYTES + 1))
        with pytest.raises(CveNowError, match="exceeded"):
            await cve_now.lookup("CVE-2021-44228")

    @pytest.mark.asyncio
    async def test_non_object_payload_rejected(self, rpc):
        rpc.queue_raw(b"[]")
        with pytest.raises(CveNowError):
            await cve_now.lookup("CVE-2021-44228")


class TestIdentifiers:
    @pytest.mark.parametrize("raw,expected", [
        ("cve-2021-44228", "CVE-2021-44228"),
        ("GHSA-jfh8-c2jp-5v3q", "GHSA-JFH8-C2JP-5V3Q"),
        ("OSV-2024-1", "OSV-2024-1"),
    ])
    def test_valid_ids_normalized(self, raw, expected):
        assert normalize_id(raw) == expected

    @pytest.mark.parametrize("raw", [
        "", "CVE-21-44228", "CVE-2021-12", "GHSA-1234", "OSV-2024",
        "CVE-2021-44228 OR kev:true", "tech:wordpress",
    ])
    def test_invalid_ids_rejected(self, raw):
        assert normalize_id(raw) is None

    def test_whitespace_padded_id_is_accepted(self):
        assert normalize_id("  cve-2021-44228\n") == "CVE-2021-44228"

    def test_lookup_input_rejects_bad_id(self):
        with pytest.raises(ValidationError):
            CveNowLookupInput(vulnerability_id="CVE-2021-1")

    def test_feed_rejects_unknown_tech(self):
        with pytest.raises(ValidationError, match="technology slugs"):
            CveNowFeedInput(tech=["wordpress", "wordpress-pro"])

    def test_feed_rejects_unknown_ecosystem(self):
        with pytest.raises(ValidationError, match="ecosystems"):
            CveNowFeedInput(ecosystem=["npm", "composer"])

    def test_feed_rejects_more_than_16_combinations(self):
        with pytest.raises(ValidationError, match="16"):
            CveNowFeedInput(tech=["nextjs", "react", "node", "php"],
                            ecosystem=["npm", "pypi", "go", "maven", "nuget"])

    def test_correlate_requires_alert_or_tech(self):
        with pytest.raises(ValidationError, match="alert document or an explicit tech"):
            CveNowCorrelateInput()

    def test_correlate_rejects_oversize_alert(self):
        with pytest.raises(ValidationError, match="trimmed alert"):
            CveNowCorrelateInput(alert={"full_log": "a" * 300_000})


class TestProjection:
    def test_projection_caps_lists_and_drops_unused_fields(self):
        record = project_vulnerability(vuln_record())
        assert len(record["references"]) == 8
        assert len(record["affected"]) == 6
        assert len(record["context"]["conditions"]) == 3
        assert len(record["exploitation"]["metasploit_modules"]) == 5
        assert len(record["exploitation"]["exploitdb_ids"]) == 5
        assert record["exploitation"]["public_poc_count"] == 2
        assert "originalDescription" not in record
        assert "faq" not in record["context"]
        assert "sources" not in record

    def test_projection_survives_null_severity(self):
        record = project_vulnerability(vuln_record(severity=None, summary=None,
                                                   exploitation=None, context=None,
                                                   ssvc=None, affected=None))
        assert record["severity"] == {"cvss": None, "vector": None, "source": None}
        assert record["summary"] is None
        assert record["kev"]["listed"] is False
        assert record["affected"] == []


class TestCache:
    @pytest.mark.asyncio
    async def test_repeat_lookup_uses_cache(self, rpc):
        rpc.queue(json.dumps(vuln_record()))
        first = await cve_now.lookup("CVE-2021-44228")
        second = await cve_now.lookup("CVE-2021-44228")
        assert first == second
        assert len(rpc.calls) == 1

    @pytest.mark.asyncio
    async def test_zero_ttl_expires_immediately(self, rpc, monkeypatch):
        monkeypatch.setattr(cve_now, "TTL_LOOKUP", 0)
        rpc.queue(json.dumps(vuln_record()))
        rpc.queue(json.dumps(vuln_record()))
        await cve_now.lookup("CVE-2021-44228")
        await cve_now.lookup("CVE-2021-44228")
        assert len(rpc.calls) == 2


class TestTechMapping:
    def test_exact_group_maps_with_evidence(self):
        technologies, unmapped = map_alert_tech({"rule": {"groups": ["wordpress", "syscheck"]}})
        assert [t["tech"] for t in technologies] == ["wordpress"]
        assert technologies[0]["evidence"] == [{"source": "rule.groups", "value": "wordpress"}]
        assert unmapped == ["syscheck"]

    @pytest.mark.parametrize("token", [
        "web", "accesslog", "web_attack", "mysql_login_fail", "nginx_error",
        "docker_drop", "php2shell", "syscheck", "authentication_failures",
        "react2shell", "windows_iis", "linux", "payload_obfuscation",
    ])
    def test_ambiguous_tokens_stay_unmapped(self, token):
        technologies, unmapped = map_alert_tech({"rule": {"groups": [token]}})
        assert technologies == []
        assert unmapped == [token]

    def test_groups_accept_comma_string(self):
        technologies, _ = map_alert_tech({"rule": {"groups": "wordpress,web"}})
        assert [t["tech"] for t in technologies] == ["wordpress"]

    def test_location_prefix_maps(self):
        technologies, _ = map_alert_tech({"location": "/var/log/nginx/access.log"})
        assert technologies[0]["tech"] == "nginx"
        assert technologies[0]["evidence"][0]["source"] == "location"

    def test_url_marker_maps(self):
        technologies, _ = map_alert_tech({"data": {"url": "/wp-login.php?action=lostpassword"}})
        assert technologies[0]["tech"] == "wordpress"
        assert technologies[0]["evidence"] == [{"source": "data.url", "value": "/wp-login.php"}]

    def test_tainted_url_does_not_invent_tech(self):
        technologies, _ = map_alert_tech({"data": {"url": "/search?q=wordpress"}})
        assert technologies == []

    def test_unmapped_groups_capped_at_20(self):
        _, unmapped = map_alert_tech({"rule": {"groups": [f"g{i}" for i in range(40)]}})
        assert len(unmapped) == 20

    @pytest.mark.parametrize("token,slug", [
        ("wordpress", "wordpress"),
        ("php", "php"),
        ("nextjs", "nextjs"),
        ("nextjs_probe", "nextjs"),
        ("nextjs_rce_payload", "nextjs"),
        ("nextjs_exploit", "nextjs"),
    ])
    def test_mapped_groups_resolve_to_their_documented_slug(self, token, slug):
        technologies, unmapped = map_alert_tech({"rule": {"groups": [token]}})
        assert [entry["tech"] for entry in technologies] == [slug]
        assert unmapped == []

    def test_every_mapped_group_carries_ruleset_provenance(self):
        """A token enters the map with the rule ids that justify it, or not at all."""
        provenance = cve_now._TECH_MAP["_meta"]["group_provenance"]
        assert set(cve_now._GROUP_MAP) == set(provenance)
        for token, entry in provenance.items():
            assert entry["slug"] == cve_now._GROUP_MAP[token]
            assert entry["slug"] in cve_now.TECH_SLUGS
            assert entry["validation"] == "ruleset-definition"
            assert entry["evidence"], token
            for item in entry["evidence"]:
                assert item["file"] and item["rules"] and item["observed"], token

    def test_ambiguous_groups_are_documented_and_stay_out_of_the_map(self):
        ambiguous = cve_now._TECH_MAP["_meta"]["ambiguous_kept_unmapped"]
        for token in ("react2shell", "mysql_login_fail", "windows_iis"):
            assert token in ambiguous
        for token in ambiguous:
            assert token not in cve_now._GROUP_MAP

    def test_map_does_not_claim_production_validation(self):
        meta = cve_now._TECH_MAP["_meta"]
        assert "No production Indexer telemetry" in meta["validation_level"]
        assert meta["audit"]["status"].startswith("not run")

    def test_alert_cves_only_from_structured_fields(self):
        alert = {
            "vulnerability": {"cve": "cve-2024-6387"},
            "rule": {"description": "exploit for CVE-2021-44228 seen"},
            "full_log": "attacker requested CVE-2020-0001",
        }
        assert alert_cve_ids(alert) == ["CVE-2024-6387"]

    def test_ranking_prefers_kev_then_cvss(self):
        entries = [
            {"id": "a", "kev": False, "cvss": 9.9, "modified": "2024-01-01"},
            {"id": "b", "kev": True, "cvss": 5.0, "modified": "2024-01-01"},
            {"id": "c", "kev": False, "cvss": 9.9, "modified": "2024-02-01"},
        ]
        assert [e["id"] for e in sorted(entries, key=_rank_key, reverse=True)] == ["b", "c", "a"]


class TestCorrelation:
    @pytest.mark.asyncio
    async def test_tech_basis_is_labelled_candidate(self, rpc):
        rpc.queue(search_payload())
        out = await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert={"rule": {"groups": ["wordpress", "web_attack"]}}, limit=2))
        assert "technology-based candidate match" in out
        assert "CISA KEV" in out
        assert "web_attack" in out
        assert "not evidence" in out.lower() or "candidate" in out.lower()

    @pytest.mark.asyncio
    async def test_tech_candidates_ranked_kev_first(self, rpc):
        rpc.queue(search_payload())
        payload = await cve_now.correlate_alert(
            {"rule": {"groups": ["wordpress"]}},
            [{"tech": "wordpress", "evidence": [{"source": "rule.groups", "value": "wordpress"}]}],
            limit=2)
        assert payload["match_basis"] == "tech_feed"
        assert payload["confidence"] == "candidate"
        assert [c["id"] for c in payload["candidates"]] == ["CVE-2024-0001", "CVE-2024-0002"]
        assert payload["candidates"][0]["relevance"] == "kev"
        assert CANDIDATE_DISCLAIMER in payload["limitations"]
        assert "no alert evidence" in payload["candidates"][0]["why"]
        assert "time_window" in payload["coverage"]

    @pytest.mark.asyncio
    async def test_direct_basis_when_alert_carries_cve(self, rpc):
        rpc.queue(json.dumps(vuln_record()))
        payload = await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert={"vulnerability": {"cve": "CVE-2021-44228"},
                   "rule": {"groups": ["wordpress"]}},
            response_format="json"))
        data = json.loads(payload)
        assert data["match_basis"] == "alert_cve"
        assert data["confidence"] == "direct"
        assert data["candidates"][0]["id"] == "CVE-2021-44228"
        assert data["candidates"][0]["kev"] is True

    @pytest.mark.asyncio
    async def test_correlate_alert_never_claims_a_direct_match(self, rpc):
        """Direct-CVE handling belongs to the tool; the core returns candidates only."""
        rpc.queue(search_payload())
        payload = await cve_now.correlate_alert(
            {"vulnerability": {"cve": "CVE-2024-9999"}},
            [{"tech": "wordpress", "evidence": []}], limit=3)
        assert payload["match_basis"] == "tech_feed"
        assert "CVE-2024-9999" not in [c["id"] for c in payload["candidates"]]

    @pytest.mark.asyncio
    async def test_unmapped_basis_makes_no_upstream_call(self, rpc):
        payload = await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert={"rule": {"groups": ["web", "accesslog"]}}, response_format="json"))
        data = json.loads(payload)
        assert data["match_basis"] == "unmapped"
        assert data["confidence"] == "none"
        assert data["candidates"] == []
        assert data["unmapped_groups"] == ["web", "accesslog"]
        assert rpc.calls == []

    @pytest.mark.asyncio
    async def test_caller_supplied_tech_is_evidenced(self, rpc):
        rpc.queue(search_payload())
        payload = await cve_now.correlate_alert({}, [{"tech": "nginx", "evidence": []}],
                                                limit=1)
        assert payload["technologies"][0]["evidence"] == []

    @pytest.mark.asyncio
    async def test_confidence_does_not_scale_with_technology_evidence(self, rpc):
        """More evidence that a technology is present must not raise confidence.

        The confidence a tech match carries is fixed at "candidate"; only an id in a
        structured alert field is direct. Production telemetry cannot promote one.
        """
        rpc.queue(search_payload())
        rpc.queue(search_payload())
        one = await cve_now.correlate_alert(
            {"rule": {"groups": ["wordpress"]}},
            [{"tech": "wordpress", "evidence": [{"source": "rule.groups", "value": "wordpress"}]}],
            limit=2)
        four = await cve_now.correlate_alert(
            {"rule": {"groups": ["wordpress"]}},
            [{"tech": "wordpress", "evidence": [
                {"source": "rule.groups", "value": "wordpress"},
                {"source": "location", "value": "/var/log/nginx/access.log"},
                {"source": "data.url", "value": "/wp-login.php"},
                {"source": "rule.groups", "value": "wordpress"},
            ]}], limit=2)
        assert one["confidence"] == four["confidence"] == "candidate"
        assert one["match_basis"] == four["match_basis"] == "tech_feed"
        assert "direct" not in json.dumps(four)

    @pytest.mark.asyncio
    async def test_include_details_fetches_top_candidate(self, rpc):
        rpc.queue(search_payload())
        rpc.queue(json.dumps(vuln_record()))
        payload = await cve_now.correlate_alert(
            {"rule": {"groups": ["wordpress"]}},
            [{"tech": "wordpress", "evidence": []}], limit=1, include_details=True)
        assert payload["candidate_detail"]["id"] == "CVE-2021-44228"


class TestDegradation:
    @pytest.mark.asyncio
    async def test_circuit_open_returns_unavailable_not_an_exception(self, rpc, monkeypatch):
        async def boom(*args, **kwargs):
            raise CircuitOpenError("circuit breaker open for 'cve_now'")
        monkeypatch.setattr(cve_now, "_api_call", boom)

        out = await blueteam_cve_now_lookup(CveNowLookupInput(
            vulnerability_id="CVE-2021-44228", response_format="json"))
        data = json.loads(out)
        assert data["cve_context"]["status"] == "unavailable"
        assert data["cve_context"]["reason"] == "circuit_open"

    @pytest.mark.asyncio
    async def test_timeout_degrades_for_correlate(self, rpc, monkeypatch):
        async def boom(*args, **kwargs):
            raise httpx.ReadTimeout("slow")
        monkeypatch.setattr(cve_now, "_api_call", boom)

        out = await blueteam_cve_now_attack_correlate(CveNowCorrelateInput(
            alert={"vulnerability": {"cve": "CVE-2021-44228"}}, response_format="json"))
        assert json.loads(out)["cve_context"]["status"] == "unavailable"

    @pytest.mark.asyncio
    async def test_not_found_is_reported_as_not_found(self, rpc):
        rpc.queue("No entry found for CVE-2024-9999", is_error=True)
        out = await blueteam_cve_now_lookup(CveNowLookupInput(
            vulnerability_id="CVE-2024-9999", response_format="json"))
        data = json.loads(out)
        assert data["found"] is False
        assert "cve_context" not in data

    @pytest.mark.asyncio
    async def test_feed_degrades_without_raising(self, rpc, monkeypatch):
        async def boom(*args, **kwargs):
            raise httpx.ConnectError("dns")
        monkeypatch.setattr(cve_now, "_api_call", boom)
        out = await blueteam_cve_now_feed(CveNowFeedInput(tech=["wordpress"],
                                                          response_format="json"))
        assert json.loads(out)["cve_context"]["status"] == "unavailable"


class TestFeed:
    @pytest.mark.asyncio
    async def test_feed_renders_and_states_coverage_limit(self, rpc):
        rpc.queue(json.dumps({
            "name": "?filter=critical&tech=wordpress",
            "title": "cve.now: critical vulnerabilities, WordPress",
            "updatedAt": "2026-10-01T14:33:53.363Z",
            "items": [{"id": "CVE-2026-62071", "title": "WP plugin SQLi",
                       "summary": "s", "updatedAt": "2026-10-01T14:33:53.363Z",
                       "kind": "new"}],
        }))
        out = await blueteam_cve_now_feed(CveNowFeedInput(tech=["wordpress"],
                                                          filter_name="critical"))
        assert "CVE-2026-62071" in out
        assert "no alert-time-window" in out

    @pytest.mark.asyncio
    async def test_feed_empty_selection_is_explicit(self, rpc):
        rpc.queue(json.dumps({"items": [], "updatedAt": "2026-10-01T00:00:00Z"}))
        out = await blueteam_cve_now_feed(CveNowFeedInput(tech=["redis"]))
        assert "No entries returned" in out


class TestAuditScript:
    """The production audit must stay read-only and must not confuse log source with meaning."""

    @staticmethod
    def _module():
        import importlib.util
        path = (pathlib.Path(__file__).resolve().parent.parent
                / "scripts" / "cve_now_tech_map_audit.py")
        spec = importlib.util.spec_from_file_location("cve_now_tech_map_audit", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_dry_run_needs_no_credentials_and_sends_no_request(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith("WAZUH_")}
        env["PATH"] = os.environ.get("PATH", "")
        result = subprocess.run(
            [sys.executable, "scripts/cve_now_tech_map_audit.py", "--dry-run", "--json"],
            cwd=str(pathlib.Path(__file__).resolve().parent.parent),
            env=env, capture_output=True, text=True, timeout=60)
        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout)
        assert payload["endpoint"].endswith("_search")
        assert payload["read_only"] is True
        assert payload["body"]["size"] == 0
        assert self._module().write_keys_in(payload["body"]) == []

    def test_read_only_guard_rejects_a_script_clause(self):
        audit = self._module()
        body = audit.build_body(7, "rule.groups", 10)
        body["aggs"]["groups"]["aggs"]["evil"] = {"script": {"source": "1"}}
        with pytest.raises(SystemExit, match="write/execute"):
            audit.assert_read_only(body, "wazuh-alerts-*")

    def test_read_only_guard_rejects_document_returns(self):
        audit = self._module()
        body = audit.build_body(7, "rule.groups", 10)
        body["size"] = 5
        with pytest.raises(SystemExit, match="size must stay 0"):
            audit.assert_read_only(body, "wazuh-alerts-*")

    def test_read_only_guard_rejects_a_write_index_pattern(self):
        audit = self._module()
        with pytest.raises(SystemExit, match="index pattern"):
            audit.assert_read_only(audit.build_body(7, "rule.groups", 10), "wazuh-alerts/_update")

    def test_name_slugs_match_whole_segments_only(self):
        audit = self._module()
        assert audit.name_slugs("mysql_login_fail", cve_now.TECH_SLUGS) == ["mysql"]
        assert audit.name_slugs("nextjs_action", cve_now.TECH_SLUGS) == ["nextjs"]
        assert audit.name_slugs("php2shell", cve_now.TECH_SLUGS) == []
        assert audit.name_slugs("web_attack", cve_now.TECH_SLUGS) == []

    def test_event_source_slugs_match_whole_values_only(self):
        audit = self._module()
        assert audit.event_source_slugs(["mysql"], [], cve_now.TECH_SLUGS) == ["mysql"]
        assert audit.event_source_slugs([], ["/var/log/nginx/access.log"],
                                        cve_now.TECH_SLUGS) == ["nginx"]
        assert audit.event_source_slugs(["mysql_login_fail"], ["/var/log/mysql_audit/x.log"],
                                        cve_now.TECH_SLUGS) == []
        assert audit.event_source_slugs(["web-accesslog"], ["/var/ossec/logs/alerts/alerts.json"],
                                        cve_now.TECH_SLUGS) == []

    @staticmethod
    def _bucket(key, docs, decoders=(), locations=()):
        return {"key": key, "doc_count": docs,
                "decoders": {"buckets": [{"key": d} for d in decoders]},
                "locations": {"buckets": [{"key": l} for l in locations]},
                "samples": {"hits": {"hits": [{"_source": {"rule.id": "1001"}}]}}}

    def test_classify_separates_confirmed_from_review(self):
        audit = self._module()
        report = audit.classify([
            self._bucket("wordpress", 10, ["web-accesslog"], ["/var/log/nginx/access.log"]),
            self._bucket("mysql_login_fail", 5, ["mysql"], ["/var/log/mysql/error.log"]),
            self._bucket("syscheck", 99, ["syscheck"], ["/var/ossec/logs/alerts/alerts.json"]),
        ], cve_now._GROUP_MAP, cve_now.TECH_SLUGS)

        assert [row["group"] for row in report["confirmed"]] == ["wordpress"]
        assert report["confirmed"][0]["slug"] == "wordpress"
        assert report["confirmed"][0]["rule_ids"] == ["1001"]
        assert [row["group"] for row in report["unmapped_needs_review"]] == ["mysql_login_fail"]
        assert report["unmapped_needs_review"][0]["name_suggests"] == ["mysql"]
        assert [row["group"] for row in report["unmapped_no_signal"]] == ["syscheck"]
        assert set(report["in_map_not_observed"]) == set(cve_now._GROUP_MAP) - {"wordpress"}

    def test_a_generic_group_on_a_known_log_source_is_not_a_mapping_candidate(self):
        audit = self._module()
        report = audit.classify(
            [self._bucket("web_attack", 50, ["web-accesslog"], ["/var/log/nginx/access.log"])],
            cve_now._GROUP_MAP, cve_now.TECH_SLUGS)
        assert report["unmapped_needs_review"] == []
        assert [row["group"] for row in report["unmapped_log_source_only"]] == ["web_attack"]
        assert report["unmapped_log_source_only"][0]["event_source_suggests"] == ["nginx"]


    @staticmethod
    def _args(audit, **over):
        import argparse
        base = dict(days=7, index="wazuh-alerts-*", field="rule.groups",
                    max_groups=300, json=True)
        base.update(over)
        return argparse.Namespace(**base)

    @staticmethod
    def _es_buckets():
        return [
            {"key": "wordpress", "doc_count": 1204,
             "decoders": {"buckets": [{"key": "web-accesslog"}]},
             "locations": {"buckets": [{"key": "/var/log/nginx/access.log"}]},
             "samples": {"hits": {"hits": [{"_source": {"rule.id": "600002"}}]}}},
            {"key": "web_attack", "doc_count": 8901,
             "decoders": {"buckets": [{"key": "web-accesslog"}]},
             "locations": {"buckets": [{"key": "/var/log/nginx/access.log"}]},
             "samples": {"hits": {"hits": []}}},
            {"key": "syscheck", "doc_count": 99,
             "decoders": {"buckets": [{"key": "syscheck"}]},
             "locations": {"buckets": [{"key": "/var/ossec/logs/alerts/alerts.json"}]},
             "samples": {"hits": {"hits": []}}},
        ]

    @pytest.mark.asyncio
    async def test_run_audit_builds_the_report_from_an_indexer_response(self, monkeypatch, capsys):
        audit = self._module()
        from mcp_server.wazuh import indexer

        async def fake_caps(fields, index):
            return {"rule.groups": "keyword", "decoder.name": "keyword", "location": "keyword"}

        captured = {}

        async def fake_post(body, index):
            captured["body"] = body
            return {"aggregations": {"groups": {"buckets": self._es_buckets()}}, "_partial": True}

        monkeypatch.setattr(indexer, "_wazuh_indexer_field_caps", fake_caps)
        monkeypatch.setattr(indexer, "_wazuh_indexer_post", fake_post)

        assert await audit.run_audit(self._args(audit)) == 0
        assert captured["body"]["size"] == 0
        assert audit.write_keys_in(captured["body"]) == []

        report = json.loads(capsys.readouterr().out)
        assert report["partial"] is True
        assert [row["group"] for row in report["confirmed"]] == ["wordpress"]
        assert report["confirmed"][0]["slug"] == "wordpress"
        assert [row["group"] for row in report["unmapped_log_source_only"]] == ["web_attack"]
        assert [row["group"] for row in report["unmapped_no_signal"]] == ["syscheck"]
        assert set(report["in_map_not_observed"]) == set(cve_now._GROUP_MAP) - {"wordpress"}
        assert report["fields_missing"] == []

    @pytest.mark.asyncio
    async def test_run_audit_drops_the_evidence_agg_for_a_missing_field(self, monkeypatch, capsys):
        audit = self._module()
        from mcp_server.wazuh import indexer

        async def fake_caps(fields, index):
            return {"rule.groups": "keyword", "location": "keyword"}

        captured = {}

        async def fake_post(body, index):
            captured["body"] = body
            return {"aggregations": {"groups": {"buckets": self._es_buckets()}}}

        monkeypatch.setattr(indexer, "_wazuh_indexer_field_caps", fake_caps)
        monkeypatch.setattr(indexer, "_wazuh_indexer_post", fake_post)

        assert await audit.run_audit(self._args(audit)) == 0
        sub = captured["body"]["aggs"]["groups"]["aggs"]
        assert "decoders" not in sub and "locations" in sub
        assert json.loads(capsys.readouterr().out)["fields_missing"] == ["decoder.name"]

    @pytest.mark.asyncio
    async def test_run_audit_refuses_when_the_group_field_is_unmapped(self, monkeypatch, capsys):
        audit = self._module()
        from mcp_server.wazuh import indexer

        async def fake_caps(fields, index):
            return {"decoder.name": "keyword"}

        async def never_called(body, index):
            raise AssertionError("the search must not run when rule.groups is unmapped")

        monkeypatch.setattr(indexer, "_wazuh_indexer_field_caps", fake_caps)
        monkeypatch.setattr(indexer, "_wazuh_indexer_post", never_called)

        assert await audit.run_audit(self._args(audit)) == 1
        assert "is not mapped" in capsys.readouterr().err

    def test_unreachable_indexer_fails_safely_and_never_prints_the_secret(self):
        canary = "not-a-real-password-7f3a"
        env = {k: v for k, v in os.environ.items() if not k.startswith("WAZUH_")}
        env.update({"PATH": os.environ.get("PATH", ""),
                    "WAZUH_INDEXER_URL": "http://127.0.0.1:1",
                    "WAZUH_INDEXER_PASSWORD": canary})
        result = subprocess.run(
            [sys.executable, "scripts/cve_now_tech_map_audit.py", "--days", "1"],
            cwd=str(pathlib.Path(__file__).resolve().parent.parent),
            env=env, capture_output=True, text=True, timeout=120)
        assert result.returncode == 1, result.stdout + result.stderr
        assert "Indexer error" in result.stderr
        assert canary not in result.stdout + result.stderr
        assert "Traceback" not in result.stderr


@pytest.mark.skipif(os.environ.get("CVE_NOW_LIVE") != "1",
                    reason="live cve.now call; set CVE_NOW_LIVE=1 to run")
def test_live_lookup_smoke():
    import asyncio

    record = asyncio.run(cve_now.lookup("CVE-2021-44228"))
    assert record and record["kev"]["listed"] is True
    assert "sazabi" not in json.dumps(record).lower()
