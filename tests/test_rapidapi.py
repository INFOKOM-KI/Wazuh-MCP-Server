#!/usr/bin/env python3
"""
Tests for RapidAPI capability lookups - pure helpers + input validation.
No network calls: the request helper and tools are exercised indirectly.
Hope my LLM doing greate during test processing, cause i'm to lazy write a test case...;P
"""
from __future__ import annotations
import os
os.environ.setdefault("WAZUH_INDEXER_URL", "https://idx:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "pw")
import json
import pytest
from mcp_server.threat_intel import rapidapi as r


def test_headers_require_key():
    os.environ.pop("RAPIDAPI_KEY", None)
    with pytest.raises(RuntimeError):
        r._rapidapi_headers("example.p.rapidapi.com")


def test_headers_include_key():
    os.environ["RAPIDAPI_KEY"] = "test-key"
    h = r._rapidapi_headers("example.p.rapidapi.com")
    assert h["x-rapidapi-key"] == "test-key"
    assert h["x-rapidapi-host"] == "example.p.rapidapi.com"
    assert h["Accept"] == "application/json"


def test_dynamic_markdown_recognizes_keys():
    out = r._dynamic_markdown("T", {"status": "blacklisted", "total": 3})
    assert "blacklisted" in out
    assert "total" in out


def test_dynamic_markdown_falls_back_to_json():
    out = r._dynamic_markdown("T", {"unrecognized_shape": {"nested": [1, 2, 3]}})
    assert "```json" in out  # unknown schema -> dump full body rather than crash.


def test_envelope_wraps_raw():
    d = json.loads(r._envelope("1.2.3.4", "apiverve_ip_blacklist", {"a": 1}))
    assert d == {"query": "1.2.3.4", "source": "apiverve_ip_blacklist", "result": {"a": 1}}


def test_breach_email_validation():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        r.BreachCheckInput(email="not-an-email")
    assert r.BreachCheckInput(email="csirt@tangerangkota.go.id").email == "csirt@tangerangkota.go.id"


def test_ip_input_rejects_private():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        r._IpInput(ip="192.168.1.1")  # RFC1918 -> public-IP validator rejects


def test_envelope_redacts_email():
    # S1 fix: the JSON envelope now runs the uniform redaction boundary, so a
    # victim email never reaches the LLM unredacted (breach-check PII leak).
    raw = {"email": "csirt@tangerangkota.go.id", "breaches": ["Adobe"]}
    out = r._envelope("csirt@tangerangkota.go.id", "rapidapi_breach_check", raw)
    assert "csirt@tangerangkota.go.id" not in out  # email masked
    assert "Adobe" in out  # non-PII breach name stays visible


def test_envelope_keeps_public_ip():
    # Public attacker IPs are NOT masked (protect_victim keeps attacker IOCs visible).
    out = r._envelope("103.107.116.202", "apiverve_ip_blacklist", {"ip": "103.107.116.202"})
    assert "103.107.116.202" in out


def test_sanitize_breach_strips_pii():
    # S7: leaked passwords/phones/addresses must be dropped; only verdict + metadata stay.
    raw = {"breached": True, "breaches": [
        {"name": "Adobe", "date": "2013", "leaked_password": "hunter2", "phone": "555-1234"},
    ]}
    out = r._sanitize_breach(raw)
    assert out["breached"] is True
    assert out["breaches"] == [{"name": "Adobe", "date": "2013"}]  # PII stripped
    assert "hunter2" not in json.dumps(out) and "555-1234" not in json.dumps(out)


def test_sanitize_breach_string_list():
    out = r._sanitize_breach({"found": True, "data": ["Adobe", "LinkedIn"]})
    assert out["breached"] is True
    assert out["breaches"] == [{"name": "Adobe"}, {"name": "LinkedIn"}]


def test_sanitize_breach_unknown_shape():
    # Unknown shape -> empty dict (nothing unsafe leaks).
    assert r._sanitize_breach({"unexpected": "shape"}) == {}


# blueteam_ioc_search WHOIS PII filter + detail_level framing
# Reduced from a real RapidAPI IOC Search body for 185.220.101.49 (Tor exit).
_WHOIS_FIXTURE = (
    "inetnum: 185.220.101.32 - 185.220.101.63\n"
    "descr: Network for Tor-Exit traffic.\n"
    "remarks: This network is used for Tor Exits.\n"
    "netname: TOR-EXIT\n"
    "country: DE\n"
    "admin-c: MM55214-RIPE\n"
    "tech-c: MM55214-RIPE\n"
    "status: ASSIGNED PA\n"
    "org-name: ForPrivacyNET\n"
    "address: Steinweg 18/20\n"
    "address: 53121 Bonn\n"
    "abuse-c: ACRO42986-RIPE\n"
    "person: Marco Maske\n"
    "address: Steinweg 18/20\n"
    "phone: +49\n"
    "fax-no: +49 228 92934876\n"
    "nic-hdl: MM55214-RIPE\n"
    "route: 185.220.101.0/24\n"
    "origin: AS60729\n"
)


def _ioc_fixture() -> dict:
    """Shape-faithful subset: 45 harmless / 14 malicious / 3 suspicious / 27 undetected."""
    return {
        "is_success": True,
        "message": "Success",
        "response_code": 200,
        "data": {
            "ip": "185.220.101.49",
            "as_owner": "Stiftung Erneuerbare Freiheit",
            "asn": 60729,
            "network": "185.220.101.0/24",
            "country": "DE",
            "continent": "EU",
            "internet_registry": "RIPE NCC",
            "reputation": 19,
            "tags": ["tor"],
            "analysis_date": 1789309660,
            "modification_date": 1789350442,
            "votes_result": {"harmless": 0, "malicious": 3},
            "security_vendor_analysis_stats": {
                "harmless": 45, "malicious": 14, "suspicious": 3, "undetected": 27,
            },
            "security_vendor_analysis": {
                "Abusix": {"enginename": "Abusix", "category": "malicious", "result": "malicious"},
                "Webroot": {"enginename": "Webroot", "category": "malicious", "result": "malicious"},
                "GreyNoise": {"enginename": "GreyNoise", "category": "suspicious", "result": "suspicious"},
                "ESET": {"enginename": "ESET", "category": "harmless", "result": "clean"},
            },
            "communicating_files": [
                {"sha256": "4a05e4fd" + "0" * 56, "names": ["ntdll.dll"],
                 "type_description": "Win32 EXE", "size": 134154,
                 "security_vendor_analysis_stats": {"malicious": 60}},
                {"sha256": "3c866319" + "0" * 56, "names": ["stealer.exe"],
                 "type_description": "Win32 EXE", "size": 416768,
                 "packers": {"Cyren": "UPX"},
                 "security_vendor_analysis_stats": {"malicious": 37}},
            ],
            "referrerFiles": [{"meaningful_name": "stealer.exe"}, {"names": ["on"]}],
            "resolutions": [
                {"host_name": "shanmorris.camdvr.org", "resolved_date": 1739247653,
                 "security_vendor_ip_address_analysis_stats": {"malicious": 14}},
                {"host_name": "gfwsxi.ldiseaselsn.xyz", "resolved_date": 1681517711,
                 "security_vendor_ip_address_analysis_stats": {"malicious": 10}},
            ],
            "whois": _WHOIS_FIXTURE,
        },
    }


class TestWhoisPiiFilter:
    """The allowlist is the PII contract: it has no bypass, at any detail_level."""
    def test_keeps_technical_registry_fields(self):
        out = r._strip_whois_pii(_WHOIS_FIXTURE)
        for keep in ("netname", "country", "org-name", "route", "origin",
                     "inetnum", "descr", "admin-c", "tech-c", "abuse-c"):
            assert keep in out, keep
        assert out["netname"] == ["TOR-EXIT"]
        assert out["route"] == ["185.220.101.0/24"]

    def test_drops_person_address_phone_fax_and_handles(self):
        out = r._strip_whois_pii(_WHOIS_FIXTURE)
        for drop in ("person", "address", "phone", "fax-no", "nic-hdl", "remarks"):
            assert drop not in out, f"{drop} must not survive the allowlist"
        blob = json.dumps(out)
        for value in ("Marco Maske", "Steinweg 18/20", "53121 Bonn", "92934876", "+49"):
            assert value not in blob, value

    def test_caps_value_length(self):
        out = r._strip_whois_pii("descr: " + "x" * 500 + "\n")
        assert len(out["descr"][0]) == 200

    def test_ignores_lines_without_a_colon(self):
        assert r._strip_whois_pii("garbage line\nnetname: TOR-EXIT\n") == {"netname": ["TOR-EXIT"]}


class TestIocSearchLevels:
    def test_summary_is_verdict_first(self):
        out = r._normalize_ioc_search("185.220.101.49", _ioc_fixture(), "summary")
        v = out["verdict"]
        assert v["malicious_engines"] == 14
        assert v["total_engines"] == 89
        assert v["malicious_ratio"] == 0.157
        assert v["band"] == "minority-malicious"
        assert v["tags"] == ["tor"]
        assert v["provided_reputation"] == 19
        assert out["network"]["asn"] == 60729

    def test_summary_omits_forensic_sections(self):
        out = r._normalize_ioc_search("185.220.101.49", _ioc_fixture(), "summary")
        assert "flagged_vendors" not in out
        assert "referrer_files" not in out
        assert out["referrer_files_count"] == 2
        assert "raw" not in out

    def test_forensic_adds_flagged_vendors_only(self):
        out = r._normalize_ioc_search("185.220.101.49", _ioc_fixture(), "forensic")
        engines = {x["engine"] for x in out["flagged_vendors"]}
        assert engines == {"Abusix", "Webroot", "GreyNoise"}  # ESET (harmless) excluded
        assert out["flagged_vendors"][0]["category"] == "malicious"  # malicious ranked first
        assert "raw" not in out

    def test_markdown_render_leads_with_the_verdict(self):
        out = r._normalize_ioc_search("185.220.101.49", _ioc_fixture(), "forensic")
        text = r._render_ioc_search(out)
        assert "14/89 engines malicious" in text.splitlines()[2]
        assert "band: minority-malicious" in text.splitlines()[2]
        assert "tor" in text.splitlines()[2]
        assert "TOR-EXIT" in text
        assert "Marco Maske" not in text and "Steinweg" not in text

    def test_resolutions_newest_first_with_iso_dates(self):
        out = r._normalize_ioc_search("185.220.101.49", _ioc_fixture(), "summary")
        names = [x["host_name"] for x in out["resolutions"]]
        assert names == ["shanmorris.camdvr.org", "gfwsxi.ldiseaselsn.xyz"]
        assert out["timestamps"]["analysis_date"].startswith("2026-")

    def test_raw_keeps_verbatim_body_with_whois_filtered(self):
        out = r._normalize_ioc_search("185.220.101.49", _ioc_fixture(), "raw")
        assert out["raw"]["is_success"] is True
        assert out["raw"]["data"]["security_vendor_analysis"]["Abusix"]["category"] == "malicious"
        assert isinstance(out["raw"]["data"]["whois"], dict)  # replaced, not verbatim
        assert "person" not in out["raw"]["data"]["whois"]
        assert "Marco Maske" not in json.dumps(out["raw"])

    def test_raw_does_not_mutate_the_cached_body(self):
        """_rapidapi_get hands back a cached object; filtering must not poison it."""
        fixture = _ioc_fixture()
        r._normalize_ioc_search("185.220.101.49", fixture, "raw")
        assert isinstance(fixture["data"]["whois"], str)
        assert "Marco Maske" in fixture["data"]["whois"]


class TestIocSearchDegradation:
    """A field we failed to map must read as unknown, never as zero."""
    def test_missing_stats_yields_no_verdict_and_no_zeros(self):
        raw = _ioc_fixture()
        del raw["data"]["security_vendor_analysis_stats"]
        out = r._normalize_ioc_search("185.220.101.49", raw, "summary")
        assert "verdict" not in out
        assert "security_vendor_analysis_stats" in out["unknown_fields"]
        assert "malicious_engines" not in json.dumps(out)

    def test_zero_total_omits_ratio_and_band(self):
        raw = _ioc_fixture()
        raw["data"]["security_vendor_analysis_stats"] = {
            "harmless": 0, "malicious": 0, "suspicious": 0, "undetected": 0}
        v = r._normalize_ioc_search("185.220.101.49", raw, "summary")["verdict"]
        assert "malicious_ratio" not in v and "band" not in v
        assert v["total_engines"] == 0

    def test_unreadable_response_errors_without_zeros(self):
        out = r._normalize_ioc_search("185.220.101.49", {"is_success": False, "message": "nope"}, "summary")
        assert out["error"] == "nope"
        assert out["unknown_fields"] == ["data"]
        assert "verdict" not in out

    def test_error_render_says_so(self):
        out = r._normalize_ioc_search("1.2.3.4", {}, "summary")
        assert "Could not read provider response" in r._render_ioc_search(out)

    @pytest.mark.asyncio
    async def test_raw_over_cap_raises_instead_of_returning_text(self, monkeypatch):
        """Regression: a returned error string reaches MCP as isError=false."""
        from mcp_server.core.exceptions import ThreatIntelError
        monkeypatch.setattr(r, "_RAW_BODY_MAX_CHARS", 10)
        monkeypatch.setattr(r, "_rapidapi_get", lambda *a, **k: _async(_ioc_fixture()))
        with pytest.raises(ThreatIntelError, match="raw cap"):
            await r.blueteam_ioc_search(r.IocSearchInput(ip="185.220.101.49", detail_level="raw"))


def _async(value):
    async def _coro():
        return value
    return _coro()


def test_limiter_serializes_requests():
    # max_concurrent=1 is what makes min_interval mean "time between request
    # starts". Under concurrency the shared limiter reserves nothing, so N waiters
    # wake together and burst straight past the free-tier ceiling.
    assert r._limiter._semaphore._value == 1
    assert r._limiter.min_interval >= 0.2


@pytest.mark.asyncio
async def test_rapidapi_get_uses_config_ttl_and_its_own_pool(monkeypatch):
    """Regression: RAPIDAPI_CACHE_TTL was dead config and the pool was shared."""
    os.environ["RAPIDAPI_KEY"] = "test-key"
    captured: dict = {}

    class _Resp:
        def json(self):
            return {"ok": True}

    async def fake_api_call(method, url, **kw):
        captured["method"] = method
        captured.update(kw)
        return _Resp()

    def fake_cache_get(namespace, key):
        return None

    def fake_cache_set(namespace, key, value, ttl):
        captured["ttl"] = ttl

    # Every RapidAPI request now runs through the account-wide budget guard, so these
    # cache/pool assertions need an armed window or they fail on "Budget closed".
    from mcp_server.threat_intel.rapidapi_quota import RapidApiBudget
    monkeypatch.setattr(r, "_QUOTA", RapidApiBudget(budget=5, hours=1))
    monkeypatch.setattr(r, "_api_call", fake_api_call)
    monkeypatch.setattr(r, "cache_get", fake_cache_get)
    monkeypatch.setattr(r, "cache_set", fake_cache_set)

    data = await r._rapidapi_get("example.p.rapidapi.com", "/x?ip=1.2.3.4")

    assert data == {"ok": True}
    assert captured["method"] == "get"
    assert captured["client_name"] == "rapidapi"  # own pool + own circuit breaker
    assert captured["ttl"] == r.RAPIDAPI_CACHE_TTL  # from config, not hardcoded 1800


@pytest.mark.asyncio
async def test_rapidapi_get_honours_explicit_ttl(monkeypatch):
    os.environ["RAPIDAPI_KEY"] = "test-key"
    captured: dict = {}

    class _Resp:
        def json(self):
            return {"ok": True}

    async def fake_api_call(method, url, **kw):
        return _Resp()

    def fake_cache_get(namespace, key):
        return None

    def fake_cache_set(namespace, key, value, ttl):
        captured["ttl"] = ttl

    from mcp_server.threat_intel.rapidapi_quota import RapidApiBudget
    monkeypatch.setattr(r, "_QUOTA", RapidApiBudget(budget=5, hours=1))
    monkeypatch.setattr(r, "_api_call", fake_api_call)
    monkeypatch.setattr(r, "cache_get", fake_cache_get)
    monkeypatch.setattr(r, "cache_set", fake_cache_set)

    await r._rapidapi_get("example.p.rapidapi.com", "/x", ttl=60)
    assert captured["ttl"] == 60
