#!/usr/bin/env python3
"""Unit tests for the offensive.agency lookup and host tools.

Every test mocks the HTTP boundary. None contacts offensive.agency, Wazuh, or
ONYPHE. The live contract was observed manually on 2026-11-25; this suite does
not claim integration validation.
"""
from __future__ import annotations

import asyncio
import json
import time

import httpx
import pytest
from pydantic import ValidationError

import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer.invalid")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import mcp_server.threat_intel.offensive_agency as oa
import mcp_server.tools.offensive_agency as tool_mod
from mcp_server import mcp
from mcp_server.core.exceptions import ThreatIntelError
from mcp_server.core.http_client import ResponseTooLargeError
from mcp_server.threat_intel._cache import cache_delete_prefix
from mcp_server.tools.offensive_agency import (
    OffensiveAgencyHostInput,
    OffensiveAgencyLookupInput,
    _project_host_payload,
    _project_match,
    blueteam_offensive_agency_host,
    blueteam_offensive_agency_lookup,
    prepare_batch,
)

ATTR = ("Data by ONYPHE (https://www.onyphe.io), published by offensive.agency. "
        "Free to use, please credit both.")


class FakeResponse:
    status_code = 200

    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


@pytest.fixture(autouse=True)
def _clear_cache():
    cache_delete_prefix("offensive_agency", "")
    tool_mod._LOOKUP_REFS.clear()
    yield
    cache_delete_prefix("offensive_agency", "")
    tool_mod._LOOKUP_REFS.clear()


def _run(coro):
    return asyncio.run(coro)


def _capture(monkeypatch, handler):
    calls = []

    async def fake(method, url, **kw):
        calls.append((method, url, kw))
        return handler(method, url, kw)

    monkeypatch.setattr(oa, "_api_call", fake)
    return calls


def _reference_for(monkeypatch, ip, host_handler=None):
    _capture(monkeypatch, lambda *_: FakeResponse(
        _lookup_payload(matches=[_match(ip)])))
    out = _run(blueteam_offensive_agency_lookup(OffensiveAgencyLookupInput(
        indicators=[ip], selection_basis="attacker_c2", response_format="json")))
    reference = json.loads(out)["lookup_reference"]
    assert isinstance(reference, str) and reference
    if host_handler is not None:
        _capture(monkeypatch, host_handler)
    return reference


def _lookup_payload(matches=None, not_found=None, invalid=None,
                    ref_day="2026-11-25"):
    return {
        "data": {
            "matches": matches or [],
            "not_found": not_found or [],
            "invalid": invalid or [],
        },
        "meta": {"ref_day": ref_day, "active_since": "2026-11-19",
                 "attribution": ATTR},
    }


def _host_payload(ip="49.51.141.166", kind="hosting", active=True,
                  services=None, domains=None):
    return {
        "data": {
            "ip": ip,
            "active": active,
            "first_seen": "2026-11-22",
            "last_seen": "2026-11-22",
            "network": {"asn": "AS132203", "country": "DE", "kind": kind,
                        "org": "Tencent", "rdns": []},
            "agents": [{"name": "ARTEX", "slug": "artex", "level": "confirmed",
                        "families": ["favicon"], "ports": [443]}],
            "clusters": ["antifox"],
            "cohosting": {"c2": [], "classes": ["Web Server"]},
            "domains": domains or [],
            "services": services or [{
                "port": 443, "products": ["Nginx"], "titles": ["AntiFox"],
                "cert_cn": ["49-51-141-166.sslip.io"], "classes": ["Web Server"],
                "tls": True, "last_seen": "2026-11-22", "agents": ["artex"],
            }],
            "sources": ["ctiscan"],
            "timeline": {"artex": ["2026-11-22"]},
            "titles": ["AntiFox"],
        },
        "meta": {"ref_day": "2026-11-25", "active_since": "2026-11-19",
                 "attribution": ATTR},
    }


def _status_error(status, payload):
    request = httpx.Request("GET", "https://www.offensive.agency/api/v1/x")
    response = httpx.Response(status, request=request, json=payload)
    return httpx.HTTPStatusError("upstream", request=request, response=response)


def _match(ip, active=True, kind="hosting"):
    return {
        "indicator": ip,
        "type": "ip",
        "hosts": [{
            "ip": ip, "active": active, "first_seen": "2026-11-22",
            "last_seen": "2026-11-22",
            "network": {"asn": "AS1", "country": "DE", "kind": kind,
                        "org": "Example", "rdns": []},
            "agents": [{"name": "ARTEX", "slug": "artex", "level": "confirmed",
                        "families": ["favicon"], "ports": [443]}],
            "clusters": ["antifox"],
            "cohosting": {"c2": [], "classes": []},
        }],
        "domains": [],
    }


# Classification and validation
@pytest.mark.parametrize("value,expected", [
    ("49.51.141.166", "ip"),
    ("2606:4700:4700::1111", "ip"),
    ("5.39.0.0/16", "cidr"),
    ("2606:4700::/32", "cidr"),
    ("evil.example.org", "domain"),
    ("EVIL.EXAMPLE.ORG.", "domain"),
])
def test_supported_types_are_sent(value, expected):
    batch = prepare_batch([value])
    assert batch.send_queries
    assert batch.groups[0]["detected_type"] == expected


@pytest.mark.parametrize("value", [
    "10.0.0.5", "127.0.0.1", "169.254.1.1", "100.64.0.1", "0.0.0.0",
    "224.0.0.1", "192.0.2.1", "198.18.0.1", "192.88.99.1",
    "::1", "fe80::1", "ff02::1", "::", "2001:db8::1", "2001:2::1",
    "2002::1", "fc00::1", "64:ff9b::1", "2001:20::1",
])
def test_private_reserved_and_special_use_rejected(value):
    batch = prepare_batch([value])
    assert not batch.send_queries
    assert batch.groups[0]["outcome"] == "rejected"
    assert batch.groups[0]["reason"]


def test_cidr_host_bits_cleared_and_reported():
    batch = prepare_batch(["1.2.3.4/24"])
    assert batch.send_queries == ["1.2.3.0/24"]
    assert batch.groups[0]["original_indicators"] == ["1.2.3.4/24"]


def test_cidr_straddling_private_space_rejected():
    batch = prepare_batch(["172.0.0.0/10"])
    assert not batch.send_queries
    assert batch.groups[0]["reason"] == "special_use_network"


def test_invalid_prefix_is_rejected_not_unsupported():
    batch = prepare_batch(["1.2.3.4/33"])
    assert batch.groups[0]["outcome"] == "rejected"
    assert batch.groups[0]["reason"] == "invalid_network"


@pytest.mark.parametrize("value,detected,reason", [
    ("999.1.1.1", "ip", "invalid_ip"),
    ("010.0.0.1", "ip", "invalid_ip"),
    ("2001:::1", "ip", "invalid_ip"),
    ("999.1.1.1/24", "cidr", "invalid_network"),
])
def test_malformed_ip_is_rejected_not_misclassified(value, detected, reason):
    batch = prepare_batch([value])
    assert batch.groups[0]["outcome"] == "rejected"
    assert batch.groups[0]["detected_type"] == detected
    assert batch.groups[0]["reason"] == reason


@pytest.mark.parametrize("value,detected", [
    ("http://evil.example/payload", "url"),
    ("hxxp://evil[.]example", "defanged"),
    ("analyst@evil.example", "email"),
    ("d41d8cd98f00b204e9800998ecf8427e", "hash"),
    ("CVE-2024-1234", "cve"),
    ("AS132203", "asn"),
    ("C:\\Windows\\System32\\cmd.exe", "file_path"),
    ("HKLM\\Software\\Example", "registry_key"),
    ("*.evil.example", "wildcard"),
    ("1.2.3.4:8080", "ip_with_port"),
    ("aa:bb:cc:dd:ee:ff", "mac_address"),
    ("evil.example:8080", "domain_with_port"),
    ("abc:8080", "domain_with_port"),
    ("Mozilla/5.0 (Windows NT 10.0)", "user_agent"),
    ("localhost", "unknown"),
])
def test_unsupported_types_preserved(value, detected):
    batch = prepare_batch([value])
    assert not batch.send_queries
    assert batch.groups[0]["outcome"] == "unsupported"
    assert batch.groups[0]["detected_type"] == detected
    assert batch.groups[0]["original_indicators"] == [value]
    assert batch.groups[0]["reason"] == "unsupported_indicator_type"


def test_url_with_ip_host_is_not_extracted():
    batch = prepare_batch(["http://1.2.3.4/path"])
    assert not batch.send_queries
    assert batch.groups[0]["detected_type"] == "url"


def test_domain_aliases_are_preserved_and_one_query_sent():
    batch = prepare_batch(["EVIL.EXAMPLE.ORG.", "evil.example.org"])
    assert batch.send_queries == ["evil.example.org"]
    assert batch.groups[0]["original_indicators"] == ["EVIL.EXAMPLE.ORG.", "evil.example.org"]
    assert batch.duplicates_removed == 1


def test_reserved_tld_rejected():
    batch = prepare_batch(["foo.example", "foo.local", "foo.onion"])
    assert not batch.send_queries
    assert all(g["reason"] == "reserved_tld" for g in batch.groups)


def test_empty_and_overlong_items_rejected():
    batch = prepare_batch(["", "a" * 3000])
    assert not batch.send_queries
    assert {g["reason"] for g in batch.groups} == {"empty_indicator",
                                                   "indicator_too_long"}


def test_control_characters_rejected():
    batch = prepare_batch(["evil\n.example", "good.example.org"])
    assert batch.send_queries == ["good.example.org"]
    assert batch.groups[0]["reason"] == "invalid_characters"


def test_raw_batch_limit():
    with pytest.raises(ValidationError):
        OffensiveAgencyLookupInput(
            indicators=["1.1.1.1"] * 10_001,
            selection_basis="confirmed_malicious_source",
        )


def test_network_limit():
    nets = [f"1.2.{i}.0/24" for i in range(201)]
    with pytest.raises(ThreatIntelError) as exc:
        prepare_batch(nets)
    assert "network_limit_exceeded" in str(exc.value)


def test_max_hosts_bounds():
    with pytest.raises(ValidationError):
        OffensiveAgencyLookupInput(
            indicators=["1.1.1.1"], selection_basis="attacker_c2",
            max_hosts_per_indicator=0)
    with pytest.raises(ValidationError):
        OffensiveAgencyLookupInput(
            indicators=["1.1.1.1"], selection_basis="attacker_c2",
            max_hosts_per_indicator=501)


def test_selection_basis_required():
    with pytest.raises(ValidationError):
        OffensiveAgencyLookupInput(indicators=["1.1.1.1"])


def test_unsupported_rows_are_paged_without_loss(monkeypatch):
    calls = _capture(monkeypatch, lambda *_: pytest.fail("must not be called"))
    indicators = [f"http://evil{i}.example/path" for i in range(150)]
    first = json.loads(_run(blueteam_offensive_agency_lookup(
        OffensiveAgencyLookupInput(
            indicators=indicators, selection_basis="attacker_infrastructure",
            response_format="json"))))
    assert not calls
    assert len(first["unsupported"]) == 100
    assert first["unsupported_total"] == 150
    assert first["unsupported_remaining"] == 50
    assert first["unsupported_next_offset"] == 100
    assert first["unsupported_by_type"] == {"url": 150}
    second = json.loads(_run(blueteam_offensive_agency_lookup(
        OffensiveAgencyLookupInput(
            indicators=indicators, selection_basis="attacker_infrastructure",
            unsupported_offset=100, response_format="json"))))
    assert not calls
    assert len(second["unsupported"]) == 50
    assert second["unsupported_total"] == 150
    assert second["unsupported_remaining"] == 0
    assert second["unsupported_next_offset"] is None
    assert second["unsupported"][0]["original_indicators"] == [
        "http://evil100.example/path"]
    assert second["unsupported"][-1]["original_indicators"] == [
        "http://evil149.example/path"]


def test_rejected_rows_are_paged_without_loss(monkeypatch):
    calls = _capture(monkeypatch, lambda *_: pytest.fail("must not be called"))
    indicators = [f"10.0.0.{i}" for i in range(150)]
    first = json.loads(_run(blueteam_offensive_agency_lookup(
        OffensiveAgencyLookupInput(
            indicators=indicators, selection_basis="attacker_network",
            response_format="json"))))
    assert not calls
    assert len(first["rejected"]) == 100
    assert first["rejected_total"] == 150
    assert first["rejected_next_offset"] == 100
    second = json.loads(_run(blueteam_offensive_agency_lookup(
        OffensiveAgencyLookupInput(
            indicators=indicators, selection_basis="attacker_network",
            rejected_offset=100, response_format="json"))))
    assert not calls
    assert len(second["rejected"]) == 50
    assert second["rejected"][0]["original_indicators"] == ["10.0.0.100"]
    assert second["rejected"][-1]["original_indicators"] == ["10.0.0.149"]
    assert second["rejected_next_offset"] is None


def test_tool_returns_rejected_for_long_item(monkeypatch):
    calls = _capture(monkeypatch, lambda *_: pytest.fail("must not be called"))
    out = _run(blueteam_offensive_agency_lookup(OffensiveAgencyLookupInput(
        indicators=["a" * 3000], selection_basis="attacker_infrastructure",
        response_format="json")))
    result = json.loads(out)
    assert not calls
    assert result["rejected"][0]["reason"] == "indicator_too_long"
    assert result["transmission"]["indicators_sent"] == 0


def test_malicious_destination_basis_accepted():
    inp = OffensiveAgencyLookupInput(indicators=["1.1.1.1"],
                                     selection_basis="malicious_destination")
    assert inp.selection_basis == "malicious_destination"


def test_no_consent_parameter():
    fields = set(OffensiveAgencyLookupInput.model_fields)
    assert not fields & {"acknowledge_ioc_sharing", "confirm", "consent",
                         "acknowledge_sharing"}


# Request and output
def test_lookup_request_body_only_indicators(monkeypatch):
    calls = _capture(monkeypatch, lambda *_: FakeResponse(
        _lookup_payload(matches=[_match("49.51.141.166")],
                        not_found=["8.8.8.8"])))
    out = _run(blueteam_offensive_agency_lookup(OffensiveAgencyLookupInput(
        indicators=["49.51.141.166", "8.8.8.8"],
        selection_basis="confirmed_malicious_source",
        evidence_ref="case IR-2026-001",
        response_format="json",
    )))
    body = calls[0][2]["json"]
    assert body == {"indicators": ["49.51.141.166", "8.8.8.8"]}
    assert "selection_basis" not in body and "evidence_ref" not in body
    result = json.loads(out)
    assert result["selection"]["basis"] == "confirmed_malicious_source"
    assert result["selection"]["evidence_ref"] == "case IR-2026-001"
    assert result["transmission"]["indicators_sent"] == 2
    assert result["matched_count"] == 1
    assert result["not_found_count"] == 1
    assert len(result["input_digest"]) == 64
    assert "49.51.141.166" not in result["input_digest"]
    assert result["display_caps"]["hosts_per_indicator"] == 25
    assert result["display_caps"]["unsupported_rows_per_page"] == 100


def test_mixed_batch_accounting(monkeypatch):
    calls = _capture(monkeypatch, lambda *_: FakeResponse(
        _lookup_payload(matches=[_match("49.51.141.166")],
                        not_found=["8.8.8.8", "evil.example.org"])))
    out = _run(blueteam_offensive_agency_lookup(OffensiveAgencyLookupInput(
        indicators=["49.51.141.166", "8.8.8.8", "10.0.0.5",
                    "http://evil.example", "EVIL.EXAMPLE.ORG.", "evil.example.org"],
        selection_basis="attacker_infrastructure",
        response_format="json",
    )))
    result = json.loads(out)
    assert result["submitted_raw"] == 6
    assert result["submitted_unique"] == 5
    assert result["duplicates_removed"] == 1
    assert result["matched_count"] == 1
    assert result["not_found_count"] == 2
    assert result["invalid_count"] == 0
    assert result["unsupported_count"] == 1
    assert result["rejected_count"] == 1
    assert result["sent_count"] == 3
    assert result["submitted_unique"] == (
        result["matched_count"] + result["not_found_count"]
        + result["invalid_count"] + result["unsupported_count"]
        + result["rejected_count"])
    assert calls[0][2]["json"] == {
        "indicators": ["49.51.141.166", "8.8.8.8", "evil.example.org"]}


def test_no_supported_indicators_makes_no_request(monkeypatch):
    calls = _capture(monkeypatch, lambda *_: pytest.fail("must not be called"))
    out = _run(blueteam_offensive_agency_lookup(OffensiveAgencyLookupInput(
        indicators=["10.0.0.5", "http://evil.example"],
        selection_basis="attacker_infrastructure",
        response_format="json",
    )))
    result = json.loads(out)
    assert not calls
    assert result["status"] == "nothing_sent"
    assert result["sent_count"] == 0
    assert result["rejected_count"] == 1
    assert result["unsupported_count"] == 1
    assert result["transmission"]["indicators_sent"] == 0
    assert result["transmission"]["unsupported_not_sent"] == 1


def test_cdn_flag_and_active_counts(monkeypatch):
    payload = _lookup_payload(matches=[
        _match("49.51.141.166", active=True, kind="cdn"),
        _match("92.255.57.87", active=False, kind="hosting"),
    ])
    _capture(monkeypatch, lambda *_: FakeResponse(payload))
    out = _run(blueteam_offensive_agency_lookup(OffensiveAgencyLookupInput(
        indicators=["49.51.141.166", "92.255.57.87"],
        selection_basis="attacker_c2",
        response_format="json",
    )))
    result = json.loads(out)
    assert result["matches"][0]["shared_cdn_hosts"] == 1
    assert result["matches"][0]["hosts"]["items"][0]["shared_cdn"] is True
    assert result["matches"][1]["inactive_hosts"] == 1
    assert result["matches"][1]["hosts"]["items"][0]["active"] is False


def test_subdomain_match_scope(monkeypatch):
    payload = _lookup_payload(matches=[{
        "indicator": "h1xx.net",
        "type": "domain",
        "hosts": [],
        "domains": [{"name": "artex.h1xx.net", "behind_cdn": False,
                     "first_seen": "2026-11-22", "last_seen": "2026-11-22",
                     "ips": ["89.167.96.25"], "agents": {"artex": "confirmed"}}],
    }])
    _capture(monkeypatch, lambda *_: FakeResponse(payload))
    out = _run(blueteam_offensive_agency_lookup(OffensiveAgencyLookupInput(
        indicators=["h1xx.net"], selection_basis="malicious_domain",
        response_format="json",
    )))
    result = json.loads(out)
    assert result["matches"][0]["match_scope"] == "domain_subdomain"
    assert result["matches"][0]["domains"]["items"][0]["name"] == "artex.h1xx.net"


def test_upstream_omission_is_invalid_not_dropped(monkeypatch):
    _capture(monkeypatch, lambda *_: FakeResponse(_lookup_payload()))
    out = _run(blueteam_offensive_agency_lookup(OffensiveAgencyLookupInput(
        indicators=["49.51.141.166"], selection_basis="attacker_c2",
        response_format="json",
    )))
    result = json.loads(out)
    assert result["invalid_count"] == 1
    assert result["invalid"][0]["reason"] == "upstream_omitted"
    assert result["invalid"][0]["original_indicators"] == ["49.51.141.166"]


def test_cache_hit_avoids_second_request(monkeypatch):
    calls = _capture(monkeypatch, lambda *_: FakeResponse(
        _lookup_payload(matches=[_match("49.51.141.166")])))
    inp = OffensiveAgencyLookupInput(
        indicators=["49.51.141.166"], selection_basis="attacker_c2",
        response_format="json")
    _run(blueteam_offensive_agency_lookup(inp))
    _run(blueteam_offensive_agency_lookup(inp))
    assert len(calls) == 1


def test_cache_merges_unsupported_items(monkeypatch):
    calls = _capture(monkeypatch, lambda *_: FakeResponse(
        _lookup_payload(matches=[_match("49.51.141.166")])))
    _run(blueteam_offensive_agency_lookup(OffensiveAgencyLookupInput(
        indicators=["49.51.141.166"], selection_basis="attacker_c2",
        response_format="json")))
    out = _run(blueteam_offensive_agency_lookup(OffensiveAgencyLookupInput(
        indicators=["49.51.141.166", "http://evil.example"],
        selection_basis="attacker_c2", response_format="json")))
    result = json.loads(out)
    assert len(calls) == 1
    assert result["matched_count"] == 1
    assert result["unsupported"][0]["original_indicators"] == ["http://evil.example"]


def test_host_projection(monkeypatch):
    reference = _reference_for(monkeypatch, "49.51.141.166",
                               lambda *_: FakeResponse(_host_payload()))
    out = _run(blueteam_offensive_agency_host(OffensiveAgencyHostInput(
        ip="49.51.141.166", lookup_reference=reference, response_format="json")))
    result = json.loads(out)
    assert result["tracked"] is True
    assert result["active"] is True
    assert result["services"]["total_count"] == 1
    assert result["services"]["items"][0]["port"] == 443
    assert result["timeline"]["items"] == {"artex": ["2026-11-22"]}
    assert result["transmission"]["indicators_sent"] == 1
    assert result["display_caps"]["services_per_host"] == 100
    assert "ONYPHE" in result["attribution"]


def test_host_markdown_renders(monkeypatch):
    reference = _reference_for(monkeypatch, "49.51.141.166",
                               lambda *_: FakeResponse(_host_payload()))
    out = _run(blueteam_offensive_agency_host(OffensiveAgencyHostInput(
        ip="49.51.141.166", lookup_reference=reference)))
    assert "## Services" in out
    assert "ARTEX" in out
    assert "ONYPHE" in out
    assert "active" in out.lower()


def test_host_404_is_a_result(monkeypatch):
    def _raise(*_):
        raise _status_error(404, {"error": {"status": 404, "code": "not_found",
                                            "message": "8.8.8.8 is not in the tracker."}})
    reference = _reference_for(monkeypatch, "8.8.8.8", _raise)
    out = _run(blueteam_offensive_agency_host(OffensiveAgencyHostInput(
        ip="8.8.8.8", lookup_reference=reference, response_format="json")))
    result = json.loads(out)
    assert result["status"] == "not_found"
    assert result["tracked"] is False
    assert "not in the tracker" in result["message"]


def test_host_requires_lookup_reference():
    with pytest.raises(ValidationError):
        OffensiveAgencyHostInput(ip="49.51.141.166")


def test_host_rejects_unknown_reference(monkeypatch):
    calls = _capture(monkeypatch, lambda *_: pytest.fail("must not be called"))
    with pytest.raises(ThreatIntelError) as exc:
        _run(blueteam_offensive_agency_host(OffensiveAgencyHostInput(
            ip="49.51.141.166", lookup_reference="unknown-reference",
            response_format="json")))
    assert "lookup_reference_invalid" in str(exc.value)
    assert not calls


def test_host_rejects_unmatched_ip(monkeypatch):
    reference = _reference_for(monkeypatch, "1.1.1.1")
    calls = _capture(monkeypatch, lambda *_: pytest.fail("must not be called"))
    with pytest.raises(ThreatIntelError) as exc:
        _run(blueteam_offensive_agency_host(OffensiveAgencyHostInput(
            ip="8.8.8.8", lookup_reference=reference, response_format="json")))
    assert "lookup_reference_mismatch" in str(exc.value)
    assert not calls


def test_host_rejects_expired_reference(monkeypatch):
    reference = _reference_for(monkeypatch, "1.1.1.1")
    tool_mod._LOOKUP_REFS[reference] = (
        time.monotonic() - 1, frozenset({"1.1.1.1"}))
    with pytest.raises(ThreatIntelError) as exc:
        _run(blueteam_offensive_agency_host(OffensiveAgencyHostInput(
            ip="1.1.1.1", lookup_reference=reference, response_format="json")))
    assert "lookup_reference_expired" in str(exc.value)


def test_lookup_400_surfaces_upstream_message(monkeypatch):
    def _raise(*_):
        raise _status_error(400, {"error": {"status": 400, "code": "bad_parameter",
                                            "message": "too many networks"}})
    _capture(monkeypatch, _raise)
    with pytest.raises(ThreatIntelError) as exc:
        _run(blueteam_offensive_agency_lookup(OffensiveAgencyLookupInput(
            indicators=["1.1.1.1"], selection_basis="attacker_c2")))
    text = str(exc.value)
    assert "bad_request" in text and "too many networks" in text


def test_timeout_is_typed(monkeypatch):
    def _raise(*_):
        request = httpx.Request("POST", "https://www.offensive.agency/api/v1/lookup")
        raise httpx.ReadTimeout("timed out", request=request)
    _capture(monkeypatch, _raise)
    with pytest.raises(ThreatIntelError) as exc:
        _run(blueteam_offensive_agency_lookup(OffensiveAgencyLookupInput(
            indicators=["1.1.1.1"], selection_basis="attacker_c2")))
    assert "timed out" in str(exc.value).lower()


def test_oversized_response_is_typed(monkeypatch):
    def _raise(*_):
        raise ResponseTooLargeError(2_000_000)
    _capture(monkeypatch, _raise)
    with pytest.raises(ThreatIntelError) as exc:
        _run(blueteam_offensive_agency_lookup(OffensiveAgencyLookupInput(
            indicators=["1.1.1.1"], selection_basis="attacker_c2")))
    assert "response_too_large" in str(exc.value)


def test_missing_envelope_is_typed(monkeypatch):
    _capture(monkeypatch, lambda *_: FakeResponse({"data": {}}))
    with pytest.raises(ThreatIntelError) as exc:
        _run(blueteam_offensive_agency_lookup(OffensiveAgencyLookupInput(
            indicators=["1.1.1.1"], selection_basis="attacker_c2")))
    assert "data/meta" in str(exc.value)


def _capped(wrapper, total, returned):
    assert wrapper["total_count"] == total
    assert wrapper["returned_count"] == returned
    assert wrapper["truncated"] is True


def test_nested_metadata_counts_in_match():
    hosts = []
    for i in range(30):
        hosts.append({
            "ip": f"8.8.{i}.1", "active": True,
            "network": {"asn": "AS1", "country": "US", "kind": "hosting",
                        "org": "X", "rdns": [f"r{j}" for j in range(12)]},
            "agents": [{"name": f"A{j}", "slug": f"a{j}", "level": "confirmed",
                        "families": [f"f{k}" for k in range(12)],
                        "ports": list(range(25))} for j in range(25)],
            "clusters": [f"C{j}" for j in range(25)],
            "cohosting": {"c2": [f"C2{j}" for j in range(25)],
                          "classes": [f"K{j}" for j in range(25)]},
        })
    domains = [{
        "name": f"d{i}.example.org", "behind_cdn": False,
        "ips": [f"9.9.9.{j}" for j in range(12)],
        "agents": {f"a{j}": "confirmed" for j in range(25)},
    } for i in range(60)]
    match = {"indicator": "103.160.37.23", "type": "ip",
             "hosts": hosts, "domains": domains}
    batch = prepare_batch(["103.160.37.23"])
    projected = _project_match(match, batch.groups[0], 25)
    _capped(projected["hosts"], 30, 25)
    _capped(projected["domains"], 60, 50)
    host = projected["hosts"]["items"][0]
    _capped(host["agents"], 25, 20)
    _capped(host["agents"]["items"][0]["families"], 12, 10)
    _capped(host["agents"]["items"][0]["ports"], 25, 20)
    _capped(host["clusters"], 25, 20)
    _capped(host["cohosting"]["c2"], 25, 20)
    _capped(host["cohosting"]["classes"], 25, 20)
    _capped(host["network"]["rdns"], 12, 10)
    domain = projected["domains"]["items"][0]
    _capped(domain["ips"], 12, 10)
    _capped(domain["agents"], 25, 20)


def test_nested_metadata_counts_in_host_detail():
    services = [{
        "port": 443, "products": [f"p{j}" for j in range(25)],
        "titles": [f"t{j}" for j in range(12)],
        "cert_cn": [f"c{j}" for j in range(12)],
        "classes": [f"k{j}" for j in range(12)],
        "agents": [f"a{j}" for j in range(12)],
        "tls": True, "last_seen": "2026-11-25",
    } for _ in range(110)]
    domains = [{"name": f"d{i}.example.org", "behind_cdn": False,
                "ips": [f"9.9.9.{j}" for j in range(12)],
                "agents": {f"a{j}": "confirmed" for j in range(25)}}
               for i in range(60)]
    data = {
        "ip": "103.160.37.23", "active": True,
        "network": {"asn": "AS1", "country": "ID", "kind": "hosting",
                    "org": "X", "rdns": [f"r{j}" for j in range(12)]},
        "agents": [{"name": f"A{j}", "slug": f"a{j}", "level": "confirmed",
                    "families": [f"f{k}" for k in range(12)],
                    "ports": list(range(25))} for j in range(25)],
        "clusters": [f"C{j}" for j in range(25)],
        "cohosting": {"c2": [f"C2{j}" for j in range(25)],
                      "classes": [f"K{j}" for j in range(25)]},
        "domains": domains, "services": services,
        "sources": [f"s{j}" for j in range(25)],
        "timeline": {f"a{i}": ["2026-11-25"] for i in range(25)},
        "titles": [f"t{j}" for j in range(25)],
    }
    result = _project_host_payload({"data": data, "meta": {"ref_day": "2026-11-25",
                                                           "attribution": ATTR}})
    _capped(result["services"], 110, 100)
    _capped(result["domains"], 60, 50)
    _capped(result["agents"], 25, 20)
    _capped(result["clusters"], 25, 20)
    _capped(result["cohosting"]["c2"], 25, 20)
    _capped(result["cohosting"]["classes"], 25, 20)
    _capped(result["network"]["rdns"], 12, 10)
    _capped(result["sources"], 25, 20)
    _capped(result["titles"], 25, 20)
    _capped(result["timeline"], 25, 20)
    service = result["services"]["items"][0]
    _capped(service["products"], 25, 20)
    _capped(service["titles"], 12, 10)
    _capped(service["cert_cn"], 12, 10)
    _capped(service["classes"], 12, 10)
    _capped(service["agents"], 12, 10)
    domain = result["domains"]["items"][0]
    _capped(domain["ips"], 12, 10)
    _capped(domain["agents"], 25, 20)


def test_markdown_contains_notice_and_cdn_warning(monkeypatch):
    _capture(monkeypatch, lambda *_: FakeResponse(_lookup_payload(
        matches=[_match("49.51.141.166", kind="cdn")])))
    out = _run(blueteam_offensive_agency_lookup(OffensiveAgencyLookupInput(
        indicators=["49.51.141.166"], selection_basis="attacker_infrastructure")))
    assert "offensive.agency" in out
    assert "Shared CDN front" in out
    assert "not independently verified" in out
    assert "ONYPHE" in out


def test_annotations_are_read_only():
    for name in ("blueteam_offensive_agency_lookup",
                 "blueteam_offensive_agency_host"):
        tool = mcp._tool_manager._tools[name]
        assert tool.annotations.readOnlyHint is True
        assert tool.annotations.destructiveHint is False
        assert tool.annotations.idempotentHint is True
        assert tool.annotations.openWorldHint is True


def test_no_write_paths_imported():
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                        "mcp_server", "tools", "offensive_agency.py")
    source = open(path, encoding="utf-8").read()
    for token in ("attacker_registry", "record_iocs", "false_positive_kb",
                  "case_store", "fail2ban", "firewall"):
        assert token not in source
