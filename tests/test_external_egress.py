#!/usr/bin/env python3
"""One switch, every provider: no outbound lookup when external egress is off.

An API key is a capability, not an authorization. Every provider client checks
`BLUETEAM_EXTERNAL_ENRICHMENT` before a DNS lookup, so a configured key cannot
restore transmission on its own.
"""
from __future__ import annotations

import asyncio
import json
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import pytest

from mcp_server.core import external_egress
from mcp_server.core.external_egress import ExternalEgressDisabled


@pytest.fixture(autouse=True)
def _egress_off(monkeypatch):
    monkeypatch.setattr(external_egress, "EXTERNAL_ENRICHMENT_ENABLED", False)


def _forbid(monkeypatch, module, name="_api_call"):
    calls = []

    async def fake(*args, **kwargs):
        calls.append(args)
        raise AssertionError("a disabled provider reached the network")

    monkeypatch.setattr(module, name, fake)
    return calls


@pytest.mark.parametrize("module_name,coro", [
    ("mcp_server.threat_intel.crowdsec",
     lambda m: m._crowdsec_request("/v2/smoke/8.8.8.8")),
    ("mcp_server.threat_intel.greynoise",
     lambda m: m._greynoise_lookup("8.8.8.8")),
    ("mcp_server.threat_intel.threatfox",
     lambda m: m._threatfox_request("8.8.8.8")),
    ("mcp_server.threat_intel.otx",
     lambda m: m._otx_request("8.8.8.8")),
    ("mcp_server.threat_intel.urlhaus",
     lambda m: m._urlhaus_post("url/", {"url": "http://example.com"})),
    ("mcp_server.threat_intel.rapidapi",
     lambda m: m._rapidapi_request("get", "example.p.rapidapi.com", "/x")),
    ("mcp_server.threat_intel.offensive_agency",
     lambda m: m.lookup(["8.8.8.8"])),
    ("mcp_server.threat_intel.cve_now",
     lambda m: m._rpc("search", {"q": "CVE-2024-0001"}, ttl=60)),
])
def test_provider_clients_refuse_before_transport(monkeypatch, module_name, coro):
    import importlib

    module = importlib.import_module(module_name)
    calls = _forbid(monkeypatch, module)
    monkeypatch.setenv("CROWDSEC_API_KEY", "key")
    monkeypatch.setenv("THREATFOX_API_KEY", "key")
    monkeypatch.setenv("OTX_API_KEY", "key")
    monkeypatch.setenv("RAPIDAPI_KEY", "key")

    with pytest.raises(ExternalEgressDisabled):
        asyncio.run(coro(module))

    assert calls == []


def test_abuseipdb_check_refuses_but_report_stays_a_separate_write(monkeypatch):
    from mcp_server.threat_intel import abuseipdb

    calls = _forbid(monkeypatch, abuseipdb)
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "key")

    with pytest.raises(ExternalEgressDisabled):
        asyncio.run(abuseipdb.check_ip("8.8.8.8"))
    assert calls == []

    # Reporting is an explicitly authorized write, not an enrichment lookup.
    with pytest.raises(abuseipdb.AbuseIPDBError) as err:
        asyncio.run(abuseipdb._request("post", "/report", limiter=abuseipdb.REPORT_LIMITER,
                                       data={"ip": "8.8.8.8", "categories": "18"}))
    assert err.value.kind != "disabled"


def test_virustotal_lookup_reports_disabled(monkeypatch):
    from mcp_server.threat_intel import virustotal as vt

    calls = _forbid(monkeypatch, vt)
    monkeypatch.setattr(vt, "VIRUSTOTAL_API_KEY", "key")

    with pytest.raises(vt.VirusTotalError) as err:
        asyncio.run(vt.lookup("ip_addresses", "8.8.8.8"))

    assert err.value.kind == "disabled"
    assert calls == []


def test_standalone_tools_report_disabled_without_transport(monkeypatch):
    from mcp_server.tools import alert_enrichment as enrich
    from mcp_server.tools import stealer_log

    monkeypatch.setenv("ARGUS_API_KEY", "key")
    monkeypatch.setenv("NETRA_API_KEY", "key")
    calls = []

    async def fake(*args, **kwargs):
        calls.append(args)
        raise AssertionError("a disabled tool reached the network")

    monkeypatch.setattr(enrich, "_api_call", fake)
    monkeypatch.setattr(stealer_log, "_api_call", fake)

    argus = json.loads(asyncio.run(enrich.argus_ip_lookup(
        enrich.ArgusIpLookupInput(ip="8.8.8.8"))))
    netra = json.loads(asyncio.run(enrich.netra_ip_analysis(
        enrich.NetraIpAnalysisInput(ip="8.8.8.8"))))
    stealer = json.loads(asyncio.run(stealer_log.stealer_log_check(
        stealer_log.StealerLogInput(email="user@example.com"))))

    assert argus["error_kind"] == "disabled"
    assert netra["error_kind"] == "disabled"
    assert stealer["error_kind"] == "disabled"
    assert calls == []


@pytest.mark.parametrize("module_name,coro", [
    ("mcp_server.threat_intel.cve_enrichment",
     lambda m: m.search_poc("CVE-2024-0001")),
    ("mcp_server.threat_intel.dependency_scan",
     lambda m: m.scan_dependencies_bulk([{"ecosystem": "PyPI", "name": "x"}])),
    ("mcp_server.threat_intel.vendor_advisory",
     lambda m: m.get_vendor_advisory("CVE-2024-0001")),
])
def test_cve_and_vendor_clients_refuse_before_transport(monkeypatch, module_name, coro):
    import importlib

    module = importlib.import_module(module_name)
    calls = _forbid(monkeypatch, module)
    with pytest.raises(ExternalEgressDisabled):
        asyncio.run(coro(module))
    assert calls == []


def test_whois_and_crtsh_tools_report_disabled(monkeypatch):
    from mcp_server.tools import wazuh_domain

    calls = _forbid(monkeypatch, wazuh_domain)
    whois = json.loads(asyncio.run(wazuh_domain.blueteam_whois_lookup(
        wazuh_domain.WhoisLookupInput(domain="example.com"))))
    crtsh = json.loads(asyncio.run(wazuh_domain.blueteam_crtsh_lookup(
        wazuh_domain.CrtshLookupInput(domain="example.com"))))

    assert whois["error_kind"] == "disabled"
    assert crtsh["error_kind"] == "disabled"
    assert calls == []


def test_config_defaults_enrichment_off(monkeypatch):
    from mcp_server.core.config import Config

    monkeypatch.delenv("BLUETEAM_EXTERNAL_ENRICHMENT", raising=False)
    monkeypatch.setenv("WAZUH_INDEXER_URL", "https://indexer:9200")
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")
    assert Config.from_env().threat_intel.external_enrichment_enabled is False
