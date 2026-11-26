#!/usr/bin/env python3
"""Standing VirusTotal sharing consent: one policy check, no elicitation.

The per-indicator approval dialog was removed because an MCP host serves one
elicitation at a time, so two concurrent lookups raced and the second failed
with ``elicitation_error``. Sharing is now a deployment decision, enforced at
``virustotal.lookup`` before the cache, the quota, or transport.

Every test here is offline: the HTTP boundary is mocked or never reached.
"""
from __future__ import annotations

import ast
import asyncio
import json
import pathlib

import pytest

from mcp_server.core.http_client import normalize_public_ip
from mcp_server.threat_intel import virustotal as vt
from mcp_server.threat_intel import virustotal_consent as policy

REPO = pathlib.Path(__file__).resolve().parent.parent
PACKAGE = REPO / "mcp_server"


def _wire(monkeypatch, tmp_path, *, sharing: bool) -> list[str]:
    """A public-IP lookup with one armed request in the local budget."""
    sent: list[str] = []

    async def fake_api_call(method, url, **kwargs):
        sent.append(url)

        class _Resp:
            status_code = 200

            def json(self):
                return {"data": {"attributes": {
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0,
                                            "harmless": 70, "undetected": 2,
                                            "timeout": 0, "confirmed-timeout": 0,
                                            "failure": 0, "type-unsupported": 0}}}}

        return _Resp()

    vt.reset_state()
    monkeypatch.setattr(vt, "_api_call", fake_api_call)
    monkeypatch.setattr(vt, "VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(vt, "VIRUSTOTAL_BUDGET", 5)
    monkeypatch.setattr(vt, "VIRUSTOTAL_STATE", str(tmp_path / "vt.db"))
    monkeypatch.setattr(policy, "VIRUSTOTAL_IOC_SHARING", sharing)
    vt._get_quota().initialize()
    return sent


def test_sharing_off_refuses_before_cache_quota_and_transport(monkeypatch, tmp_path):
    sent = _wire(monkeypatch, tmp_path, sharing=False)

    with pytest.raises(vt.VirusTotalError) as err:
        asyncio.run(vt.lookup("ip_addresses", "8.8.8.8"))

    assert err.value.kind == "consent_required"
    assert "BLUETEAM_VIRUSTOTAL_IOC_SHARING" in err.value.message
    assert sent == []
    assert vt._get_quota().state()["spent"] == 0
    assert vt.cache_get("virustotal", "ip_addresses:8.8.8.8") is None


def test_sharing_on_sends_a_registered_public_indicator(monkeypatch, tmp_path):
    from mcp_server.core.attacker_registry import register_attacker_ioc

    sent = _wire(monkeypatch, tmp_path, sharing=True)
    register_attacker_ioc("8.8.8.8", source="wazuh_alerts", evidence={"decision": "accepted", "via": "wazuh_alerts", "alert_id": "test-alert", "rule_id": "100200", "rule_level": 12, "groups": ["attack"], "matched_field": "data.srcip", "signal": "attack_group"})

    result = asyncio.run(vt.lookup("ip_addresses", "8.8.8.8"))

    assert result["harmless"] == 70
    assert sent and sent[0].endswith("/ip_addresses/8.8.8.8")
    assert vt._get_quota().state()["spent"] == 1


@pytest.mark.parametrize("address", [
    "10.0.0.1", "172.16.5.4", "192.168.1.10",          # RFC 1918
    "127.0.0.1", "::1",                                 # loopback
    "169.254.169.254",                                  # link-local / metadata
    "100.64.0.1",                                       # CGNAT
    "fd00::1",                                          # ULA
    "::ffff:10.0.0.1",                                  # IPv4-mapped private
])
def test_non_public_addresses_never_reach_the_policy(monkeypatch, tmp_path, address):
    sent = _wire(monkeypatch, tmp_path, sharing=True)

    with pytest.raises(vt.VirusTotalError) as err:
        asyncio.run(vt.lookup("ip_addresses", address))

    assert err.value.kind == "bad_request"
    assert sent == []
    assert vt._get_quota().state()["spent"] == 0
    with pytest.raises(ValueError):
        normalize_public_ip(address)


def test_policy_rechecks_the_address_at_the_egress_boundary(monkeypatch):
    """A caller that skips input normalization still cannot send RFC 1918."""
    monkeypatch.setattr(policy, "VIRUSTOTAL_IOC_SHARING", True)

    with pytest.raises(vt.VirusTotalError) as err:
        policy.authorize_ioc_sharing("ip_addresses", "10.0.0.1")

    assert err.value.kind == "bad_request"


def test_parallel_lookups_do_not_contend_for_a_dialog(monkeypatch, tmp_path):
    from mcp_server.core.attacker_registry import register_attacker_ips

    sent = _wire(monkeypatch, tmp_path, sharing=True)
    register_attacker_ips(["8.8.8.8", "1.1.1.1"], source="wazuh_alerts", evidence={"decision": "accepted", "via": "wazuh_alerts", "alert_id": "test-alert", "rule_id": "100200", "rule_level": 12, "groups": ["attack"], "matched_field": "data.srcip", "signal": "attack_group"})

    async def both():
        return await asyncio.gather(
            vt.lookup("ip_addresses", "8.8.8.8"),
            vt.lookup("ip_addresses", "1.1.1.1"),
        )

    results = asyncio.run(both())

    assert [r["indicator"] for r in results] == ["8.8.8.8", "1.1.1.1"]
    assert len(sent) == 2


def test_enrichment_with_full_evidence_is_still_rejected(monkeypatch, tmp_path):
    """Evidence does not upgrade a source that proves nothing about attribution."""
    from mcp_server.core.attacker_registry import (attacker_ioc_provenance,
                                                   register_attacker_ioc)

    _wire(monkeypatch, tmp_path, sharing=True)
    register_attacker_ioc("8.8.8.8", source="enrichment",
                          evidence={"decision": "accepted", "via": "enrichment",
                                    "alert_id": "a", "rule_id": "1",
                                    "rule_level": 12, "matched_field": "data.srcip"})

    assert attacker_ioc_provenance("8.8.8.8") is None


def test_operator_attestation_is_not_wazuh_provenance(monkeypatch, tmp_path):
    """A manual CLI attestation is a separate class and cannot feed the automated gate."""
    from mcp_server.core.attacker_registry import register_attacker_ioc

    sent = _wire(monkeypatch, tmp_path, sharing=True)
    register_attacker_ioc("9.9.9.9", source="operator_cli",
                          evidence={"decision": "accepted", "via": "operator_cli",
                                    "tool": "virustotal_live",
                                    "operator_attested": True})

    with pytest.raises(vt.VirusTotalError) as err:
        asyncio.run(vt.lookup("ip_addresses", "9.9.9.9"))
    assert err.value.kind == "not_attacker_ioc"
    assert sent == []

    result = asyncio.run(vt.lookup("ip_addresses", "9.9.9.9",
                                   operator_attested=True))
    assert result["harmless"] == 70


def test_operator_attested_requires_the_recorded_attestation(monkeypatch, tmp_path):
    from mcp_server.core.attacker_registry import register_attacker_ioc

    _wire(monkeypatch, tmp_path, sharing=True)
    register_attacker_ioc("9.9.9.9", source="wazuh_alerts",
                          evidence={"decision": "accepted", "via": "wazuh_alerts",
                                    "alert_id": "a", "rule_id": "1",
                                    "rule_level": 12, "matched_field": "data.srcip"})

    with pytest.raises(vt.VirusTotalError) as err:
        asyncio.run(vt.lookup("ip_addresses", "9.9.9.9", operator_attested=True))
    assert err.value.kind == "not_attacker_ioc"


def test_operator_flag_is_only_passed_by_the_cli():
    """The automated tools must never take the operator path."""
    offenders: list[str] = []
    for path in PACKAGE.rglob("*.py"):
        rel = str(path.relative_to(REPO))
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call):
                continue
            for kw in node.keywords:
                if (kw.arg == "operator_attested"
                        and getattr(kw.value, "value", None) is True
                        and rel != "mcp_server/threat_intel/virustotal_live.py"):
                    offenders.append(f"{rel}:{node.lineno}")
    assert offenders == []


def test_unregistered_public_ip_is_refused_before_transport(monkeypatch, tmp_path):
    sent = _wire(monkeypatch, tmp_path, sharing=True)

    with pytest.raises(vt.VirusTotalError) as err:
        asyncio.run(vt.lookup("ip_addresses", "8.8.4.4"))

    assert err.value.kind == "not_attacker_ioc"
    assert sent == []
    assert vt._get_quota().state()["spent"] == 0
    assert vt.cache_get("virustotal", "ip_addresses:8.8.4.4") is None


def test_trusted_label_without_evidence_does_not_authorize(monkeypatch, tmp_path):
    """Spoofing the source string is not enough: the procedure must leave proof."""
    from mcp_server.core.attacker_registry import register_attacker_ioc

    sent = _wire(monkeypatch, tmp_path, sharing=True)
    register_attacker_ioc("8.8.8.8", source="verdict")

    with pytest.raises(vt.VirusTotalError) as err:
        asyncio.run(vt.lookup("ip_addresses", "8.8.8.8"))

    assert err.value.kind == "not_attacker_ioc"
    assert sent == []


def test_partial_or_rejected_evidence_is_not_provenance(monkeypatch, tmp_path):
    from mcp_server.core.attacker_registry import (attacker_ioc_provenance,
                                                   register_attacker_ioc)

    _wire(monkeypatch, tmp_path, sharing=True)
    register_attacker_ioc("8.8.8.8", source="wazuh_alerts",
                          evidence={"decision": "accepted", "alert_id": "a"})
    register_attacker_ioc("1.0.0.1", source="verdict",
                          evidence={"decision": "rejected", "verdict": "false_positive"})

    assert attacker_ioc_provenance("8.8.8.8") is None
    assert attacker_ioc_provenance("1.0.0.1") is None


def test_enrichment_source_is_not_provenance(monkeypatch, tmp_path):
    """The VT lookup registers 'enrichment' itself; that cannot authorize it."""
    from mcp_server.core.attacker_registry import register_attacker_ioc

    sent = _wire(monkeypatch, tmp_path, sharing=True)
    register_attacker_ioc("8.8.4.4", source="enrichment")

    with pytest.raises(vt.VirusTotalError) as err:
        asyncio.run(vt.lookup("ip_addresses", "8.8.4.4"))

    assert err.value.kind == "not_attacker_ioc"
    assert sent == []


def _alert(**data):
    return {"_source": {"rule": {"id": "100200", "level": 12,
                                 "groups": ["attack", "web_attack"]},
                        "data": {"srcip": "8.8.4.4", "dstip": "10.0.0.5", **data}}}


def test_provenance_resolver_records_an_attacker_alert(monkeypatch, tmp_path):
    from mcp_server.tools import ioc_provenance

    calls = []

    async def fake_post(body, index_pattern=None):
        calls.append(body)
        return {"hits": {"hits": [_alert()]}}

    monkeypatch.setattr(ioc_provenance, "_wazuh_indexer_post", fake_post)
    source, detail = asyncio.run(
        ioc_provenance.ensure_attacker_provenance("ip_addresses", "8.8.4.4"))

    assert source == "wazuh_alerts"
    assert "attacker-side evidence" in detail
    assert len(calls) == 1
    assert calls[0]["size"] == 50          # bounded evidence window
    assert calls[0]["query"]                # one filtered search, no scan

    # A registry hit answers without touching the Indexer.
    source, _ = asyncio.run(
        ioc_provenance.ensure_attacker_provenance("ip_addresses", "8.8.4.4"))
    assert source == "wazuh_alerts"
    assert len(calls) == 1


@pytest.mark.parametrize("hit,why", [
    # the address was the destination, not the actor
    (_alert(dstip="8.8.4.4"), "direction"),
    # healthy-host rule
    ({"_source": {"rule": {"id": "1", "level": 12,
                           "groups": ["authentication_success"]},
                  "data": {"srcip": "8.8.4.4"}}}, "noise"),
    # suspicious but no attack signal
    ({"_source": {"rule": {"id": "2", "level": 7, "groups": ["syslog"]},
                  "data": {"srcip": "8.8.4.4"}}}, "level"),
])
def test_provenance_resolver_rejects_weak_alert_semantics(monkeypatch, hit, why):
    from mcp_server.core.attacker_registry import attacker_ioc_source
    from mcp_server.tools import ioc_provenance

    async def fake_post(body, index_pattern=None):
        return {"hits": {"hits": [hit]}}

    monkeypatch.setattr(ioc_provenance, "_wazuh_indexer_post", fake_post)
    source, detail = asyncio.run(
        ioc_provenance.ensure_attacker_provenance("ip_addresses", "8.8.4.4"))

    assert source is None, why
    assert attacker_ioc_source("8.8.4.4") is None


def test_owned_domain_is_refused_even_when_registered(monkeypatch):
    from mcp_server.core.attacker_registry import register_attacker_ioc
    from mcp_server.tools import ioc_provenance

    monkeypatch.setattr(ioc_provenance, "BLUETEAM_OWNED_DOMAINS", "corp.example")
    register_attacker_ioc("mail.corp.example", source="verdict")
    source, detail = asyncio.run(
        ioc_provenance.ensure_attacker_provenance("domains", "mail.corp.example"))

    assert source is None
    assert "BLUETEAM_OWNED_DOMAINS" in detail


def test_expanded_ipv6_alert_form_still_matches(monkeypatch):
    from mcp_server.tools import ioc_provenance

    hit = {"_source": {"rule": {"id": "42", "level": 11, "groups": ["attack"]},
                       "data": {"srcip": "2606:4700:4700:0000:0000:0000:0000:1111"}}}

    async def fake_post(body, index_pattern=None):
        return {"hits": {"hits": [hit]}}

    monkeypatch.setattr(ioc_provenance, "_wazuh_indexer_post", fake_post)
    source, _ = asyncio.run(
        ioc_provenance.ensure_attacker_provenance("ip_addresses", "2606:4700:4700::1111"))

    assert source == "wazuh_alerts"


def test_domain_presence_in_an_alert_is_not_attribution(monkeypatch):
    from mcp_server.tools import ioc_provenance

    async def forbidden(body, index_pattern=None):
        raise AssertionError("no Indexer attribution exists for domains")

    monkeypatch.setattr(ioc_provenance, "_wazuh_indexer_post", forbidden)
    source, detail = asyncio.run(
        ioc_provenance.ensure_attacker_provenance("domains", "evil.example.com"))

    assert source is None
    assert "analyst verdict" in detail


def test_provenance_resolver_reports_an_unreachable_indexer(monkeypatch):
    from mcp_server.tools import ioc_provenance

    async def fake_post(body, index_pattern=None):
        return {"error": "connection refused"}

    monkeypatch.setattr(ioc_provenance, "_wazuh_indexer_post", fake_post)
    source, detail = asyncio.run(
        ioc_provenance.ensure_attacker_provenance("ip_addresses", "8.8.4.4"))

    assert source is None
    assert ioc_provenance.provenance_refusal(detail)[0] == "provenance_unchecked"


@pytest.mark.parametrize("address,network", [
    ("13.32.1.1", "13.32.0.0/15"),
    ("2600:9000::1", "2600:9000::/28"),
])
def test_shared_infrastructure_exclusion_blocks_before_transport(
        monkeypatch, tmp_path, address, network):
    from mcp_server.core.attacker_registry import (attacker_ioc_provenance,
                                                   register_attacker_ioc)

    sent = _wire(monkeypatch, tmp_path, sharing=True)
    monkeypatch.setattr(policy, "VIRUSTOTAL_ATTRIBUTION_EXCLUDE", network)
    register_attacker_ioc(address, source="wazuh_alerts",
                          evidence={"decision": "accepted", "via": "wazuh_alerts",
                                    "alert_id": "a", "rule_id": "1",
                                    "rule_level": 12, "matched_field": "data.srcip"})

    with pytest.raises(vt.VirusTotalError) as err:
        asyncio.run(vt.lookup("ip_addresses", address))

    assert err.value.kind == "excluded_infrastructure"
    assert sent == []
    assert vt._get_quota().state()["spent"] == 0
    assert attacker_ioc_provenance(address) == "wazuh_alerts"


def test_exclusion_applies_before_registry_promotion(monkeypatch):
    from mcp_server.core.attacker_registry import attacker_ioc_source
    from mcp_server.tools import ioc_provenance

    monkeypatch.setattr(policy, "VIRUSTOTAL_ATTRIBUTION_EXCLUDE", "13.32.0.0/15")
    hit = {"_id": "a1", "_source": {
        "@timestamp": "2026-11-26T00:00:00Z",
        "rule": {"id": "100200", "level": 12, "groups": ["attack"]},
        "data": {"srcip": "13.32.1.1"}}}

    async def fake_post(body, index_pattern=None):
        return {"hits": {"hits": [hit]}}

    monkeypatch.setattr(ioc_provenance, "_wazuh_indexer_post", fake_post)
    source, detail = asyncio.run(
        ioc_provenance.ensure_attacker_provenance("ip_addresses", "13.32.1.1"))

    assert source is None
    assert "exclusion" in detail
    assert attacker_ioc_source("13.32.1.1") is None


def test_invalid_exclusion_is_a_startup_error(monkeypatch):
    from mcp_server.core.config import Config
    from mcp_server.core.exceptions import ConfigurationError

    monkeypatch.setenv("WAZUH_INDEXER_URL", "https://indexer:9200")
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")
    monkeypatch.setenv("BLUETEAM_VIRUSTOTAL_ATTRIBUTION_EXCLUDE", "13.32.0.0/15,not-a-cidr")

    with pytest.raises(ConfigurationError):
        Config.from_env().validate()


def test_no_module_calls_mcp_elicitation():
    """Regression guard for the parallel-call failure: no tool may prompt.

    An MCP host serves one elicitation per session. Two tool calls that both
    elicit make the second fail, which is the report this policy replaced.
    """
    offenders: list[str] = []
    for path in PACKAGE.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            name = None
            if isinstance(node, ast.Attribute):
                name = node.attr
            elif isinstance(node, ast.Name):
                name = node.id
            if name in {"elicit", "elicit_form"}:
                offenders.append(f"{path.relative_to(REPO)}:{node.lineno}")
    assert offenders == []


def test_trusted_sources_are_only_written_by_their_owning_module():
    """A trusted label is a claim about a procedure; only its module may make it."""
    owners = {
        "wazuh_alerts": "mcp_server/tools/ioc_provenance.py",
        "engine_a": "mcp_server/tools/correlation.py",
        "verdict": "mcp_server/tools/investigation_history.py",
        "webshell_check": "mcp_server/tools/webshell_check.py",
        "operator_cli": "mcp_server/threat_intel/virustotal_live.py",
    }
    offenders: list[str] = []
    for path in PACKAGE.rglob("*.py"):
        rel = str(path.relative_to(REPO))
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if name not in {"register_attacker_ioc", "register_attacker_ips"}:
                continue
            for kw in node.keywords:
                label = getattr(kw.value, "value", None)
                if kw.arg == "source" and label in owners and rel != owners[label]:
                    offenders.append(f"{rel}:{node.lineno} writes {label}")
    assert offenders == []


def test_config_defaults_sharing_off(monkeypatch):
    from mcp_server.core.config import Config

    monkeypatch.delenv("BLUETEAM_VIRUSTOTAL_IOC_SHARING", raising=False)
    monkeypatch.setenv("WAZUH_INDEXER_URL", "https://indexer:9200")
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")
    assert Config.from_env().threat_intel.virustotal_ioc_sharing is False


def test_config_reads_the_sharing_switch(monkeypatch):
    from mcp_server.core.config import Config

    monkeypatch.setenv("BLUETEAM_VIRUSTOTAL_IOC_SHARING", "false")
    monkeypatch.setenv("WAZUH_INDEXER_URL", "https://indexer:9200")
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")
    assert Config.from_env().threat_intel.virustotal_ioc_sharing is False
