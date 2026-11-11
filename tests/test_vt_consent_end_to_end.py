"""Accepted consent must reach the quota guard with zero outbound traffic.

Budget stays at 0 and the transport fails the test if it is called, so this
passes only if approval moves the failure past consent with nothing sent.
"""
from __future__ import annotations

import asyncio
import json

from mcp_server.threat_intel import virustotal as vt
from mcp_server.threat_intel import virustotal_consent as consent
from mcp_server.tools import threat_intel_aggregate as agg

QUOTA_GUARDS = {"budget_closed", "state_missing", "not_armed", "state_corrupt",
                "policy_mismatch", "storage_unavailable", "config_invalid"}


def _stub(name):
    async def provider(*args, **kwargs):
        return agg.TIProviderResult(provider=name, is_malicious=None)
    return provider


def test_approved_consent_reaches_the_quota_guard_without_http(
        monkeypatch, tmp_path, consent_approval):
    sent = []

    async def forbidden(*args, **kwargs):
        sent.append(1)
        raise AssertionError("no VirusTotal request may follow the quota guard")

    monkeypatch.setattr(vt, "_api_call", forbidden)
    monkeypatch.setattr(vt, "VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(vt, "VIRUSTOTAL_BUDGET", 0)
    monkeypatch.setattr(vt, "VIRUSTOTAL_STATE", str(tmp_path / "vt.db"))
    monkeypatch.setattr(agg, "VIRUSTOTAL_API_KEY", "test-key")

    issued, consumed = [], []
    real_issue, real_consume = agg.issue_consent, vt.consume_consent

    def spy_issue(kind, value, ttl=consent._CONSENT_TTL_SECONDS):
        token = real_issue(kind, value, ttl)
        issued.append((kind, value, token))
        return token

    def spy_consume(token, kind, value):
        consumed.append((kind, value, token))
        return real_consume(token, kind, value)

    monkeypatch.setattr(agg, "issue_consent", spy_issue)
    monkeypatch.setattr(vt, "consume_consent", spy_consume)
    for name in ("_crowdsec_provider", "_threatfox_provider", "_otx_provider",
                 "_greynoise_provider", "_abuseipdb_provider"):
        monkeypatch.setattr(agg, name, _stub(name.strip("_")))
    vt.reset_state()

    params = agg.ThreatIntelAggregateInput(
        indicator="182.8.5.232", acknowledge_ioc_sharing=True,
        response_format="json")
    out = json.loads(asyncio.run(
        agg.blueteam_threat_intel_aggregate(params, consent_approval)))

    row = [r for r in out["results"] if r["provider"] == "virustotal"][0]
    assert consent_approval.messages, "the consent text must reach the host"
    assert row["error_kind"] in QUOTA_GUARDS, row["error"]
    assert row["error_kind"] != "consent_required"
    assert row["detail"].get("consent_reason") is None
    assert sent == []
    assert not (tmp_path / "vt.db").exists()
    assert [(kind, value) for kind, value, _ in issued] == [
        ("ip_addresses", "182.8.5.232")]
    assert isinstance(issued[0][2], str) and len(issued[0][2]) >= 20
    assert consumed == issued      # the same token came back for consumption
    assert consent._TOKENS == {}   # issued, consumed, single use
