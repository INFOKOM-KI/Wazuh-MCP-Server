"""VirusTotal reputation classification and its effect on the aggregate.

No network: `lookup()` is replaced with a normalized payload, which is the same
shape `_normalize_response` produces.
"""
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import patch

from mcp_server.tools import threat_intel_aggregate as agg


def _payload(malicious=0, suspicious=0, harmless=60, undetected=10,
             timeout=0, complete=True):
    stats = {"malicious": malicious, "suspicious": suspicious,
             "harmless": harmless, "undetected": undetected, "timeout": timeout}
    total = sum(stats.values())
    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "timeout": timeout,
        "stats_complete": complete,
        "missing_stats": [] if complete else ["timeout"],
        "analysis_stats": stats,
        "total_engines": total if complete else None,
        "detection_percent": (int(malicious / total * 100) if complete and total
                              else None),
        "any_detection": malicious > 0,
        "community_reputation": 0,
        "last_analysis_date": 1_700_000_000,
        "retrieved_at": "2026-01-01T00:00:00+00:00",
    }


def _run(payload):
    async def fake_lookup(kind, indicator):
        return payload

    with patch.object(agg, "VIRUSTOTAL_API_KEY", "test-key"), \
            patch("mcp_server.threat_intel.virustotal.lookup", fake_lookup):
        return asyncio.run(agg._virustotal_provider("182.8.5.232", "IPv4"))


def test_one_engine_detection_is_malicious_not_clean():
    result = _run(_payload(malicious=1))
    assert result.is_malicious is True
    assert result.detail["vt_verdict"] == "malicious"
    assert result.risk_level == "medium"      # 1% never reads as low risk
    assert result.detail["detections"] == "1/71"


def test_many_detections_are_high_risk():
    result = _run(_payload(malicious=40, harmless=30))
    assert result.is_malicious is True
    assert result.risk_level == "high"


def test_suspicious_without_malicious_is_not_clean():
    result = _run(_payload(suspicious=2))
    assert result.is_malicious is None        # inconclusive, never a clean vote
    assert result.detail["vt_verdict"] == "suspicious"
    assert result.risk_level == "medium"


def test_zero_detections_is_no_detections_not_safe():
    result = _run(_payload())
    assert result.is_malicious is False
    assert result.detail["vt_verdict"] == "no_detections"
    assert result.risk_level == "none"


def test_incomplete_stats_are_inconclusive():
    result = _run(_payload(malicious=3, complete=False))
    assert result.is_malicious is None
    assert result.detail["vt_verdict"] == "inconclusive"
    assert result.reputation_score is None


def test_community_reputation_never_overrides_engine_stats():
    payload = _payload()
    payload["community_reputation"] = 99
    result = _run(payload)
    assert result.is_malicious is False
    assert result.reputation_score == 0
    assert result.detail["community_reputation"] == 99


def _stub(name, malicious=False):
    async def provider(*args, **kwargs):
        return agg.TIProviderResult(provider=name, indicator="182.8.5.232",
                                    indicator_type="IPv4", is_malicious=malicious,
                                    risk_level="none")
    return provider


def _aggregate(monkeypatch):
    for name in ("_crowdsec_provider", "_threatfox_provider", "_otx_provider",
                 "_greynoise_provider", "_abuseipdb_provider"):
        monkeypatch.setattr(agg, name, _stub(name.strip("_")))
    monkeypatch.setattr(agg, "VIRUSTOTAL_API_KEY", "test-key")
    params = agg.ThreatIntelAggregateInput(
        indicator="182.8.5.232", response_format="json")
    return asyncio.run(agg.blueteam_threat_intel_aggregate(params))


def test_sharing_off_skips_vt_without_querying(monkeypatch):
    import asyncio
    from unittest.mock import patch

    from mcp_server.threat_intel import virustotal_consent as policy
    from mcp_server.tools import threat_intel_aggregate as module

    with patch.object(module, "VIRUSTOTAL_API_KEY", "test-key"), \
            patch.object(policy, "VIRUSTOTAL_IOC_SHARING", False):
        result = asyncio.run(module._virustotal_provider("182.8.5.232", "IPv4"))

    assert result.error_kind == "consent_required"
    assert result.is_malicious is None
