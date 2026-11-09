#!/usr/bin/env python3
"""Markdown rendering for the aggregate: verdict accounting, VT attributes, clipping.

The aggregate keeps ``aggregated_risk_level`` as the highest risk any provider
reported. The additions here make the tally legible and stop a failed, skipped, or
inconclusive provider from reading as clean.
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

from mcp_server.tools import threat_intel_aggregate as agg


def _vt(**detail) -> agg.TIProviderResult:
    base = {"detections": "6/70", "total_engines": 70, "stats_complete": True}
    base.update(detail)
    return agg.TIProviderResult(
        provider="virustotal", indicator="8.8.8.8", indicator_type="IPv4",
        risk_level="low", reputation_score=8, is_malicious=False, detail=base)


def _md(results) -> str:
    # Reuse the tool's renderer by calling its inner markdown path through the
    # public output object; the aggregate function is the only writer.
    out = agg._aggregate(results)
    return out


# --------------------------------------------------------------------------
# Verdict accounting
# --------------------------------------------------------------------------

def test_a_failed_provider_is_not_counted_clean():
    out = _md([
        agg.TIProviderResult(provider="crowdsec", is_malicious=False,
                             risk_level="none", reputation_score=0),
        agg.TIProviderResult(provider="otx", error="boom",
                             error_kind="upstream_error"),
    ])
    assert out.verdicts_clean == 1
    assert out.providers_failed == 1
    assert out.verdicts_inconclusive == 0
    assert out.verdict_basis == "all_clean"


def test_an_inconclusive_provider_is_not_counted_clean():
    out = _md([
        agg.TIProviderResult(provider="virustotal", is_malicious=None,
                             risk_level=None, detail={"stats_complete": False}),
    ])
    assert out.verdicts_clean == 0
    assert out.verdicts_inconclusive == 1
    assert out.verdict_basis == "inconclusive"


def test_a_skipped_provider_is_counted_separately():
    out = _md([
        agg.TIProviderResult(provider="virustotal", error="consent required",
                             error_kind="consent_required"),
        agg.TIProviderResult(provider="greynoise", error="not configured",
                             error_kind="not_configured"),
    ])
    assert out.providers_skipped == 2
    assert out.providers_failed == 0
    assert out.providers_ok == 0
    assert out.verdict_basis == "no_provider_answered"


def test_configured_and_queried_counts_differ_from_attempted():
    out = _md([
        agg.TIProviderResult(provider="crowdsec", is_malicious=False,
                             risk_level="none"),
        agg.TIProviderResult(provider="threatfox", error="not configured",
                             error_kind="not_configured"),
        agg.TIProviderResult(provider="otx", error="timeout",
                             error_kind="timeout"),
    ])
    # threatfox answered "not configured" without leaving the process, so it is
    # not configured, not queried, and not counted as an attempt.
    assert out.providers_configured == 2      # crowdsec + otx
    assert out.providers_queried == 2         # both were actually sent
    assert out.providers_total == 2           # legacy alias for the same set
    assert out.providers_ok == 1
    assert out.providers_failed == 1
    assert out.providers_skipped == 1


def test_highest_risk_wins_and_is_labelled_as_such():
    out = _md([
        agg.TIProviderResult(provider="crowdsec", is_malicious=False,
                             risk_level="none", reputation_score=0),
        agg.TIProviderResult(provider="abuseipdb", is_malicious=True,
                             risk_level="high", reputation_score=90),
    ])
    assert out.aggregated_risk_level == "high"
    assert out.verdicts_malicious == 1
    assert out.consensus_malicious == 1


def test_mixed_clean_and_inconclusive_has_its_own_basis():
    out = _md([
        agg.TIProviderResult(provider="crowdsec", is_malicious=False,
                             risk_level="none"),
        agg.TIProviderResult(provider="virustotal", is_malicious=None,
                             risk_level=None, detail={"stats_complete": False}),
    ])
    assert out.verdict_basis == "mixed_clean_and_inconclusive"


# --------------------------------------------------------------------------
# Clipping (Gap 9)
# --------------------------------------------------------------------------

@pytest.mark.parametrize("length,cut", [
    (5, False),
    (39, False),
    (40, False),
    (41, True),
    (400, True),
])
def test_clip_preserves_the_display_limit_and_marks_the_cut(length, cut):
    text = "x" * length
    clipped = agg._clip(text, 40)
    assert len(clipped) <= 40
    if cut:
        assert clipped.endswith("\u2026")
        assert len(clipped) == 40
    else:
        assert clipped == text


def test_clip_normalises_newlines_and_empty_values():
    assert agg._clip("line one\nline two", 40) == "line one line two"
    assert agg._clip(None, 40) == "-"
    assert agg._clip("", 40) == "-"
    assert agg._clip("   ", 40) == "-"


def test_clip_never_cuts_below_the_ellipsis():
    assert agg._clip("abcdef", 1) == "\u2026"


# --------------------------------------------------------------------------
# VirusTotal network attributes in Markdown (Gap 6)
# --------------------------------------------------------------------------

def _render_markdown(results, monkeypatch) -> str:
    """Drive the real markdown branch of the tool with providers stubbed out."""
    import asyncio

    _i = [0]

    async def one(*args, **kwargs):
        value = results[_i[0]]
        _i[0] += 1
        return value

    for name in ("_crowdsec_provider", "_threatfox_provider", "_otx_provider",
                 "_greynoise_provider", "_abuseipdb_provider",
                 "_virustotal_provider"):
        monkeypatch.setattr(agg, name, one)
    monkeypatch.setattr(agg, "VIRUSTOTAL_API_KEY", "")
    params = agg.ThreatIntelAggregateInput(indicator="8.8.8.8")
    return asyncio.run(agg.blueteam_threat_intel_aggregate(params, None))


def test_vt_network_attributes_render_when_present(monkeypatch):
    results = [
        agg.TIProviderResult(provider="crowdsec", is_malicious=False,
                             risk_level="none"),
        agg.TIProviderResult(provider="threatfox", is_malicious=False),
        agg.TIProviderResult(provider="otx", is_malicious=False),
        agg.TIProviderResult(provider="greynoise", is_malicious=False),
        agg.TIProviderResult(provider="abuseipdb", is_malicious=False),
        _vt(asn=15169, as_owner="Google LLC", country="US",
            network="8.8.8.0/24"),
    ]
    text = _render_markdown(results, monkeypatch)
    assert "### VirusTotal network attributes" in text
    assert "| AS15169 |" in text
    assert "Google LLC" in text
    assert "| US |" in text
    assert "8.8.8.0/24" in text


def test_absent_vt_attributes_render_as_dashes(monkeypatch):
    results = [
        agg.TIProviderResult(provider="crowdsec", is_malicious=False,
                             risk_level="none"),
        agg.TIProviderResult(provider="threatfox", is_malicious=False),
        agg.TIProviderResult(provider="otx", is_malicious=False),
        agg.TIProviderResult(provider="greynoise", is_malicious=False),
        agg.TIProviderResult(provider="abuseipdb", is_malicious=False),
        _vt(),
    ]
    text = _render_markdown(results, monkeypatch)
    row = [l for l in text.splitlines() if l.startswith("| `8.8.8.8`")][-1]
    assert row.count("| - ") >= 3
    assert "None" not in row


def test_malformed_vt_attribute_types_do_not_crash(monkeypatch):
    results = [
        agg.TIProviderResult(provider="crowdsec", is_malicious=False,
                             risk_level="none"),
        agg.TIProviderResult(provider="threatfox", is_malicious=False),
        agg.TIProviderResult(provider="otx", is_malicious=False),
        agg.TIProviderResult(provider="greynoise", is_malicious=False),
        agg.TIProviderResult(provider="abuseipdb", is_malicious=False),
        _vt(asn="not-an-int", as_owner={"nested": 1}, country=["US"],
            network=12345),
    ]
    text = _render_markdown(results, monkeypatch)
    assert "### VirusTotal network attributes" in text
    assert "ASnot-an-int" not in text


def test_incomplete_vt_stats_stay_inconclusive_in_markdown(monkeypatch):
    results = [
        agg.TIProviderResult(provider="crowdsec", is_malicious=False,
                             risk_level="none"),
        agg.TIProviderResult(provider="threatfox", is_malicious=False),
        agg.TIProviderResult(provider="otx", is_malicious=False),
        agg.TIProviderResult(provider="greynoise", is_malicious=False),
        agg.TIProviderResult(provider="abuseipdb", is_malicious=False),
        _vt(stats_complete=False, detections="6/? (incomplete)"),
    ]
    results[-1].is_malicious = None
    results[-1].risk_level = None
    text = _render_markdown(results, monkeypatch)
    assert "1 inconclusive" in text
    assert "not a clean verdict" in text or "partially assessed" in text
