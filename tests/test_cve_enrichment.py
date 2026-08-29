#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Tests for CVE enrichment: pure scoring + CVE-ID validation.
"""
from __future__ import annotations
import pytest
from mcp_server.threat_intel.cve_enrichment import (
    normalize_cve,
    score_cve,
    _extract_cvss_score,
)


def test_normalize_cve():
    assert normalize_cve("cve-2024-6387") == "CVE-2024-6387"
    assert normalize_cve("CVE-2021-44228") == "CVE-2021-44228"
    assert normalize_cve("2024-6387") is None
    assert normalize_cve("CVE-6387") is None
    assert normalize_cve("cve-2024-638") is None


def test_extract_cvss_score_v31_first():
    nvd = {"metrics": {
        "cvssMetricV31": [{"cvssData": {"baseScore": 8.1}}],
        "cvssMetricV2": [{"cvssData": {"baseScore": 6.0}}],
    }}
    assert _extract_cvss_score(nvd) == 8.1


def test_score_cve_kev_hard_floor():
    """KEV membership forces CRITICAL regardless of low CVSS/EPSS."""
    nvd = {"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 4.0}}]}}
    kev = {"cveID": "CVE-2024-6387"}
    result = score_cve("CVE-2024-6387", nvd, {"probability": 0.1}, kev, None)
    assert result["risk_label"] == "CRITICAL"
    assert result["risk_score"] >= 76.0
    assert result["components"]["in_kev"] is True


def test_score_cve_low_risk():
    nvd = {"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 3.0}}]}}
    result = score_cve("CVE-2024-0001", nvd, {"probability": 0.01}, None, None)
    assert result["risk_label"] in ("LOW", "MEDIUM")
    assert result["components"]["cvss_score"] == 3.0


def test_score_cve_poc_and_epss_boost():
    nvd = {"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.5}}]}}
    kev = {"cveID": "CVE-2024-6387"}
    poc = {"confidence": "PUBLIC_EXPLOIT"}
    result = score_cve("CVE-2024-6387", nvd, {"probability": 0.9}, kev, poc)
    assert "KEV+PoC" in result["boosters_applied"]
    assert "CVSS>=9+EPSS>0.7" in result["boosters_applied"]
    assert result["urgency"] == "PATCH IMMEDIATELY"
