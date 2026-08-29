#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Tests for seam-3 pure helpers: CVE techniques -> 3-Sum category -> scores.
"""
from __future__ import annotations
from mcp_server.correlation.three_sum_core import (
    vuln_techniques_to_categories,
    vuln_category_scores,
)

def test_techniques_to_categories():
    # execution -> B, persistence -> C per MITRE_TACTIC_TO_CATEGORY
    assert vuln_techniques_to_categories([{"tactics": ["execution", "persistence"]}]) == {"B", "C"}
    assert vuln_techniques_to_categories([{"tactics": ["reconnaissance"]}]) == {"A"}
    assert vuln_techniques_to_categories([{"tactics": ["unknown-tactic"]}]) == set()
    assert vuln_techniques_to_categories([]) == set()


def test_vuln_category_scores_kev():
    # KEV-listed CVE (risk 88) mapping to B -> 8.8 in B
    ctx = [{"cve_id": "CVE-2024-6387", "risk_score": 88,
            "techniques": [{"technique_id": "T1190", "tactics": ["initial access"]}]}]
    scores = vuln_category_scores(ctx)
    assert scores["A"] == 0.0
    assert scores["B"] == 8.8
    assert scores["C"] == 0.0


def test_vuln_category_scores_max_not_sum():
    # Two CVEs both mapping to B: strongest wins, no stacking
    ctx = [
        {"cve_id": "CVE-A", "risk_score": 88, "techniques": [{"tactics": ["execution"]}]},
        {"cve_id": "CVE-B", "risk_score": 30, "techniques": [{"tactics": ["execution"]}]},
    ]
    scores = vuln_category_scores(ctx)
    assert scores["B"] == 8.8


def test_vuln_category_scores_multicategory():
    # One CVE spanning B and C contributes to both
    ctx = [{"cve_id": "CVE-C", "risk_score": 76,
            "techniques": [{"tactics": ["execution", "persistence"]}]}]
    scores = vuln_category_scores(ctx)
    assert scores["B"] == 7.6
    assert scores["C"] == 7.6
