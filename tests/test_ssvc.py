#!/usr/bin/env python3
"""Self-checks for the SSVC CISA Deployer decision tree (logic).
Run:  python -m pytest tests/test_ssvc.py -q
"""
from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "http://127.0.0.1:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "x")

from mcp_server.threat_intel.ssvc import ssvc_decision  # noqa: E402


def test_kev_active_total_open_is_act():
    r = ssvc_decision(in_kev=True, epss_probability=0.5, poc_confidence="NONE",
                      cvss_score=9.5, exposure="open")
    assert r["action"] == "Act"
    assert r["exploitation"] == "active"
    assert r["decision"]["automatable"] == "yes"


def test_no_exploitation_partial_is_track():
    r = ssvc_decision(in_kev=False, epss_probability=0.0, poc_confidence="NONE",
                      cvss_score=5.0, exposure="open")
    assert r["action"] == "Track"
    assert r["decision"]["technical_impact"] == "partial"


def test_controlled_exposure_drops_kev_cve_to_track():
    # KEV active but access controlled and CVSS 8 -> Automatable=no, Technical=partial
    r = ssvc_decision(in_kev=True, epss_probability=0.5, poc_confidence="NONE",
                      cvss_score=8.0, exposure="controlled")
    assert r["action"] == "Track"
    assert r["decision"]["automatable"] == "no"


def test_unknown_exposure_defaults_to_open():
    r = ssvc_decision(in_kev=False, epss_probability=0.0, poc_confidence="NONE",
                      cvss_score=0.0, exposure="garbage")
    assert r["exposure"] == "open"


def test_inputs_clamped_and_coerced():
    r = ssvc_decision(in_kev=True, epss_probability="1.9", poc_confidence="NONE",
                      cvss_score=99.0, exposure="open")
    assert r["action"] == "Act"  # clamped to valid ranges, no exception.
