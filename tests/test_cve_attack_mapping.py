#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Tests for CVE ATT&CK mapping and CVE IOC extraction.
"""
from __future__ import annotations
import pytest
import mcp_server.tools.stix_correlation as sc
from mcp_server.tools.ioc_tools import _extract_iocs


@pytest.fixture
def fake_stix(monkeypatch):
    bundle = {
        "by_type": {
            "attack-pattern": [{
                "id": "attack-pattern--abc",
                "name": "Exploitation for Client Execution",
                "description": "Adversaries may exploit CVE-2024-6387 in OpenSSH.",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1203"}],
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
                "revoked": False, "x_mitre_deprecated": False,
            }],
            "intrusion-set": [{
                "id": "intrusion-set--xyz", "name": "APT Test Group",
                "revoked": False, "x_mitre_deprecated": False,
            }],
        },
        "relationships": [{
            "relationship_type": "uses",
            "source_ref": "intrusion-set--xyz",
            "target_ref": "attack-pattern--abc",
        }],
    }
    monkeypatch.setattr(sc, "_stix_data", bundle)
    monkeypatch.setattr(sc, "_stix_error", None)
    return bundle


def test_find_techniques_for_cve(fake_stix):
    techs = sc._find_techniques_for_cve("CVE-2024-6387")
    assert len(techs) == 1
    assert techs[0]["technique_id"] == "T1203"
    assert techs[0]["tactics"] == ["execution"]


def test_find_techniques_no_match(fake_stix):
    assert sc._find_techniques_for_cve("CVE-1999-0001") == []


def test_find_groups_using_techniques(fake_stix):
    assert sc._find_groups_using_techniques({"T1203"}) == ["APT Test Group"]


def test_extract_iocs_cves():
    iocs = _extract_iocs("CVE-2024-6387 exploited from 1.2.3.4, also cve-2021-44228")
    assert iocs["cves"] == ["CVE-2024-6387", "CVE-2021-44228"]


def test_extract_iocs_no_cve():
    iocs = _extract_iocs("nothing here 1.2.3.4")
    assert iocs["cves"] == []
