#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Tests for CVE ATT&CK mapping and CVE IOC extraction.
"""
from __future__ import annotations
import os

# mcp_server/__init__.py calls init_config() at import and hard-fails without
# WAZUH_INDEXER_* (ConfigurationError). This module imports mcp_server at module
# level, so without these the file errors during collection when run alone.
os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import pytest
import json
import mcp_server.tools.stix_correlation as sc
from mcp_server.tools.ioc_tools import _extract_iocs


@pytest.fixture
def fake_stix(monkeypatch):
    # Mirrors the shape _load_stix() builds from the real bundle (by_id/by_type/
    # rel_index). An incomplete fixture is what let the target only traversal in
    # blueteam_stix_analyze survive.
    objects = [
        {
            "id": "attack-pattern--abc",
            "type": "attack-pattern",
            "name": "Exploitation for Client Execution",
            "description": "Adversaries may exploit CVE-2024-6387 in OpenSSH.",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1203"}],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
            "revoked": False, "x_mitre_deprecated": False,
        },
        {
            "id": "intrusion-set--xyz", "type": "intrusion-set", "name": "APT Test Group",
            "external_references": [{"source_name": "mitre-attack", "external_id": "G9999"}],
            "revoked": False, "x_mitre_deprecated": False,
        },
        {
            "id": "course-of-action--m1", "type": "course-of-action",
            "name": "Patch Test Mitigation",
            "external_references": [{"source_name": "mitre-attack", "external_id": "M1051"}],
        },
    ]
    relationships = [
        {"relationship_type": "uses", "source_ref": "intrusion-set--xyz",
         "target_ref": "attack-pattern--abc"},
        {"relationship_type": "mitigates", "source_ref": "course-of-action--m1",
         "target_ref": "attack-pattern--abc"},
    ]
    by_id: dict = {}
    by_type: dict = {}
    rel_index: dict = {}
    for o in objects:
        by_id[o["id"]] = o
        by_type.setdefault(o["type"], []).append(o)
    for r in relationships:
        for key in ("source_ref", "target_ref"):
            rel_index.setdefault(r[key], []).append(r)
    bundle = {"by_id": by_id, "by_type": by_type,
              "relationships": relationships, "rel_index": rel_index}
    monkeypatch.setattr(sc, "_stix_data", bundle)
    monkeypatch.setattr(sc, "_stix_error", None)
    monkeypatch.setattr(sc, "_stix_retry_at", 0.0)
    # Keep _load_stix() off the network and off the production cache. With data
    # already loaded and a non-http source, _needs_refresh() is False.
    monkeypatch.setattr(sc, "_STIX_PATH", "/nonexistent/enterprise-attack.json")
    return bundle


@pytest.mark.asyncio
async def test_stix_analyze_technique_resolves_actors_and_mitigations(fake_stix):
    """Regression: a technique is the TARGET of 'uses'/'mitigates', so a
    target-only walk returned zero actors and zero mitigations."""
    out = await sc.blueteam_stix_analyze(
        sc.StixAnalyzeInput(technique_id="T1203", response_format="json"))
    data = json.loads(out)
    assert [a["name"] for a in data["actors"]] == ["APT Test Group"]
    assert [m["name"] for m in data["mitigations"]] == ["Patch Test Mitigation"]


@pytest.mark.asyncio
async def test_stix_analyze_actor_still_resolves_techniques(fake_stix):
    """The forward direction (actor -> technique) must keep working."""
    out = await sc.blueteam_stix_analyze(
        sc.StixAnalyzeInput(actor_name="APT Test", response_format="json"))
    data = json.loads(out)
    assert [t["mitre_id"] for t in data["ttps"]] == ["T1203"]


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
