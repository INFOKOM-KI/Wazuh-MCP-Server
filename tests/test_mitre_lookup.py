#!/usr/bin/env python3
"""Regression tests for ``blueteam_mitre_lookup``.

The tool advertised "MITRE ATT&CK tactic or technique" lookup but only substring
matched tactic names. A valid technique id such as ``T1190`` or ``T1499.003``
returned ``result: "not_found"``, which reads as "this alert has no MITRE
relationship" rather than "this build cannot resolve technique ids".

Technique resolution uses the already-loaded ATT&CK STIX bundle (the same one
``blueteam_stix_analyze`` loads). The tests inject a synthetic bundle; no network
fetch and no real ATT&CK file is required.
"""
from __future__ import annotations

import asyncio
import json
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import pytest

from mcp_server.tools import stix_correlation, wazuh_siem


def _tool():
    fn = wazuh_siem.blueteam_mitre_lookup
    return getattr(fn, "__wrapped__", fn)


def _call(query: str) -> dict:
    return json.loads(asyncio.run(_tool()(
        wazuh_siem.MitreLookupInput(tactic_or_technique=query))))


def _synthetic_bundle() -> dict:
    return {
        "by_id": {},
        "by_type": {"attack-pattern": [
            {
                "name": "Exploit Public-Facing Application",
                "external_references": [{"external_id": "T1190"}],
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack",
                                       "phase_name": "initial-access"}],
            },
            {
                "name": "Endpoint Denial of Service",
                "external_references": [{"external_id": "T1499.003"}],
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack",
                                       "phase_name": "impact"}],
            },
        ]},
        "relationships": [], "rel_index": {},
    }


@pytest.fixture
def loaded_bundle(monkeypatch):
    monkeypatch.setattr(stix_correlation, "_stix_data", _synthetic_bundle())
    monkeypatch.setattr(stix_correlation, "_stix_error", None)
    return _synthetic_bundle()


def test_tactic_lookup_still_works():
    data = _call("initial access")
    assert data["result"] == "tactic"
    assert data["tactic"]["external_id"] == "TA0001"


def test_tactic_lookup_accepts_tactic_id():
    data = _call("TA0002")
    assert data["result"] == "tactic"
    assert data["tactic"]["name"] == "Execution"


def test_technique_lookup_resolves_loaded_stix(loaded_bundle):
    data = _call("T1190")
    assert data["result"] == "technique"
    assert data["technique"]["id"] == "T1190"
    assert data["technique"]["name"] == "Exploit Public-Facing Application"
    assert data["technique"]["tactic"] == "initial access"


def test_sub_technique_lookup_is_not_globally_not_found(loaded_bundle):
    data = _call("t1499.003")
    assert data["result"] == "technique"
    assert data["technique"]["id"] == "T1499.003"
    assert data["technique"]["tactic"] == "impact"


def test_technique_lookup_without_bundle_is_unavailable_not_absent(monkeypatch):
    monkeypatch.setattr(stix_correlation, "_stix_data", None)
    monkeypatch.setattr(stix_correlation, "_stix_error", None)
    data = _call("T1190")
    assert data["result"] == "unavailable"
    assert "not loaded" in data["reason"].lower()


def test_unknown_identifier_still_reports_not_found():
    data = _call("not-a-tactic")
    assert data["result"] == "not_found"
    assert data["query"] == "not-a-tactic"
