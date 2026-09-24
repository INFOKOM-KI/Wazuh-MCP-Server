#!/usr/bin/env python3
"""Tests for the ATT&CK bake (bake_mitre_tactics.py) and the vocabulary union.
The union is the point: STIX ships 15 x-mitre-tactic objects while this deployment
scores 16 names, because the production ruleset still emits the pre-v18 "Defense
Evasion". A bake that trusted upstream alone would drop it and the criteria guard
would raise at import, taking the whole tool registry down with it.
"""
from __future__ import annotations
import importlib.util
import json
import re
import sys
from pathlib import Path
import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

spec = importlib.util.spec_from_file_location("bake_mitre_tactics", REPO / "bake_mitre_tactics.py")
bake = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bake)


def _fixture() -> dict:
    """Three usable tactics plus two objects the extractor must refuse."""
    def tactic(shortname, name, external, description="Planted by an adversary."):
        return {"type": "x-mitre-tactic", "name": name, "x_mitre_shortname": shortname,
                "description": description,
                "external_references": [{"external_id": external, "source_name": "mitre-attack"}]}

    return {"type": "bundle", "objects": [
        tactic("impact", "Impact", "TA0040"),
        tactic("reconnaissance", "Reconnaissance", "TA0043"),
        {"type": "x-mitre-tactic", "name": "No External Id", "x_mitre_shortname": "broken"},
        {"type": "attack-pattern", "name": "Not A Tactic", "x_mitre_shortname": "x"},
        tactic("stealth", "Stealth", "TA0005", description="Multi-line\n   description.  "),
    ]}


def test_extract_keeps_only_identified_tactics_sorted_by_id():
    tactics = bake.extract_tactics(_fixture())
    assert [t["external_id"] for t in tactics] == ["TA0005", "TA0040", "TA0043"]
    assert [t["name"] for t in tactics] == ["Stealth", "Impact", "Reconnaissance"]
    assert tactics[0]["description"] == "Multi-line description."


def test_extract_ignores_non_tactic_objects():
    tactics = bake.extract_tactics({"objects": [{"type": "attack-pattern", "name": "X"}]})
    assert tactics == []


def test_attack_version_reads_the_collection_object():
    bundle = {"objects": [{"type": "x-mitre-collection", "x_mitre_version": "19.2"}]}
    assert bake.attack_version(bundle) == "19.2"
    assert bake.attack_version({"objects": []}) == "unknown"


def test_vocabulary_drift_excludes_legacy_names():
    from mcp_server.core.constants import LEGACY_MITRE_TACTICS, MITRE_TACTIC_TO_CATEGORY
    expected = set(MITRE_TACTIC_TO_CATEGORY)
    legacy = set(LEGACY_MITRE_TACTICS)
    upstream = expected - legacy
    assert bake.vocabulary_drift(upstream, expected, legacy) == ([], [])
    missing, _extra = bake.vocabulary_drift(upstream - {"Impact"}, expected, legacy)
    assert missing == ["Impact"]


def test_render_emits_importable_python():
    source = bake.render(bake.extract_tactics(_fixture()), "bundle.json", "a" * 64, "19.2")
    namespace: dict = {}
    exec(compile(source, "generated.py", "exec"), namespace)
    assert set(namespace["TACTICS"]) == {"impact", "reconnaissance", "stealth"}
    assert namespace["TACTICS"]["impact"]["external_id"] == "TA0040"
    assert namespace["SOURCE_SHA256"] == "a" * 64
    assert namespace["ATTACK_VERSION"] == "19.2"


def test_baked_module_is_well_formed():
    from mcp_server.label.mitre_tactics_generated import ATTACK_VERSION, SOURCE_SHA256, TACTICS
    assert len(TACTICS) >= 10
    assert re.fullmatch(r"[0-9a-f]{64}", SOURCE_SHA256)
    assert ATTACK_VERSION
    for shortname, spec_ in TACTICS.items():
        assert re.fullmatch(r"[a-z0-9-]+", shortname), shortname
        assert re.fullmatch(r"TA\d{4}", spec_["external_id"]), spec_
        assert spec_["name"] and spec_["description"]


def test_baked_vocabulary_covers_the_scored_vocabulary():
    from mcp_server.core.constants import LEGACY_MITRE_TACTICS, MITRE_TACTIC_TO_CATEGORY
    from mcp_server.label.mitre_tactics_generated import TACTICS

    upstream = {spec_["name"] for spec_ in TACTICS.values()}
    assert upstream | set(LEGACY_MITRE_TACTICS) >= set(MITRE_TACTIC_TO_CATEGORY)
    assert len(TACTICS) == 15
    assert "Defense Evasion" not in upstream
    assert "Defense Evasion" in MITRE_TACTIC_TO_CATEGORY


def test_criteria_guard_passes_with_the_bake_and_fails_when_it_goes_stale(monkeypatch):
    from mcp_server.label import criteria

    criteria._assert_vocabulary()

    stale = {k: v for k, v in criteria.MITRE_TACTICS.items() if v["name"] != "Impact"}
    monkeypatch.setattr(criteria, "MITRE_TACTICS", stale)
    with pytest.raises(RuntimeError, match="baked ATT&CK vocabulary is stale"):
        criteria._assert_vocabulary()


def test_criteria_version_is_stable_and_covers_every_tactic():
    from mcp_server.core.constants import MITRE_TACTIC_TO_CATEGORY
    from mcp_server.label import criteria

    assert criteria.TACTICS == tuple(sorted(MITRE_TACTIC_TO_CATEGORY))
    assert set(criteria.criteria_map()) == set(MITRE_TACTIC_TO_CATEGORY)
    assert re.fullmatch(r"v1:[0-9a-f]{8}", criteria.version())


def test_generated_file_records_its_source(tmp_path):
    bundle = tmp_path / "bundle.json"
    bundle.write_text(json.dumps(_fixture()))
    assert bundle.is_file()
    assert bake.EXTERNAL_ID.match("TA0001")
    assert not bake.EXTERNAL_ID.match("T1059")
