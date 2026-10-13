#!/usr/bin/env python3
"""Integrity checks for the routing benchmark datasets.

The dataset is the evidence future routing work is measured against, so a broken label
or a leaked pair invalidates the measurement rather than failing loudly on its own.
Each test below encodes one property that would otherwise be discovered as a wrong
score months later.

Everything except the version-difference tests runs against both versions. Every count
comes from tests/routing_dataset.py, which the benchmark harness also reads, so the
dataset, the tests and the harness cannot hold three opinions about the same file.

Run: pytest tests/test_routing_benchmark.py -q
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from collections import Counter

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import pytest

from tests import bench_routing_benchmark as bench
from tests import routing_dataset as ds
from mcp_server.tools import register_all_tools
from mcp_server import mcp

# Frozen contract. v2 changes four prompt wordings and nothing else, so it holds the
# same contract as v1. Changing any number here is a new dataset version, not an edit.
EXPECTED = {
    "v1": {"records": 170, "pairs": 85, "splits": {"dev": 102, "held": 68},
           "languages": {"en": 85, "id": 85},
           "languages_by_split": {"dev": {"en": 51, "id": 51},
                                  "held": {"en": 34, "id": 34}}},
    "v2": {"records": 170, "pairs": 85, "splits": {"dev": 102, "held": 68},
           "languages": {"en": 85, "id": 85},
           "languages_by_split": {"dev": {"en": 51, "id": 51},
                                  "held": {"en": 34, "id": 34}}},
}

# The scheduled report run cannot pay for these, so a label naming only metered tools
# would mark every run as a miss. The router may still surface them.
METERED = {"blueteam_ioc_search", "blueteam_ioc_search_bulk", "blueteam_ip_intel_bulk",
           "blueteam_breach_check"}

REQUIRED_FIELDS = ("id", "pair", "lang", "intent", "type", "split", "prompt",
                   "acceptable", "rationale")

# Fields that must be identical between two records of the same id across versions.
FROZEN_FIELDS = ("pair", "lang", "intent", "type", "split", "acceptable")


@pytest.fixture(params=ds.VERSIONS)
def version(request) -> str:
    return request.param


@pytest.fixture
def doc(version) -> dict:
    return ds.load(version)


@pytest.fixture
def info(version, doc) -> dict:
    return ds.stats(doc, version)


@pytest.fixture(scope="module")
def registry() -> set[str]:
    register_all_tools()
    return {tool.name for tool in mcp._tool_manager.list_tools()
            if getattr(tool.fn, "__module__", "").startswith("mcp_server.")}


def test_dataset_matches_the_frozen_contract(version, info):
    expected = EXPECTED[version]
    assert info["records"] == expected["records"], info["records"]
    assert info["pairs"] == expected["pairs"], info["pairs"]
    assert info["splits"] == expected["splits"], info["splits"]
    assert info["languages"] == expected["languages"], info["languages"]
    assert info["languages_by_split"] == expected["languages_by_split"], \
        info["languages_by_split"]


def test_every_record_is_well_formed(doc, info):
    problems = []
    for record in doc["records"]:
        missing = [field for field in REQUIRED_FIELDS if not record.get(field)]
        if missing:
            problems.append(f"{record.get('id', '?')}: missing {missing}")
        if record.get("lang") not in ds.LANGS:
            problems.append(f"{record['id']}: lang {record.get('lang')!r}")
        if record.get("split") not in ds.SPLITS:
            problems.append(f"{record['id']}: split {record.get('split')!r}")
        if record.get("type") not in ds.RECORD_TYPES:
            problems.append(f"{record['id']}: type {record.get('type')!r}")
        if record.get("intent") not in ds.AREAS:
            problems.append(f"{record['id']}: intent {record.get('intent')!r}")
    assert not problems, f"{len(problems)} malformed record(s): {problems}"

    assert set(info["by_intent"]) == set(ds.AREAS), (
        "the areas present in the dataset and the areas the report groups by differ: "
        f"{sorted(set(ds.AREAS) - set(info['by_intent']))} / "
        f"{sorted(set(info['by_intent']) - set(ds.AREAS))}"
    )
    ids = [record["id"] for record in doc["records"]]
    assert not [name for name, count in Counter(ids).items() if count > 1]


def test_per_intent_counts_reconcile_with_the_overall_counts(info):
    totals = {key: sum(cell[key] for cell in info["by_intent"].values())
              for key in ("records", "dev", "held")}
    assert totals["records"] == info["records"], totals
    assert totals["dev"] == info["splits"]["dev"], totals
    assert totals["held"] == info["splits"]["held"], totals
    for area, cell in info["by_intent"].items():
        assert cell["dev"] + cell["held"] == cell["records"], (area, cell)


def test_low_confidence_flags_follow_the_configured_threshold(info):
    """The flag and the number behind it must come from one derivation."""
    threshold = info["low_confidence_threshold"]
    expected = sorted(area for area, cell in info["by_intent"].items()
                      if cell["held"] < threshold)
    assert info["low_confidence_areas"] == expected, (
        f"flags {info['low_confidence_areas']} do not match the threshold "
        f"{threshold} applied to the held-out counts"
    )
    for area, cell in info["by_intent"].items():
        assert cell["low_confidence"] == (cell["held"] < threshold), (area, cell)

    assert len(info["low_confidence_areas"]) == 14, (
        f"{len(info['low_confidence_areas'])} low-confidence areas. If this moved, the "
        "held-out split changed and every per-area number in a report needs redoing."
    )
    assert [area for area, cell in info["by_intent"].items()
            if not cell["low_confidence"]] == ["ip_triage", "reporting_intelligence",
                                               "wazuh_manager_config"]


def test_every_label_names_a_registered_tool(doc, registry):
    unknown = sorted({tool for record in doc["records"] for tool in record["acceptable"]}
                     - registry)
    assert not unknown, (
        f"{len(unknown)} label(s) do not resolve to a registered tool: {unknown}. A "
        "label is only meaningful while the tool it names exists."
    )


def test_no_label_names_only_metered_tools(doc):
    offenders = [record["id"] for record in doc["records"]
                 if set(record["acceptable"]) <= METERED]
    assert not offenders, (
        f"{len(offenders)} record(s) accept only metered RapidAPI tools: {offenders}. "
        "The scheduled budget refuses them, so both the engine and a scheduled run "
        "would score a certain miss."
    )


def test_pairs_are_bilingual_and_never_span_splits(doc, info):
    """A wording variant in both halves leaks the answer into the held-out score."""
    assert not info["pair_leaks"], f"pair(s) present in both splits: {info['pair_leaks']}"

    by_pair: dict[str, set[str]] = {}
    for record in doc["records"]:
        by_pair.setdefault(record["pair"], set()).add(record["lang"])
        assert record["pair"] in record["id"], (
            f"{record['id']}: pair {record['pair']!r} is not part of the id, so the "
            "pairing is invisible when reading the file"
        )
    incomplete = sorted(pair for pair, langs in by_pair.items() if len(langs) < 2)
    assert not incomplete, (
        f"{len(incomplete)} pair(s) have only one language: {incomplete}. The pair-level "
        "comparison needs both, and a one-sided pair inflates the language it has."
    )


def test_no_prompt_is_repeated(doc, info):
    repeats = [prompt[:60] for prompt, count in Counter(
        " ".join(record["prompt"].lower().split()) for record in doc["records"]
    ).items() if count > 1]
    assert info["duplicate_prompts"] == 0, f"duplicate prompt(s): {repeats}"


def test_every_area_appears_in_both_splits(info):
    """An area absent from one half cannot be reduced or confirmed by the other."""
    missing_dev = sorted(area for area, cell in info["by_intent"].items() if not cell["dev"])
    missing_held = sorted(area for area, cell in info["by_intent"].items() if not cell["held"])
    assert not missing_dev, f"areas missing from the development half: {missing_dev}"
    assert not missing_held, f"areas missing from the held-out half: {missing_held}"


def test_split_is_roughly_sixty_forty(info):
    """A held-out half larger than the development half leaves nothing to tune on."""
    dev_share = info["splits"]["dev"] / info["records"]
    assert 0.5 <= dev_share <= 0.7, (
        f"development share is {dev_share:.0%} ({info['splits']}); the intended band is "
        "50 to 70 percent"
    )


def test_v1_is_unchanged_since_v2_was_derived():
    """v1 is the historical reference for its own results, so nothing may edit it."""
    parent = ds.load("v2")["derived_from"]
    digest = hashlib.sha256(ds.path_for("v1").read_bytes()).hexdigest()
    assert digest == parent["file_sha256"], (
        f"{ds.path_for('v1').name} has changed since v2 was derived "
        f"({digest[:16]} against the recorded {parent['file_sha256'][:16]}). v1 is "
        "supposed to be immutable; restore it instead of updating the record."
    )


def test_v2_differs_from_v1_only_in_the_logged_records():
    """The whole justification for v2 is that it is v1 plus four wordings."""
    v1, v2 = ds.load("v1"), ds.load("v2")
    log = {entry["id"]: entry for entry in v2["change_log"]}
    assert log, "v2 has no change log, so its difference from v1 is undocumented"

    v1_records = {record["id"]: record for record in v1["records"]}
    v2_records = {record["id"]: record for record in v2["records"]}
    assert list(v1_records) == list(v2_records), "record ids or order changed"

    changed = []
    for rid, after in v2_records.items():
        before = v1_records[rid]
        for field in FROZEN_FIELDS:
            assert before[field] == after[field], (
                f"{rid}: {field} changed between v1 and v2. Only a prompt wording may "
                "change; a label or split change needs its own report."
            )
        if before["prompt"] != after["prompt"]:
            changed.append(rid)
            assert rid in log, f"{rid} changed its prompt with no change-log entry"
            assert log[rid]["before"] == before["prompt"], f"{rid}: logged before differs"
            assert log[rid]["after"] == after["prompt"], f"{rid}: logged after differs"

    assert sorted(changed) == sorted(log), (
        f"records whose prompt changed: {sorted(changed)}; logged: {sorted(log)}"
    )


def test_v2_change_log_entries_are_complete():
    for entry in ds.load("v2")["change_log"]:
        assert entry["field"] == "prompt", entry
        assert entry["reason"].strip(), f"{entry['id']}: no reason"
        assert entry["lexical_check"].strip(), (
            f"{entry['id']}: no lexical check. Every wording change has to record "
            "whether it made the expected tool easier to reach."
        )


def test_the_two_versions_have_distinct_digests():
    assert ds.dataset_digest(ds.load("v1")) != ds.dataset_digest(ds.load("v2"))


def test_harness_reports_the_dataset_statistics_unchanged(tmp_path, monkeypatch):
    """The one check that catches a harness table drifting from the file it came from."""
    assert bench.ds.DATASET_PATHS == ds.DATASET_PATHS
    assert bench.ds.AREAS == ds.AREAS

    out = tmp_path / "held.json"
    monkeypatch.setattr(sys, "argv",
                        ["bench_routing_benchmark", "--dataset", ds.CURRENT,
                         "--split", "held", "--quiet", "--json", str(out)])
    assert bench.main() == 0
    payload = json.loads(out.read_text())

    assert payload["dataset_stats"] == ds.stats(ds.load(ds.CURRENT), ds.CURRENT)
    assert payload["summary"]["overall"]["n"] == payload["dataset_stats"]["splits"]["held"]
    assert payload["dataset_digest"] == payload["dataset_stats"]["digest"]
    flagged = sorted(area for area, cell in payload["by_intent"].items()
                     if cell["low_confidence"])
    assert flagged == payload["dataset_stats"]["low_confidence_areas"]
