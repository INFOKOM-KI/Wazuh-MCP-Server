#!/usr/bin/env python3
"""W0 field-coverage gate.

Every quoted field reference under ``mcp_server/`` must be classified in
``tests/fixtures/field_manifest.json`` against the pinned template fixture. Known
baseline debt (dead ``.keyword`` aliases, mapping conflicts) is grandfathered;
anything new fails. Set ``FIELD_COVERAGE_STRICT=1`` to enforce the post-W2/W4
target of zero dead, zero conflicting, zero unclassified references.
"""
from __future__ import annotations

import os

import pytest

from tests import field_coverage_lib as cov


@pytest.fixture(scope="module")
def harness():
    manifest = cov.load_manifest()
    index = cov.load_template_index()
    refs = cov.scan_references()
    return {
        "manifest": manifest,
        "index": index,
        "refs": refs,
        "fixture_errors": cov.validate_fixture(manifest, index),
        "result": cov.validate_references(manifest, index, refs),
    }


def test_template_fixture_matches_manifest(harness):
    errors = [message for code, message in harness["fixture_errors"]]
    assert not errors, "\n".join(errors)


def test_leaf_counts_are_derived_from_fixture(harness):
    derived = harness["manifest"]["template"]["derived"]
    index = harness["index"]
    assert len(index.default_fields) == derived["default_field_entries"]
    assert len(index.mapping_leaves) == derived["mapping_leaves"]
    assert len(index.containers) == derived["container_entries"]
    assert len(index.unique_leaves) == derived["unique_leaves"]


def test_every_scanned_reference_is_classified(harness):
    bad = [message for code, message in harness["result"].errors
           if code in ("new_reference", "invalid_class", "missing_rationale")]
    assert not bad, "\n".join(bad)


def test_manifest_classes_match_fixture_facts(harness):
    bad = [message for code, message in harness["result"].errors
           if code == "class_mismatch"]
    assert not bad, "\n".join(bad)


def test_no_new_baseline_debt(harness):
    bad = [message for code, message in harness["result"].errors
           if code == "new_debt"]
    assert not bad, "\n".join(bad)


def test_no_stale_manifest_entries(harness):
    bad = [message for code, message in harness["result"].errors
           if code == "stale_reference"]
    assert not bad, "\n".join(bad)


def test_baseline_snapshot_is_recorded(harness):
    baseline = harness["manifest"]["baseline"]
    assert baseline["dead_keyword"] == 0
    assert baseline["mapping_conflict"] == 0
    assert baseline["unclassified"] == 0
    bad = [message for code, message in harness["result"].errors
           if code == "baseline_count_mismatch"]
    assert not bad, "\n".join(bad)


def test_no_unclassified_literals(harness):
    assert harness["result"].counts.get("unclassified", 0) == 0


@pytest.mark.skipif(os.environ.get("FIELD_COVERAGE_STRICT") != "1",
                    reason="set FIELD_COVERAGE_STRICT=1 for the post-W2/W4 zero-debt target")
def test_strict_mode_requires_zero_debt(harness):
    strict = cov.validate_references(harness["manifest"], harness["index"],
                                     harness["refs"], strict=True)
    remaining = [message for code, message in strict.errors if code == "strict_debt"]
    assert not remaining, "\n".join(remaining)
