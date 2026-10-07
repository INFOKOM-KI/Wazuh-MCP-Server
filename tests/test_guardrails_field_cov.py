#!/usr/bin/env python3
"""Self-tests for the FIELD-COV guardrail check (W7).

The check consumes the W0/W0.5 harness, so these tests exercise it with synthetic
manifest/reference mutations instead of editing the real fixtures.
"""
from __future__ import annotations

import copy

import pytest

import check_guardrails as guard
from tests import field_coverage_lib as cov


@pytest.fixture(scope="module")
def base():
    return cov.load_manifest(), cov.load_template_index(), cov.scan_references()


def _codes(issues):
    return {issue["detail"].split("]")[0].lstrip("[") for issue in issues}


def _check(manifest, index, refs, strict=True):
    return guard.check_field_coverage(strict=strict, manifest=manifest, index=index, refs=refs)


def test_clean_repository_passes(base):
    manifest, index, refs = base
    issues, counts = _check(manifest, index, refs)
    assert issues == []
    assert counts == {"dead_keyword": 0, "mapping_conflict": 0, "unclassified": 0}


def test_new_unclassified_literal_fails_strict(base):
    manifest, index, refs = base
    refs2 = dict(refs)
    refs2["data.zzz_new"] = [("mcp_server/tools/fake.py", 1)]
    issues, _ = _check(manifest, index, refs2)
    assert "new_reference" in _codes(issues)


def test_new_dead_keyword_literal_fails_strict(base):
    manifest, index, refs = base
    refs2 = dict(refs)
    refs2["data.zzz.keyword"] = [("mcp_server/tools/fake.py", 1)]

    issues, _ = _check(manifest, index, refs2)
    assert "new_reference" in _codes(issues)

    unflagged = copy.deepcopy(manifest)
    unflagged["references"]["data.zzz.keyword"] = {"class": "dead_keyword",
                                                   "rationale": "synthetic unflagged"}
    issues, _ = _check(unflagged, index, refs2)
    assert "new_debt" in _codes(issues)

    flagged = copy.deepcopy(manifest)
    flagged["references"]["data.zzz.keyword"] = {
        "class": "dead_keyword", "rationale": "synthetic flagged",
        "baseline_debt": True, "impact": "redundant"}
    issues, _ = _check(flagged, index, refs2)
    assert "strict_debt" in _codes(issues)


def test_new_mapping_conflict_fails_strict(base):
    manifest, index, refs = base
    refs2 = dict(refs)
    refs2["data.file.path"] = [("mcp_server/tools/fake.py", 1)]

    issues, _ = _check(manifest, index, refs2)
    assert "new_reference" in _codes(issues)

    unflagged = copy.deepcopy(manifest)
    unflagged["references"]["data.file.path"] = {"class": "mapping_conflict",
                                                 "rationale": "synthetic unflagged"}
    issues, _ = _check(unflagged, index, refs2)
    assert "new_debt" in _codes(issues)


def test_fixture_hash_mismatch_fails_strict(base):
    manifest, index, refs = base
    stale_hash = copy.deepcopy(manifest)
    stale_hash["template"]["sha256"] = "0" * 64
    issues, _ = _check(stale_hash, index, refs)
    assert "fixture_hash_mismatch" in _codes(issues)


def test_stale_manifest_entry_fails_strict(base):
    manifest, index, refs = base
    stale = copy.deepcopy(manifest)
    stale["references"]["data.zzz_stale"] = {"class": "allowlisted_dynamic",
                                             "rationale": "synthetic stale"}
    issues, _ = _check(stale, index, refs)
    assert "stale_reference" in _codes(issues)


def test_inconsistent_classification_fails_strict(base):
    manifest, index, refs = base
    wrong = copy.deepcopy(manifest)
    wrong["references"]["agent.name"] = {"class": "allowlisted_dynamic",
                                         "rationale": "synthetic wrong class"}
    issues, _ = _check(wrong, index, refs)
    assert "class_mismatch" in _codes(issues)


def test_valid_dynamic_and_native_entries_pass(base):
    manifest, index, refs = base
    assert manifest["references"]["data.domain"]["class"] == "allowlisted_dynamic"
    assert manifest["references"]["agent.name"]["class"] == "template_native"
    issues, _ = _check(manifest, index, refs)
    assert issues == []


def test_new_allowlisted_dynamic_entry_passes(base):
    manifest, index, refs = base
    refs2 = dict(refs)
    refs2["data.zzz_dynamic"] = [("mcp_server/tools/fake.py", 1)]
    dynamic = copy.deepcopy(manifest)
    dynamic["references"]["data.zzz_dynamic"] = {
        "class": "allowlisted_dynamic", "rationale": "decoder-emitted dynamic field"}
    issues, _ = _check(dynamic, index, refs2)
    assert issues == []
