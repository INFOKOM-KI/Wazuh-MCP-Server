#!/usr/bin/env python3
"""W0.5 handling-capability gate.

Three layers per template leaf: what the mapping permits, what the MCP server
implements, and what an executable test verifies. Snapshot numbers are the
audited baseline; update them in the change that moves a workstream forward.
"""
from __future__ import annotations

import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import pytest

from tests import field_coverage_lib as cov

# Audited baseline: 602 default-field entries, 611 mapping leaves, 761 unique leaves.
BASELINE = {
    "unique_leaves": 761,
    "status": {"generically_handled": 677, "fully_handled": 69,
               "intentionally_unsupported": 10, "privacy_restricted": 5},
    "mapping_query": {"exact_term": 444, "exact_term_dynamic": 150, "range": 93,
                      "nested_required": 57, "analyzed_match_only": 15, "geo_shape_or_bbox": 2},
    "mapping_aggregation": {"terms": 444, "terms_dynamic": 150, "stats_terms_histogram": 67,
                            "nested_terms_required": 57, "date_histogram": 26,
                            "not_aggregatable": 15, "geo_metrics": 2},
    "privacy": {"value_shape_regex": 582, "not_applicable_non_string": 100,
                "identity_path_masked": 58, "credential_field_l1": 9,
                "ioc_by_design": 8, "identity_key_masked": 4},
    "nested_required": 57,
    "defective_leaves": [],
    "evidence": {"mapping_only": 0, "generic_implementation": 761,
                 "specialized_implementation": 69, "executable_test": 761,
                 "field_level_tests": 3, "no_handling_path": 0,
                 "nested_unenforced": 57, "text_no_aggregation_path": 15},
}


@pytest.fixture(scope="module")
def model():
    index = cov.load_template_index()
    overlay = cov.load_overlay()
    manifest = cov.load_manifest()
    rows = cov.derive_capabilities(index, overlay, manifest)
    return {
        "index": index,
        "overlay": overlay,
        "manifest": manifest,
        "rows": rows,
        "summary": cov.capability_summary(rows),
        "errors": cov.validate_capabilities(overlay, index, manifest, rows),
    }


def test_capability_model_is_consistent(model):
    assert not model["errors"], "\n".join(f"[{c}] {m}" for c, m in model["errors"])


def test_every_leaf_has_one_capability_row(model):
    assert len(model["rows"]) == len(model["index"].unique_leaves)
    paths = {row.path for row in model["rows"]}
    assert paths == set(model["index"].unique_leaves)


def test_baseline_snapshot(model):
    summary = model["summary"]
    assert summary["total_leaves"] == BASELINE["unique_leaves"]
    for dimension in ("status", "mapping_query", "mapping_aggregation", "privacy"):
        for value, count in BASELINE[dimension].items():
            assert summary[dimension].get(value, 0) == count, (
                f"{dimension}.{value}: {summary[dimension].get(value, 0)} != {count}")
    assert summary["nested_required"] == BASELINE["nested_required"]
    assert sorted(summary["defective_leaves"]) == BASELINE["defective_leaves"]
    assert summary["evidence"] == BASELINE["evidence"]


def test_every_leaf_has_an_mcp_handling_path(model):
    summary = model["summary"]
    assert summary["evidence"]["mapping_only"] == 0, "mapping facts alone are not handling"
    assert summary["evidence"]["no_handling_path"] == 0
    for row in model["rows"]:
        assert row.handling_path in ("generic", "specialized", "unsupported",
                                     "privacy_restricted"), row.path
        assert "generic_implementation" in row.evidence_sources or \
               "specialized_implementation" in row.evidence_sources, row.path


def test_unsupported_leaves_are_documented(model):
    overlay = model["overlay"]["intentionally_unsupported"]
    rows = {row.path: row for row in model["rows"]}
    for leaf, reason in overlay.items():
        assert str(reason).strip(), leaf
        assert rows[leaf].handling_path == "unsupported", leaf
        assert rows[leaf].status == "intentionally_unsupported", leaf


def test_privacy_restricted_leaves_are_documented(model):
    """Restricted credentials stay queryable and are protected, not unsupported."""
    overlay = model["overlay"]["privacy_restricted"]
    rows = {row.path: row for row in model["rows"]}
    for leaf, reason in overlay.items():
        assert str(reason).strip(), leaf
        assert rows[leaf].handling_path == "privacy_restricted", leaf
        assert rows[leaf].status == "privacy_restricted", leaf
        assert rows[leaf].privacy == "credential_field_l1", leaf


def test_text_leaves_have_no_aggregation_path(model):
    for row in model["rows"]:
        if row.mapping_type == "text":
            assert row.mapping_query == "analyzed_match_only", row.path
            assert row.mapping_aggregation == "not_aggregatable", row.path
            assert row.implemented_aggregation == "none_by_mapping", row.path


def test_nested_leaves_carry_the_enforcement_warning(model):
    nested = [row for row in model["rows"] if row.nested_path]
    assert len(nested) == BASELINE["nested_required"]
    for row in nested:
        assert row.mapping_query == "nested_required", row.path
        assert row.nested_semantics_enforced is False, row.path
        assert "unenforced" in row.implemented_query, row.path


def test_defective_leaves_match_tool_degrading_refs(model):
    manifest = model["manifest"]
    degrading = {literal[:-8] if literal.endswith(".keyword") else literal
                 for literal, entry in manifest["references"].items()
                 if entry.get("impact") == "tool_degrading"}
    leaf_rows = {row.path for row in model["rows"]}
    expected = degrading & leaf_rows
    actual = {row.path for row in model["rows"] if row.status == "defective"}
    assert actual == expected


def test_specialized_leaves_resolve_to_a_tool(model):
    overlay = model["overlay"]["specialized"]
    for leaf, spec in overlay.items():
        assert spec.get("tool") and spec.get("role"), leaf
        row = next(r for r in model["rows"] if r.path == leaf)
        assert row.analysis_kind == "specialized", leaf
        assert row.handling_path == "specialized", leaf


def test_production_syscheck_field_set_matches_pinned_template(model):
    """The W6 validator list is the fixture's syscheck leaf set, not a copy that can drift."""
    from mcp_server.wazuh import indexer
    expected = {leaf for leaf in model["index"].unique_leaves if leaf.startswith("syscheck.")}
    assert set(indexer._SYSCHECK_FIELD_PATHS) == expected


def test_syscheck_leaves_carry_the_validated_field_selection_path(model):
    for row in model["rows"]:
        if row.path.startswith("syscheck.") and row.analysis_kind != "specialized":
            assert "validated field selection" in row.implemented_analysis, row.path


def test_production_identity_set_matches_overlay(model):
    """The overlay's masked-identity lists are the production redaction set (W1)."""
    from mcp_server.core import redact
    privacy = model["overlay"]["privacy"]
    expected = set(privacy["identity_key_masked"]) | set(privacy["identity_path_masked"])
    assert set(redact._IDENTITY_PATHS) == expected


def test_production_credential_layer_covers_overlay(model):
    """Every credential-classified leaf is masked by key suffix, explicit path, or identity path."""
    from mcp_server.core import redact
    for path in model["overlay"]["privacy"]["credential_fields"]:
        assert redact._is_credential_path(path) or path in redact._IDENTITY_PATHS, path
