#!/usr/bin/env python3
# © NAuliajati - TangerangKota-CSIRT
"""Tests for scripts/correlation_label_inventory.py. Synthetic temporary fixtures
only: no live store, no Indexer, no production path, no real labels.
"""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
import sqlite3
from pathlib import Path

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "correlation_label_inventory.py"
_spec = importlib.util.spec_from_file_location("correlation_label_inventory", SCRIPT)
inv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(inv)

MEMORY_COLUMNS = (
    "unit_id", "type", "subject", "subject_kind", "text", "entities", "occurred_at",
    "first_seen", "last_seen", "support_count", "source", "provenance", "tainted",
    "confidence", "case_id", "invalidated_by", "kind", "value", "dedupe_key",
)
MEM_ENV = {"BLUETEAM_MEM_ENABLED": "true",
           inv.MEMORY_QUIESCENT_ENV: "true"}

# The engine writes this title with an em dash (correlation.py:670); fixtures reuse
# the exact shipped string so the title heuristic runs on the production shape.
ENGINE_CASE_TITLE = "3-Sum APT — 2 trigger(s)"


def _write_jsonl(path: Path, rows: list) -> Path:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return path


def _decision(subject: str, verdict: str, *, source: str = "verdict",
              provenance: str = "analyst", unit_type: str = "world", tainted: int = 0,
              case_id: str = "", first_seen: str = "2026-03-01T00:00:00+00:00",
              suffix: str = "") -> tuple:
    return (f"mem-{subject}-{verdict}-{source}-{case_id or 'none'}{suffix}", unit_type,
            subject, "srcip", f"verdict {verdict}", "[]", "", first_seen, first_seen, 1,
            source, provenance, tainted, None, case_id, "", "decision", verdict,
            f"dedupe-{subject}-{verdict}-{source}{suffix}")


def _memory_db(path: Path, decisions: list[tuple], *, columns: tuple = MEMORY_COLUMNS,
               journal_mode: str = "DELETE") -> Path:
    conn = sqlite3.connect(path)
    if journal_mode != "DELETE":
        conn.execute(f"PRAGMA journal_mode={journal_mode}")
    conn.execute(f"CREATE TABLE units ({', '.join(columns)})")
    placeholders = ", ".join("?" for _ in columns)
    conn.executemany(f"INSERT INTO units VALUES ({placeholders})", decisions)
    conn.commit()
    conn.close()
    return path


def _stores(tmp_path: Path, **paths) -> dict:
    """Resolved store map with only the named stores configured."""
    env = {inv.STORE_ENV[name]: str(path) for name, path in paths.items()}
    return inv.resolve_store_paths(env, root=str(tmp_path))


def _hashes(root: Path) -> dict:
    return {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file()}


def test_root_is_required_and_absolute(tmp_path):
    for env in ({}, {inv.ROOT_ENV: "relative/root"}):
        try:
            inv.resolve_store_paths(env)
        except inv.Refused as exc:
            assert "BLUETEAM_INVENTORY_ROOT" in str(exc)
        else:
            raise AssertionError("expected Refused")


def test_filesystem_root_is_refused():
    try:
        inv.resolve_store_paths({}, root="/")
    except inv.Refused as exc:
        assert "filesystem root" in str(exc)
    else:
        raise AssertionError("expected Refused")


def test_production_path_is_refused(tmp_path):
    env = {inv.ROOT_ENV: str(tmp_path),
           "BLUETEAM_CASE_STORE": "/var/ossec/queue/alerts.jsonl"}
    try:
        inv.resolve_store_paths(env)
    except inv.Refused as exc:
        assert "production" in str(exc)
    else:
        raise AssertionError("expected Refused")


def test_path_outside_root_is_refused(tmp_path):
    outside = tmp_path.parent / "not-staging" / "cases.jsonl"
    env = {inv.ROOT_ENV: str(tmp_path), "BLUETEAM_CASE_STORE": str(outside)}
    try:
        inv.resolve_store_paths(env)
    except inv.Refused as exc:
        assert "outside" in str(exc)
    else:
        raise AssertionError("expected Refused")


def test_symlink_escape_is_refused(tmp_path):
    outside = tmp_path.parent / "escape-target.jsonl"
    outside.write_text("{}\n", encoding="utf-8")
    link = tmp_path / "link.jsonl"
    link.symlink_to(outside)
    env = {inv.ROOT_ENV: str(tmp_path), "BLUETEAM_CASE_STORE": str(link)}
    try:
        inv.resolve_store_paths(env)
    except inv.Refused as exc:
        assert "outside" in str(exc)
    else:
        raise AssertionError("expected Refused")


def test_duplicate_store_paths_are_refused(tmp_path):
    shared = tmp_path / "shared.jsonl"
    shared.write_text("{}\n", encoding="utf-8")
    env = {inv.ROOT_ENV: str(tmp_path),
           "BLUETEAM_CASE_STORE": str(shared),
           "BLUETEAM_INVESTIGATION_HISTORY": str(shared)}
    try:
        inv.resolve_store_paths(env)
    except inv.Refused as exc:
        assert "ambiguous" in str(exc)
    else:
        raise AssertionError("expected Refused")


def test_production_marker_matches_on_component_boundary():
    assert inv._is_production(Path("/var/ossec")) is True
    assert inv._is_production(Path("/var/ossec/queue/alerts.jsonl")) is True
    assert inv._is_production(Path("/var/ossec_extra/alerts.jsonl")) is False
    assert inv._is_production(Path("/opt/blue-team-mcp-backup")) is False


def test_root_is_canonicalized(tmp_path):
    (tmp_path / "sub").mkdir()
    resolved = inv.resolve_store_paths({}, root=str(tmp_path) + "/./sub/..")
    assert resolved["root"] == str(tmp_path.resolve())


def test_resolved_environment_states_the_trust_boundary(tmp_path):
    resolved = _stores(tmp_path)
    assert resolved["root_declared_by"] == "operator"
    assert "not exhaustive" in resolved["production_marker_check"]


def test_unconfigured_stores_report_not_configured(tmp_path):
    resolved = _stores(tmp_path)
    payload = inv.build_inventory(resolved, {})
    assert payload["evaluability"]["status"] == "not_evaluable"
    assert payload["positive_label_stock"] == "none"
    for name in ("case_store", "investigation_history", "memory_store",
                 "attacker_registry", "ioc_store"):
        assert payload[name]["status"] == "not_configured"
        assert payload[name].get("records") is None
        assert payload[name].get("decision_units") is None


def test_preflight_root_refusal_blocks_stores_without_probing(tmp_path, monkeypatch):
    """A root refusal happens before any store variable is examined."""
    def _must_not_resolve(*args, **kwargs):
        raise AssertionError("store path resolved after a root refusal")

    monkeypatch.setattr(inv, "_resolve_checked", _must_not_resolve)
    env = {"BLUETEAM_CASE_STORE": str(tmp_path / "cases.jsonl"),
           "BLUETEAM_MEM_DB": str(tmp_path / "memory.db")}
    report = inv.preflight(env)
    assert report["status"] == "refused"
    assert inv.ROOT_ENV in report["reason"]
    assert report["root"] is None
    assert all(entry["status"] == "blocked_by_root"
               for entry in report["stores"].values())
    assert "not_configured" not in inv.render_preflight(report)


def test_preflight_keeps_checked_statuses_before_a_store_refusal(tmp_path):
    """Checked stores keep their real status; the rest stay not_checked."""
    outside = tmp_path.parent / "not-staging" / "memory.db"
    env = {inv.ROOT_ENV: str(tmp_path),
           "BLUETEAM_CASE_STORE": str(tmp_path / "cases.jsonl"),
           "BLUETEAM_MEM_DB": str(outside)}
    report = inv.preflight(env)
    assert report["status"] == "refused"
    assert "memory_store" in report["reason"]
    stores = report["stores"]
    assert stores["case_store"]["status"] == "configured"
    assert stores["investigation_history"]["status"] == "not_configured"
    assert stores["memory_store"]["status"] == "not_checked"
    assert stores["attacker_registry"]["status"] == "not_checked"
    assert stores["ioc_store"]["status"] == "not_checked"


def test_preflight_unset_stores_are_not_configured_after_root_passes(tmp_path):
    report = inv.preflight({}, root=str(tmp_path))
    assert report["status"] == "ok"
    assert all(entry["status"] == "not_configured"
               for entry in report["stores"].values())


def test_configured_missing_store_is_absent(tmp_path):
    resolved = _stores(tmp_path, case_store=tmp_path / "missing.jsonl")
    case = inv.build_inventory(resolved, {})["case_store"]
    assert case["status"] == "absent"
    assert case["records"] is None


def test_directory_as_store_reports_unreadable(tmp_path):
    """An open error becomes unreadable; it is never parsed as data."""
    directory = tmp_path / "history-dir"
    directory.mkdir()
    resolved = _stores(tmp_path, investigation_history=directory)
    history = inv.build_inventory(resolved, {})["investigation_history"]
    assert history["status"] == "unreadable"
    assert history["records"] is None


def test_history_missing_provenance_and_case_id_are_counted(tmp_path):
    path = _write_jsonl(tmp_path / "history.jsonl", [
        {"ts": "2026-03-01T00:00:00Z", "srcip": "203.0.113.1",
         "verdict": "true_positive", "notes": "C2 beacon"},
        {"ts": "2026-03-02T00:00:00Z", "srcip": "203.0.113.1",
         "verdict": "false_positive", "notes": "same host, scanner"},
        {"ts": "2026-03-03T00:00:00Z", "srcip": "203.0.113.2",
         "verdict": "suspicious", "notes": inv.WORKFLOW_NOTE},
    ])
    resolved = _stores(tmp_path, investigation_history=path)
    history = inv.build_inventory(resolved, {})["investigation_history"]
    assert history["status"] == "ok"
    assert history["records"] == 3
    assert history["unique_subjects"] == 2
    assert history["repeated_subject_records"] == 1
    assert history["repeated_subject_rate"] == round(1 - 2 / 3, 4)
    assert history["exact_duplicate_records"] == 0
    assert history["case_id_field_present"] is False
    assert history["entries_with_case_id"] == 0
    assert history["recorded_by_field_present"] is False
    assert history["missing_provenance_entries"] == 3
    assert history["workflow_marker_entries"] == 1
    assert history["analyst_attributed_entries"] == 2


def test_history_exact_duplicate_is_distinct_from_repeated_subject(tmp_path):
    row = {"ts": "2026-03-01T00:00:00Z", "srcip": "203.0.113.1",
           "verdict": "true_positive", "notes": "C2 beacon"}
    other = {"ts": "2026-03-04T00:00:00Z", "srcip": "203.0.113.1",
             "verdict": "true_positive", "notes": "C2 beacon"}
    path = _write_jsonl(tmp_path / "history.jsonl", [row, dict(row), other])
    resolved = _stores(tmp_path, investigation_history=path)
    history = inv.build_inventory(resolved, {})["investigation_history"]
    assert history["records"] == 3
    assert history["unique_subjects"] == 1
    assert history["repeated_subject_records"] == 2      # same IP in three events
    assert history["exact_duplicate_records"] == 1       # only the byte-identical row
    assert history["exact_duplicate_rate"] == round(1 / 3, 4)


def test_history_malformed_lines_are_counted_not_parsed(tmp_path):
    path = tmp_path / "history.jsonl"
    path.write_text('{"srcip": "203.0.113.9", "verdict": "clean"}\nnot json\n\n',
                    encoding="utf-8")
    resolved = _stores(tmp_path, investigation_history=path)
    history = inv.build_inventory(resolved, {})["investigation_history"]
    assert history["records"] == 1
    assert history["malformed_lines"] == 1


def test_case_verdict_conflicts_and_duplicates(tmp_path):
    path = _write_jsonl(tmp_path / "cases.jsonl", [
        {"case_id": "case_a", "title": "Analyst campaign",
         "created_at": "2026-03-01T00:00:00+00:00",
         "srcips": ["203.0.113.1", "203.0.113.2"],
         "verdicts": [
             {"srcip": "203.0.113.1", "verdict": "true_positive", "ts": "T1"},
             {"srcip": "203.0.113.1", "verdict": "true_positive", "ts": "T1"},
             {"srcip": "203.0.113.1", "verdict": "false_positive", "ts": "T2"},
             {"srcip": "203.0.113.2", "verdict": "suspicious", "ts": "T3"}]},
        {"case_id": "case_a", "title": ENGINE_CASE_TITLE,
         "created_at": "2026-03-05T00:00:00+00:00", "srcips": [], "verdicts": []},
    ])
    resolved = _stores(tmp_path, case_store=path)
    case = inv.build_inventory(resolved, {})["case_store"]
    assert case["status"] == "ok"
    assert case["records"] == 2
    assert case["case_verdicts"] == 4
    assert case["cases_with_conflicting_verdicts"] == 1
    assert case["cases_with_mixed_verdicts"] == 1
    assert case["duplicate_case_ids"] == 1
    assert case["duplicate_verdict_entries"] == 1
    assert case["cases_engine_title_heuristic"] == 1


def test_memory_provenance_split_groups_and_pairs(tmp_path):
    db = _memory_db(tmp_path / "memory.db", [
        _decision("srcip:203.0.113.1", "true_positive", case_id="case_a"),
        _decision("srcip:203.0.113.1", "false_positive", case_id="case_a"),
        _decision("srcip:203.0.113.2", "suspicious", case_id="case_a"),
        _decision("srcip:203.0.113.3", "false_positive", case_id="case_a"),
        _decision("srcip:203.0.113.4", "suspicious", case_id="case_b"),
        _decision("srcip:203.0.113.5", "suspicious", source="workflow",
                  provenance="tool_output", unit_type="observation", tainted=1,
                  case_id="case_b"),
        _decision("srcip:203.0.113.6", "true_positive", case_id="case_c"),
        _decision("srcip:203.0.113.7", "true_positive", case_id="case_c"),
        _decision("srcip:203.0.113.8", "true_positive"),  # no case link
    ])
    resolved = _stores(tmp_path, memory_store=db)
    payload = inv.build_inventory(resolved, MEM_ENV)
    memory = payload["memory_store"]
    assert memory["status"] == "ok"
    assert memory["read_mode"] == "immutable"
    assert memory["analyst_declared_decisions"] == 8
    assert memory["advisory_decisions"] == 1
    assert memory["analyst_declared_decisions_with_case_id"] == 7
    assert memory["distinct_analyst_declared_case_ids"] == 3
    assert memory["analyst_declared_case_scoped_conflicting_subjects"] == 1
    assert memory["analyst_declared_subjects_with_mixed_verdicts_without_case_context"] == 0
    labels = payload["independent_labels"]
    assert labels["analyst_declared_incident_groups"] == 3
    assert labels["analyst_declared_incident_groups_with_multiple_subjects"] == 2
    assert labels["candidate_same_incident_pairs"] == 4  # C(3,2) + C(2,2)
    assert payload["pairing_frame"]["same_incident_labelled_pairs"]["available"] is None
    assert payload["evaluability"]["status"] == "not_evaluable"


def test_memory_conflict_requires_case_context(tmp_path):
    db = _memory_db(tmp_path / "memory.db", [
        # Same IP, different cases: not a conflict, the events are unrelated.
        _decision("srcip:203.0.113.1", "true_positive", case_id="case_a"),
        _decision("srcip:203.0.113.1", "false_positive", case_id="case_b"),
        # Same IP, no case context on either decision: data-quality flag only.
        _decision("srcip:203.0.113.9", "true_positive"),
        _decision("srcip:203.0.113.9", "false_positive"),
    ])
    resolved = _stores(tmp_path, memory_store=db)
    memory = inv.build_inventory(resolved, MEM_ENV)["memory_store"]
    assert memory["analyst_declared_case_scoped_conflicting_subjects"] == 0
    assert memory["analyst_declared_subjects_with_mixed_verdicts_without_case_context"] == 1


def test_memory_requires_quiescence_declaration(tmp_path):
    db = _memory_db(tmp_path / "memory.db", [
        _decision("srcip:203.0.113.1", "true_positive", case_id="case_a")])
    resolved = _stores(tmp_path, memory_store=db)
    payload = inv.build_inventory(resolved, {"BLUETEAM_MEM_ENABLED": "true"})
    memory = payload["memory_store"]
    assert memory["status"] == "refused"
    assert inv.MEMORY_QUIESCENT_ENV in memory["reason"]
    assert memory["decision_units"] is None
    assert payload["independent_labels"]["candidate_same_incident_pairs"] is None


def test_memory_store_path_with_uri_special_characters(tmp_path):
    """A '#' in the store path must not be read as a URI fragment."""
    weird = tmp_path / "store #1"
    weird.mkdir()
    db = _memory_db(weird / "memory.db", [
        _decision("srcip:203.0.113.1", "true_positive", case_id="case_a")])
    resolved = _stores(tmp_path, memory_store=db)
    memory = inv.build_inventory(resolved, MEM_ENV)["memory_store"]
    assert memory["status"] == "ok"
    assert memory["analyst_declared_decisions"] == 1


def test_memory_wal_side_file_is_refused(tmp_path):
    db = _memory_db(tmp_path / "memory.db", [
        _decision("srcip:203.0.113.1", "true_positive", case_id="case_a")])
    db.with_name(db.name + "-wal").write_bytes(b"")
    resolved = _stores(tmp_path, memory_store=db)
    memory = inv.build_inventory(resolved, MEM_ENV)["memory_store"]
    assert memory["status"] == "refused"
    assert "-wal" in memory["reason"]
    assert memory["decision_units"] is None


def test_memory_concurrent_writer_is_detected(tmp_path, monkeypatch):
    db = _memory_db(tmp_path / "memory.db", [
        _decision("srcip:203.0.113.1", "true_positive", case_id="case_a")])
    resolved = _stores(tmp_path, memory_store=db)
    calls = {"n": 0}

    def fake_side_files(path):
        calls["n"] += 1
        return [] if calls["n"] == 1 else ["-wal"]

    monkeypatch.setattr(inv, "_side_files", fake_side_files)
    memory = inv.build_inventory(resolved, MEM_ENV)["memory_store"]
    assert memory["status"] == "refused"
    assert "during the read" in memory["reason"]
    assert memory["decision_units"] is None


def test_memory_disabled_reports_disabled_not_measured(tmp_path):
    db = _memory_db(tmp_path / "memory.db", [
        _decision("srcip:203.0.113.1", "true_positive", case_id="case_a")])
    resolved = _stores(tmp_path, memory_store=db)
    memory = inv.build_inventory(resolved, {})["memory_store"]
    assert memory["status"] == "disabled"
    assert memory["decision_units"] is None
    assert inv.build_inventory(resolved, {})["independent_labels"][
        "candidate_same_incident_pairs"] is None


def test_memory_schema_incomplete_fails_closed(tmp_path):
    db = _memory_db(tmp_path / "memory.db", [], columns=("subject", "kind", "value"))
    resolved = _stores(tmp_path, memory_store=db)
    payload = inv.build_inventory(resolved, MEM_ENV)
    memory = payload["memory_store"]
    assert memory["status"] == "schema_incomplete"
    assert "case_id" in memory["schema_missing_columns"]
    assert payload["independent_labels"]["analyst_declared_incident_groups"] is None
    assert payload["positive_label_stock"] == "none"


def test_registry_separates_engine_from_unverified(tmp_path):
    path = _write_jsonl(tmp_path / "registry.jsonl", [
        {"ioc": "203.0.113.1", "source": "engine_a"},
        {"ioc": "203.0.113.2", "source": "auto_promote"},
        {"ioc": "203.0.113.3", "source": "enrichment"},
        {"ioc": "203.0.113.4", "source": "verdict"},
        {"ioc": "203.0.113.5", "source": "manual"},
    ])
    resolved = _stores(tmp_path, attacker_registry=path)
    registry = inv.build_inventory(resolved, {})["attacker_registry"]
    assert registry["records"] == 5
    assert registry["operator_verified"] == 0      # verdict is provenance-blind
    assert registry["engine_derived"] == 3
    assert registry["unverified"] == 2             # verdict + manual
    assert registry["source_evidence"]["verdict"]["class"] == "unverified"
    assert "workflow" in registry["source_evidence"]["verdict"]["reason"]
    labels = inv.build_inventory(resolved, {})["independent_labels"]
    assert labels["operator_verified_indicator_labels"] == 0
    assert labels["unverified_indicator_registrations"] == 2
    assert labels["engine_derived_confirmed_flags"] == 3


def test_registry_untraced_source_is_unknown(tmp_path):
    path = _write_jsonl(tmp_path / "registry.jsonl", [
        {"ioc": "203.0.113.1", "source": "some_new_writer"},
        {"ioc": "203.0.113.2", "source": "analyst"},
    ])
    resolved = _stores(tmp_path, attacker_registry=path)
    registry = inv.build_inventory(resolved, {})["attacker_registry"]
    assert registry["operator_verified"] == 0
    assert registry["unverified"] == 1             # analyst has no demonstrated writer
    assert registry["unknown"] == 1
    assert registry["source_evidence"]["some_new_writer"]["class"] == "unknown"


def test_ioc_cooccurrence_bearing_count_is_aggregate(tmp_path):
    path = _write_jsonl(tmp_path / "iocs.jsonl", [
        {"ioc": "203.0.113.1", "batches": [1, 2]},
        {"ioc": "203.0.113.2", "batches": [2]},
        {"ioc": "203.0.113.3", "batches": [9]},
    ])
    resolved = _stores(tmp_path, ioc_store=path)
    ioc = inv.build_inventory(resolved, {})["ioc_store"]
    assert ioc["records"] == 3
    assert ioc["cooccurrence_bearing_iocs"] == 2


def test_engine_only_fixture_is_not_evaluable(tmp_path):
    history = _write_jsonl(tmp_path / "history.jsonl", [
        {"ts": "2026-03-01T00:00:00Z", "srcip": "203.0.113.1",
         "verdict": "suspicious", "notes": inv.WORKFLOW_NOTE}])
    registry = _write_jsonl(tmp_path / "registry.jsonl", [
        {"ioc": "203.0.113.1", "source": "engine_a"},
        {"ioc": "203.0.113.2", "source": "auto_promote"}])
    cases = _write_jsonl(tmp_path / "cases.jsonl", [
        {"case_id": "case_b", "title": ENGINE_CASE_TITLE,
         "srcips": ["203.0.113.1", "203.0.113.2"], "verdicts": []}])
    db = _memory_db(tmp_path / "memory.db", [
        _decision("srcip:203.0.113.1", "suspicious", source="workflow",
                  provenance="tool_output", unit_type="observation", tainted=1,
                  case_id="case_b")])
    resolved = _stores(tmp_path, investigation_history=history,
                       attacker_registry=registry, case_store=cases, memory_store=db)
    payload = inv.build_inventory(resolved, MEM_ENV)
    assert payload["evaluability"]["status"] == "not_evaluable"
    assert payload["positive_label_stock"] == "engine_derived_only"
    assert payload["independent_labels"]["candidate_same_incident_pairs"] == 0
    assert payload["independent_labels"]["operator_verified_indicator_labels"] == 0
    assert payload["independent_labels"]["engine_derived_confirmed_flags"] == 2
    assert payload["pairing_frame"]["same_incident_labelled_pairs"]["available"] is None
    assert any("negative pairs" in item for item in payload["evaluability"]["blocking"])
    assert "f1" not in json.dumps(payload).lower()


def test_candidate_pairs_are_not_labelled_pairs(tmp_path):
    db = _memory_db(tmp_path / "memory.db", [
        _decision("srcip:203.0.113.1", "true_positive", case_id="case_a"),
        _decision("srcip:203.0.113.2", "true_positive", case_id="case_a"),
        _decision("srcip:203.0.113.3", "true_positive", case_id="case_a"),
    ])
    resolved = _stores(tmp_path, memory_store=db)
    payload = inv.build_inventory(resolved, MEM_ENV)
    assert payload["independent_labels"]["candidate_same_incident_pairs"] == 3
    labelled = payload["pairing_frame"]["same_incident_labelled_pairs"]
    assert labelled["available"] is None and labelled["status"] == "unavailable"
    assert payload["evaluability"]["status"] == "not_evaluable"
    assert any("pair-level" in item for item in payload["evaluability"]["blocking"])


def test_memory_declaration_is_not_operator_verified(tmp_path):
    """The writer trusts the caller-supplied recorded_by; the inventory must not
    promote that declaration to an independently verified label."""
    db = _memory_db(tmp_path / "memory.db", [
        _decision("srcip:203.0.113.1", "true_positive", case_id="case_a"),
        _decision("srcip:203.0.113.2", "true_positive", case_id="case_a"),
    ])
    registry = _write_jsonl(tmp_path / "registry.jsonl", [
        {"ioc": "203.0.113.1", "source": "verdict"},
        {"ioc": "203.0.113.2", "source": "engine_a"},
    ])
    resolved = _stores(tmp_path, memory_store=db, attacker_registry=registry)
    payload = inv.build_inventory(resolved, MEM_ENV)
    assert payload["memory_store"]["analyst_declared_decisions"] == 2
    assert payload["positive_label_stock"] == "analyst_declared"
    labels = payload["independent_labels"]
    assert labels["operator_verified_indicator_labels"] == 0
    assert labels["unverified_indicator_registrations"] == 1
    assert labels["analyst_declared_case_linked_decisions"] == 2
    assert labels["analyst_declared_cases"] == 1
    assert payload["evaluability"]["status"] == "not_evaluable"
    assert any("not authenticated" in item for item in payload["evaluability"]["blocking"])
    assert "analyst_declared" in payload["definitions"]


def test_recorded_by_is_caller_supplied_not_authenticated():
    """Evidence pin: recorded_by is a free string defaulting to the trusted value;
    no server-side identity binds it."""
    from mcp_server.tools.investigation_history import MarkInvestigatedInput
    field = MarkInvestigatedInput.model_fields["recorded_by"]
    assert field.default == "analyst"
    params = MarkInvestigatedInput(srcip="203.0.113.1", verdict="suspicious",
                                   recorded_by="whoever")
    assert params.recorded_by == "whoever"


def test_aggregate_output_carries_no_raw_record_values(tmp_path):
    marker_ip = "203.0.113.77"
    marker_note = "ticket-secret-abc-4412"
    marker_title = "campaign-secret-xyz"
    cases = _write_jsonl(tmp_path / "cases.jsonl", [
        {"case_id": "case_secret", "title": marker_title,
         "srcips": [marker_ip], "notes": marker_note,
         "verdicts": [{"srcip": marker_ip, "verdict": "true_positive",
                       "notes": marker_note}]}])
    history = _write_jsonl(tmp_path / "history.jsonl", [
        {"ts": "2026-03-01T00:00:00Z", "srcip": marker_ip,
         "verdict": "true_positive", "notes": marker_note}])
    registry = _write_jsonl(tmp_path / "registry.jsonl", [
        {"ioc": marker_ip, "source": "verdict"}])
    db = _memory_db(tmp_path / "memory.db", [
        _decision(f"srcip:{marker_ip}", "true_positive", case_id="case_secret")])
    resolved = _stores(tmp_path, case_store=cases, investigation_history=history,
                       attacker_registry=registry, memory_store=db)
    payload = inv.build_inventory(resolved, MEM_ENV)
    rendered = json.dumps(payload, sort_keys=True) + inv.render_markdown(payload)
    for marker in (marker_ip, marker_note, marker_title):
        assert marker not in rendered


def test_inventory_leaves_store_files_unchanged(tmp_path):
    cases = _write_jsonl(tmp_path / "cases.jsonl", [
        {"case_id": "case_a", "title": "x", "srcips": ["203.0.113.1"],
         "verdicts": [{"srcip": "203.0.113.1", "verdict": "true_positive"}]}])
    history = _write_jsonl(tmp_path / "history.jsonl", [
        {"ts": "2026-03-01T00:00:00Z", "srcip": "203.0.113.1",
         "verdict": "true_positive", "notes": "analyst note"}])
    db = _memory_db(tmp_path / "memory.db", [
        _decision("srcip:203.0.113.1", "true_positive", case_id="case_a")])
    resolved = _stores(tmp_path, case_store=cases, investigation_history=history,
                       memory_store=db)
    before_files = _hashes(tmp_path)
    inv.build_inventory(resolved, MEM_ENV)
    assert _hashes(tmp_path) == before_files
    assert all(not p.name.endswith(("-wal", "-shm")) for p in tmp_path.iterdir())


def test_constants_match_runtime_sources():
    from mcp_server.core.attacker_registry import ANALYST_SOURCES as runtime_sources
    from mcp_server.core.memory_store import AUTO_VERDICT_NOTE
    assert inv.ANALYST_SOURCES == runtime_sources
    assert inv.WORKFLOW_NOTE == AUTO_VERDICT_NOTE


def test_cli_refuses_without_root(monkeypatch, capsys):
    monkeypatch.delenv(inv.ROOT_ENV, raising=False)
    assert inv.main(["--json"]) == 2
    captured = capsys.readouterr()
    assert "refused" in captured.err
    report = json.loads(captured.out)
    assert report["status"] == "refused"
    assert all(entry["status"] == "blocked_by_root"
               for entry in report["stores"].values())


def test_cli_text_preflight_agrees_with_json(monkeypatch, capsys):
    monkeypatch.delenv(inv.ROOT_ENV, raising=False)
    assert inv.main([]) == 2
    captured = capsys.readouterr()
    assert "refused" in captured.err
    assert "blocked_by_root" in captured.out
    assert "not_configured" not in captured.out


def test_cli_prints_aggregate_json(monkeypatch, capsys, tmp_path):
    history = _write_jsonl(tmp_path / "history.jsonl", [
        {"ts": "2026-03-01T00:00:00Z", "srcip": "203.0.113.5",
         "verdict": "suspicious", "notes": inv.WORKFLOW_NOTE}])
    monkeypatch.setenv(inv.ROOT_ENV, str(tmp_path))
    monkeypatch.setenv(inv.STORE_ENV["investigation_history"], str(history))
    assert inv.main(["--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["evaluability"]["status"] == "not_evaluable"
    assert "203.0.113.5" not in json.dumps(payload)
