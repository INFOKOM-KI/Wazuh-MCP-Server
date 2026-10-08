#!/usr/bin/env python3
"""Tests for scripts/export_case_labels.py. Synthetic store files only: no Indexer,
no model assets, no network, no real labels.
"""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "export_case_labels.py"
_spec = importlib.util.spec_from_file_location("export_case_labels", SCRIPT)
ex = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ex)

PROVENANCE_FIELDS = (
    "id", "source", "source_ref", "case_ref", "observed_at", "text", "text_origin",
    "ground_truth_tactic", "review_state", "reviewer", "adjudicator", "exclude_reason",
    "corpus_version", "split", "criteria_version",
)


def _write(path: Path, rows: list[dict]) -> str:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return str(path)


def _candidate(**over) -> dict:
    base = {"id": "investigation_history:1.2.3.4", "source": "investigation_history",
            "source_ref": "1.2.3.4", "case_ref": "", "observed_at": "2026-09-01T00:00:00+00:00",
            "text": "srcip=1.2.3.4 analyst verdict=true_positive notes=C2 beaconing",
            "text_origin": "synthesized_notes", "ground_truth_tactic": None,
            "review_state": "unreviewed", "reviewer": "", "adjudicator": "",
            "exclude_reason": "", "corpus_version": "", "split": None,
            "criteria_version": ""}
    base.update(over)
    return base


def test_loaders_skip_torn_lines(tmp_path):
    fp = tmp_path / "fp.jsonl"
    fp.write_text('{"ioc": "1.2.3.4", "ts": 1700000000, "reason": "scanner"}\nbroken\n\n',
                  encoding="utf-8")
    assert ex.load_false_positive_kb(str(fp)) == [
        {"ioc": "1.2.3.4", "ts": 1700000000, "reason": "scanner"}]
    history = tmp_path / "history.jsonl"
    history.write_text('{"srcip": "5.6.7.8", "ts": "2026-09-01T00:00:00Z", '
                       '"verdict": "true_positive", "notes": "C2 beaconing"}\n[]\n',
                       encoding="utf-8")
    assert ex.load_history(str(history)) == [
        {"srcip": "5.6.7.8", "ts": "2026-09-01T00:00:00Z",
         "verdict": "true_positive", "notes": "C2 beaconing", "case_id": ""}]


def test_candidate_rows_carry_provenance_and_no_invented_label():
    fp_rows = [{"ioc": "1.2.3.4", "ts": 1700000000.0, "reason": "scanner"}]
    history_rows = [{"srcip": "5.6.7.8", "ts": "2026-09-01T00:00:00Z",
                     "verdict": "true_positive", "notes": "C2 beaconing",
                     "case_id": "CASE-7"}]
    rows = ex.build_rows(fp_rows, history_rows)
    assert len(rows) == 2
    for row in rows:
        assert set(PROVENANCE_FIELDS) <= set(row)
        assert row["ground_truth_tactic"] is None
        assert row["review_state"] == "unreviewed"
        assert row["text_origin"] == "synthesized_notes"
        assert row["split"] is None
        assert row["corpus_version"] == ""
    fp_row, history_row = rows
    assert fp_row["observed_at"].startswith("2023-11-14")
    assert fp_row["source_ref"] == "1.2.3.4"
    assert history_row["observed_at"] == "2026-09-01T00:00:00+00:00"
    assert history_row["case_ref"] == "CASE-7"


def test_history_replaces_fp_for_same_indicator_and_order_is_deterministic():
    fp_rows = [{"ioc": "1.2.3.4", "ts": 1700000000.0, "reason": "scanner"}]
    history_rows = [{"srcip": "1.2.3.4", "ts": "2026-09-01T00:00:00Z",
                     "verdict": "false_positive", "notes": "known scanner", "case_id": ""}]
    first = ex.build_rows(fp_rows, history_rows)
    second = ex.build_rows(fp_rows, history_rows)
    assert first == second
    assert len(first) == 1
    row = first[0]
    assert row["source"] == "investigation_history"
    assert row["id"] == "investigation_history:1.2.3.4"
    assert "verdict=false_positive" in row["text"] and "known scanner" in row["text"]


def test_distinct_indicators_and_limit():
    fp_rows = [{"ioc": "1.1.1.1", "ts": None, "reason": ""},
               {"ioc": "2.2.2.2", "ts": None, "reason": ""}]
    history_rows = [{"srcip": "3.3.3.3", "ts": None, "verdict": "suspicious",
                     "notes": "", "case_id": ""}]
    rows = ex.build_rows(fp_rows, history_rows)
    assert [row["id"] for row in rows] == [
        "false_positive_kb:1.1.1.1", "false_positive_kb:2.2.2.2",
        "investigation_history:3.3.3.3"]
    assert len(ex.build_rows(fp_rows, history_rows, limit=2)) == 2


def test_write_rows_emits_jsonl(tmp_path):
    out = tmp_path / "candidates.jsonl"
    ex.write_rows([{"id": "x", "source": "s", "text": "t"}], str(out))
    row = json.loads(out.read_text(encoding="utf-8").strip())
    assert row == {"id": "x", "source": "s", "text": "t"}


# review mode


def test_review_assigns_split_and_provenance():
    candidates = [_candidate(id="b:2"), _candidate(id="a:1")]
    decisions = [
        {"id": "a:1", "ground_truth_tactic": "Impact", "reviewer": "AA",
         "split": "test", "text": "rule.description=mass file encryption"},
        {"id": "b:2", "ground_truth_tactic": "Discovery", "reviewer": "AA",
         "adjudicator": "BB", "split": "tuning"},
    ]
    accepted, excluded, unreviewed = ex.apply_reviews(
        candidates, decisions, corpus_version="eval-v1", criteria_version="v1:test")
    assert [row["id"] for row in accepted] == ["a:1", "b:2"]
    assert not excluded and not unreviewed
    first = accepted[0]
    assert first["ground_truth_tactic"] == "Impact"
    assert first["split"] == "test"
    assert first["review_state"] == "reviewed"
    assert first["reviewer"] == "AA"
    assert first["text_origin"] == "reviewer_text"
    assert first["text"] == "rule.description=mass file encryption"
    assert first["corpus_version"] == "eval-v1"
    assert first["criteria_version"] == "v1:test"
    assert accepted[1]["adjudicator"] == "BB"


def test_review_alert_passthrough_marks_production_alert():
    alert = {"rule": {"level": 10, "description": "sudoers change"}}
    decisions = [{"id": "investigation_history:1.2.3.4", "ground_truth_tactic": "Persistence",
                  "reviewer": "AA", "split": "test", "alert": alert}]
    accepted, _excluded, _unreviewed = ex.apply_reviews([_candidate()], decisions)
    row = accepted[0]
    assert row["alert"] == alert
    assert "text" not in row
    assert row["text_origin"] == "production_alert"


def test_review_rejects_alert_leakage_fields():
    for alert, path in (
            ({"rule": {"id": "100234", "description": "sudoers change"}}, "rule.id"),
            ({"rule": {"description": "x", "mitre": {"id": "T1068"}}}, "rule.mitre"),
            ({"agent": {"name": "srv-1"}, "rule": {"description": "x"}}, "agent.name")):
        decision = {"id": "investigation_history:1.2.3.4", "ground_truth_tactic": "Persistence",
                    "reviewer": "AA", "split": "test", "alert": alert}
        try:
            ex.apply_reviews([_candidate()], [decision])
            assert False, path
        except ValueError as exc:
            assert path in str(exc) and "leakage fields" in str(exc)


def test_review_excludes_ambiguous_cases_rather_than_relabeling_them():
    decisions = [{"id": "investigation_history:1.2.3.4", "reviewer": "AA",
                  "exclude_reason": "multi_tactic"}]
    accepted, excluded, unreviewed = ex.apply_reviews([_candidate()], decisions)
    assert accepted == [] and unreviewed == []
    assert excluded[0]["review_state"] == "excluded"
    assert excluded[0]["exclude_reason"] == "multi_tactic"
    assert excluded[0]["ground_truth_tactic"] is None
    assert excluded[0]["split"] is None


def test_review_rejects_invalid_or_missing_tactic():
    for tactic in (None, "", "NotATactic"):
        decisions = [{"id": "investigation_history:1.2.3.4", "ground_truth_tactic": tactic,
                      "reviewer": "AA", "split": "test"}]
        try:
            ex.apply_reviews([_candidate()], decisions)
            assert False, tactic
        except ValueError as exc:
            assert "16 tactics" in str(exc)


def test_review_requires_reviewer_and_explicit_split():
    base = {"id": "investigation_history:1.2.3.4", "ground_truth_tactic": "Impact"}
    for decision, needle in ((dict(base), "reviewer"), ({**base, "reviewer": "AA"}, "split")):
        try:
            ex.apply_reviews([_candidate()], [decision])
            assert False, decision
        except ValueError as exc:
            assert needle in str(exc)


def test_review_rejects_unknown_duplicate_and_already_reviewed_rows():
    decision = {"id": "investigation_history:1.2.3.4", "ground_truth_tactic": "Impact",
                "reviewer": "AA", "split": "test"}
    with_unknown = [decision, {**decision, "id": "missing:1"}]
    try:
        ex.apply_reviews([_candidate()], with_unknown)
        assert False
    except ValueError as exc:
        assert "no candidate" in str(exc)
    try:
        ex.apply_reviews([_candidate()], [decision, dict(decision)])
        assert False
    except ValueError as exc:
        assert "duplicate review row" in str(exc)
    reviewed = _candidate(review_state="reviewed")
    try:
        ex.apply_reviews([reviewed], [decision])
        assert False
    except ValueError as exc:
        assert "already reviewed" in str(exc)


def test_review_rejects_projected_candidates():
    projected = _candidate(id="car:T1059", source="car",
                           text="CommandLine=whoami", text_origin="synthesized_notes")
    decision = {"id": "car:T1059", "ground_truth_tactic": "Execution",
                "reviewer": "AA", "split": "test"}
    try:
        ex.apply_reviews([projected], [decision])
        assert False
    except ValueError as exc:
        assert "not an analyst store" in str(exc)


def test_manifest_binds_the_evaluation_file_and_is_reproducible(tmp_path):
    evaluation = tmp_path / "evaluation.jsonl"
    accepted = [_candidate(review_state="reviewed", reviewer="AA", split="test",
                           ground_truth_tactic="Impact", corpus_version="eval-v1",
                           criteria_version="v1:test")]
    ex.write_rows(accepted, str(evaluation))
    provenance = {"corpus_version": "eval-v1", "criteria_version": "v1:test",
                  "backend": "onnx", "model_path": "/opt/laya", "model_sha256": "ab",
                  "confidence_floor": 0.6, "temperature": 0.05, "host": "stage-1"}
    first = ex.build_manifest("ds", str(evaluation), accepted, [], [],
                              str(tmp_path / "ex.jsonl"), provenance)
    second = ex.build_manifest("ds", str(evaluation), accepted, [], [],
                               str(tmp_path / "ex.jsonl"), provenance)
    assert first["evaluation_sha256"] == second["evaluation_sha256"]
    assert first["evaluation_sha256"] == hashlib.sha256(
        evaluation.read_bytes()).hexdigest()
    assert first["by_tactic"] == {"Impact": 1}
    assert first["split_counts"] == {"test": 1}
    assert first["reviewers"] == ["AA"]
    assert first["backend"] == "onnx" and first["confidence_floor"] == 0.6
    changed = [dict(accepted[0], ground_truth_tactic="Discovery")]
    ex.write_rows(changed, str(evaluation))
    third = ex.build_manifest("ds", str(evaluation), changed, [], [],
                              str(tmp_path / "ex.jsonl"), provenance)
    assert third["evaluation_sha256"] != first["evaluation_sha256"]


def test_main_review_mode_writes_evaluation_exclusions_and_manifest(tmp_path, monkeypatch):
    from mcp_server.label.criteria import version
    criteria = version()
    candidates = ex.build_rows([], [
        {"srcip": "1.2.3.4", "ts": "2026-09-01T00:00:00Z", "verdict": "true_positive",
         "notes": "C2 beaconing", "case_id": ""},
        {"srcip": "5.6.7.8", "ts": "2026-09-02T00:00:00Z", "verdict": "false_positive",
         "notes": "scanner", "case_id": ""},
    ])
    _write(tmp_path / "candidates.jsonl", candidates)
    _write(tmp_path / "reviews.jsonl", [
        {"id": "investigation_history:1.2.3.4", "ground_truth_tactic": "Command and Control",
         "reviewer": "AA", "split": "test", "text": "rule.description=periodic beacon"},
        {"id": "investigation_history:5.6.7.8", "reviewer": "AA",
         "exclude_reason": "ambiguous"},
    ])
    out = tmp_path / "evaluation.jsonl"
    manifest = tmp_path / "manifest.json"
    monkeypatch.setattr(sys, "argv", [
        "export_case_labels.py", "--candidates", str(tmp_path / "candidates.jsonl"),
        "--reviews", str(tmp_path / "reviews.jsonl"), "--out", str(out),
        "--manifest", str(manifest), "--dataset", "analyst-eval-v1",
        "--criteria-version", criteria, "--backend", "onnx",
        "--confidence-floor", "0.6", "--temperature", "0.05", "--host", "stage-1"])
    assert ex.main() == 0
    accepted = json.loads(out.read_text(encoding="utf-8").strip())
    assert accepted["ground_truth_tactic"] == "Command and Control"
    assert accepted["split"] == "test" and accepted["criteria_version"] == criteria
    sidecar = json.loads((tmp_path / "evaluation.jsonl.exclusions.jsonl")
                         .read_text(encoding="utf-8").strip())
    assert sidecar["exclude_reason"] == "ambiguous"
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    assert payload["evaluation_sha256"] == hashlib.sha256(out.read_bytes()).hexdigest()
    assert payload["rows"] == {"evaluation": 1, "excluded": 1, "unreviewed": 0}
    assert payload["criteria_version"] == criteria
    assert payload["host"] == "stage-1"


def test_main_manifest_requires_a_matching_criteria_version(tmp_path, monkeypatch):
    _write(tmp_path / "candidates.jsonl", [_candidate()])
    _write(tmp_path / "reviews.jsonl", [
        {"id": "investigation_history:1.2.3.4", "ground_truth_tactic": "Impact",
         "reviewer": "AA", "split": "test"}])
    manifest = tmp_path / "manifest.json"
    base = ["export_case_labels.py", "--candidates", str(tmp_path / "candidates.jsonl"),
            "--reviews", str(tmp_path / "reviews.jsonl"),
            "--out", str(tmp_path / "eval.jsonl"), "--manifest", str(manifest)]

    monkeypatch.setattr(sys, "argv", base)
    assert ex.main() == 2 and not manifest.exists()

    monkeypatch.setattr(sys, "argv", base + ["--criteria-version", "v1:not-this-host"])
    assert ex.main() == 2 and not manifest.exists()

    from mcp_server.label.criteria import version
    monkeypatch.setattr(sys, "argv", base + ["--criteria-version", version()])
    assert ex.main() == 0 and manifest.exists()


def test_main_review_mode_fails_closed_on_invalid_decision(tmp_path, monkeypatch):
    _write(tmp_path / "candidates.jsonl", [_candidate()])
    _write(tmp_path / "reviews.jsonl", [
        {"id": "investigation_history:1.2.3.4", "ground_truth_tactic": "NotATactic",
         "reviewer": "AA", "split": "test"}])
    monkeypatch.setattr(sys, "argv", [
        "export_case_labels.py", "--candidates", str(tmp_path / "candidates.jsonl"),
        "--reviews", str(tmp_path / "reviews.jsonl"), "--out", str(tmp_path / "eval.jsonl")])
    assert ex.main() == 2
    assert not (tmp_path / "eval.jsonl").exists()
