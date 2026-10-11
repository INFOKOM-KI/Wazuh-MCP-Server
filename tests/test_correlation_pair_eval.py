#!/usr/bin/env python3
"""Tests for scripts/correlation_pair_eval.py. Synthetic fixtures only: no store,
no engine call, no real labels."""
from __future__ import annotations

import importlib.util
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

os.environ.setdefault("WAZUH_INDEXER_URL", "https://idx:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "pw")
os.environ.setdefault("BLUETEAM_REDACTION_POLICY", "full")

from mcp_server.correlation import pair_features as pf

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "correlation_pair_eval.py"
_spec = importlib.util.spec_from_file_location("correlation_pair_eval", SCRIPT)
ev = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ev)

BASE = datetime(2026, 3, 1, tzinfo=timezone.utc)


def _stamp(seconds: int) -> str:
    return (BASE + timedelta(seconds=seconds)).isoformat()


def _alert(alert_id: str, *, srcip: str = "203.0.113.10", seconds: int = 0) -> dict:
    return {"alert_id": alert_id, "srcip": srcip, "agent": "agent-1",
            "timestamp": _stamp(seconds), "tactics": ["Credential Access"],
            "domains": [], "urls": [], "analyst_iocs": [], "engine_iocs": []}


def _record(alert_a: dict, alert_b: dict, *, group: str, label: str = "same_incident",
            source: str = "adjudicated", split: str = "test") -> dict:
    return pf.build_pair_record(alert_a, alert_b, group_id=group, split=split, label=label,
                                label_source=source, recorded_by="reviewer-a")


def _pair(prefix: str, index: str, *, offset: int, label: str, group: str,
          source: str = "adjudicated", split: str = "test") -> dict:
    left = _alert(f"{prefix}{index}a", seconds=0)
    right = _alert(f"{prefix}{index}b", seconds=offset)
    return _record(left, right, group=group, label=label, source=source, split=split)


def _cohort(*, positives: int, negatives: int, prefix: str, source: str = "adjudicated",
            split: str = "test", pos_offset: int = 100, neg_offset: int = 7200) -> list[dict]:
    rows = []
    for index in range(positives):
        rows.append(_pair(prefix, f"p{index}", offset=pos_offset, label="same_incident",
                          group=f"{prefix}-gp{index}", source=source, split=split))
    for index in range(negatives):
        rows.append(_pair(prefix, f"n{index}", offset=neg_offset, label="unrelated",
                          group=f"{prefix}-gn{index}", source=source, split=split))
    return rows


def _unscorable_pair(prefix: str, index: str, group: str) -> dict:
    """A same-incident pair whose left alert has no subject, so the baseline declines."""
    left = _alert(f"{prefix}{index}a", srcip=None, seconds=0)
    right = _alert(f"{prefix}{index}b", seconds=100)
    return pf.build_pair_record(left, right, group_id=group, split="test",
                                label="same_incident", label_source="adjudicated",
                                recorded_by="reviewer-a")


def _checks(issues: list[dict]) -> set[str]:
    return {issue["check"] for issue in issues}


def test_valid_records_pass_validation():
    assert ev.validate_records(_cohort(positives=5, negatives=5, prefix="ok")) == []


def test_metrics_arithmetic():
    rows = [
        _pair("x", "1", offset=100, label="same_incident", group="x-g1"),
        _pair("x", "2", offset=100, label="same_incident", group="x-g2"),
        _pair("x", "3", offset=100, label="same_incident", group="x-g3"),
        _pair("x", "4", offset=7200, label="same_incident", group="x-g4"),
        _pair("x", "5", offset=100, label="unrelated", group="x-g5"),
        _pair("x", "6", offset=7200, label="unrelated", group="x-g6"),
        _pair("x", "7", offset=7200, label="unrelated", group="x-g7"),
        _pair("x", "8", offset=7200, label="unrelated", group="x-g8"),
    ]
    payload = ev.run_evaluation(rows, [], window_seconds=3600, min_positives=1,
                                min_negatives=1, min_groups=1, bootstrap_n=100, seed=3,
                                dataset_origin="operator_declared_official")
    metrics = payload["official"]["metrics"]
    assert (metrics["tp"], metrics["fp"], metrics["tn"], metrics["fn"]) == (3, 1, 3, 1)
    assert metrics["precision"] == 0.75
    assert metrics["recall"] == 0.75
    assert metrics["f1"] == 0.75


def test_not_evaluable_when_a_class_is_missing():
    payload = ev.run_evaluation(_cohort(positives=5, negatives=0, prefix="one"),
                                [], min_positives=1, min_negatives=1, min_groups=1,
                                bootstrap_n=50, seed=1)
    official = payload["official"]
    assert official["status"] == "not_evaluable"
    assert official["metrics"] is None
    assert any("negatives" in reason for reason in official["reasons"])


def test_ambiguous_labels_stay_out_of_binary_metrics():
    rows = _cohort(positives=5, negatives=5, prefix="amb")
    rows.append(_pair("amb", "z", offset=100, label="insufficient_evidence", group="amb-gz"))
    payload = ev.run_evaluation(rows, [], min_positives=1, min_negatives=1, min_groups=1,
                                bootstrap_n=50, seed=1)
    assert payload["excluded_labels"]["insufficient_evidence"] == 1
    assert payload["official"]["positives"] == 5
    assert payload["official"]["negatives"] == 5


def test_pilots_never_enter_official_metrics():
    rows = _cohort(positives=1, negatives=1, prefix="off")
    rows += _cohort(positives=5, negatives=5, prefix="weak", source="weak_case_link")
    payload = ev.run_evaluation(rows, [], min_positives=5, min_negatives=5, min_groups=1,
                                bootstrap_n=100, seed=5)
    assert payload["official"]["status"] == "not_evaluable"
    pilot = payload["pilots"]["weak_label_pilot"]
    assert pilot["pilot_only"] is True
    assert pilot["ground_truth"] == "not_independent"
    assert pilot["status"] == "ok"
    assert pilot["metrics"]["f1"] == 1.0


def test_duplicate_pair_and_conflict_are_distinct():
    record = _pair("dup", "1", offset=100, label="same_incident", group="dup-g1")
    duplicate = json.loads(json.dumps(record))
    assert "duplicate_pair" in _checks(ev.validate_records([record, duplicate]))
    conflict = json.loads(json.dumps(record))
    conflict["label"] = "unrelated"
    assert "conflicting_adjudication" in _checks(ev.validate_records([record, conflict]))


def test_group_split_leakage_is_flagged():
    train = _pair("leak", "1", offset=100, label="same_incident", group="leak-g1", split="train")
    test = _pair("leak", "2", offset=100, label="same_incident", group="leak-g1", split="test")
    assert "group_split_leakage" in _checks(ev.validate_records([train, test]))


def test_invalid_provenance_is_flagged():
    record = _pair("prov", "1", offset=100, label="same_incident", group="prov-g1")
    record["recorded_by"] = ""
    assert "provenance" in _checks(ev.validate_records([record]))


def test_label_derived_feature_is_flagged():
    record = _pair("ld", "1", offset=100, label="same_incident", group="ld-g1")
    record["features"]["same_case"] = True
    assert "label_derived_feature" in _checks(ev.validate_records([record]))


def test_version_mismatch_and_tampered_features_are_flagged():
    versioned = _pair("ver", "1", offset=100, label="same_incident", group="ver-g1")
    versioned["feature_version"] = "v0"
    assert "feature_version" in _checks(ev.validate_records([versioned]))
    tampered = _pair("ver", "2", offset=100, label="same_incident", group="ver-g2")
    tampered["features"]["same_subject"] = False
    assert "feature_mismatch" in _checks(ev.validate_records([tampered]))


def test_pair_id_mismatch_is_flagged():
    record = _pair("pid", "1", offset=100, label="same_incident", group="pid-g1")
    record["pair_id"] = "0" * 16
    assert "pair_id" in _checks(ev.validate_records([record]))


def test_baseline_predictions():
    record = _pair("base", "1", offset=100, label="same_incident", group="base-g1")
    assert ev.baseline_predict(record, 3600) is True
    assert ev.baseline_predict(record, 50) is False
    different_subject = _record(_alert("ds1"), _alert("ds2", srcip="198.51.100.4"),
                                group="base-g2")
    assert ev.baseline_predict(different_subject, 3600) is False
    missing_subject = _record({"alert_id": "ms1"}, {"alert_id": "ms2"}, group="base-g3")
    assert ev.baseline_predict(missing_subject, 3600) is None


def test_grouped_bootstrap_is_deterministic():
    rows = _cohort(positives=5, negatives=5, prefix="boot")
    first = ev.grouped_bootstrap(rows, 3600, 200, 11)
    second = ev.grouped_bootstrap(rows, 3600, 200, 11)
    assert first == second
    assert first["available"] is True
    assert first["ci"]["f1"]["lo"] <= first["ci"]["f1"]["hi"]


def test_sweep_freezes_the_window_from_validation():
    validation = _cohort(positives=3, negatives=3, prefix="vv", split="validation")
    test = _cohort(positives=2, negatives=2, prefix="tt", split="test")
    payload = ev.run_evaluation(validation + test, [], window_seconds=3600,
                                sweep_windows=[600, 86400], min_positives=1, min_negatives=1,
                                min_groups=1, bootstrap_n=100, seed=9,
                                dataset_origin="operator_declared_official")
    threshold = payload["official"]["threshold"]
    assert threshold["status"] == "frozen_from_validation"
    assert threshold["window_seconds"] == 600
    assert payload["official"]["window_seconds"] == 600
    assert payload["official"]["metrics"]["f1"] == 1.0


def test_invalid_dataset_blocks_metrics():
    record = _pair("blk", "1", offset=100, label="same_incident", group="blk-g1")
    duplicate = json.loads(json.dumps(record))
    payload = ev.run_evaluation([record, duplicate], ev.validate_records([record, duplicate]),
                                min_positives=1, min_negatives=1, min_groups=1)
    assert payload["validation"]["status"] == "invalid"
    assert payload["official"]["status"] == "invalid_dataset"
    assert payload["official"]["metrics"] is None


def test_cli_reports_not_evaluable(tmp_path, capsys):
    path = tmp_path / "pairs.jsonl"
    path.write_text(json.dumps(_pair("cli", "1", offset=100, label="same_incident",
                                     group="cli-g1")) + "\n", encoding="utf-8")
    code = ev.main(["--pairs", str(path), "--json", "--min-positives", "1",
                    "--min-negatives", "1", "--min-groups", "1", "--bootstrap", "50"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert code == 0
    assert payload["official"]["status"] == "not_evaluable"


def test_cli_refuses_missing_file(tmp_path, capsys):
    code = ev.main(["--pairs", str(tmp_path / "missing.jsonl")])
    captured = capsys.readouterr()
    assert code == 2
    assert "refused" in captured.err


def test_markdown_report_renders(tmp_path, capsys):
    path = tmp_path / "pairs.jsonl"
    rows = _cohort(positives=1, negatives=1, prefix="md")
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    code = ev.main(["--pairs", str(path), "--min-positives", "1", "--min-negatives", "1",
                    "--min-groups", "1", "--bootstrap", "50"])
    captured = capsys.readouterr()
    assert code == 0
    assert "Correlation pair evaluation" in captured.out
    assert "Official" in captured.out


def test_unscorable_pairs_do_not_satisfy_the_support_floor():
    rows = _cohort(positives=5, negatives=5, prefix="un")
    rows[0] = _unscorable_pair("un", "p0", "un-gp0")
    payload = ev.run_evaluation(rows, [], window_seconds=3600, min_positives=5, min_negatives=5,
                                min_groups=1, bootstrap_n=100, seed=1)
    official = payload["official"]
    assert official["positives"] == 5
    assert official["scorable_positives"] == 4
    assert official["unscorable_pairs"] == 1
    assert official["status"] == "not_evaluable"
    assert official["metrics"] is None
    assert any("scorable positives 4" in reason for reason in official["reasons"])


def test_unscorable_pairs_mark_the_result_inconclusive():
    rows = _cohort(positives=5, negatives=5, prefix="ui")
    rows[0] = _unscorable_pair("ui", "p0", "ui-gp0")
    payload = ev.run_evaluation(rows, [], window_seconds=3600, min_positives=1, min_negatives=1,
                                min_groups=1, bootstrap_n=100, seed=1,
                                dataset_origin="operator_declared_official")
    official = payload["official"]
    assert official["status"] == "inconclusive"
    assert official["metrics"]["tp"] + official["metrics"]["fn"] == 4
    assert any("unscorable" in note for note in official["notes"])


def test_undefined_metrics_are_not_evaluable():
    rows = _cohort(positives=5, negatives=5, prefix="ud", pos_offset=7200, neg_offset=7200)
    payload = ev.run_evaluation(rows, [], window_seconds=3600, min_positives=1, min_negatives=1,
                                min_groups=1, bootstrap_n=50, seed=1)
    official = payload["official"]
    assert official["status"] == "not_evaluable"
    assert official["metrics"] is None
    assert any("precision" in reason for reason in official["reasons"])


def test_cli_rejects_zero_and_negative_minima(tmp_path, capsys):
    rows = _cohort(positives=1, negatives=1, prefix="cl")
    path = tmp_path / "pairs.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    for extra in (["--min-positives", "0"], ["--min-negatives", "0"], ["--min-positives", "-2"]):
        code = ev.main(["--pairs", str(path), *extra])
        captured = capsys.readouterr()
        assert code == 2
        assert "refused" in captured.err


def test_official_gate_stays_closed_when_only_pilots_have_labels():
    rows = _cohort(positives=5, negatives=5, prefix="pilot", source="weak_case_link")
    payload = ev.run_evaluation(rows, [], window_seconds=3600, min_positives=1, min_negatives=1,
                                min_groups=1, bootstrap_n=100, seed=1)
    official = payload["official"]
    assert official["status"] == "not_evaluable"
    assert official["metrics"] is None
    pilot = payload["pilots"]["weak_label_pilot"]
    assert pilot["pilot_only"] is True
    assert pilot["metrics"]["f1"] == 1.0
    assert payload["dataset_origin"] == "unspecified"


def test_synthetic_run_cannot_claim_official_metrics():
    rows = _cohort(positives=5, negatives=5, prefix="syn")
    payload = ev.run_evaluation(rows, [], window_seconds=3600, min_positives=1, min_negatives=1,
                                min_groups=1, bootstrap_n=100, seed=1, dataset_origin="synthetic")
    official = payload["official"]
    assert payload["dataset_origin"] == "synthetic"
    assert official["official_eligible"] is False
    assert official["status"] == "not_evaluable"
    assert official["metrics"] is None
    assert official["ci"] is None
    assert payload["ineligible_reference"]["dataset_origin"] == "synthetic"
    assert payload["ineligible_reference"]["metrics"]["f1"] == 1.0


def test_cli_synthetic_flag_marks_the_run(tmp_path, capsys):
    rows = _cohort(positives=5, negatives=5, prefix="syncli")
    path = tmp_path / "pairs.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    code = ev.main(["--pairs", str(path), "--json", "--synthetic", "--min-positives", "1",
                    "--min-negatives", "1", "--min-groups", "1", "--bootstrap", "100"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["dataset_origin"] == "synthetic"
    assert payload["official"]["status"] == "not_evaluable"
    assert payload["official"]["metrics"] is None
    assert payload["ineligible_reference"]["dataset_origin"] == "synthetic"


def test_unspecified_origin_fails_closed():
    rows = _cohort(positives=5, negatives=5, prefix="uns")
    payload = ev.run_evaluation(rows, [], window_seconds=3600, min_positives=1, min_negatives=1,
                                min_groups=1, bootstrap_n=100, seed=1)
    official = payload["official"]
    assert payload["dataset_origin"] == "unspecified"
    assert official["official_eligible"] is False
    assert official["status"] == "not_evaluable"
    assert official["metrics"] is None
    assert official["ci"] is None
    assert payload["ineligible_reference"]["dataset_origin"] == "unspecified"
    assert payload["ineligible_reference"]["metrics"]["f1"] == 1.0


def test_cli_without_origin_declaration_fails_closed(tmp_path, capsys):
    rows = _cohort(positives=5, negatives=5, prefix="cliuns")
    path = tmp_path / "pairs.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    code = ev.main(["--pairs", str(path), "--json", "--min-positives", "1",
                    "--min-negatives", "1", "--min-groups", "1", "--bootstrap", "100"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["dataset_origin"] == "unspecified"
    assert payload["official"]["official_eligible"] is False
    assert payload["official"]["status"] == "not_evaluable"
    assert payload["official"]["metrics"] is None


def test_operator_declared_official_is_eligible_but_declared():
    rows = _cohort(positives=5, negatives=5, prefix="decl")
    payload = ev.run_evaluation(rows, [], window_seconds=3600, min_positives=1, min_negatives=1,
                                min_groups=1, bootstrap_n=100, seed=1,
                                dataset_origin="operator_declared_official")
    official = payload["official"]
    assert official["official_eligible"] is True
    assert official["status"] == "ok"
    assert official["metrics"]["f1"] == 1.0
    assert any("declarations" in item for item in payload["limitations"])


def test_non_official_origins_never_enter_the_official_path():
    rows = _cohort(positives=5, negatives=5, prefix="org")
    for origin in ("synthetic", "weak_label_pilot", "external_reference_agreement", "mystery"):
        payload = ev.run_evaluation(rows, [], window_seconds=3600, min_positives=1,
                                    min_negatives=1, min_groups=1, bootstrap_n=50, seed=1,
                                    dataset_origin=origin)
        official = payload["official"]
        assert official["official_eligible"] is False, origin
        assert official["status"] == "not_evaluable", origin
        assert official["metrics"] is None, origin
        assert payload["ineligible_reference"]["dataset_origin"] == origin, origin


def test_pilot_metrics_stay_in_their_named_fields():
    rows = _cohort(positives=5, negatives=5, prefix="wp", source="weak_case_link")
    rows += _cohort(positives=5, negatives=5, prefix="xp", source="external_reference")
    payload = ev.run_evaluation(rows, [], window_seconds=3600, min_positives=1, min_negatives=1,
                                min_groups=1, bootstrap_n=100, seed=1)
    assert payload["official"]["status"] == "not_evaluable"
    weak = payload["pilots"]["weak_label_pilot"]
    external = payload["pilots"]["external_reference_agreement"]
    assert weak["pilot_only"] is True and weak["metrics"]["f1"] == 1.0
    assert external["pilot_only"] is True and external["metrics"]["f1"] == 1.0
    assert "official" not in weak and "official" not in external


def test_cli_rejects_conflicting_origin_and_synthetic_flag(tmp_path, capsys):
    rows = _cohort(positives=1, negatives=1, prefix="conf")
    path = tmp_path / "pairs.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    code = ev.main(["--pairs", str(path), "--dataset-origin", "operator_declared_official",
                    "--synthetic"])
    captured = capsys.readouterr()
    assert code == 2
    assert "conflicts" in captured.err
