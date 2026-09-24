#!/usr/bin/env python3
"""Tests for scripts/export_case_labels.py. Synthetic store files only."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "export_case_labels.py"
_spec = importlib.util.spec_from_file_location("export_case_labels", SCRIPT)
ex = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ex)


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
         "verdict": "true_positive", "notes": "C2 beaconing"}]


def test_build_rows_prefers_history_and_dedups():
    fp_rows = [{"ioc": "1.2.3.4", "ts": 1700000000.0, "reason": "scanner"}]
    history_rows = [{"srcip": "1.2.3.4", "ts": "2026-09-01T00:00:00Z",
                     "verdict": "false_positive", "notes": "known scanner"}]
    rows = ex.build_rows(fp_rows, history_rows)
    assert len(rows) == 1
    row = rows[0]
    assert row["source"] == "investigation_history"
    assert row["id"] == "investigation_history:1.2.3.4"
    assert "verdict=false_positive" in row["text"] and "known scanner" in row["text"]
    assert row["ground_truth_tactic"] == ""


def test_build_rows_keeps_distinct_indicators_and_honors_limit():
    fp_rows = [{"ioc": "1.1.1.1", "ts": None, "reason": ""},
               {"ioc": "2.2.2.2", "ts": None, "reason": ""}]
    history_rows = [{"srcip": "3.3.3.3", "ts": None, "verdict": "suspicious", "notes": ""}]
    rows = ex.build_rows(fp_rows, history_rows)
    assert [row["id"] for row in rows] == [
        "false_positive_kb:1.1.1.1", "false_positive_kb:2.2.2.2",
        "investigation_history:3.3.3.3"]
    assert len(ex.build_rows(fp_rows, history_rows, limit=2)) == 2


def test_write_rows_emits_jsonl(tmp_path):
    out = tmp_path / "candidates.jsonl"
    ex.write_rows([{"id": "x", "source": "s", "text": "t", "ground_truth_tactic": ""}], str(out))
    row = json.loads(out.read_text(encoding="utf-8").strip())
    assert row == {"id": "x", "source": "s", "text": "t", "ground_truth_tactic": ""}
