#!/usr/bin/env python3
"""Tests for scripts/calibrate_labeler.py.
The model never runs here: the grid test injects a fake classifier, and the parser
and scoring functions are pure.
"""
from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import importlib.util
import json
from pathlib import Path
import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "calibrate_labeler.py"
_spec = importlib.util.spec_from_file_location("calibrate_labeler", SCRIPT)
cal = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cal)


def _write(tmp_path, rows: list[dict]) -> Path:
    path = tmp_path / "labels.jsonl"
    path.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
    return path


def test_load_cases_accepts_text_and_alert_rows(tmp_path):
    path = _write(tmp_path, [
        {"id": "c1", "text": "mass file encryption observed", "ground_truth_tactic": "Impact"},
        {"id": "c2", "alert": {"rule": {"id": "100234", "level": 10,
                                        "description": "Beaconing to a known C2 domain"},
                               "data": {"srcip": "45.194.92.25"}},
         "ground_truth_tactic": "Command and Control"},
    ])
    cases = cal.load_cases(path)
    assert [case["id"] for case in cases] == ["c1", "c2"]
    assert [case["truth"] for case in cases] == ["Impact", "Command and Control"]
    assert all(case["state_text"] for case in cases)


def test_load_cases_rejects_bad_rows(tmp_path):
    bad_rows = [
        {"text": "x", "ground_truth_tactic": "Not A Tactic"},
        {"text": "x", "alert": {"rule": {"description": "y"}}, "ground_truth_tactic": "Impact"},
        {"ground_truth_tactic": "Impact"},
    ]
    for row in bad_rows:
        with pytest.raises(ValueError):
            cal.load_cases(_write(tmp_path, [row]))


def _case(truth: str, state_text: str = "x") -> dict:
    return {"id": state_text, "state_text": state_text, "truth": truth}


def test_score_counts_top1_uncertain_and_support():
    cases = [_case("Impact"), _case("Command and Control"), _case("Impact")]
    predictions = [
        {"status": "ok", "label": "Impact"},
        {"status": "uncertain", "label": None},
        {"status": "ok", "label": "Impact"},
    ]
    row = cal.score(cases, predictions, floor=0.6, temperature=0.05)
    assert row["correct"] == 2 and row["top1"] == pytest.approx(2 / 3)
    assert row["answered"] == 3 and row["uncertain"] == 1
    assert row["support"]["Impact"] == {"support": 2, "correct": 2}
    assert row["confusion"]["Command and Control"] == {"uncertain": 1}


def _row(floor: float, correct: int, uncertain: int, cases: int = 3) -> dict:
    return {"floor": floor, "temperature": 0.05, "cases": cases, "correct": correct,
            "uncertain": uncertain, "top1": correct / cases}


def test_suggest_prefers_accuracy_then_less_uncertainty():
    rows = [_row(0.4, 1, 2), _row(0.5, 1, 0), _row(0.9, 0, 1)]
    assert cal.suggest(rows)["floor"] == 0.5


class _FakeClassifier:
    def __init__(self, correct: dict[str, str]):
        self._correct = correct

    async def classify_many(self, texts: list[str]) -> list[dict]:
        out = []
        for text in texts:
            label = self._correct.get(text)
            if label:
                out.append({"status": "ok", "label": label, "probabilities": {label: 0.9}})
            else:
                out.append({"status": "uncertain", "label": None,
                            "probabilities": {"Impact": 0.1}})
        return out


@pytest.mark.asyncio
async def test_run_writes_the_report(tmp_path):
    source = _write(tmp_path, [
        {"text": "beacon to c2", "ground_truth_tactic": "Command and Control"},
        {"text": "encryption note", "ground_truth_tactic": "Impact"},
    ])
    out = tmp_path / "report.md"
    best = await cal.run(source, out, floors=(0.6,), temperatures=(0.05,),
                         factory=lambda floor, temperature: _FakeClassifier(
                             {"beacon to c2": "Command and Control",
                              "encryption note": "Impact"}))
    report = out.read_text(encoding="utf-8")
    assert best["correct"] == 2
    assert "# Labeler calibration - 2 cases" in report
    assert "## Suggested values" in report
    assert "export BLUETEAM_LAYA_TEMPERATURE=0.05" in report
    assert "| truth \\ predicted |" in report


@pytest.mark.asyncio
async def test_run_handles_a_thousand_cases_without_a_cap(tmp_path):
    source = _write(tmp_path, [{"text": f"case {i}", "ground_truth_tactic": "Impact"}
                               for i in range(1200)])
    out = tmp_path / "report.md"
    best = await cal.run(source, out, floors=(0.6,), temperatures=(0.05,),
                         factory=lambda floor, temperature: _FakeClassifier(
                             {f"case {i}": "Impact" for i in range(1200)}))
    assert best["cases"] == 1200 and best["correct"] == 1200
    report = out.read_text(encoding="utf-8")
    assert "# Labeler calibration 1200 cases" in report
