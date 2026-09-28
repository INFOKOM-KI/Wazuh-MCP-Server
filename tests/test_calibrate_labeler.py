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
    # No confidence in these verdicts, so calibration cannot be claimed.
    assert row["ece"] is None


def test_macro_f1_averages_over_the_whole_vocabulary():
    cases = [_case("Impact"), _case("Command and Control"), _case("Impact")]
    predictions = [
        {"status": "ok", "label": "Impact", "confidence": 0.9},
        {"status": "uncertain", "label": None, "confidence": None},
        {"status": "ok", "label": "Impact", "confidence": 0.95},
    ]
    row = cal.score(cases, predictions, floor=0.6, temperature=0.05)
    # Impact is perfect, Command and Control is a total miss, the other 14 classes have
    # no support and still count: 1.0/16, not 1.0/2.
    assert row["macro_f1"] == pytest.approx(1 / 16)
    assert row["per_tactic"]["Impact"]["f1"] == pytest.approx(1.0)
    assert row["per_tactic"]["Command and Control"]["recall"] == 0.0


def test_ece_measures_overconfidence_on_answered_rows():
    cases = [_case("Impact"), _case("Impact")]
    predictions = [{"status": "ok", "label": "Impact", "confidence": 0.9},
                   {"status": "ok", "label": "Impact", "confidence": 0.95}]
    row = cal.score(cases, predictions, floor=0.6, temperature=0.05)
    assert row["coverage"] == 1.0
    # 0.9 lands in the [0.867, 0.933) bin and 0.95 in the last one: mean |acc - conf|
    # is (0.1 + 0.05) / 2.
    assert row["ece"] == pytest.approx(0.075, abs=1e-9)


def test_gate_fails_closed_and_names_each_miss():
    best = {"macro_f1": 0.5, "top1_answered": 0.95, "coverage": 0.7, "ece": 0.2}
    failures = cal.evaluate_gate(best, cal.GATE_DEFAULTS)
    assert len(failures) == 2
    assert any("macro-F1" in item for item in failures)
    assert any("ECE" in item for item in failures)
    assert cal.evaluate_gate(best, {"min_macro_f1": 0.4, "max_ece": 0.3}) == []
    unmeasured = {"macro_f1": None, "top1_answered": 1.0, "coverage": 1.0, "ece": 0.0}
    assert cal.evaluate_gate(unmeasured, cal.GATE_DEFAULTS) == ["macro-F1 is unmeasured"]


def test_suggest_prefers_macro_f1_over_raw_correct():
    majority = {"floor": 0.4, "temperature": 0.05, "cases": 10, "correct": 8,
                "uncertain": 1, "top1": 0.8, "macro_f1": 0.2}
    balanced = {"floor": 0.6, "temperature": 0.05, "cases": 10, "correct": 7,
                "uncertain": 2, "top1": 0.7, "macro_f1": 0.6}
    assert cal.suggest([majority, balanced])["floor"] == 0.6


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
    assert "1200 cases" in report


def test_default_factory_selects_the_configured_backend(monkeypatch):
    from mcp_server.core.config import config
    from mcp_server.label.backends import LayaLabeler, ONNXPrototypeLabeler

    monkeypatch.setattr(config.label, "model_path", "/tmp/vendored")
    monkeypatch.setattr(config.label, "model_sha256", "0" * 64)
    monkeypatch.setattr(config.label, "max_len", 4096)
    laya = cal._default_factory("laya")(0.0, 0.7)
    assert isinstance(laya, LayaLabeler)
    assert laya.temperature == 0.7 and laya.max_len == 4096
    assert isinstance(cal._default_factory("onnx")(0.0, 0.7), ONNXPrototypeLabeler)


@pytest.mark.asyncio
async def test_run_filters_a_split_and_gates_the_suggested_point(tmp_path):
    source = _write(tmp_path, [
        {"text": "a", "ground_truth_tactic": "Impact", "split": "train"},
        {"text": "b", "ground_truth_tactic": "Impact", "split": "test"},
    ])
    out = tmp_path / "report.md"
    best = await cal.run(source, out, floors=(0.5,), temperatures=(0.05,),
                         factory=lambda floor, temperature: _FakeClassifier(
                             {"a": "Impact", "b": "Impact"}),
                         split="test", gate={"min_macro_f1": 0.9, "max_ece": 0.2})
    assert best["cases"] == 1 and best["correct"] == 1
    # Only Impact is covered in this split, so macro-F1 over the 16-class vocabulary is 1/16.
    assert best["macro_f1"] == pytest.approx(1 / 16)
    assert any("macro-F1" in item for item in best["gate_failures"])
    report = out.read_text(encoding="utf-8")
    assert "- Split: `test`" in report and "**FAIL**" in report

    passing = await cal.run(source, tmp_path / "pass.md", floors=(0.5,), temperatures=(0.05,),
                            factory=lambda floor, temperature: _FakeClassifier(
                                {"a": "Impact", "b": "Impact"}),
                            split="test", gate={"min_coverage": 1.0, "max_ece": 0.2})
    assert passing["gate_failures"] == []
    assert "**PASS**" in (tmp_path / "pass.md").read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_run_rejects_a_split_no_row_carries(tmp_path):
    source = _write(tmp_path, [{"text": "a", "ground_truth_tactic": "Impact"}])
    with pytest.raises(ValueError, match="split='test'"):
        await cal.run(source, tmp_path / "r.md", floors=(0.5,), temperatures=(0.05,),
                      factory=lambda floor, temperature: _FakeClassifier({"a": "Impact"}),
                      split="test")
