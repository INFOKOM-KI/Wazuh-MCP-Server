#!/usr/bin/env python3
"""Tests for scripts/label_health.py. Synthetic audit JSONL only, no server state."""
from __future__ import annotations
import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "label_health.py"
_spec = importlib.util.spec_from_file_location("label_health", SCRIPT)
cal = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cal)

NOW = datetime(2026, 9, 25, 12, 0, tzinfo=timezone.utc)


def _at(hours_ago: float) -> str:
    return (NOW - timedelta(hours=hours_ago)).isoformat().replace("+00:00", "Z")


def _label(hours_ago: float, status: str) -> dict:
    return {"ts": _at(hours_ago), "tool": "blueteam_incident_label",
            "params": {"status": status}}


def _workflow(hours_ago: float) -> dict:
    return {"ts": _at(hours_ago), "tool": "blueteam_investigation_workflow", "params": {}}


def test_summarize_computes_coverage_and_uncertain_ratio():
    entries = [
        _label(10, "ok"), _label(20, "ok"), _label(30, "uncertain"),
        _label(40, "unavailable"), _workflow(15), _workflow(25),
        _label(200, "ok"), _label(220, "ok"), _label(240, "uncertain"),
    ]
    summary = cal.summarize(entries, NOW, window_days=7)
    current = summary["current"]
    assert current["labels"] == 4 and current["covered"] == 3
    assert current["coverage"] == pytest.approx(0.75)
    assert current["uncertain_ratio"] == pytest.approx(1 / 3)
    assert current["labels_per_investigation"] == pytest.approx(2.0)
    assert summary["previous"]["uncertain_ratio"] == pytest.approx(1 / 3)


def test_summarize_detects_the_uncertain_drift_between_windows():
    entries = [_label(10, "uncertain"), _label(11, "ok"),
               _label(200, "ok"), _label(210, "ok"), _label(220, "ok"),
               _label(230, "ok"), _label(240, "uncertain")]
    summary = cal.summarize(entries, NOW, window_days=7)
    assert summary["uncertain_drift_points"] == pytest.approx((0.5 - 0.2) * 100)
    failures = cal.health_failures(summary, min_coverage=0.0, max_drift_points=10.0)
    assert any("drifted" in failure for failure in failures)


def test_gate_fails_on_low_coverage_and_ignores_drift_without_a_previous_window():
    summary = cal.summarize([_label(10, "unavailable"), _workflow(20)], NOW, window_days=7)
    failures = cal.health_failures(summary, min_coverage=0.8, max_drift_points=10.0)
    assert any("coverage" in failure for failure in failures)
    assert not any("drifted" in failure for failure in failures)
    assert summary["uncertain_drift_points"] is None
    empty = cal.summarize([_workflow(10)], NOW, window_days=7)
    assert "no label calls" in cal.health_failures(empty)[0]


def test_iter_entries_skips_torn_lines_and_event_rows(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text("\n".join([
        json.dumps(_label(5, "ok")),
        "not json at all",
        "",
        json.dumps({"ts": _at(5), "event": "forensic_bypass_response"}),
        json.dumps(_workflow(6)),
    ]), encoding="utf-8")
    entries = list(cal.iter_entries(str(path)))
    assert len(entries) == 3
    assert sum(1 for entry in entries if "tool" in entry) == 2


def test_render_states_the_gate_result():
    ok = cal.render(cal.summarize([_label(1, "ok")], NOW, window_days=7))
    assert "Status: OK" in ok
    bad = cal.render(cal.summarize([_label(1, "unavailable")], NOW, window_days=7))
    assert "Status: FAIL" in bad and "coverage" in bad
