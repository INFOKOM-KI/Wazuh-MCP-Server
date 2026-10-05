#!/usr/bin/env python3
"""Phase 2 concurrency: the per-subject cap and the dedupe idempotency contract.

These encode the measured behaviour of the probe run in the design review. A
deferred transaction (the pre-Phase-2 shape) let 40 threads write 25 rows against a
cap of 10, so the cap test fails if BEGIN IMMEDIATE is ever dropped.
"""
from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import sqlite3
import threading
import tempfile
from pathlib import Path
import pytest
from mcp_server.core import memory_store
from mcp_server.core.config import config

CAP = 10
WRITERS = 40


@pytest.fixture(autouse=True)
def _store(tmp_path):
    config.memory.enabled = True
    config.memory.db_path = str(tmp_path / "memory.db")
    config.memory.max_units_per_subject = CAP
    yield
    config.memory.enabled = False
    config.memory.db_path = ""
    config.memory.max_units_per_subject = 50


def _run_writers(calls: list[dict]) -> list[dict]:
    """Run every call on its own thread, released together, and collect results."""
    results: list[dict] = []
    barrier = threading.Barrier(len(calls))

    def worker(kwargs: dict) -> None:
        barrier.wait()
        try:
            results.append(memory_store.record_decision(**kwargs))
        except Exception as e:  # a raised exception is a failure of the contract
            results.append({"status": f"raised: {type(e).__name__}: {e}"})

    threads = [threading.Thread(target=worker, args=(kwargs,)) for kwargs in calls]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return results


def _rows(subject: str) -> int:
    with memory_store._store() as conn:
        return int(conn.execute("SELECT COUNT(*) FROM units WHERE subject = ?",
                                (subject,)).fetchone()[0])


def _outcome(results: list[dict], key: str) -> list[str]:
    return [str(result.get(key)) for result in results]


def test_cap_holds_under_contention():
    subject = "srcip:203.0.113.201"
    results = _run_writers([
        {"srcip": "203.0.113.201", "verdict": "suspicious", "notes": f"distinct note {i}"}
        for i in range(WRITERS)])

    rows = _rows(subject)
    assert rows <= CAP, f"cap exceeded: {rows} rows"
    assert rows == len(memory_store.units_for_subject(subject, limit=1000)[0])
    assert len(results) == WRITERS
    assert all(str(result["status"]).startswith(("ok", "unavailable")) for result in results)
    assert any(outcome == "capacity" for outcome in _outcome(results, "reason"))


def test_identical_writes_collapse_to_one_row():
    subject = "srcip:203.0.113.202"
    note = "the same decision, forty times"
    results = _run_writers([
        {"srcip": "203.0.113.202", "verdict": "false_positive", "notes": note}
        for _ in range(WRITERS)])

    assert _rows(subject) == 2, "one decision unit plus one reason unit"
    outcomes = _outcome(results, "decision") + _outcome(results, "reason")
    assert all(outcome in ("inserted", "reaffirmed") for outcome in outcomes)
    units, _ = memory_store.units_for_subject(subject, include_invalidated=True)
    # Every writer bumped the same two rows: no lost updates under contention.
    assert sorted(unit["support_count"] for unit in units) == [WRITERS, WRITERS]


def test_capacity_refusal_does_not_touch_another_subject(tmp_path):
    """A refusal is per subject: another subject keeps writing normally."""
    full = "srcip:203.0.113.204"
    other = "srcip:203.0.113.205"
    for index in range(CAP):
        memory_store.record_decision(srcip="203.0.113.204", verdict="suspicious",
                                     notes=f"fill {index}")
    assert _rows(full) == CAP
    refused = memory_store.record_decision(srcip="203.0.113.204", verdict="suspicious",
                                           notes="one more")
    assert refused["reason"] == "capacity"
    accepted = memory_store.record_decision(srcip="203.0.113.205", verdict="true_positive",
                                            notes="unrelated subject")
    assert accepted["decision"] == "inserted" and accepted["reason"] == "inserted"
    assert _rows(other) == 2
    assert _rows(full) == CAP


def test_lock_contention_degrades_instead_of_raising(tmp_path, monkeypatch):
    """A writer that loses the lock wait returns a status; nothing escapes."""
    memory_store.record_unit(unit_type="observation", subject="srcip:203.0.113.206",
                             text="create the file", provenance="alert_text", source="engine_a")
    monkeypatch.setattr(memory_store, "_LOCK_TIMEOUT", 0.2)
    blocker = sqlite3.connect(config.memory.db_path, timeout=1.0)
    try:
        blocker.execute("BEGIN IMMEDIATE")
        result = memory_store.record_decision(srcip="203.0.113.207", verdict="false_positive",
                                              notes="blocked by a held write lock")
    finally:
        blocker.rollback()
        blocker.close()
    assert result["status"].startswith("unavailable"), result
    assert result["decision"] is None
    assert _rows("srcip:203.0.113.207") == 0


def test_reaffirm_at_cap_is_allowed_and_new_rows_are_refused():
    subject = "srcip:203.0.113.203"
    for index in range(CAP):
        memory_store.record_decision(srcip="203.0.113.203", verdict="suspicious",
                                     notes=f"fill {index}")
    # The decision row and its reasons share the cap, so the last note is refused.
    assert _rows(subject) == CAP

    reaffirm = memory_store.record_decision(srcip="203.0.113.203", verdict="suspicious",
                                            notes="fill 0")
    assert reaffirm["decision"] == "reaffirmed"
    assert reaffirm["reason"] == "reaffirmed"
    assert _rows(subject) == CAP

    refused = memory_store.record_decision(srcip="203.0.113.203", verdict="suspicious",
                                           notes="a brand new reason")
    assert refused["decision"] == "reaffirmed"
    assert refused["reason"] == "capacity"
    assert _rows(subject) == CAP
    unit = next(unit for unit in memory_store.units_for_subject(subject, limit=1000)[0]
                if unit["kind"] == "reason" and "fill 0" in unit["text"])
    assert unit["support_count"] == 2
