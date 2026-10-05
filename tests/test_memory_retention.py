#!/usr/bin/env python3
"""Phase 3 retention and consolidation: TTL, eviction order, folding duplicates.

The retention clock is last_seen and every case here backdates rows rather than
sleeping, so the matrix is deterministic. Two ages matter at once: the horizon
(ttl times the confirmation count) and the decay floor, which is why a short TTL
cannot drop a unit that was confirmed recently.
"""
from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import sqlite3
import threading
from datetime import datetime, timedelta, timezone
import pytest
from mcp_server.core import memory_store
from mcp_server.core.config import config

DAY = 86400
TTL_DAYS = 60
IP = "203.0.113.160"


@pytest.fixture(autouse=True)
def _store(tmp_path):
    config.memory.enabled = True
    config.memory.db_path = str(tmp_path / "memory.db")
    config.memory.max_units_per_subject = 50
    config.memory.ttl_seconds = TTL_DAYS * DAY
    yield
    config.memory.enabled = False
    config.memory.db_path = ""
    config.memory.max_units_per_subject = 50
    config.memory.ttl_seconds = 7776000


def _stamp(days: float) -> str:
    """An ISO timestamp this many days in the past."""
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _backdate(unit_id: str, days: float, *, support: int | None = None) -> None:
    with memory_store._store() as conn:
        if support is None:
            conn.execute("UPDATE units SET first_seen = ?, last_seen = ? WHERE unit_id = ?",
                         (_stamp(days), _stamp(days), unit_id))
        else:
            conn.execute("UPDATE units SET first_seen = ?, last_seen = ?, support_count = ? "
                         "WHERE unit_id = ?", (_stamp(days), _stamp(days), support, unit_id))


def _subject_units(subject: str) -> list[dict]:
    return memory_store.units_for_subject(subject, limit=1000, include_invalidated=True)[0]


def _a_reason(subject: str, notes: str, verdict: str = "suspicious") -> dict:
    memory_store.record_decision(srcip=subject.split(":", 1)[1], verdict=verdict, notes=notes)
    return next(unit for unit in _subject_units(subject)
                if unit["kind"] == "reason" and unit["text"] == notes.strip())


# Retention matrix


@pytest.mark.parametrize("age_days,support,ttl_days,expect_pruned", [
    (59.0, 1, 60, False),    # just before the horizon
    (59.99931, 1, 60, False),  # one minute inside the horizon: the sweep clock moves,
                               # so an exact equality test is not representable
    (60.01, 1, 60, True),    # just past it, and below the decay floor
    (100.0, 2, 60, False),   # support doubles the horizon
    (121.0, 2, 60, True),
    (200.0, 9, 60, False),   # the multiplier is capped at four
    (241.0, 9, 60, True),
    (2.0, 1, 1, False),      # decay floor: recent, so never dead weight
])
def test_retention_matrix(age_days, support, ttl_days, expect_pruned):
    config.memory.ttl_seconds = ttl_days * DAY
    unit = _a_reason("srcip:203.0.113.161", "single observation")
    _backdate(unit["unit_id"], age_days, support=support)
    result = memory_store.prune_memory()
    assert result["status"] == "ok"
    assert (unit["unit_id"] not in [u["unit_id"] for u in _subject_units("srcip:203.0.113.161")]) \
        is expect_pruned


def test_low_ttl_never_prunes_a_recent_unit():
    """The decay floor is what makes a misconfigured TTL harmless."""
    config.memory.ttl_seconds = 60
    unit = _a_reason("srcip:203.0.113.162", "confirmed minutes ago")
    _backdate(unit["unit_id"], 0.01)
    assert memory_store.prune_memory()["pruned"] == 0
    assert len(_subject_units("srcip:203.0.113.162")) == 2


def test_ttl_zero_keeps_everything():
    config.memory.ttl_seconds = 0
    unit = _a_reason("srcip:203.0.113.163", "ancient but retained")
    _backdate(unit["unit_id"], 900)
    assert memory_store.prune_memory()["pruned"] == 0
    assert len(_subject_units("srcip:203.0.113.163")) == 2


def test_analyst_decision_survives_any_age():
    memory_store.record_decision(srcip="203.0.113.164", verdict="true_positive", notes="confirmed")
    decision = next(unit for unit in _subject_units("srcip:203.0.113.164")
                    if unit["kind"] == "decision")
    _backdate(decision["unit_id"], 400)
    result = memory_store.prune_memory()
    assert result["pruned"] == 0
    assert memory_store.get_unit(decision["unit_id"])["type"] == "world"


def test_invalidated_row_is_never_pruned_or_resurrected():
    unit = _a_reason("srcip:203.0.113.165", "withdrawn evidence")
    memory_store.invalidate_unit(unit["unit_id"], reason="analyst withdrew it")
    _backdate(unit["unit_id"], 400)
    assert memory_store.prune_memory()["pruned"] == 0
    stored = memory_store.get_unit(unit["unit_id"])
    assert stored["invalidated_by"] == "analyst withdrew it"
    assert memory_store.recall_subject("srcip:203.0.113.165")["recent_reasons"] == []


def test_at_most_five_protected_rows_per_subject():
    for verdict in memory_store.VERDICTS:
        memory_store.record_decision(srcip="203.0.113.166", verdict=verdict, notes=f"note for {verdict}")
    memory_store.record_decision(srcip="203.0.113.166", verdict="clean", notes="note for clean")
    protected = [unit for unit in _subject_units("srcip:203.0.113.166")
                 if memory_store._is_protected(unit)]
    assert len(protected) == len(memory_store.VERDICTS)


def test_eviction_order_is_total():
    subject = "srcip:203.0.113.167"
    first = _a_reason(subject, "oldest evidence")
    tied = [_a_reason(subject, f"tied evidence {index}") for index in range(3)]
    for unit in tied:
        _backdate(unit["unit_id"], 100)
    _backdate(first["unit_id"], 200)
    order = memory_store._eviction_order(_subject_units(subject))
    ids = [unit["unit_id"] for unit in order]
    assert ids[0] == first["unit_id"]
    assert ids[1:] == sorted(unit["unit_id"] for unit in tied)


# Capacity interaction


def test_prune_makes_room_at_capacity():
    config.memory.max_units_per_subject = 2
    memory_store.record_decision(srcip="203.0.113.168", verdict="true_positive", notes="confirmed")
    stale = _a_reason("srcip:203.0.113.168", "confirmed", verdict="true_positive")
    _backdate(stale["unit_id"], 400)
    assert len(_subject_units("srcip:203.0.113.168")) == 2
    memory_store.record_decision(srcip="203.0.113.168", verdict="true_positive",
                                 notes="new evidence")
    units = _subject_units("srcip:203.0.113.168")
    assert len(units) == 2
    assert stale["unit_id"] not in [unit["unit_id"] for unit in units]
    assert any(unit["kind"] == "decision" and unit["type"] == "world" for unit in units)
    assert any(unit["text"] == "new evidence" for unit in units)


def test_fresh_rows_at_capacity_are_still_refused():
    config.memory.max_units_per_subject = 2
    memory_store.record_decision(srcip="203.0.113.169", verdict="true_positive", notes="one")
    refused = memory_store.record_decision(srcip="203.0.113.169", verdict="suspicious", notes="two")
    assert refused["decision"] == "capacity"
    assert refused["reason"] == "capacity"
    assert len(_subject_units("srcip:203.0.113.169")) == 2


# Consolidation


def test_duplicate_reasons_merge():
    subject = "srcip:203.0.113.170"
    first = _a_reason(subject, "Scanner noise from the hosting range")
    second = _a_reason(subject, "  scanner   noise from the hosting range ")
    assert first["unit_id"] != second["unit_id"]
    result = memory_store.prune_memory()
    assert result["merged"] == 1
    units = _subject_units(subject)
    reasons = [unit for unit in units if unit["kind"] == "reason"]
    assert len(reasons) == 1
    survivor = reasons[0]
    assert survivor["support_count"] == 2
    assert survivor["first_seen"] == min(first["first_seen"], second["first_seen"])
    assert survivor["last_seen"] == max(first["last_seen"], second["last_seen"])
    assert survivor["tainted"] is True and survivor["provenance"] == "tool_output"


def test_consolidation_is_idempotent():
    subject = "srcip:203.0.113.171"
    _a_reason(subject, "Repeated evidence")
    _a_reason(subject, "repeated evidence")
    assert memory_store.prune_memory()["merged"] == 1
    assert memory_store.prune_memory()["merged"] == 0
    assert len([u for u in _subject_units(subject) if u["kind"] == "reason"]) == 1


def test_similar_but_different_text_never_merges():
    subject = "srcip:203.0.113.172"
    _a_reason(subject, "scanner noise")
    _a_reason(subject, "scanner noise, second pass")
    assert memory_store.prune_memory()["merged"] == 0
    assert len([u for u in _subject_units(subject) if u["kind"] == "reason"]) == 2


def test_different_subjects_never_merge():
    _a_reason("srcip:203.0.113.173", "same words, different subject")
    _a_reason("srcip:203.0.113.174", "same words, different subject")
    assert memory_store.prune_memory()["merged"] == 0
    assert len([u for u in _subject_units("srcip:203.0.113.173") if u["kind"] == "reason"]) == 1
    assert len([u for u in _subject_units("srcip:203.0.113.174") if u["kind"] == "reason"]) == 1


def test_different_trust_classes_never_merge():
    subject = "srcip:203.0.113.175"
    _a_reason(subject, "identical wording")
    with memory_store._store() as conn:
        conn.execute(
            "INSERT INTO units (unit_id, type, subject, subject_kind, text, entities, occurred_at, "
            "first_seen, last_seen, support_count, source, provenance, tainted, confidence, case_id, "
            "invalidated_by, kind, value, dedupe_key) VALUES ('mem_analyst_reason', 'world', ?, "
            "'srcip', 'identical wording', '[]', '', ?, ?, 1, 'verdict', 'analyst', 0, NULL, '', '', "
            "'reason', '', 'analyst-reason-key')", (subject, _stamp(1), _stamp(1)))
    assert memory_store.prune_memory()["merged"] == 0
    assert len([u for u in _subject_units(subject) if u["kind"] == "reason"]) == 2


def test_analyst_decision_and_identical_text_never_merge():
    subject = "srcip:203.0.113.176"
    memory_store.record_decision(srcip="203.0.113.176", verdict="true_positive",
                                 notes="verified by the analyst")
    _a_reason(subject, "verified by the analyst", verdict="true_positive")
    assert memory_store.prune_memory()["merged"] == 0
    kinds = [unit["kind"] for unit in _subject_units(subject)]
    assert kinds.count("decision") == 1 and kinds.count("reason") == 1


def test_invalidated_duplicate_is_not_merged_into_the_active_row():
    subject = "srcip:203.0.113.177"
    withdrawn = _a_reason(subject, "duplicate wording")
    memory_store.invalidate_unit(withdrawn["unit_id"], reason="withdrawn")
    # A different raw string, so this is a second row rather than a reaffirmation.
    active = _a_reason(subject, "duplicate   wording")
    assert active["unit_id"] != withdrawn["unit_id"]
    assert memory_store.prune_memory()["merged"] == 0
    assert memory_store.get_unit(withdrawn["unit_id"])["invalidated_by"] == "withdrawn"
    assert memory_store.get_unit(active["unit_id"])["invalidated_by"] == ""
    assert memory_store.recall_subject(subject)["recent_reasons"][0]["unit_id"] == active["unit_id"]


def test_merge_preserves_recall_evidence_and_rank():
    subject = "srcip:203.0.113.178"
    older = _a_reason(subject, "Evidence text repeated")
    _a_reason(subject, "evidence   text repeated")
    _backdate(older["unit_id"], 3)
    memory_store.prune_memory()
    envelope = memory_store.recall_subject(subject)
    reasons = envelope["recent_reasons"]
    assert len(reasons) == 1
    assert "evidence" in reasons[0]["text"].lower() and reasons[0]["tainted"] is True
    assert reasons[0]["support_count"] == 2
    assert envelope["decisions"][0]["verdict"] == "suspicious"


# Failure and disabled behaviour


def test_failed_prune_rolls_back_without_losing_the_store(monkeypatch):
    config.memory.max_units_per_subject = 3
    memory_store.record_decision(srcip="203.0.113.179", verdict="true_positive", notes="confirmed")
    _a_reason("srcip:203.0.113.179", "evidence", verdict="true_positive")
    before = len(_subject_units("srcip:203.0.113.179"))

    def exploding(*args, **kwargs):
        raise sqlite3.OperationalError("disk went away")

    monkeypatch.setattr(memory_store, "_prune_subject", exploding)
    result = memory_store.record_decision(srcip="203.0.113.179", verdict="suspicious", notes="new")
    assert result["status"].startswith("unavailable"), result
    assert len(_subject_units("srcip:203.0.113.179")) == before


def test_prune_memory_is_a_noop_when_disabled(tmp_path, monkeypatch):
    config.memory.enabled = False
    config.memory.db_path = str(tmp_path / "never.db")
    calls: list[str] = []
    monkeypatch.setattr(memory_store, "_connect",
                        lambda *a, **k: calls.append("connect") or None)
    assert memory_store.prune_memory() == {"status": "disabled", "subjects": 0,
                                           "pruned": 0, "merged": 0}
    assert calls == []
    assert not os.path.exists(config.memory.db_path)


def test_concurrent_writes_at_capacity_never_exceed_it():
    config.memory.max_units_per_subject = 5
    for index in range(4):
        stale = _a_reason("srcip:203.0.113.180", f"expired {index}")
        _backdate(stale["unit_id"], 400)
    results: list[dict] = []
    barrier = threading.Barrier(20)

    def worker(index: int) -> None:
        barrier.wait()
        try:
            results.append(memory_store.record_decision(
                srcip="203.0.113.180", verdict="suspicious", notes=f"fresh {index}"))
        except Exception as e:
            results.append({"status": f"raised: {e}"})

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    rows = len(_subject_units("srcip:203.0.113.180"))
    assert rows <= 5, f"cap exceeded: {rows}"
    assert all(str(result["status"]).startswith(("ok", "unavailable")) for result in results)
    assert results
