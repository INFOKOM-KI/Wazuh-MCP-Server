#!/usr/bin/env python3
"""Phase 1 typed memory store (core/memory_store.py).

The load-bearing claims are the taint rules: a caller cannot declare
alert-derived text clean, and automated text cannot become authoritative ``world``
memory. The rest covers the disabled path, the config gate, additive schema
changes, unreadable rows, decay ordering, and the offline guarantee.
"""
from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import asyncio
import json
import socket
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
import pathlib
import pytest
from mcp_server.agents import investigation_graph as ig
from mcp_server.core import memory_store
from mcp_server.core.config import MemoryConfig, config
from mcp_server.core.exceptions import ConfigurationError
from mcp_server.tools import investigation_history as ih


@pytest.fixture(autouse=True)
def _disabled_by_default():
    config.memory.enabled = False
    config.memory.db_path = ""
    config.memory.max_units_per_subject = 50
    yield
    config.memory.enabled = False
    config.memory.db_path = ""
    config.memory.max_units_per_subject = 50


def _enable(tmp_path) -> str:
    path = str(tmp_path / "memory.db")
    config.memory.enabled = True
    config.memory.db_path = path
    return path


def _cap(value: int) -> None:
    config.memory.max_units_per_subject = value


def _observation(**overrides) -> dict:
    kwargs = dict(unit_type="observation", subject="srcip:203.0.113.5",
                  text="repeated ssh auth failures", provenance="alert_text",
                  source="engine_a", entities=["203.0.113.5"])
    kwargs.update(overrides)
    return kwargs


def test_disabled_is_inert(tmp_path):
    path = str(tmp_path / "never.db")
    config.memory.db_path = path
    assert memory_store.record_unit(**_observation())["status"] == "disabled"
    assert memory_store.units_for_subject("srcip:203.0.113.5") == ([], "disabled")
    assert memory_store.get_unit("mem_missing") is None
    assert memory_store.invalidate_unit("mem_missing") is None
    assert memory_store.memory_stats()["enabled"] is False
    assert not os.path.exists(path)


def test_disabled_store_does_not_raise_on_a_refused_payload(tmp_path):
    """The off switch wins over validation: a disabled store must never be able to
    fail an investigation, whatever a caller passes."""
    config.memory.db_path = str(tmp_path / "never.db")
    assert memory_store.record_unit(**_observation(
        unit_type="world", provenance="alert_text"))["status"] == "disabled"


def test_enabled_requires_an_absolute_path():
    with pytest.raises(ConfigurationError):
        MemoryConfig(enabled=True, db_path="").validate()
    with pytest.raises(ConfigurationError):
        MemoryConfig(enabled=True, db_path="memory.db").validate()
    MemoryConfig(enabled=True, db_path="/var/lib/blue-team-mcp/memory.db").validate()
    MemoryConfig().validate()
    assert isinstance(config.memory, MemoryConfig)


def test_taint_is_derived_from_provenance(tmp_path):
    _enable(tmp_path)
    alert = memory_store.record_unit(**_observation())["unit"]
    tool = memory_store.record_unit(**_observation(provenance="tool_output"))["unit"]
    human = memory_store.record_unit(**_observation(
        provenance="analyst", source="analyst"))["unit"]
    assert alert["tainted"] is True
    assert tool["tainted"] is True
    assert human["tainted"] is False
    assert memory_store.get_unit(alert["unit_id"])["tainted"] is True


def test_tainted_text_cannot_become_world(tmp_path):
    _enable(tmp_path)
    for provenance in ("alert_text", "tool_output"):
        with pytest.raises(memory_store.MemoryStoreError):
            memory_store.record_unit(**_observation(
                unit_type="world", provenance=provenance, source="verdict"))


def test_world_requires_an_analyst_source(tmp_path):
    _enable(tmp_path)
    with pytest.raises(memory_store.MemoryStoreError):
        memory_store.record_unit(**_observation(
            unit_type="world", provenance="analyst", source="enrichment"))
    stored = memory_store.record_unit(**_observation(
        unit_type="world", provenance="analyst", source="verdict",
        text="analyst closed this as scanner noise"))
    assert stored["status"] == "ok"
    assert stored["unit"]["type"] == "world"
    assert stored["unit"]["tainted"] is False


@pytest.mark.parametrize("overrides", [
    {"unit_type": "rumour"},
    {"provenance": "hearsay"},
    {"subject": "203.0.113.5"},
    {"subject": "host:web-01"},
    {"text": "   "},
    {"text": "x" * (memory_store.MAX_TEXT_CHARS + 1)},
])
def test_refused_writes(tmp_path, overrides):
    _enable(tmp_path)
    with pytest.raises(memory_store.MemoryStoreError):
        memory_store.record_unit(**_observation(**overrides))


def test_entities_are_normalized(tmp_path):
    _enable(tmp_path)
    unit = memory_store.record_unit(**_observation(
        entities=[" 203.0.113.5 ", "Evil.example", "evil.example"]))["unit"]
    assert unit["entities"] == ["203.0.113.5", "evil.example"]


def test_missing_column_is_added_without_losing_rows(tmp_path):
    path = _enable(tmp_path)
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE units (unit_id TEXT PRIMARY KEY, type TEXT NOT NULL, subject TEXT NOT NULL, "
        "subject_kind TEXT NOT NULL, text TEXT NOT NULL, first_seen TEXT NOT NULL, "
        "last_seen TEXT NOT NULL, source TEXT NOT NULL, provenance TEXT NOT NULL, "
        "tainted INTEGER NOT NULL)")
    conn.execute(
        "INSERT INTO units VALUES ('mem_old', 'observation', 'srcip:198.51.100.1', 'srcip', "
        "'old row', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 'engine_a', 'alert_text', 1)")
    conn.commit()
    conn.close()
    units, status = memory_store.units_for_subject("srcip:198.51.100.1")
    assert status is None
    assert [unit["unit_id"] for unit in units] == ["mem_old"]
    assert units[0]["entities"] == []
    assert memory_store.record_unit(**_observation())["status"] == "ok"


def test_unreadable_entity_column_does_not_break_the_read(tmp_path):
    path = _enable(tmp_path)
    unit = memory_store.record_unit(**_observation())["unit"]
    conn = sqlite3.connect(path)
    conn.execute("UPDATE units SET entities = ? WHERE unit_id = ?", ("{not json", unit["unit_id"]))
    conn.commit()
    conn.close()
    units, status = memory_store.units_for_subject(unit["subject"])
    assert status is None
    assert units[0]["entities"] == []
    assert memory_store.memory_stats()["units"] == 1


def test_subject_read_is_ordered_by_decay(tmp_path):
    path = _enable(tmp_path)
    fresh = memory_store.record_unit(**_observation(text="fresh"))["unit"]
    stale = memory_store.record_unit(**_observation(text="stale"))["unit"]
    old = (datetime.now(timezone.utc) - timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn = sqlite3.connect(path)
    conn.execute("UPDATE units SET first_seen = ?, last_seen = ? WHERE unit_id = ?",
                 (old, old, stale["unit_id"]))
    conn.commit()
    conn.close()
    units, status = memory_store.units_for_subject(fresh["subject"])
    assert status is None
    assert [unit["text"] for unit in units] == ["fresh", "stale"]
    assert units[0]["decay_weight"] > units[1]["decay_weight"]
    assert units[1]["decay_weight"] < 1.0


def test_invalidated_unit_is_hidden_but_kept_for_audit(tmp_path):
    _enable(tmp_path)
    unit = memory_store.record_unit(**_observation())["unit"]
    assert memory_store.invalidate_unit(unit["unit_id"], reason="superseded")["invalidated_by"] == "superseded"
    assert memory_store.units_for_subject(unit["subject"]) == ([], None)
    audit, _ = memory_store.units_for_subject(unit["subject"], include_invalidated=True)
    assert audit[0]["invalidated_by"] == "superseded"
    assert memory_store.get_unit(unit["unit_id"]) is not None


def test_stats_and_clear(tmp_path):
    path = _enable(tmp_path)
    memory_store.record_unit(**_observation())
    memory_store.record_unit(**_observation(
        unit_type="world", provenance="analyst", source="verdict"))
    stats = memory_store.memory_stats()
    assert stats["units"] == 2
    assert stats["by_type"] == {"observation": 1, "world": 1}
    assert stats["by_source"] == {"engine_a": 1, "verdict": 1}
    assert stats["db_path"] == path
    assert os.path.exists(path)
    memory_store.clear_memory_store()
    assert not os.path.exists(path)


def _refuse_socket(*args, **kwargs):
    raise AssertionError("the memory store opened a socket")


def test_record_decision_inserted_then_reaffirmed(tmp_path):
    _enable(tmp_path)
    first = memory_store.record_decision(srcip="203.0.113.61", verdict="false_positive",
                                         notes="CrowdSec noise")
    again = memory_store.record_decision(srcip="203.0.113.61", verdict="false_positive",
                                         notes="CrowdSec noise")
    assert (first["decision"], first["reason"]) == ("inserted", "inserted")
    assert (again["decision"], again["reason"]) == ("reaffirmed", "reaffirmed")
    units, _ = memory_store.units_for_subject("srcip:203.0.113.61", include_invalidated=True)
    assert len(units) == 2
    assert all(unit["support_count"] == 2 for unit in units)


def test_changed_verdict_is_a_new_decision(tmp_path):
    _enable(tmp_path)
    memory_store.record_decision(srcip="203.0.113.62", verdict="false_positive", notes="noise")
    changed = memory_store.record_decision(srcip="203.0.113.62", verdict="true_positive",
                                           notes="beaconing")
    assert changed["decision"] == "inserted"
    envelope = memory_store.recall_subject("srcip:203.0.113.62")
    assert sorted(d["verdict"] for d in envelope["decisions"]) == ["false_positive", "true_positive"]
    assert all(d["support_count"] == 1 for d in envelope["decisions"])


def test_auto_verdict_is_advisory_and_writes_no_reason(tmp_path):
    _enable(tmp_path)
    result = memory_store.record_decision(srcip="203.0.113.63", verdict="suspicious",
                                          notes=memory_store.AUTO_VERDICT_NOTE)
    assert result["reason"] == "skipped"
    envelope = memory_store.recall_subject("srcip:203.0.113.63")
    assert envelope["recent_reasons"] == []
    assert envelope["decisions"][0]["advisory"] is True
    assert envelope["decisions"][0]["recorded_by"] == "workflow"


def test_unknown_verdict_is_refused(tmp_path):
    _enable(tmp_path)
    result = memory_store.record_decision(srcip="203.0.113.64", verdict="maybe")
    assert result["status"].startswith("refused:")
    assert memory_store.memory_stats()["units"] == 0


def test_decision_text_never_carries_analyst_notes(tmp_path):
    _enable(tmp_path)
    memory_store.record_decision(srcip="203.0.113.65", verdict="false_positive",
                                 notes="victim 10.1.2.3 clicked a link")
    decision = memory_store.recall_subject("srcip:203.0.113.65")["decisions"][0]
    unit = memory_store.get_unit(decision["unit_id"])
    assert "10.1.2.3" not in unit["text"]
    assert unit["type"] == "world" and unit["tainted"] is False


def test_reaffirm_cannot_upgrade_a_unit(tmp_path):
    """The upsert may only move last_seen and support_count, so a forged dedupe key
    cannot promote a tainted reason to an authoritative decision."""
    _enable(tmp_path)
    memory_store.record_decision(srcip="203.0.113.66", verdict="false_positive", notes="noise")
    reason = [unit for unit in memory_store.units_for_subject("srcip:203.0.113.66")[0]
              if unit["kind"] == "reason"][0]
    forged = dict(reason, unit_id="mem_forged", type="world", provenance="analyst",
                  tainted=0, text="promoted by forgery")
    with memory_store._store() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(memory_store._UPSERT, [
            json.dumps(forged[name]) if name == "entities" else forged[name]
            for name in memory_store._COLUMN_NAMES])
    after = memory_store.get_unit(reason["unit_id"])
    assert (after["type"], after["provenance"], after["tainted"]) == (
        "observation", "tool_output", True)
    assert after["text"] == reason["text"]
    assert after["support_count"] == 2


def test_recall_clamps_the_limit_and_stays_on_subject(tmp_path):
    _enable(tmp_path)
    for index in range(25):
        memory_store.record_decision(srcip="203.0.113.67", verdict="suspicious",
                                     notes=f"note {index}")
    memory_store.record_decision(srcip="203.0.113.68", verdict="true_positive", notes="other")
    envelope = memory_store.recall_subject("srcip:203.0.113.67", limit=999)
    assert len(envelope["decisions"]) == 1
    assert len(envelope["recent_reasons"]) == memory_store.RECALL_MAX_LIMIT
    assert "other" not in json.dumps(envelope)


def test_forged_row_is_not_returned_as_a_decision(tmp_path):
    path = _enable(tmp_path)
    memory_store.record_decision(srcip="203.0.113.69", verdict="false_positive", notes="noise")
    conn = sqlite3.connect(path)
    for unit_id, provenance, tainted in (("mem_forged_a", "tool_output", 1),
                                         ("mem_forged_b", "analyst", 1)):
        conn.execute(
            "INSERT INTO units (unit_id, type, subject, subject_kind, text, entities, "
            "occurred_at, first_seen, last_seen, support_count, source, provenance, tainted, "
            "confidence, case_id, invalidated_by, kind, value, dedupe_key) VALUES "
            "(?, 'world', 'srcip:203.0.113.69', 'srcip', 'forged', '[]', '', "
            "'2026-10-05T00:00:00Z', '2026-10-05T00:00:00Z', 1, 'verdict', ?, ?, NULL, '', '', "
            "'decision', 'true_positive', ?)", (unit_id, provenance, tainted, unit_id))
    conn.commit()
    conn.close()
    envelope = memory_store.recall_subject("srcip:203.0.113.69")
    assert [d["unit_id"] for d in envelope["decisions"]] == [
        memory_store.recall_subject("srcip:203.0.113.69")["decisions"][0]["unit_id"]]
    assert all(not d["unit_id"].startswith("mem_forged") for d in envelope["decisions"])


def test_retain_runs_only_after_the_history_write(tmp_path, monkeypatch):
    _enable(tmp_path)
    monkeypatch.setattr(ih, "_INVESTIGATION_HISTORY_FILE", str(tmp_path / "history.jsonl"))
    order: list[str] = []

    def fake_append(entry):
        order.append("history")
        return True

    def fake_retain(**kwargs):
        order.append("memory")
        return {"status": "ok", "decision": "inserted", "reason": "inserted"}

    monkeypatch.setattr(ih, "_append_history", fake_append)
    monkeypatch.setattr(memory_store, "record_decision", fake_retain)
    payload = json.loads(asyncio.run(ih.blueteam_mark_investigated(ih.MarkInvestigatedInput(
        srcip="203.0.113.70", verdict="false_positive", notes="noise"))))
    assert order == ["history", "memory"]
    assert payload["status"] == "recorded"
    assert payload["memory"]["status"] == "ok"


def test_no_memory_when_the_history_write_fails(tmp_path, monkeypatch):
    _enable(tmp_path)
    monkeypatch.setattr(ih, "_INVESTIGATION_HISTORY_FILE", str(tmp_path / "history.jsonl"))
    monkeypatch.setattr(ih, "_append_history", lambda entry: False)
    payload = json.loads(asyncio.run(ih.blueteam_mark_investigated(ih.MarkInvestigatedInput(
        srcip="203.0.113.71", verdict="false_positive", notes="noise"))))
    assert "error" in payload
    assert memory_store.memory_stats()["units"] == 0


def test_retain_failure_keeps_the_recorded_verdict(tmp_path, monkeypatch):
    _enable(tmp_path)
    monkeypatch.setattr(ih, "_INVESTIGATION_HISTORY_FILE", str(tmp_path / "history.jsonl"))
    monkeypatch.setattr(ih, "_append_history", lambda entry: True)

    def exploding(**kwargs):
        raise RuntimeError("store on fire")

    monkeypatch.setattr(memory_store, "record_decision", exploding)
    payload = json.loads(asyncio.run(ih.blueteam_mark_investigated(ih.MarkInvestigatedInput(
        srcip="203.0.113.72", verdict="true_positive", notes="confirmed"))))
    assert payload["status"] == "recorded"
    assert payload["entry"]["verdict"] == "true_positive"
    assert payload["memory"]["status"].startswith("unavailable:")


def test_auto_verdict_marker_matches_the_graph():
    """AUTO_VERDICT_NOTE is how a machine verdict is told apart from an analyst one,
    so a change to the graph's note must fail here instead of silently reclassifying."""
    source = pathlib.Path(ig.__file__).read_text(encoding="utf-8")
    assert f'notes="{memory_store.AUTO_VERDICT_NOTE}"' in source


def test_memory_subject_matches_the_thread_key():
    assert memory_store.subject_for_srcip("203.0.113.9") == ig.subject_key("srcip", "203.0.113.9")
    assert memory_store.subject_for_srcip(" 203.0.113.9 ") == ig.subject_key("srcip", " 203.0.113.9 ")


def _raw_row(path: str, **overrides) -> None:
    """Insert one row straight into SQLite, so the read guard can be probed."""
    row = {"unit_id": "mem_raw", "type": "world", "subject": "srcip:203.0.113.90",
           "subject_kind": "srcip", "text": "raw", "entities": "[]", "occurred_at": "",
           "first_seen": "2026-10-05T00:00:00Z", "last_seen": "2026-10-05T00:00:00Z",
           "support_count": 1, "source": "verdict", "provenance": "analyst", "tainted": 0,
           "confidence": None, "case_id": "", "invalidated_by": "", "kind": "decision",
           "value": "true_positive", "dedupe_key": "raw-key"}
    row.update(overrides)
    conn = sqlite3.connect(path)
    conn.execute(f"INSERT INTO units ({', '.join(row)}) VALUES ({', '.join('?' * len(row))})",
                 list(row.values()))
    conn.commit()
    conn.close()


@pytest.mark.parametrize("overrides", [
    {"kind": "rumour"},                            # unknown kind
    {"type": "fact"},                              # unknown type
    {"provenance": "rumour"},                      # unknown provenance
    {"tainted": 0, "provenance": "tool_output"},   # taint disagrees with provenance
    {"value": "not_a_verdict"},                    # decision without a known verdict
])
def test_read_guard_drops_inconsistent_rows(tmp_path, overrides):
    path = _enable(tmp_path)
    memory_store.memory_stats()  # create the schema before the raw insert
    _raw_row(path, **overrides)
    envelope = memory_store.recall_subject("srcip:203.0.113.90")
    assert envelope["decisions"] == [] and envelope["recent_reasons"] == []


def test_unique_index_survives_reopen(tmp_path):
    """The dedupe constraint has to outlive the connection that created it."""
    _enable(tmp_path)
    memory_store.record_decision(srcip="203.0.113.91", verdict="true_positive", notes="confirmed")
    with memory_store._store() as conn:
        key = conn.execute("SELECT dedupe_key FROM units WHERE kind = 'decision'").fetchone()[0]
        index = conn.execute("SELECT name FROM sqlite_master WHERE type = 'index' "
                             "AND name = 'idx_units_dedupe'").fetchone()
    assert index[0] == "idx_units_dedupe"
    with pytest.raises(sqlite3.IntegrityError):
        with memory_store._store() as conn:
            conn.execute(
                "INSERT INTO units (unit_id, type, subject, subject_kind, text, entities, "
                "occurred_at, first_seen, last_seen, support_count, source, provenance, tainted, "
                "confidence, case_id, invalidated_by, kind, value, dedupe_key) VALUES "
                "('mem_dup', 'world', 'srcip:203.0.113.91', 'srcip', 'dup', '[]', '', "
                "'2026-10-05T00:00:00Z', '2026-10-05T00:00:00Z', 1, 'verdict', 'analyst', 0, NULL, "
                "'', '', 'decision', 'true_positive', ?)", (key,))


def test_trust_class_separates_machine_and_analyst_decisions(tmp_path):
    """An analyst confirming a machine verdict must write an authoritative row, not
    bump the advisory one, because a reaffirmation never upgrades a unit."""
    _enable(tmp_path)
    machine = memory_store.record_decision(srcip="203.0.113.80", verdict="suspicious",
                                           notes=memory_store.AUTO_VERDICT_NOTE,
                                           recorded_by="workflow")
    analyst = memory_store.record_decision(srcip="203.0.113.80", verdict="suspicious",
                                           notes="analyst agrees after review")
    assert (machine["decision"], analyst["decision"]) == ("inserted", "inserted")
    envelope = memory_store.recall_subject("srcip:203.0.113.80")
    assert sorted(d["advisory"] for d in envelope["decisions"]) == [False, True]
    again = memory_store.record_decision(srcip="203.0.113.80", verdict="suspicious",
                                         notes="analyst agrees after review")
    assert again["decision"] == "reaffirmed"
    twice = memory_store.recall_subject("srcip:203.0.113.80")
    assert sorted(d["support_count"] for d in twice["decisions"] if not d["advisory"]) == [2]
    assert sorted(d["support_count"] for d in twice["decisions"] if d["advisory"]) == [1]


def test_legacy_row_without_kind_is_never_returned_as_a_decision(tmp_path):
    path = _enable(tmp_path)
    memory_store.record_unit(unit_type="observation", subject="srcip:203.0.113.81",
                             text="phase 1 row", provenance="alert_text", source="engine_a")
    envelope = memory_store.recall_subject("srcip:203.0.113.81")
    assert envelope["status"] == "empty"
    assert envelope["decisions"] == [] and envelope["recent_reasons"] == []
    units, status = memory_store.units_for_subject("srcip:203.0.113.81")
    assert status is None and len(units) == 1  # still readable on the audit path
    conn = sqlite3.connect(path)
    assert conn.execute("SELECT kind, dedupe_key FROM units").fetchone() == ("", "")
    conn.close()


def test_decision_with_an_unknown_verdict_is_dropped(tmp_path):
    path = _enable(tmp_path)
    memory_store.memory_stats()  # create the schema before the raw insert
    conn = sqlite3.connect(path)
    conn.execute(
        "INSERT INTO units (unit_id, type, subject, subject_kind, text, entities, occurred_at, "
        "first_seen, last_seen, support_count, source, provenance, tainted, confidence, case_id, "
        "invalidated_by, kind, value, dedupe_key) VALUES ('mem_forged', 'world', "
        "'srcip:203.0.113.82', 'srcip', 'forged', '[]', '', '2026-10-05T00:00:00Z', "
        "'2026-10-05T00:00:00Z', 1, 'verdict', 'analyst', 0, NULL, '', '', 'decision', "
        "'not_a_verdict', 'forged')")
    conn.commit()
    conn.close()
    assert memory_store.recall_subject("srcip:203.0.113.82")["decisions"] == []


def test_schema_creation_is_idempotent_and_reopen_keeps_the_fields(tmp_path):
    _enable(tmp_path)
    memory_store.record_decision(srcip="203.0.113.83", verdict="true_positive", notes="confirmed")
    with memory_store._store() as conn:
        memory_store._ensure_schema(conn)
        memory_store._ensure_schema(conn)
    with memory_store._store() as conn:
        row = conn.execute("SELECT kind, value, dedupe_key, type, tainted FROM units "
                           "WHERE kind = 'decision'").fetchone()
    assert row["value"] == "true_positive" and row["type"] == "world"
    assert row["tainted"] == 0 and row["dedupe_key"][:8] and row["kind"] == "decision"


def test_many_rows_share_the_empty_dedupe_key(tmp_path):
    """The unique index is partial, so rows written before Phase 2 never collide."""
    _enable(tmp_path)
    for index in range(5):
        memory_store.record_unit(unit_type="observation", subject="srcip:203.0.113.84",
                                 text=f"row {index}", provenance="alert_text", source="engine_a")
    assert len(memory_store.units_for_subject("srcip:203.0.113.84")[0]) == 5


def test_no_embedder_and_no_network(tmp_path, monkeypatch):
    _enable(tmp_path)
    from mcp_server.core import rag_store
    modules_before = set(sys.modules)
    monkeypatch.setattr(socket, "socket", _refuse_socket)
    unit = memory_store.record_unit(**_observation())["unit"]
    assert memory_store.units_for_subject(unit["subject"])[0]
    assert memory_store.memory_stats()["units"] == 1
    assert getattr(rag_store, "_embedder", None) is None
    assert "fastembed" not in set(sys.modules) - modules_before
