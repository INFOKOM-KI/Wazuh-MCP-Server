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

import socket
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
import pytest
from mcp_server.core import memory_store
from mcp_server.core.config import MemoryConfig, config
from mcp_server.core.exceptions import ConfigurationError


@pytest.fixture(autouse=True)
def _disabled_by_default():
    config.memory.enabled = False
    config.memory.db_path = ""
    yield
    config.memory.enabled = False
    config.memory.db_path = ""


def _enable(tmp_path) -> str:
    path = str(tmp_path / "memory.db")
    config.memory.enabled = True
    config.memory.db_path = path
    return path


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
