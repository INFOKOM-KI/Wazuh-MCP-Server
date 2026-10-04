#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Typed investigation memory: subject-keyed units with provenance and taint.

A unit is a statement about a subject: its kind ("observation" | "experience" |
"world"), where it came from, and whether its text is attacker-influenced. Memory
answers "what happened with this subject, and what did we decide last time".
Document retrieval stays in ``core/rag_store.py``, indicator occurrence in
``core/ioc_store.py``, node topology in ``core/attack_graph.py``, and suppression
authority in ``core/false_positive_kb.py``.

Two rules are enforced in the writer:

- ``world`` (authoritative) requires analyst provenance and a source in
  ``ANALYST_SOURCES``. Everything automated is an observation.
- Taint is derived from provenance. ``alert_text`` and ``tool_output`` are
  attacker-influenced, so they can be recalled and shown but never promoted to
  ``world``, and a caller cannot declare them clean.

Disabled by default (``BLUETEAM_MEM_ENABLED``) and with no default path
(``BLUETEAM_MEM_DB``): an unconfigured store answers "disabled" and writes
nothing. Retention, capacity and consolidation land with the code that enforces
them, so no TTL is applied yet.
"""
from __future__ import annotations
import json
import logging
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional
from mcp_server.core.attacker_registry import ANALYST_SOURCES
from mcp_server.core.config import config
from mcp_server.core.exceptions import BlueTeamMCPError
from mcp_server.correlation.three_sum_core import compute_time_decay_weight

logger = logging.getLogger("blue_team_mcp.memory_store")

UNIT_TYPES = ("observation", "experience", "world")
PROVENANCES = ("alert_text", "tool_output", "analyst")
# Provenances whose text is attacker-influenced by construction.
_TAINTED_PROVENANCES = frozenset({"alert_text", "tool_output"})
SUBJECT_KINDS = ("srcip", "campaign", "env", "cve", "indicator", "alert")

# A unit is a derived statement, not a document: anything longer belongs in the
# RAG corpus, and storing it here would make recall return payloads.
MAX_TEXT_CHARS = 4000
_ENTITY_CAP = 64


class MemoryStoreError(BlueTeamMCPError):
    """Memory store is unconfigured, or a write violated the type/taint rules."""


# New columns must carry a DEFAULT: SQLite refuses ADD COLUMN ... NOT NULL without one.
_COLUMNS = (
    "unit_id        TEXT PRIMARY KEY",
    "type           TEXT NOT NULL",
    "subject        TEXT NOT NULL",
    "subject_kind   TEXT NOT NULL",
    "text           TEXT NOT NULL",
    "entities       TEXT NOT NULL DEFAULT '[]'",
    "occurred_at    TEXT NOT NULL DEFAULT ''",
    "first_seen     TEXT NOT NULL",
    "last_seen      TEXT NOT NULL",
    "support_count  INTEGER NOT NULL DEFAULT 1",
    "source         TEXT NOT NULL",
    "provenance     TEXT NOT NULL",
    "tainted        INTEGER NOT NULL",
    "confidence     REAL",
    "case_id        TEXT NOT NULL DEFAULT ''",
    "invalidated_by TEXT NOT NULL DEFAULT ''",
)
_SUBJECT_INDEX = "CREATE INDEX IF NOT EXISTS idx_units_subject ON units (subject)"


def _enabled() -> bool:
    memory = getattr(config, "memory", None)
    return bool(memory is not None and memory.enabled)


def _db_path() -> str:
    memory = getattr(config, "memory", None) if config is not None else None
    path = (getattr(memory, "db_path", "") or "").strip()
    if not path:
        raise MemoryStoreError(
            "Memory store is not configured. Set BLUETEAM_MEM_DB to an absolute path "
            "and BLUETEAM_MEM_ENABLED=true, then restart the server."
        )
    return path


def _ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the table, then add any column an older store is missing."""
    conn.execute("CREATE TABLE IF NOT EXISTS units (" + ", ".join(_COLUMNS) + ")")
    present = {row[1] for row in conn.execute("PRAGMA table_info(units)")}
    for column in _COLUMNS:
        name = column.split()[0]
        if name not in present and "PRIMARY KEY" not in column:
            conn.execute(f"ALTER TABLE units ADD COLUMN {column}")
    conn.execute(_SUBJECT_INDEX)


def _connect() -> sqlite3.Connection:
    """Open the store, creating the file and schema on first use. Per-call
    connection: sqlite3 connections are bound to the thread that made them."""
    path = _db_path()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    fresh = not os.path.exists(path)
    conn = sqlite3.connect(path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    _ensure_schema(conn)
    # Commit here as well: a read path that never writes would otherwise leave the
    # schema in an uncommitted transaction and drop it on close.
    conn.commit()
    if fresh:
        os.chmod(path, 0o600)
    return conn


@contextmanager
def _store() -> Iterator[sqlite3.Connection]:
    """Commit on success, always close. The sqlite3 connection context manager
    commits but does not close, which leaks a file handle per call."""
    conn = _connect()
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _norm_entities(entities: Optional[list[str]]) -> list[str]:
    seen = {(e or "").strip().lower() for e in (entities or [])}
    return sorted(e for e in seen if e)[:_ENTITY_CAP]


def _row_to_unit(row: sqlite3.Row) -> dict:
    unit = {key: row[key] for key in row.keys()}
    try:
        entities = json.loads(unit.get("entities") or "[]")
        unit["entities"] = [str(e) for e in entities] if isinstance(entities, list) else []
    except (ValueError, TypeError):
        logger.warning("memory_store: unreadable entity list on %s", unit.get("unit_id"))
        unit["entities"] = []
    unit["tainted"] = bool(unit.get("tainted"))
    return unit


def record_unit(*, unit_type: str, subject: str, text: str, provenance: str, source: str,
                entities: Optional[list[str]] = None, occurred_at: str = "",
                confidence: Optional[float] = None, case_id: str = "") -> dict:
    """Store one unit. Returns ``{"status": "ok", "unit": {...}}``, or
    ``{"status": "disabled"}`` while the store is off, or
    ``{"status": "unavailable: ..."}`` when the file cannot be written, so a
    caller can degrade instead of failing an investigation on memory.

    Raises ``MemoryStoreError`` for a refused write: unknown type or provenance, a
    subject that is not ``<kind>:<value>``, empty or too long text, or a ``world``
    unit without analyst provenance and an analyst source.

    ``occurred_at`` is when the event happened, if the caller knows it;
    ``first_seen``/``last_seen`` are always the time of this write.
    """
    if not _enabled():
        return {"status": "disabled", "unit": None}
    if unit_type not in UNIT_TYPES:
        raise MemoryStoreError(
            f"unknown unit type {unit_type!r}; expected one of {UNIT_TYPES}")
    if provenance not in PROVENANCES:
        raise MemoryStoreError(
            f"unknown provenance {provenance!r}; expected one of {PROVENANCES}")
    subject = (subject or "").strip()
    kind = subject.split(":", 1)[0] if ":" in subject else ""
    if kind not in SUBJECT_KINDS:
        raise MemoryStoreError(
            f"subject must be '<kind>:<value>' with kind in {SUBJECT_KINDS} (got {subject!r})")
    body = (text or "").strip()
    if not body:
        raise MemoryStoreError("a memory unit needs text")
    if len(body) > MAX_TEXT_CHARS:
        raise MemoryStoreError(
            f"text is {len(body)} chars, over the {MAX_TEXT_CHARS} limit; a longer "
            "statement belongs in the RAG corpus, not in memory")
    tainted = provenance in _TAINTED_PROVENANCES
    if unit_type == "world" and (provenance != "analyst" or source not in ANALYST_SOURCES):
        raise MemoryStoreError(
            "world units require analyst provenance and an analyst source "
            f"(got provenance={provenance!r}, source={source!r}); automated text is "
            "attacker-influenced and can only be an observation")
    now = _now_iso()
    unit = {
        "unit_id": "mem_" + uuid.uuid4().hex[:12],
        "type": unit_type,
        "subject": subject,
        "subject_kind": kind,
        "text": body,
        "entities": _norm_entities(entities),
        "occurred_at": (occurred_at or "").strip(),
        "first_seen": now,
        "last_seen": now,
        "support_count": 1,
        "source": (source or "").strip() or "unknown",
        "provenance": provenance,
        "tainted": tainted,
        "confidence": confidence,
        "case_id": (case_id or "").strip(),
        "invalidated_by": "",
    }
    # JSON in the column, a list in the returned unit.
    row = dict(unit, entities=json.dumps(unit["entities"]))
    placeholders = ", ".join("?" * len(row))
    try:
        with _store() as conn:
            conn.execute(
                f"INSERT INTO units ({', '.join(row.keys())}) VALUES ({placeholders})",
                list(row.values()))
    except (sqlite3.Error, MemoryStoreError) as e:
        logger.warning("memory_store: write failed (%s)", e)
        return {"status": f"unavailable: {e}", "unit": None}
    return {"status": "ok", "unit": unit}


def get_unit(unit_id: str) -> Optional[dict]:
    """One unit by id, or None when absent or when the store is disabled."""
    if not _enabled():
        return None
    try:
        with _store() as conn:
            row = conn.execute(
                "SELECT * FROM units WHERE unit_id = ?", (unit_id,)).fetchone()
    except (sqlite3.Error, MemoryStoreError) as e:
        logger.warning("memory_store: read failed (%s)", e)
        return None
    return _row_to_unit(row) if row else None


def units_for_subject(subject: str, *, limit: int = 10,
                      include_invalidated: bool = False) -> tuple[list[dict], Optional[str]]:
    """``(units, status)`` for one subject, most relevant first, where relevance is
    the shared time-decay weight (``compute_time_decay_weight``) with the most
    recent write as the tie-break. ``status`` is None on success, else
    ``"disabled"`` or ``"unavailable: ..."``.

    Withdrawn units are skipped unless ``include_invalidated`` is set, which is the
    audit read: invalidation hides a unit from recall, it does not delete it.
    Each unit carries its ``decay_weight``.
    """
    if not _enabled():
        return [], "disabled"
    sql = "SELECT * FROM units WHERE subject = ?"
    if not include_invalidated:
        sql += " AND invalidated_by = ''"
    try:
        with _store() as conn:
            rows = conn.execute(sql, (subject,)).fetchall()
    except (sqlite3.Error, MemoryStoreError) as e:
        logger.warning("memory_store: read failed (%s)", e)
        return [], f"unavailable: {e}"
    units = [_row_to_unit(row) for row in rows]
    for unit in units:
        unit["decay_weight"] = compute_time_decay_weight(
            unit["first_seen"], unit["last_seen"])
    # Ordering is computed here, so a SQL LIMIT would cut the wrong rows.
    units.sort(key=lambda u: u["last_seen"], reverse=True)
    units.sort(key=lambda u: u["decay_weight"], reverse=True)
    return units[:max(0, limit)], None


def invalidate_unit(unit_id: str, *, reason: str = "") -> Optional[dict]:
    """Withdraw a unit from recall, keeping the row for audit. ``invalidated_by``
    records the reason, or the id of the unit that replaced it. Returns the
    updated unit, or None when it is absent or the store is disabled."""
    if not _enabled():
        return None
    note = (reason or "").strip()[:200] or "unspecified"
    try:
        with _store() as conn:
            cursor = conn.execute(
                "UPDATE units SET invalidated_by = ? WHERE unit_id = ?", (note, unit_id))
            if not cursor.rowcount:
                return None
    except (sqlite3.Error, MemoryStoreError) as e:
        logger.warning("memory_store: invalidate failed (%s)", e)
        return None
    return get_unit(unit_id)


def memory_stats() -> dict:
    """Operational counters: unit count by type and source, plus the store path."""
    if not _enabled():
        return {"enabled": False, "db_path": None, "units": 0, "by_type": {}, "by_source": {}}
    try:
        with _store() as conn:
            total = conn.execute("SELECT COUNT(*) FROM units").fetchone()[0]
            by_type = {row[0]: row[1] for row in conn.execute(
                "SELECT type, COUNT(*) FROM units GROUP BY type")}
            by_source = {row[0]: row[1] for row in conn.execute(
                "SELECT source, COUNT(*) FROM units GROUP BY source")}
    except (sqlite3.Error, MemoryStoreError) as e:
        logger.warning("memory_store: stats failed (%s)", e)
        return {"enabled": True, "db_path": None, "units": 0, "by_type": {},
                "by_source": {}, "status": f"unavailable: {e}"}
    return {"enabled": True, "db_path": _db_path(), "units": int(total),
            "by_type": by_type, "by_source": by_source}


def clear_memory_store() -> None:
    """Remove the store file. Ops and tests only; no effect while disabled."""
    if not _enabled():
        return
    path = _db_path()
    for suffix in ("", "-wal", "-shm"):
        try:
            Path(path + suffix).unlink(missing_ok=True)
        except OSError:
            logger.warning("memory_store: could not remove %s%s", path, suffix, exc_info=True)
