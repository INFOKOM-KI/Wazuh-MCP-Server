#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
SQLite persistence for source forecasting observations and ingest runs.
Separate store from the tactic-forecast store: the source layer keeps its own
retention lifecycle, and the shared index never grows source tables.
"""
from __future__ import annotations
import json
import logging
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional
from mcp_server.core.config import config
from mcp_server.core.exceptions import BlueTeamMCPError

logger = logging.getLogger("blue_team_mcp.source_store")


class SourceStoreError(BlueTeamMCPError):
    """Source store is unconfigured, unreachable, or schema-incompatible."""


def _db_path() -> str:
    section = getattr(config, "source", None)
    path = (getattr(section, "store_path", "") or "").strip() if section else ""
    if not path:
        raise SourceStoreError(
            "Source store is not configured. Set BLUETEAM_SOURCE_STORE to an "
            "absolute path and BLUETEAM_SOURCE_FORECAST_ENABLED=true, then restart "
            "the server."
        )
    return path


def _max_rows() -> int:
    return max(1, int(getattr(config.source, "max_rows", 200000) or 200000))


def _secure_side_files(path: str) -> None:
    """SQLite creates WAL/SHM with umask permissions; tighten them so a
    PII-adjacent store is not group/world-readable while it is open."""
    for suffix in ("-wal", "-shm"):
        try:
            os.chmod(path + suffix, 0o600)
        except FileNotFoundError:
            pass
        except OSError as exc:
            logger.warning("could not tighten %s permissions: %s", suffix, exc)


def _connect() -> sqlite3.Connection:
    path = _db_path()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    fresh = not os.path.exists(path)
    conn = sqlite3.connect(path, timeout=5.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS source_observations (
            source_ip   TEXT NOT NULL,
            netblock    TEXT NOT NULL,
            country     TEXT,
            tactic      TEXT NOT NULL,
            observed_at REAL NOT NULL,
            PRIMARY KEY (source_ip, tactic, observed_at)
        );
        CREATE INDEX IF NOT EXISTS idx_source_seen ON source_observations (observed_at);
        CREATE INDEX IF NOT EXISTS idx_source_country ON source_observations (country);
        CREATE INDEX IF NOT EXISTS idx_source_netblock ON source_observations (netblock);

        CREATE TABLE IF NOT EXISTS source_ingests (
            ingest_id           TEXT PRIMARY KEY,
            since_ts            REAL NOT NULL,
            until_ts            REAL NOT NULL,
            window_complete     INTEGER NOT NULL,
            snapshot_consistent INTEGER NOT NULL,
            stats               TEXT NOT NULL,
            created_at          REAL NOT NULL
        );
        """
    )
    if fresh:
        os.chmod(path, 0o600)
    _secure_side_files(path)
    return conn


@contextmanager
def _store() -> Iterator[sqlite3.Connection]:
    """Commit on success, always close. The sqlite3 context manager commits but
    does not close, which leaks a file handle per call."""
    conn = _connect()
    try:
        with conn:
            yield conn
        _secure_side_files(_db_path())
    finally:
        conn.close()


def save_source_observations(rows: list[dict]) -> int:
    """Append normalized source rows, ignoring duplicates.
    The primary key makes a re-ingest idempotent; rows beyond ``max_rows`` are
    trimmed oldest-first.
    """
    if not rows:
        return 0
    payload = [(str(row["source_ip"]), str(row.get("netblock") or ""), row.get("country"),
                str(row.get("tactic") or ""), float(row["observed_at"])) for row in rows]
    with _store() as conn:
        cursor = conn.executemany(
            "INSERT OR IGNORE INTO source_observations"
            " (source_ip, netblock, country, tactic, observed_at) VALUES (?,?,?,?,?)",
            payload,
        )
        inserted = cursor.rowcount if cursor.rowcount and cursor.rowcount > 0 else 0
        conn.execute(
            "DELETE FROM source_observations WHERE rowid IN ("
            "SELECT rowid FROM source_observations ORDER BY observed_at DESC LIMIT -1 OFFSET ?)",
            (_max_rows(),),
        )
    return inserted


def load_source_observations(since_ts: float,
                             until_ts: Optional[float] = None) -> list[dict]:
    """Rows in ``[since_ts, until_ts)`` ordered by ``(observed_at, source_ip)``."""
    with _store() as conn:
        if until_ts is None:
            rows = conn.execute(
                "SELECT source_ip, netblock, country, tactic, observed_at"
                " FROM source_observations WHERE observed_at >= ?"
                " ORDER BY observed_at, source_ip", (float(since_ts),)).fetchall()
        else:
            rows = conn.execute(
                "SELECT source_ip, netblock, country, tactic, observed_at"
                " FROM source_observations WHERE observed_at >= ? AND observed_at < ?"
                " ORDER BY observed_at, source_ip",
                (float(since_ts), float(until_ts))).fetchall()
    return [{"source_ip": row[0], "netblock": row[1], "country": row[2],
             "tactic": row[3], "observed_at": float(row[4])} for row in rows]


def save_ingest(ingest_id: str, since_ts: float, until_ts: float,
                window_complete: bool, snapshot_consistent: bool,
                stats: Optional[dict] = None) -> None:
    """Record one ingest run's window and completeness, replacing a rerun."""
    with _store() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO source_ingests (ingest_id, since_ts, until_ts,"
            " window_complete, snapshot_consistent, stats, created_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (ingest_id, float(since_ts), float(until_ts),
             1 if window_complete else 0, 1 if snapshot_consistent else 0,
             json.dumps(stats or {}, sort_keys=True), time.time()),
        )


def _ingest_row(row) -> dict:
    return {"ingest_id": row[0], "since_ts": float(row[1]), "until_ts": float(row[2]),
            "window_complete": bool(row[3]), "snapshot_consistent": bool(row[4]),
            "stats": json.loads(row[5] or "{}"), "created_at": float(row[6])}


def load_ingest(ingest_id: Optional[str] = None) -> Optional[dict]:
    """One ingest run by id, or the newest when the id is omitted."""
    columns = ("SELECT ingest_id, since_ts, until_ts, window_complete,"
               " snapshot_consistent, stats, created_at FROM source_ingests")
    with _store() as conn:
        if ingest_id:
            row = conn.execute(f"{columns} WHERE ingest_id = ?", (ingest_id,)).fetchone()
        else:
            row = conn.execute(f"{columns} ORDER BY created_at DESC LIMIT 1").fetchone()
    return _ingest_row(row) if row is not None else None


def complete_ingest_covering(since_ts: float, until_ts: float) -> Optional[dict]:
    """Newest complete ingest whose window covers ``[since_ts, until_ts]``.
    A prediction must not run against history that no verified ingest bounds.
    """
    with _store() as conn:
        row = conn.execute(
            "SELECT ingest_id, since_ts, until_ts, window_complete, snapshot_consistent,"
            " stats, created_at FROM source_ingests"
            " WHERE window_complete = 1 AND snapshot_consistent = 1"
            " AND since_ts <= ? AND until_ts >= ?"
            " ORDER BY created_at DESC LIMIT 1",
            (float(since_ts), float(until_ts))).fetchone()
    return _ingest_row(row) if row is not None else None


def purge_expired() -> dict:
    """Delete observations older than ``retention_days`` (0 disables)."""
    days = float(getattr(config.source, "retention_days", 365) or 0)
    if days <= 0:
        return {"rows": 0, "cutoff": None}
    cutoff = time.time() - days * 86400.0
    with _store() as conn:
        cursor = conn.execute(
            "DELETE FROM source_observations WHERE observed_at < ?", (cutoff,))
        removed = cursor.rowcount if cursor.rowcount and cursor.rowcount > 0 else 0
    return {"rows": removed, "cutoff": cutoff}


def store_stats() -> dict:
    """Counts and coverage for diagnostics; never returns source values."""
    try:
        with _store() as conn:
            rows = conn.execute("SELECT COUNT(*) FROM source_observations").fetchone()[0]
            sources = conn.execute(
                "SELECT COUNT(DISTINCT source_ip) FROM source_observations").fetchone()[0]
            geo = conn.execute(
                "SELECT COUNT(*) FROM source_observations"
                " WHERE country IS NOT NULL AND country != ''").fetchone()[0]
            first = conn.execute("SELECT MIN(observed_at) FROM source_observations").fetchone()[0]
            last = conn.execute("SELECT MAX(observed_at) FROM source_observations").fetchone()[0]
            ingests = conn.execute("SELECT COUNT(*) FROM source_ingests").fetchone()[0]
        return {"rows": int(rows), "sources": int(sources),
                "first_observed_at": None if first is None else float(first),
                "last_observed_at": None if last is None else float(last),
                "geo_coverage": (round(int(geo) / int(rows), 4) if int(rows) else None),
                "ingests": int(ingests)}
    except (SourceStoreError, sqlite3.Error) as exc:
        return {"rows": 0, "sources": 0, "first_observed_at": None,
                "last_observed_at": None, "geo_coverage": None, "ingests": 0,
                "status": f"unavailable: {exc}"}
