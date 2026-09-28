#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
SQLite persistence for tactic-sequence forecasting (blueteam_tactic_forecast).
Two tables with different lifetimes:
``observations``
    Append-only ``(entity_key, tactic, observed_at)`` rows. The primary key
    makes re-ingesting an overlapping window idempotent, so a daily train does
    not inflate transition counts. Retention is by age and row cap; this is the
    training corpus and it is the only thing that lets a forecast improve over
    time, so its TTL is deliberately much longer than the cluster store's.
``models``
    Fitted parameters as JSON, stamped with ``TAXONOMY_VERSION``. A model
    written under a different vocabulary is refused on read, the same way
    ``cluster_store`` refuses a fit under another ``FEATURE_VERSION`` -
    scoring against shifted columns would produce confident nonsense.
Layout follows ``core/cluster_store.py``: connection per call (connections are
thread bound and calls run inside ``asyncio.to_thread``), WAL, ``0600``, no
default path. Entity keys are source IPs, so the file is PII-adjacent and must
never be committed.
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
from mcp_server.correlation.forecast_core import (
    TAXONOMY_VERSION,
    TACTIC_ORDER,
    VOLUME_KIND,
    validate_model,
)

logger = logging.getLogger("blue_team_mcp.forecast_store")

_MAX_MODELS = 50

class ForecastStoreError(BlueTeamMCPError):
    """Forecast store is unconfigured, unreachable, or taxonomy incompatible."""
def _db_path() -> str:
    """Configured store path, or raise. Never returns a default: a corpus
    written to an unconfigured location is invisible state."""
    forecast = getattr(config, "forecast", None) if config is not None else None
    path = (getattr(forecast, "store_path", "") or "").strip()
    if not path:
        raise ForecastStoreError(
            "Forecast store is not configured. Set BLUETEAM_FORECAST_STORE to an "
            "absolute path and BLUETEAM_FORECAST_ENABLED=true, then restart the server."
        )
    return path


def _connect() -> sqlite3.Connection:
    """Open the store, creating the schema on first use."""
    path = _db_path()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    fresh = not os.path.exists(path)
    conn = sqlite3.connect(path, timeout=5.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS observations (
            entity_key  TEXT NOT NULL,
            tactic      TEXT NOT NULL,
            observed_at REAL NOT NULL,
            PRIMARY KEY (entity_key, tactic, observed_at)
        );
        CREATE INDEX IF NOT EXISTS idx_observations_seen ON observations (observed_at);

        CREATE TABLE IF NOT EXISTS counts (
            bucket_ts REAL PRIMARY KEY,
            count     INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS models (
            model_id         TEXT PRIMARY KEY,
            kind             TEXT NOT NULL,
            taxonomy_version TEXT NOT NULL,
            tactics          TEXT NOT NULL,
            params           TEXT NOT NULL,
            startprob        TEXT NOT NULL,
            transmat         TEXT NOT NULL,
            emissionprob     TEXT,
            row_support      TEXT,
            n_sequences      INTEGER NOT NULL,
            n_transitions    INTEGER NOT NULL,
            created_at       REAL NOT NULL
        );
        """
    )
    if fresh:
        os.chmod(path, 0o600)
    return conn


@contextmanager
def _store() -> Iterator[sqlite3.Connection]:
    """Commit on success, always close. The sqlite3 context manager commits but
    does not close, which leaks a file handle per call."""
    conn = _connect()
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def append_observations(rows: list[tuple[str, str, float]]) -> int:
    """Append ``(entity_key, tactic, observed_at)`` rows, ignoring duplicates.
    Returns the number of new rows. Duplicate suppression is what makes a
    repeated train over an overlapping window idempotent: without it every
    re-ingest would double the weight of that window in the transition counts.
    The oldest rows beyond ``BLUETEAM_FORECAST_STORE_MAX`` are trimmed after
    the insert.
    """
    if not rows:
        return 0
    cap = max(1, int(getattr(config.forecast, "store_max", 200000) or 200000))
    with _store() as conn:
        cursor = conn.executemany(
            "INSERT OR IGNORE INTO observations (entity_key, tactic, observed_at)"
            " VALUES (?,?,?)",
            [(str(key), str(tactic), float(observed_at)) for key, tactic, observed_at in rows],
        )
        inserted = cursor.rowcount if cursor.rowcount and cursor.rowcount > 0 else 0
        conn.execute(
            "DELETE FROM observations WHERE rowid IN (SELECT rowid FROM observations"
            " ORDER BY observed_at DESC LIMIT -1 OFFSET ?)", (cap,),
        )
    return inserted


def load_observations(since_ts: Optional[float] = None) -> list[dict]:
    """Observation rows ordered by time, optionally bounded by an epoch start.
    Ordered output lets ``build_sequences`` sort by timestamp without a second
    pass, and a bounded read keeps a long-retention corpus from being loaded
    wholesale on every call.
    """
    with _store() as conn:
        if since_ts is None:
            rows = conn.execute(
                "SELECT entity_key, tactic, observed_at FROM observations"
                " ORDER BY observed_at").fetchall()
        else:
            rows = conn.execute(
                "SELECT entity_key, tactic, observed_at FROM observations"
                " WHERE observed_at >= ? ORDER BY observed_at", (float(since_ts),)).fetchall()
    return [{"entity_key": row[0], "tactic": row[1], "observed_at": float(row[2])}
            for row in rows]


def upsert_counts(rows: list[tuple[float, int]]) -> int:
    """Write ``(bucket_ts, count)`` pairs, replacing a bucket that already exists.
    Replace, not ignore: a re-aggregation of the same window returns the same
    count for a closed bucket, and the newest value is the correct one if a
    trailing partial bucket was counted mid-interval. One row per bucket keeps
    the series small (a year of hourly buckets is under 9,000 rows) and makes
    a repeated train idempotent.
    """
    if not rows:
        return 0
    cap = max(1, int(getattr(config.forecast, "store_max", 200000) or 200000))
    with _store() as conn:
        conn.executemany(
            "INSERT OR REPLACE INTO counts (bucket_ts, count) VALUES (?,?)",
            [(float(bucket_ts), int(count)) for bucket_ts, count in rows],
        )
        conn.execute(
            "DELETE FROM counts WHERE rowid IN (SELECT rowid FROM counts"
            " ORDER BY bucket_ts DESC LIMIT -1 OFFSET ?)", (cap,),
        )
    return len(rows)


def load_counts(since_ts: Optional[float] = None) -> list[float]:
    """Bucket counts ordered oldest-first, optionally bounded by an epoch start.
    The order is the series order: the last items are the most recent context,
    with no gap marker. A missing bucket is not interpolated, because a zero is
    an observation and a gap is not.
    """
    with _store() as conn:
        if since_ts is None:
            rows = conn.execute("SELECT count FROM counts ORDER BY bucket_ts").fetchall()
        else:
            rows = conn.execute("SELECT count FROM counts WHERE bucket_ts >= ?"
                                " ORDER BY bucket_ts", (float(since_ts),)).fetchall()
    return [int(row[0]) for row in rows]


def save_model(model_id: str, kind: str, params: dict, startprob: list,
               transmat: list, emissionprob: Optional[list] = None,
               row_support: Optional[list] = None,
               n_sequences: int = 0, n_transitions: int = 0) -> None:
    """Persist one fitted model under its content addressed id.
    The id is derived from the parameters by the caller, so re-training on the
    same corpus replaces the row instead of accumulating duplicates. Models
    beyond the newest ``_MAX_MODELS`` are evicted with their params.
    """
    with _store() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO models (model_id, kind, taxonomy_version, tactics,"
            " params, startprob, transmat, emissionprob, row_support, n_sequences,"
            " n_transitions, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (model_id, kind, TAXONOMY_VERSION, json.dumps(list(TACTIC_ORDER)),
             json.dumps(params, sort_keys=True), json.dumps(list(startprob)),
             json.dumps(list(transmat)),
             None if emissionprob is None else json.dumps(list(emissionprob)),
             None if row_support is None else json.dumps(list(row_support)),
             int(n_sequences), int(n_transitions), time.time()),
        )
        stale = [row[0] for row in conn.execute(
            "SELECT model_id FROM models ORDER BY created_at DESC LIMIT -1 OFFSET ?",
            (_MAX_MODELS,)).fetchall()]
        for old in stale:
            conn.execute("DELETE FROM models WHERE model_id = ?", (old,))


def load_model(model_id: Optional[str] = None) -> Optional[dict]:
    """Return a model, newest when ``model_id`` is omitted, or ``None`` when empty.
    A stored model under a different ``TAXONOMY_VERSION``, a mismatched tactic
    list, or a matrix that fails ``validate_model`` raises: returning it would
    score a live sequence against columns that no longer mean the same thing.
    """
    with _store() as conn:
        if model_id:
            row = conn.execute(
                "SELECT model_id, kind, taxonomy_version, tactics, params, startprob,"
                " transmat, emissionprob, row_support, n_sequences, n_transitions,"
                " created_at FROM models WHERE model_id = ?", (model_id,)).fetchone()
        else:
            row = conn.execute(
                "SELECT model_id, kind, taxonomy_version, tactics, params, startprob,"
                " transmat, emissionprob, row_support, n_sequences, n_transitions,"
                " created_at FROM models ORDER BY created_at DESC LIMIT 1").fetchone()
    if row is None:
        return None
    if row[1] in ("markov", "hmm") and row[2] != TAXONOMY_VERSION:
        raise ForecastStoreError(
            f"Stored model {row[0]} uses taxonomy {row[2]}, this server builds "
            f"{TAXONOMY_VERSION}. Refusing to score a live sequence against a shifted "
            "tactic vocabulary; retrain with blueteam_tactic_forecast."
        )
    model = {
        "model_id": row[0], "kind": row[1], "taxonomy_version": row[2],
        "tactics": json.loads(row[3]), "params": json.loads(row[4] or "{}"),
        "startprob": json.loads(row[5]), "transmat": json.loads(row[6]),
        "emissionprob": None if row[7] is None else json.loads(row[7]),
        "row_support": None if row[8] is None else json.loads(row[8]),
        "n_sequences": int(row[9]), "n_transitions": int(row[10]),
        "created_at": float(row[11]),
    }
    if model["kind"] == VOLUME_KIND:
        model["lambdas"] = model["params"].get("lambdas")
    try:
        validate_model(model)
    except ValueError as exc:
        raise ForecastStoreError(f"Stored model {row[0]} is unusable: {exc}") from exc
    return model


def purge_expired() -> dict:
    """Delete observations older than ``BLUETEAM_FORECAST_RETENTION_DAYS``.
    Models are pruned by the save-time cap, not by age: a model is cheap and a
    corpus is expensive, so dropping the evidence before the parameters would
    only make the next retrain worse.
    """
    days = float(getattr(config.forecast, "retention_days", 365) or 0)
    if days <= 0:
        return {"observations": 0, "cutoff": None}
    cutoff = time.time() - days * 86400.0
    with _store() as conn:
        cursor = conn.execute("DELETE FROM observations WHERE observed_at < ?", (cutoff,))
        removed = cursor.rowcount if cursor.rowcount and cursor.rowcount > 0 else 0
        count_cursor = conn.execute("DELETE FROM counts WHERE bucket_ts < ?", (cutoff,))
        counts_removed = (count_cursor.rowcount
                          if count_cursor.rowcount and count_cursor.rowcount > 0 else 0)
    return {"observations": removed, "counts": counts_removed, "cutoff": cutoff}


def store_stats() -> dict:
    """Counts and path for diagnostics. Never returns entity keys."""
    try:
        with _store() as conn:
            observations = conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
            entities = conn.execute(
                "SELECT COUNT(DISTINCT entity_key) FROM observations").fetchone()[0]
            models = conn.execute("SELECT COUNT(*) FROM models").fetchone()[0]
            counts = conn.execute("SELECT COUNT(*) FROM counts").fetchone()[0]
            oldest = conn.execute("SELECT MIN(observed_at) FROM observations").fetchone()[0]
        return {"observations": int(observations), "entities": int(entities),
                "models": int(models), "counts": int(counts),
                "oldest_observation": None if oldest is None else float(oldest),
                "path": _db_path()}
    except (ForecastStoreError, sqlite3.Error) as exc:
        return {"observations": 0, "entities": 0, "models": 0, "counts": 0,
                "oldest_observation": None, "path": "", "status": f"unavailable: {exc}"}
