#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
SQLite persistence for alert entity clusters (blueteam_alert_cluster).

Stores one fit (HDBSCAN parameters, feature version, centroids, medoids and
per-cluster radii) plus the assignment of every entity that has been scored
against it. Nearest-centroid assignment needs the centroids to outlive the
process; a stateless refit on every call would also make ``noise`` vs
``novel`` meaningless, because the label space changes each run.
Layout follows ``core/rag_store.py``: SQLite opened per call (connections are
thread-bound and calls run inside ``asyncio.to_thread``), WAL, ``0600``, and a
hard refusal to read a fit written under a different ``FEATURE_VERSION`` -
mixing layouts would assign entities to meaningless centroids.
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
from mcp_server.core.cluster_features import FEATURE_VERSION

logger = logging.getLogger("blue_team_mcp.cluster_store")

_MAX_FITS = 50


class ClusterStoreError(BlueTeamMCPError):
    """Cluster store is unconfigured, unreachable, or version-incompatible."""


def _db_path() -> str:
    """Configured store path, or raise. Never returns a default: a cluster
    store written to an unconfigured location is invisible state."""
    cluster = getattr(config, "cluster", None) if config is not None else None
    path = (getattr(cluster, "store_path", "") or "").strip()
    if not path:
        raise ClusterStoreError(
            "Cluster store is not configured. Set BLUETEAM_CLUSTER_STORE to an "
            "absolute path and BLUETEAM_CLUSTER_ENABLED=true, then restart the server."
        )
    return path


def _connect() -> sqlite3.Connection:
    """Open the store, creating the schema on first use. Per-call connection:
    a module-level one is bound to whichever thread created it."""
    path = _db_path()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    fresh = not os.path.exists(path)
    conn = sqlite3.connect(path, timeout=5.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS fits (
            fit_id          TEXT PRIMARY KEY,
            feature_version TEXT NOT NULL,
            params          TEXT NOT NULL,
            window_since    TEXT,
            window_until    TEXT,
            entity_count    INTEGER NOT NULL,
            noise_count     INTEGER NOT NULL,
            created_at      REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS centroids (
            fit_id   TEXT NOT NULL,
            label    INTEGER NOT NULL,
            centroid TEXT NOT NULL,
            medoid   TEXT NOT NULL,
            size     INTEGER NOT NULL,
            radius   REAL NOT NULL,
            PRIMARY KEY (fit_id, label)
        );
        CREATE TABLE IF NOT EXISTS entities (
            entity_key  TEXT NOT NULL,
            fit_id      TEXT NOT NULL,
            label       INTEGER NOT NULL,
            distance    REAL,
            novelty     INTEGER NOT NULL DEFAULT 0,
            assigned_at REAL NOT NULL,
            PRIMARY KEY (entity_key, fit_id)
        );
        CREATE INDEX IF NOT EXISTS idx_entities_assigned ON entities (assigned_at);
        """
    )
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


def save_fit(fit_id: str, params: dict, clusters: list[dict],
             entity_count: int, noise_count: int,
             window: Optional[dict] = None) -> None:
    """Persist one fit and its clusters, replacing any fit with the same id.
    ``clusters`` items: ``{"label", "centroid", "medoid", "size", "radius"}``.
    Vectors are stored as JSON lists - the layout is pinned by
    ``feature_version``, so a binary blob buys nothing.
    """
    window = window or {}
    with _store() as conn:
        conn.execute("DELETE FROM centroids WHERE fit_id = ?", (fit_id,))
        conn.execute(
            "INSERT OR REPLACE INTO fits (fit_id, feature_version, params, window_since,"
            " window_until, entity_count, noise_count, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (fit_id, FEATURE_VERSION, json.dumps(params, sort_keys=True),
             window.get("since"), window.get("until"),
             int(entity_count), int(noise_count), time.time()),
        )
        conn.executemany(
            "INSERT OR REPLACE INTO centroids (fit_id, label, centroid, medoid, size, radius)"
            " VALUES (?,?,?,?,?,?)",
            [(fit_id, int(c["label"]), json.dumps(list(c["centroid"])),
              json.dumps(list(c["medoid"])), int(c["size"]), float(c["radius"]))
             for c in clusters],
        )
        stale = [row[0] for row in conn.execute(
            "SELECT fit_id FROM fits ORDER BY created_at DESC LIMIT -1 OFFSET ?",
            (_MAX_FITS,),
        ).fetchall()]
        for old in stale:
            conn.execute("DELETE FROM fits WHERE fit_id = ?", (old,))
            conn.execute("DELETE FROM centroids WHERE fit_id = ?", (old,))
            conn.execute("DELETE FROM entities WHERE fit_id = ?", (old,))


def load_fit(fit_id: Optional[str] = None) -> Optional[dict]:
    """Return a fit with its clusters, or ``None`` when the store is empty.
    ``fit_id=None`` loads the newest fit. A stored fit written under a different
    ``FEATURE_VERSION`` raises: returning it would silently score entities in
    the wrong space.
    """
    with _store() as conn:
        if fit_id:
            row = conn.execute(
                "SELECT fit_id, feature_version, params, window_since, window_until,"
                " entity_count, noise_count, created_at FROM fits WHERE fit_id = ?",
                (fit_id,),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT fit_id, feature_version, params, window_since, window_until,"
                " entity_count, noise_count, created_at FROM fits ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
        if row is None:
            return None
        if row[1] != FEATURE_VERSION:
            raise ClusterStoreError(
                f"Stored fit {row[0]} uses feature version {row[1]}, this server "
                f"builds {FEATURE_VERSION}. Refusing to assign entities across vector "
                "layouts; refit with blueteam_alert_cluster."
            )
        clusters = [
            {"label": int(c[0]), "centroid": json.loads(c[1]), "medoid": json.loads(c[2]),
             "size": int(c[3]), "radius": float(c[4])}
            for c in conn.execute(
                "SELECT label, centroid, medoid, size, radius FROM centroids"
                " WHERE fit_id = ? ORDER BY label", (row[0],),
            ).fetchall()
        ]
    return {
        "fit_id": row[0], "feature_version": row[1], "params": json.loads(row[2] or "{}"),
        "window": {"since": row[3], "until": row[4]},
        "entity_count": int(row[5]), "noise_count": int(row[6]),
        "created_at": float(row[7]), "clusters": clusters,
    }


def record_assignment(entity_key: str, fit_id: str, label: int,
                      distance: Optional[float], novelty: bool) -> None:
    """Upsert one entity's assignment, then enforce the row cap oldest-first."""
    cap = max(1, int(getattr(config.cluster, "store_max", 20000) or 20000))
    with _store() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO entities (entity_key, fit_id, label, distance,"
            " novelty, assigned_at) VALUES (?,?,?,?,?,?)",
            (entity_key, fit_id, int(label),
             None if distance is None else float(distance), 1 if novelty else 0, time.time()),
        )
        conn.execute(
            "DELETE FROM entities WHERE rowid IN (SELECT rowid FROM entities"
            " ORDER BY assigned_at DESC LIMIT -1 OFFSET ?)", (cap,),
        )


def get_assignment(entity_key: str, fit_id: Optional[str] = None) -> Optional[dict]:
    """Last assignment for an entity, newest first when ``fit_id`` is omitted."""
    with _store() as conn:
        if fit_id:
            row = conn.execute(
                "SELECT fit_id, label, distance, novelty, assigned_at FROM entities"
                " WHERE entity_key = ? AND fit_id = ?", (entity_key, fit_id),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT fit_id, label, distance, novelty, assigned_at FROM entities"
                " WHERE entity_key = ? ORDER BY assigned_at DESC LIMIT 1", (entity_key,),
            ).fetchone()
    if row is None:
        return None
    return {"fit_id": row[0], "label": int(row[1]),
            "distance": None if row[2] is None else float(row[2]),
            "novelty": bool(row[3]), "assigned_at": float(row[4])}


def pending_novelty_count(fit_id: str) -> int:
    """Entities assigned as novel since the fit - the refit trigger. The refit
    itself stays an explicit call: an automatic one would change labels under an
    open investigation."""
    with _store() as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM entities WHERE fit_id = ? AND novelty = 1", (fit_id,),
        ).fetchone()
    return int(row[0] if row else 0)


def purge_expired() -> int:
    """Delete fits older than the configured TTL (0 disables). Returns fit count removed."""
    ttl = float(getattr(config.cluster, "ttl_seconds", 86400) or 0)
    if ttl <= 0:
        return 0
    cutoff = time.time() - ttl
    with _store() as conn:
        stale = [row[0] for row in conn.execute(
            "SELECT fit_id FROM fits WHERE created_at < ?", (cutoff,)).fetchall()]
        for fit_id in stale:
            conn.execute("DELETE FROM fits WHERE fit_id = ?", (fit_id,))
            conn.execute("DELETE FROM centroids WHERE fit_id = ?", (fit_id,))
            conn.execute("DELETE FROM entities WHERE fit_id = ?", (fit_id,))
    return len(stale)


def store_stats() -> dict:
    """Row counts and path, for diagnostics. Never returns entity keys."""
    try:
        with _store() as conn:
            fits = conn.execute("SELECT COUNT(*) FROM fits").fetchone()[0]
            entities = conn.execute("SELECT COUNT(*) FROM entities").fetchone()[0]
        return {"fits": int(fits), "entities": int(entities), "path": _db_path()}
    except (ClusterStoreError, sqlite3.Error) as exc:
        return {"fits": 0, "entities": 0, "path": "", "status": f"unavailable: {exc}"}
