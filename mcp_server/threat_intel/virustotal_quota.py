#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Persistent, cross-process VirusTotal request budget and quota accounting.

The operator creates the state with the `init` command. Normal service startup
only loads and validates an existing state; it never creates one. The state
records the authorized budget, window, rate, and daily limit so every process
shares the same policy, and it keeps request accounting across restarts.
"""
from __future__ import annotations

import argparse
import json
import logging
import math
import os
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("blue_team_mcp.threat_intel.virustotal_quota")

_SCHEMA_VERSION = "2"
_LEGACY_SCHEMA_VERSION = "1"
_POLICY_VERSION = "1"
_PENDING_TTL_SECONDS = 300.0
_RATE_WINDOW_SECONDS = 60.0
_CLOCK_SKEW_SECONDS = 300.0
_RETENTION_MARGIN_SECONDS = 86400.0


class VirusTotalQuotaError(Exception):
    """A local VirusTotal budget, policy, state, or storage refusal."""

    def __init__(self, message: str, kind: str = "budget_closed",
                 retry_after_seconds: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.kind = kind
        self.retry_after_seconds = retry_after_seconds


@dataclass(frozen=True)
class ReservationResult:
    """A reserved request id, or a wait before the next rate slot."""
    reservation_id: int | None = None
    wait_seconds: float = 0.0


def _utc_day_start(now: float) -> float:
    current = datetime.fromtimestamp(now, timezone.utc)
    start = current.replace(hour=0, minute=0, second=0, microsecond=0)
    return start.timestamp()


def _seconds_until_utc_midnight(now: float) -> int:
    current = datetime.fromtimestamp(now, timezone.utc)
    tomorrow = (current + timedelta(days=1)).replace(
        hour=0, minute=0, second=0, microsecond=0)
    return max(1, int((tomorrow - current).total_seconds()) + 1)


def _policy_summary(path: str, state: dict[str, Any], now: float) -> dict[str, Any]:
    return {
        "state": path,
        "budget": state["budget"],
        "window_hours": state["window_hours"],
        "rate_per_minute": state["rate_limit"],
        "daily_limit": state["daily_limit"],
        "armed_at": state["armed_at"],
        "created_at": state["created_at"],
        "timestamp": now,
    }


class VirusTotalQuota:
    """SQLite-backed budget, arm window, policy, daily quota, and rate window."""

    def __init__(self, path: str, *, budget: int, hours: float,
                 rate_per_minute: int, daily_limit: int,
                 clock=time.time) -> None:
        self._path = str(path or "")
        self._budget = int(budget)
        self._hours = float(hours)
        self._rate = int(rate_per_minute)
        self._daily = int(daily_limit)
        self._clock = clock
        if not self._path or not os.path.isabs(self._path):
            raise VirusTotalQuotaError(
                "VirusTotal quota state path must be absolute", "config_invalid")
        if (self._budget < 0 or not math.isfinite(self._hours) or self._hours <= 0
                or self._rate <= 0 or self._daily <= 0):
            raise VirusTotalQuotaError(
                "invalid VirusTotal metering policy", "config_invalid")

    def _now(self, now: float | None) -> float:
        return float(self._clock() if now is None else now)

    def _connect(self) -> sqlite3.Connection:
        if not self._path:
            raise VirusTotalQuotaError(
                "VirusTotal quota state path is empty; set "
                "BLUETEAM_VIRUSTOTAL_STATE to an absolute path",
                "state_missing")
        try:
            conn = sqlite3.connect(self._path, timeout=5.0, isolation_level=None)
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute("PRAGMA journal_mode=WAL")
            return conn
        except (sqlite3.Error, OSError) as exc:
            raise VirusTotalQuotaError(
                "VirusTotal quota state is unavailable", "storage_unavailable") from exc

    def _missing_state_error(self) -> VirusTotalQuotaError:
        """Return the missing-state error with the path and the init command.

        Without them, a path mismatch between the server's
        BLUETEAM_VIRUSTOTAL_STATE and the CLI leaves the operator no next step.
        """
        return VirusTotalQuotaError(
            "VirusTotal quota state is missing at "
            f"{self._path}; run `python -m mcp_server.threat_intel."
            "virustotal_quota init --state "
            f"{self._path} --budget <n> --hours <h> --rate <n> --daily <n>` "
            "with the values from BLUETEAM_VIRUSTOTAL_BUDGET, "
            "BLUETEAM_VIRUSTOTAL_BUDGET_HOURS, "
            "BLUETEAM_VIRUSTOTAL_RATE_PER_MINUTE and "
            "BLUETEAM_VIRUSTOTAL_DAILY",
            "state_missing")

    def _connect_existing(self) -> sqlite3.Connection:
        if not os.path.exists(self._path):
            raise self._missing_state_error()
        self._check_parent()
        return self._connect()

    def _check_parent(self) -> None:
        parent = Path(self._path).parent
        try:
            mode = parent.stat().st_mode
        except OSError as exc:
            raise VirusTotalQuotaError(
                "VirusTotal quota state directory is unavailable",
                "storage_unavailable") from exc
        if mode & 0o022:
            raise VirusTotalQuotaError(
                "VirusTotal quota state directory is group or world writable",
                "storage_unavailable")

    def _secure(self) -> None:
        self._check_parent()
        try:
            os.chmod(self._path, 0o600)
        except OSError as exc:
            raise VirusTotalQuotaError(
                "VirusTotal quota state cannot be secured", "storage_unavailable") from exc

    def _init_schema(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS vt_meta ("
            "key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS vt_requests ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "reserved_at REAL NOT NULL, "
            "status TEXT NOT NULL CHECK(status IN ('pending','committed')))"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS vt_requests_time "
            "ON vt_requests(reserved_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS vt_requests_status_time "
            "ON vt_requests(status, reserved_at)"
        )

    def _tables(self, conn: sqlite3.Connection) -> set[str]:
        try:
            rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        except sqlite3.Error as exc:
            raise VirusTotalQuotaError(
                "VirusTotal quota state is unreadable", "state_corrupt") from exc
        return {str(row[0]) for row in rows}

    def _read_meta(self, conn: sqlite3.Connection) -> dict[str, str]:
        try:
            rows = conn.execute("SELECT key, value FROM vt_meta").fetchall()
        except sqlite3.Error as exc:
            raise VirusTotalQuotaError(
                "VirusTotal quota state is unreadable", "state_corrupt") from exc
        meta = {str(key): str(value) for key, value in rows}
        if meta.get("version") != _SCHEMA_VERSION:
            raise VirusTotalQuotaError(
                "VirusTotal quota state has an unsupported schema", "state_corrupt")
        return meta

    def _read_policy(self, meta: dict[str, str]) -> dict[str, Any]:
        if meta.get("policy_version") != _POLICY_VERSION:
            raise VirusTotalQuotaError(
                "VirusTotal quota state has an unsupported policy", "state_corrupt")
        try:
            budget = int(meta["budget"])
            hours = float(meta["hours"])
            rate = int(meta["rate"])
            daily = int(meta["daily"])
            armed_at = float(meta["armed_at"])
            created_at = float(meta["created_at"])
            budget_since = float(meta.get("budget_since", armed_at))
        except (KeyError, TypeError, ValueError) as exc:
            raise VirusTotalQuotaError(
                "VirusTotal quota state has invalid policy metadata",
                "state_corrupt") from exc
        if (budget <= 0 or not math.isfinite(hours) or hours <= 0
                or rate <= 0 or daily <= 0):
            raise VirusTotalQuotaError(
                "VirusTotal quota state has an invalid policy", "state_corrupt")
        if not math.isfinite(armed_at) or armed_at <= 0:
            raise VirusTotalQuotaError(
                "VirusTotal quota state has an invalid arm timestamp", "state_corrupt")
        if not math.isfinite(created_at) or created_at <= 0:
            raise VirusTotalQuotaError(
                "VirusTotal quota state has an invalid creation timestamp",
                "state_corrupt")
        if not math.isfinite(budget_since) or budget_since <= 0:
            raise VirusTotalQuotaError(
                "VirusTotal quota state has an invalid budget timestamp",
                "state_corrupt")
        return {
            "budget": budget,
            "hours": hours,
            "rate": rate,
            "daily": daily,
            "armed_at": armed_at,
            "created_at": created_at,
            "budget_since": budget_since,
        }

    def _current_policy(self) -> dict[str, Any]:
        return {
            "budget": self._budget,
            "hours": self._hours,
            "rate": self._rate,
            "daily": self._daily,
        }

    def _write_policy(self, conn: sqlite3.Connection, now: float,
                      *, reset_arm: bool, new_state: bool = False) -> None:
        values = {
            "version": _SCHEMA_VERSION,
            "policy_version": _POLICY_VERSION,
            "budget": str(self._budget),
            "hours": str(self._hours),
            "rate": str(self._rate),
            "daily": str(self._daily),
            "cooldown_until": "0" if reset_arm else None,
        }
        if reset_arm:
            values["armed_at"] = str(now)
            values["budget_since"] = str(now)
            if new_state:
                values["created_at"] = str(now)
            values["last_rearmed_at"] = "0"
        for key, value in values.items():
            if value is not None:
                conn.execute(
                    "INSERT OR REPLACE INTO vt_meta(key, value) VALUES(?, ?)",
                    (key, value))

    def initialize(self, now: float | None = None) -> None:
        """Create a new state. Refuse if any state already exists."""
        current = self._now(now)
        if self._budget <= 0:
            raise VirusTotalQuotaError(
                "VirusTotal budget must be positive to initialize", "config_invalid")
        if os.path.exists(self._path):
            raise VirusTotalQuotaError(
                "VirusTotal quota state already exists; use policy or rearm",
                "state_exists")
        try:
            Path(self._path).parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as exc:
            raise VirusTotalQuotaError(
                "VirusTotal quota state directory is unavailable",
                "storage_unavailable") from exc
        self._check_parent()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            self._init_schema(conn)
            self._write_policy(conn, current, reset_arm=True, new_state=True)
            conn.execute("COMMIT")
        except BaseException:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()
        self._secure()

    def update_policy(self, now: float | None = None) -> None:
        """Update the authorized policy without changing accounting or the arm."""
        if self._budget <= 0:
            raise VirusTotalQuotaError(
                "VirusTotal budget must be positive", "config_invalid")
        self._check_parent()
        conn = self._connect_existing()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                if not {"vt_meta", "vt_requests"} <= self._tables(conn):
                    raise VirusTotalQuotaError(
                        "VirusTotal quota state is missing", "state_missing")
                meta = self._read_meta(conn)
                self._read_policy(meta)
                self._write_policy(conn, self._now(now), reset_arm=False)
                conn.execute("COMMIT")
            except BaseException:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
        except sqlite3.Error as exc:
            raise VirusTotalQuotaError(
                "VirusTotal quota state is unavailable", "storage_unavailable") from exc
        finally:
            conn.close()
        self._secure()

    def rearm(self, now: float | None = None) -> None:
        """Start a new arm window, update policy, and keep stored rows."""
        if self._budget <= 0:
            raise VirusTotalQuotaError(
                "VirusTotal budget must be positive", "config_invalid")
        current = self._now(now)
        self._check_parent()
        conn = self._connect_existing()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                if not {"vt_meta", "vt_requests"} <= self._tables(conn):
                    raise VirusTotalQuotaError(
                        "VirusTotal quota state is missing", "state_missing")
                meta = self._read_meta(conn)
                self._read_policy(meta)
                self._write_policy(conn, current, reset_arm=True)
                conn.execute(
                    "INSERT OR REPLACE INTO vt_meta(key, value) VALUES(?, ?)",
                    ("last_rearmed_at", str(current)))
                conn.execute("COMMIT")
            except BaseException:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
        except sqlite3.Error as exc:
            raise VirusTotalQuotaError(
                "VirusTotal quota state is unavailable", "storage_unavailable") from exc
        finally:
            conn.close()
        self._secure()

    def _open(self, now: float, *, check_budget: bool = True,
              check_arm: bool = True, check_cooldown: bool = True,
              check_policy: bool = True) -> sqlite3.Connection:
        if check_budget and self._budget <= 0:
            raise VirusTotalQuotaError(
                "VirusTotal budget is closed at 0 requests", "budget_closed")
        if not os.path.exists(self._path):
            raise self._missing_state_error()
        conn = self._connect()
        try:
            tables = self._tables(conn)
            if not {"vt_meta", "vt_requests"} <= tables:
                raise VirusTotalQuotaError(
                    "VirusTotal quota state is inconsistent", "state_corrupt")
            meta = self._read_meta(conn)
            policy = self._read_policy(meta)
            if check_policy:
                current = self._current_policy()
                stored = {key: policy[key] for key in current}
                if stored != current:
                    raise VirusTotalQuotaError(
                        "VirusTotal metering policy changed; run the policy or rearm command",
                        "policy_mismatch")
            armed_at = policy["armed_at"]
            created_at = policy["created_at"]
            budget_since = policy["budget_since"]
            if armed_at > now + _CLOCK_SKEW_SECONDS:
                raise VirusTotalQuotaError(
                    "VirusTotal arm timestamp is in the future", "state_corrupt")
            if created_at > now + _CLOCK_SKEW_SECONDS or created_at > armed_at + _CLOCK_SKEW_SECONDS:
                raise VirusTotalQuotaError(
                    "VirusTotal creation timestamp is inconsistent", "state_corrupt")
            if budget_since > now + _CLOCK_SKEW_SECONDS:
                raise VirusTotalQuotaError(
                    "VirusTotal budget timestamp is in the future", "state_corrupt")
            try:
                cooldown = float(meta.get("cooldown_until", "0") or "0")
            except (TypeError, ValueError) as exc:
                raise VirusTotalQuotaError(
                    "VirusTotal quota state has an invalid cooldown",
                    "state_corrupt") from exc
            if not math.isfinite(cooldown) or cooldown < 0:
                raise VirusTotalQuotaError(
                    "VirusTotal quota state has an invalid cooldown",
                    "state_corrupt")
            if check_arm and now - armed_at > policy["hours"] * 3600:
                raise VirusTotalQuotaError(
                    "VirusTotal arm window has expired; run the rearm command",
                    "arm_expired")
            if check_cooldown and cooldown > now:
                raise VirusTotalQuotaError(
                    "VirusTotal rate limit cooldown is active", "cooldown",
                    max(1, int(cooldown - now) + 1))
            self._secure()
            return conn
        except BaseException:
            conn.close()
            raise

    def adopt_legacy(self, now: float | None = None) -> dict[str, Any]:
        """Adopt a schema-1 state, preserving rows and current-day accounting.

        The caller supplies the new policy through the constructor. The old
        ``armed_at`` is retained as ``legacy_armed_at``; the new arm starts now,
        and ``budget_since`` starts at the current UTC day so already-consumed
        same-day quota is not handed back.
        """
        current = self._now(now)
        if self._budget <= 0:
            raise VirusTotalQuotaError(
                "VirusTotal migration requires a positive budget", "config_invalid")
        if not os.path.exists(self._path):
            raise VirusTotalQuotaError(
                "VirusTotal quota state is missing; use init for a new deployment",
                "state_missing")
        self._check_parent()
        conn = self._connect_existing()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                if not {"vt_meta", "vt_requests"} <= self._tables(conn):
                    raise VirusTotalQuotaError(
                        "VirusTotal legacy state is incomplete", "state_corrupt")
                meta = {str(key): str(value) for key, value in
                        conn.execute("SELECT key, value FROM vt_meta").fetchall()}
                version = meta.get("version")
                if version == _SCHEMA_VERSION:
                    raise VirusTotalQuotaError(
                        "VirusTotal state is already current; use policy or rearm",
                        "state_exists")
                if version != _LEGACY_SCHEMA_VERSION:
                    raise VirusTotalQuotaError(
                        "VirusTotal legacy state has an unsupported version",
                        "state_corrupt")
                try:
                    legacy_armed = float(meta["armed_at"])
                    cooldown = float(meta.get("cooldown_until", "0") or "0")
                except (KeyError, TypeError, ValueError) as exc:
                    raise VirusTotalQuotaError(
                        "VirusTotal legacy state has invalid timestamps",
                        "state_corrupt") from exc
                if (not math.isfinite(legacy_armed) or legacy_armed <= 0
                        or legacy_armed > current + _CLOCK_SKEW_SECONDS):
                    raise VirusTotalQuotaError(
                        "VirusTotal legacy arm timestamp is invalid",
                        "state_corrupt")
                if not math.isfinite(cooldown) or cooldown < 0:
                    raise VirusTotalQuotaError(
                        "VirusTotal legacy cooldown is invalid", "state_corrupt")
                columns = {str(row[1]) for row in
                           conn.execute("PRAGMA table_info(vt_requests)").fetchall()}
                if not {"reserved_at", "status"} <= columns:
                    raise VirusTotalQuotaError(
                        "VirusTotal legacy request table is incomplete",
                        "state_corrupt")
                rows = conn.execute(
                    "SELECT id, reserved_at, status FROM vt_requests").fetchall()
                for _, reserved_at, status in rows:
                    try:
                        timestamp = float(reserved_at)
                    except (TypeError, ValueError) as exc:
                        raise VirusTotalQuotaError(
                            "VirusTotal legacy request timestamp is invalid",
                            "state_corrupt") from exc
                    if (not math.isfinite(timestamp) or timestamp <= 0
                            or timestamp > current + _CLOCK_SKEW_SECONDS):
                        raise VirusTotalQuotaError(
                            "VirusTotal legacy request timestamp is invalid",
                            "state_corrupt")
                    if status not in ("pending", "committed"):
                        raise VirusTotalQuotaError(
                            "VirusTotal legacy request status is invalid",
                            "state_corrupt")
                stale = current - _PENDING_TTL_SECONDS
                cursor = conn.execute(
                    "UPDATE vt_requests SET status='committed' "
                    "WHERE status='pending' AND reserved_at < ?", (stale,))
                stale_promoted = int(cursor.rowcount or 0)
                counts = {str(status): int(count) for status, count in
                          conn.execute(
                              "SELECT status, COUNT(*) FROM vt_requests "
                              "GROUP BY status").fetchall()}
                budget_since = _utc_day_start(current)
                values = {
                    "version": _SCHEMA_VERSION,
                    "policy_version": _POLICY_VERSION,
                    "budget": str(self._budget),
                    "hours": str(self._hours),
                    "rate": str(self._rate),
                    "daily": str(self._daily),
                    "armed_at": str(current),
                    "created_at": str(current),
                    "budget_since": str(budget_since),
                    "legacy_armed_at": str(legacy_armed),
                    "last_rearmed_at": "0",
                    "cooldown_until": str(cooldown),
                }
                for key, value in values.items():
                    conn.execute(
                        "INSERT OR REPLACE INTO vt_meta(key, value) VALUES(?, ?)",
                        (key, value))
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS vt_requests_status_time "
                    "ON vt_requests(status, reserved_at)")
                conn.execute("COMMIT")
                self._secure()
                return {
                    "state": self._path,
                    "committed": counts.get("committed", 0),
                    "pending": counts.get("pending", 0),
                    "stale_promoted": stale_promoted,
                    "legacy_armed_at": legacy_armed,
                    "cooldown_until": cooldown,
                    "budget_since": budget_since,
                }
            except BaseException:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
        except sqlite3.Error as exc:
            raise VirusTotalQuotaError(
                "VirusTotal legacy state is unavailable", "storage_unavailable") from exc
        finally:
            conn.close()

    def _prune_locked(self, conn: sqlite3.Connection, now: float,
                      policy: dict[str, Any]) -> int:
        stale = now - _PENDING_TTL_SECONDS
        conn.execute(
            "UPDATE vt_requests SET status='committed' "
            "WHERE status='pending' AND reserved_at < ?", (stale,))
        cutoff = now - (max(policy["hours"] * 3600, 86400.0)
                        + _RETENTION_MARGIN_SECONDS)
        cursor = conn.execute(
            "DELETE FROM vt_requests WHERE status='committed' AND reserved_at < ?",
            (cutoff,))
        return int(cursor.rowcount or 0)

    def reserve(self, now: float | None = None) -> ReservationResult:
        """Reserve one request, or return the wait until a rate slot opens."""
        current = self._now(now)
        conn = self._open(current)
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                meta = self._read_meta(conn)
                policy = self._read_policy(meta)
                self._prune_locked(conn, current, policy)
                armed_at = policy["armed_at"]
                if current - armed_at > policy["hours"] * 3600:
                    raise VirusTotalQuotaError(
                        "VirusTotal arm window has expired; run the rearm command",
                        "arm_expired")
                local_spent = conn.execute(
                    "SELECT COUNT(*) FROM vt_requests "
                    "WHERE status IN ('pending','committed') AND reserved_at >= ?",
                    (policy["budget_since"],)).fetchone()[0]
                if local_spent >= policy["budget"]:
                    raise VirusTotalQuotaError(
                        f"VirusTotal budget exhausted: {local_spent}/{policy['budget']} "
                        "requests used in this arm window", "budget_exhausted")
                daily_start = _utc_day_start(current)
                daily_spent = conn.execute(
                    "SELECT COUNT(*) FROM vt_requests "
                    "WHERE status IN ('pending','committed') AND reserved_at >= ?",
                    (daily_start,)).fetchone()[0]
                if daily_spent >= policy["daily"]:
                    raise VirusTotalQuotaError(
                        f"VirusTotal daily provider limit reached: "
                        f"{daily_spent}/{policy['daily']} requests today",
                        "daily_exhausted",
                        _seconds_until_utc_midnight(current))
                rate_start = current - _RATE_WINDOW_SECONDS
                rate_count, oldest = conn.execute(
                    "SELECT COUNT(*), MIN(reserved_at) FROM vt_requests "
                    "WHERE status IN ('pending','committed') AND reserved_at >= ?",
                    (rate_start,)).fetchone()
                if rate_count >= policy["rate"]:
                    wait = max(1e-6, _RATE_WINDOW_SECONDS - (current - oldest) + 1e-6)
                    conn.execute("COMMIT")
                    return ReservationResult(wait_seconds=wait)
                cursor = conn.execute(
                    "INSERT INTO vt_requests(reserved_at, status) VALUES(?, 'pending')",
                    (current,))
                conn.execute("COMMIT")
                return ReservationResult(reservation_id=int(cursor.lastrowid))
            except BaseException:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
        except sqlite3.Error as exc:
            raise VirusTotalQuotaError(
                "VirusTotal quota state is unavailable", "storage_unavailable") from exc
        finally:
            conn.close()

    def prune(self, now: float | None = None) -> int:
        """Prune old committed rows without changing active accounting."""
        current = self._now(now)
        conn = self._open(current, check_budget=False, check_arm=False,
                          check_cooldown=False, check_policy=False)
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                meta = self._read_meta(conn)
                policy = self._read_policy(meta)
                removed = self._prune_locked(conn, current, policy)
                conn.execute("COMMIT")
                return removed
            except BaseException:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
        except sqlite3.Error as exc:
            raise VirusTotalQuotaError(
                "VirusTotal quota state is unavailable", "storage_unavailable") from exc
        finally:
            conn.close()

    def finalize(self, reservation_id: int, *, consumed: bool) -> None:
        """Mark one reservation committed or delete it; idempotent."""
        conn = self._connect_existing()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                if consumed:
                    conn.execute(
                        "UPDATE vt_requests SET status='committed' "
                        "WHERE id=? AND status='pending'", (int(reservation_id),))
                else:
                    conn.execute(
                        "DELETE FROM vt_requests WHERE id=? AND status='pending'",
                        (int(reservation_id),))
                conn.execute("COMMIT")
            except BaseException:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
        except sqlite3.Error as exc:
            raise VirusTotalQuotaError(
                "VirusTotal quota state is unavailable", "storage_unavailable") from exc
        finally:
            conn.close()

    def set_cooldown(self, seconds: int, now: float | None = None) -> None:
        """Record a 429 cooldown so another process honors it too."""
        current = self._now(now)
        until = current + max(0, int(seconds))
        conn = self._connect_existing()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                meta = self._read_meta(conn)
                self._read_policy(meta)
                previous = float(meta.get("cooldown_until", "0") or "0")
                conn.execute(
                    "INSERT OR REPLACE INTO vt_meta(key, value) VALUES(?, ?)",
                    ("cooldown_until", str(max(previous, until))))
                conn.execute("COMMIT")
            except BaseException:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
        except sqlite3.Error as exc:
            raise VirusTotalQuotaError(
                "VirusTotal quota state is unavailable", "storage_unavailable") from exc
        finally:
            conn.close()

    def state(self, now: float | None = None) -> dict[str, Any]:
        """Operational view; includes pending reservations as reserved capacity."""
        current = self._now(now)
        conn = self._open(current, check_budget=False, check_arm=False,
                          check_cooldown=False)
        try:
            meta = self._read_meta(conn)
            policy = self._read_policy(meta)
            rows = conn.execute(
                "SELECT status, COUNT(*) FROM vt_requests "
                "WHERE reserved_at >= ? GROUP BY status",
                (policy["budget_since"],)).fetchall()
            counts = {str(status): int(count) for status, count in rows}
            pending = counts.get("pending", 0)
            committed = counts.get("committed", 0)
            daily_start = _utc_day_start(current)
            daily_spent = conn.execute(
                "SELECT COUNT(*) FROM vt_requests "
                "WHERE status IN ('pending','committed') AND reserved_at >= ?",
                (daily_start,)).fetchone()[0]
            rate_spent = conn.execute(
                "SELECT COUNT(*) FROM vt_requests "
                "WHERE status IN ('pending','committed') AND reserved_at >= ?",
                (current - _RATE_WINDOW_SECONDS,)).fetchone()[0]
            return {
                "budget": policy["budget"],
                "spent": pending + committed,
                "committed": committed,
                "pending": pending,
                "remaining": max(0, policy["budget"] - pending - committed),
                "armed_at": policy["armed_at"],
                "created_at": policy["created_at"],
                "budget_since": policy["budget_since"],
                "window_hours": policy["hours"],
                "window_open": (current - policy["armed_at"]
                                <= policy["hours"] * 3600),
                "daily_limit": policy["daily"],
                "daily_spent": daily_spent,
                "rate_limit": policy["rate"],
                "rate_spent": rate_spent,
                "state_path": self._path,
            }
        finally:
            conn.close()


def _quota_from_args(args) -> VirusTotalQuota:
    return VirusTotalQuota(
        args.state, budget=args.budget, hours=args.hours,
        rate_per_minute=args.rate, daily_limit=args.daily)


def _add_policy_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--state", default=os.environ.get("BLUETEAM_VIRUSTOTAL_STATE", ""),
                        help="absolute path to the SQLite quota state")
    parser.add_argument("--budget", type=int,
                        default=int(os.environ.get("BLUETEAM_VIRUSTOTAL_BUDGET", "0")),
                        help="authorized request budget for the window")
    parser.add_argument("--hours", type=float,
                        default=float(os.environ.get("BLUETEAM_VIRUSTOTAL_BUDGET_HOURS", "8")),
                        help="arm-window duration in hours")
    parser.add_argument("--rate", type=int,
                        default=int(os.environ.get("VIRUSTOTAL_RATE_PER_MINUTE", "4")),
                        help="provider requests per rolling minute")
    parser.add_argument("--daily", type=int,
                        default=int(os.environ.get("VIRUSTOTAL_DAILY_LIMIT", "500")),
                        help="provider requests per UTC day")


def main(argv: list[str] | None = None) -> int:
    """Operator CLI. It never prints or writes the API key."""
    parser = argparse.ArgumentParser(description="VirusTotal quota state administration")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("init", "create a new state and start the first arm window"),
        ("policy", "update the stored policy without changing accounting or the arm"),
        ("rearm", "start a new arm window, keep stored rows"),
        ("migrate", "adopt a schema-1 state with the supplied policy"),
        ("prune", "remove committed rows older than the retention window"),
    ):
        command = sub.add_parser(name, help=help_text)
        _add_policy_args(command)
        if name == "migrate":
            command.add_argument(
                "--confirm", action="store_true",
                help="confirm adoption of the legacy state")
    args = parser.parse_args(argv)
    try:
        quota = _quota_from_args(args)
        if args.command == "init":
            quota.initialize()
        elif args.command == "policy":
            quota.update_policy()
        elif args.command == "rearm":
            quota.rearm()
        elif args.command == "migrate":
            if not args.confirm:
                print(json.dumps({
                    "error": "confirmation_required",
                    "detail": "rerun migrate with --confirm to adopt the legacy state",
                }))
                return 2
            print(json.dumps(quota.adopt_legacy()))
            return 0
        else:
            removed = quota.prune()
            print(json.dumps({"pruned": removed}))
            return 0
        print(json.dumps(_policy_summary(
            args.state, quota.state(), time.time())))
        return 0
    except VirusTotalQuotaError as exc:
        print(json.dumps({"error": exc.kind, "detail": exc.message}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
