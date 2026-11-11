#!/usr/bin/env python3
"""Persistent VirusTotal budget, policy, recovery, retention, and URL tests.

No live VirusTotal or Wazuh request is made. SQLite state uses temporary paths.
"""
from __future__ import annotations

import multiprocessing
import os
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import pytest

from mcp_server.core.config import ThreatIntelConfig
from mcp_server.core.exceptions import ConfigurationError
from mcp_server.core.url_policy import validate_https_base_url
from mcp_server.threat_intel.virustotal_quota import (VirusTotalQuota,
                                                      VirusTotalQuotaError, main)


def _quota(path, budget=5, hours=8.0, rate=4, daily=500):
    return VirusTotalQuota(str(path), budget=budget, hours=hours,
                           rate_per_minute=rate, daily_limit=daily)


def _init(path, **kwargs):
    quota = _quota(path, **kwargs)
    quota.initialize(1000.0)
    return quota


def _set_meta(path, key, value):
    conn = sqlite3.connect(str(path))
    try:
        conn.execute("UPDATE vt_meta SET value=? WHERE key=?", (str(value), key))
        conn.commit()
    finally:
        conn.close()


def _row_counts(path):
    conn = sqlite3.connect(str(path))
    try:
        rows = conn.execute(
            "SELECT status, COUNT(*) FROM vt_requests GROUP BY status").fetchall()
        return {status: count for status, count in rows}
    finally:
        conn.close()


def _reserve_worker(path, now, barrier, output):
    quota = _quota(path, budget=4, rate=100, daily=100)
    barrier.wait()
    try:
        reservation = quota.reserve(now)
        if reservation.reservation_id is None:
            output.put(0)
            return
        quota.finalize(reservation.reservation_id, consumed=True)
        output.put(1)
    except VirusTotalQuotaError:
        output.put(0)


def _conflict_worker(path, now, output):
    quota = _quota(path, budget=4, rate=100, daily=100)
    try:
        quota.reserve(now)
        output.put(1)
    except VirusTotalQuotaError:
        output.put(0)


def test_default_budget_is_zero(tmp_path):
    assert ThreatIntelConfig().virustotal_budget == 0
    quota = _quota(tmp_path / "vt.db", budget=0)
    with pytest.raises(VirusTotalQuotaError) as error:
        quota.reserve(1000.0)
    assert error.value.kind == "budget_closed"
    assert not (tmp_path / "vt.db").exists()


def test_missing_state_fails_closed(tmp_path):
    quota = _quota(tmp_path / "vt.db")
    with pytest.raises(VirusTotalQuotaError) as error:
        quota.reserve(1000.0)
    assert error.value.kind == "state_missing"
    assert not (tmp_path / "vt.db").exists()


def test_initialize_is_the_only_creation_path(tmp_path):
    path = tmp_path / "vt.db"
    quota = _quota(path, budget=0)
    with pytest.raises(VirusTotalQuotaError) as error:
        quota.initialize(1000.0)
    assert error.value.kind == "config_invalid"
    assert not path.exists()

    quota = _quota(path)
    quota.initialize(1000.0)
    with pytest.raises(VirusTotalQuotaError) as error:
        quota.initialize(1001.0)
    assert error.value.kind == "state_exists"


def test_existing_state_loads_without_creation(tmp_path):
    path = tmp_path / "vt.db"
    _init(path)
    after_restart = _quota(path)
    reservation = after_restart.reserve(1000.0)
    assert reservation.reservation_id is not None
    after_restart.finalize(reservation.reservation_id, consumed=True)


def test_arm_window_expiry(tmp_path):
    quota = _init(tmp_path / "vt.db", hours=1.0)
    reservation = quota.reserve(1000.0)
    quota.finalize(reservation.reservation_id, consumed=True)
    assert quota.state(1001.0)["spent"] == 1
    with pytest.raises(VirusTotalQuotaError) as error:
        quota.reserve(1000.0 + 3600.0 + 1.0)
    assert error.value.kind == "arm_expired"


def test_rearm_starts_a_new_window_without_deleting_rows(tmp_path):
    path = tmp_path / "vt.db"
    quota = _init(path, hours=1.0)
    reservation = quota.reserve(1000.0)
    quota.finalize(reservation.reservation_id, consumed=True)
    with pytest.raises(VirusTotalQuotaError):
        quota.reserve(1000.0 + 3601.0)
    quota.rearm(1000.0 + 3601.0)
    assert quota.state(1000.0 + 3601.0)["window_open"] is True
    assert quota.state(1000.0 + 3601.0)["spent"] == 0


def test_state_survives_restart_and_exhausts(tmp_path):
    path = tmp_path / "vt.db"
    first = _init(path, budget=2)
    reservation = first.reserve(1000.0)
    first.finalize(reservation.reservation_id, consumed=True)

    second = _quota(path, budget=2)
    assert second.state(1000.0)["spent"] == 1
    reservation = second.reserve(1000.0)
    second.finalize(reservation.reservation_id, consumed=True)

    third = _quota(path, budget=2)
    with pytest.raises(VirusTotalQuotaError) as error:
        third.reserve(1000.0)
    assert error.value.kind == "budget_exhausted"


def test_policy_mismatch_fails_closed_and_policy_update_is_explicit(tmp_path):
    path = tmp_path / "vt.db"
    _init(path, budget=5)
    changed = _quota(path, budget=6)
    with pytest.raises(VirusTotalQuotaError) as error:
        changed.reserve(1000.0)
    assert error.value.kind == "policy_mismatch"
    changed.update_policy(1000.0)
    reservation = changed.reserve(1000.0)
    changed.finalize(reservation.reservation_id, consumed=True)
    assert changed.state(1000.0)["budget"] == 6


@pytest.mark.parametrize("field,value", [
    ("hours", 9.0),
    ("rate", 2),
    ("daily", 2),
])
def test_other_policy_changes_fail_closed(tmp_path, field, value):
    path = tmp_path / "vt.db"
    _init(path)
    changed = _quota(path, **{field: value})
    with pytest.raises(VirusTotalQuotaError) as error:
        changed.reserve(1000.0)
    assert error.value.kind == "policy_mismatch"
    changed.update_policy(1000.0)
    changed.state(1000.0)


def test_daily_limit_resets_only_at_utc_midnight(tmp_path):
    quota = _init(tmp_path / "vt.db", budget=10, hours=48, daily=1)
    reservation = quota.reserve(1000.0)
    quota.finalize(reservation.reservation_id, consumed=True)
    with pytest.raises(VirusTotalQuotaError) as error:
        quota.reserve(1001.0)
    assert error.value.kind == "daily_exhausted"
    reservation = quota.reserve(1000.0 + 86400.0)
    quota.finalize(reservation.reservation_id, consumed=True)


def test_rate_window_blocks_the_fifth_at_the_exact_boundary(tmp_path):
    quota = _init(tmp_path / "vt.db", budget=10, hours=48, rate=4, daily=10)
    for timestamp in (1000.0, 1015.0, 1030.0, 1045.0):
        reservation = quota.reserve(timestamp)
        assert reservation.reservation_id is not None
        quota.finalize(reservation.reservation_id, consumed=True)
    blocked = quota.reserve(1060.0)
    assert blocked.reservation_id is None
    assert blocked.wait_seconds > 0
    allowed = quota.reserve(1060.000001)
    assert allowed.reservation_id is not None


def test_finalize_is_idempotent(tmp_path):
    quota = _init(tmp_path / "vt.db")
    reservation = quota.reserve(1000.0)
    quota.finalize(reservation.reservation_id, consumed=True)
    quota.finalize(reservation.reservation_id, consumed=True)
    quota.finalize(reservation.reservation_id, consumed=False)
    assert quota.state(1000.0)["spent"] == 1


def test_threaded_reservations_cannot_exceed_daily_limit(tmp_path):
    quota = _init(tmp_path / "vt.db", budget=10, daily=2, rate=100)

    def reserve(_):
        try:
            return quota.reserve(1000.0).reservation_id
        except VirusTotalQuotaError:
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(reserve, range(8)))
    assert sum(1 for value in results if value is not None) == 2


def test_threaded_reservations_cannot_exceed_budget(tmp_path):
    quota = _init(tmp_path / "vt.db", budget=4, rate=100)

    def reserve(_):
        try:
            return quota.reserve(1000.0).reservation_id
        except VirusTotalQuotaError:
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(reserve, range(8)))
    assert sum(1 for value in results if value is not None) == 4


def test_processes_share_one_budget(tmp_path):
    path = str(tmp_path / "vt.db")
    parent = _init(path, budget=4, rate=100, daily=100)
    ctx = multiprocessing.get_context("fork")
    barrier = ctx.Barrier(8)
    output = ctx.Queue()
    processes = [ctx.Process(target=_reserve_worker,
                             args=(path, 1000.0, barrier, output))
                 for _ in range(8)]
    for process in processes:
        process.start()
    for process in processes:
        process.join(10)
    values = [output.get(timeout=2) for _ in processes]
    assert sum(values) == 4


def test_conflicting_process_policy_fails_closed(tmp_path):
    path = str(tmp_path / "vt.db")
    _init(path, budget=5, rate=100, daily=100)
    ctx = multiprocessing.get_context("fork")
    output = ctx.Queue()
    process = ctx.Process(target=_conflict_worker, args=(path, 1000.0, output))
    process.start()
    process.join(10)
    assert output.get(timeout=2) == 0


def test_corrupt_state_fails_closed(tmp_path):
    path = tmp_path / "vt.db"
    path.write_bytes(b"not a sqlite database")
    quota = _quota(path)
    with pytest.raises(VirusTotalQuotaError) as error:
        quota.reserve(1000.0)
    assert error.value.kind in ("state_corrupt", "storage_unavailable")


def test_unavailable_storage_fails_closed(tmp_path):
    path = tmp_path / "state-dir"
    path.mkdir()
    quota = _quota(path)
    with pytest.raises(VirusTotalQuotaError) as error:
        quota.reserve(1000.0)
    assert error.value.kind == "storage_unavailable"


@pytest.mark.parametrize("field,value", [
    ("virustotal_budget", -1),
    ("virustotal_budget_hours", 0),
    ("virustotal_rate_per_minute", 0),
    ("virustotal_daily_limit", 0),
    ("virustotal_max_response_bytes", 0),
    ("virustotal_state_path", "relative.db"),
    ("virustotal_budget_hours", float("nan")),
    ("virustotal_base_url", "http://www.virustotal.com/api/v3"),
    ("virustotal_base_url", "https://evil.example/api/v3"),
    ("virustotal_base_url", "https://127.0.0.1/api/v3"),
    ("virustotal_base_url", "https://127.0.0.1./api/v3"),
    ("virustotal_base_url", "https://user@www.virustotal.com/api/v3"),
    ("virustotal_base_url", "https://www.virustotal.com:8443/api/v3"),
    ("virustotal_base_url", "https://[bad/api/v3"),
])
def test_invalid_virustotal_configuration(field, value):
    config = ThreatIntelConfig(**{field: value})
    with pytest.raises(ConfigurationError):
        config.validate()


def test_nan_window_is_rejected(tmp_path):
    with pytest.raises(VirusTotalQuotaError) as error:
        _quota(tmp_path / "vt.db", hours=float("nan"))
    assert error.value.kind == "config_invalid"


@pytest.mark.parametrize("armed_at", [0, -1, 1400])
def test_invalid_arm_timestamps_fail_closed(tmp_path, armed_at):
    path = tmp_path / "vt.db"
    _init(path)
    _set_meta(path, "armed_at", armed_at)
    quota = _quota(path)
    with pytest.raises(VirusTotalQuotaError) as error:
        quota.reserve(1000.0)
    assert error.value.kind == "state_corrupt"


def test_small_clock_skew_is_allowed(tmp_path):
    path = tmp_path / "vt.db"
    _init(path)
    _set_meta(path, "armed_at", 1100.0)
    quota = _quota(path)
    reservation = quota.reserve(1000.0)
    assert reservation.reservation_id is not None


@pytest.mark.parametrize("url", [
    "http://www.virustotal.com/api/v3",
    "https://evil.example/api/v3",
    "https://127.0.0.1/api/v3",
    "https://user@www.virustotal.com/api/v3",
    "https://www.virustotal.com:8443/api/v3",
    "https://www.virustotal.com/api/v3?x=1",
    "https://www.virustotal.com/not-v3",
    "https://www.virustotal.com.evil/api/v3",
    "https://[bad/api/v3",
    "https://www.virustotal.com:bad/api/v3",
])
def test_base_url_policy_rejects_invalid_shapes(url):
    with pytest.raises(ValueError):
        validate_https_base_url(url, "www.virustotal.com")


def test_base_url_policy_accepts_authorized_host():
    assert validate_https_base_url(
        "https://vt.internal/api/v3/", "www.virustotal.com,vt.internal"
    ) == "https://vt.internal/api/v3"


def test_retention_keeps_current_rows_and_prunes_old_committed(tmp_path):
    path = tmp_path / "vt.db"
    quota = _init(path, budget=10, hours=2)
    first = quota.reserve(1000.0)
    quota.finalize(first.reservation_id, consumed=True)
    quota.prune(1000.0 + 3600.0)
    assert _row_counts(path).get("committed") == 1

    retention = max(2 * 3600.0, 86400.0) + 86400.0
    quota.prune(1000.0 + retention + 1.0)
    assert _row_counts(path).get("committed") is None


def test_retention_never_deletes_a_recent_pending_row(tmp_path):
    path = tmp_path / "vt.db"
    quota = _init(path, budget=10)
    quota.reserve(1000.0)
    quota.prune(1001.0)
    assert _row_counts(path).get("pending") == 1


def test_retention_and_reservations_remain_correct_together(tmp_path):
    path = tmp_path / "vt.db"
    quota = _init(path, budget=20, rate=100, daily=100)

    def reserve(_):
        try:
            result = quota.reserve(1000.0)
            if result.reservation_id is not None:
                quota.finalize(result.reservation_id, consumed=True)
            return True
        except VirusTotalQuotaError:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        reservations = list(pool.map(reserve, range(8)))
    quota.prune(1000.0)
    assert all(reservations)
    assert quota.state(1000.0)["committed"] == 8


def test_cli_init_policy_rearm_and_prune(tmp_path, capsys):
    path = str(tmp_path / "vt.db")
    base = ["--state", path, "--budget", "5", "--hours", "8",
            "--rate", "4", "--daily", "500"]
    assert main(["init", *base]) == 0
    assert main(["init", *base]) == 2
    assert main(["policy", *base[:2], "--budget", "6", "--hours", "8",
                 "--rate", "4", "--daily", "500"]) == 0
    assert _quota(path, budget=6).state(time.time())["budget"] == 6
    assert main(["rearm", *base[:2], "--budget", "6", "--hours", "8",
                 "--rate", "4", "--daily", "500"]) == 0
    assert main(["prune", *base[:2], "--budget", "6", "--hours", "8",
                 "--rate", "4", "--daily", "500"]) == 0
    assert "pruned" in capsys.readouterr().out


def test_deleted_state_fails_closed_and_requires_explicit_recovery(tmp_path):
    path = tmp_path / "vt.db"
    _init(path)
    path.unlink()
    with pytest.raises(VirusTotalQuotaError) as error:
        _quota(path).reserve(1000.0)
    assert error.value.kind == "state_missing"
    # The message must name the file and command, otherwise a path mismatch
    # between the server and the CLI reads as an unbreakable loop.
    assert str(path) in error.value.message
    assert "virustotal_quota init --state" in error.value.message
    assert not path.exists()
    # A marker now survives the deleted file, so recreating is an explicit act.
    with pytest.raises(VirusTotalQuotaError) as again:
        _quota(path).initialize(1000.0)
    assert again.value.kind == "state_missing"
    _quota(path).initialize(1000.0, force=True)
    assert path.exists()


def test_moved_state_is_not_recreated_at_the_old_path(tmp_path):
    path = tmp_path / "vt.db"
    moved = tmp_path / "moved.db"
    _init(path)
    path.rename(moved)
    with pytest.raises(VirusTotalQuotaError) as error:
        _quota(path).reserve(1000.0)
    assert error.value.kind == "state_missing"
    assert not path.exists()
    _quota(moved).state(1000.0)


def test_legacy_arm_environment_does_not_create_state(tmp_path, monkeypatch):
    monkeypatch.setenv("BLUETEAM_VIRUSTOTAL_ARM", "true")
    path = tmp_path / "vt.db"
    with pytest.raises(VirusTotalQuotaError) as error:
        _quota(path).reserve(1000.0)
    assert error.value.kind == "state_missing"
    assert not path.exists()


def test_policy_update_preserves_existing_accounting(tmp_path):
    path = tmp_path / "vt.db"
    first = _init(path, budget=5)
    reservation = first.reserve(1000.0)
    first.finalize(reservation.reservation_id, consumed=True)
    changed = _quota(path, budget=6)
    changed.update_policy(1000.0)
    assert changed.state(1000.0)["spent"] == 1
    assert _row_counts(path).get("committed") == 1


def test_rearm_preserves_request_rows(tmp_path):
    path = tmp_path / "vt.db"
    quota = _init(path, hours=1.0)
    reservation = quota.reserve(1000.0)
    quota.finalize(reservation.reservation_id, consumed=True)
    quota.rearm(4601.0)
    assert _row_counts(path).get("committed") == 1
    assert quota.state(4601.0)["spent"] == 0


def test_retention_keeps_current_utc_day_rows(tmp_path):
    path = tmp_path / "vt.db"
    quota = _init(path, hours=2)
    reservation = quota.reserve(1000.0)
    quota.finalize(reservation.reservation_id, consumed=True)
    quota.prune(1000.0 + 86400.0)
    assert _row_counts(path).get("committed") == 1


def test_stale_pending_is_committed_before_retention(tmp_path):
    path = tmp_path / "vt.db"
    quota = _init(path, budget=10)
    quota.reserve(1000.0)
    quota.prune(1000.0 + 301.0)
    assert _row_counts(path).get("committed") == 1
    assert "pending" not in _row_counts(path)


def test_prune_and_reservations_are_transactional(tmp_path):
    path = tmp_path / "vt.db"
    quota = _init(path, budget=20, rate=100, daily=100)

    def reserve(_):
        try:
            result = quota.reserve(1000.0)
            if result.reservation_id is not None:
                quota.finalize(result.reservation_id, consumed=True)
            return True
        except VirusTotalQuotaError:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        reservations = list(pool.map(reserve, range(8)))
    quota.prune(1000.0)
    assert all(reservations)
    assert quota.state(1000.0)["committed"] == 8


def test_prune_can_run_without_matching_runtime_budget(tmp_path):
    path = tmp_path / "vt.db"
    _init(path)
    assert _quota(path, budget=0).prune(1000.0) >= 0


def _legacy_state(path, rows, *, armed_at=96000.0, cooldown=0.0, version="1"):
    conn = sqlite3.connect(str(path))
    try:
        conn.execute("CREATE TABLE vt_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        conn.execute(
            "CREATE TABLE vt_requests ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "reserved_at REAL NOT NULL, status TEXT NOT NULL)")
        conn.executemany(
            "INSERT INTO vt_meta(key, value) VALUES(?, ?)",
            [("version", version), ("armed_at", str(armed_at)),
             ("cooldown_until", str(cooldown))])
        conn.executemany(
            "INSERT INTO vt_requests(reserved_at, status) VALUES(?, ?)", rows)
        conn.commit()
    finally:
        conn.close()
    os.chmod(path, 0o600)


def _meta_value(path, key):
    conn = sqlite3.connect(str(path))
    try:
        row = conn.execute("SELECT value FROM vt_meta WHERE key=?", (key,)).fetchone()
        return None if row is None else row[0]
    finally:
        conn.close()


def test_migrate_preserves_current_day_accounting(tmp_path):
    path = tmp_path / "vt.db"
    now = 100000.0
    _legacy_state(path, [(now - 1.0, "committed") for _ in range(450)])
    migrated = _quota(path, budget=500, hours=8, rate=4, daily=500)
    summary = migrated.adopt_legacy(now)

    assert summary["committed"] == 450
    assert summary["legacy_armed_at"] == 96000.0
    state = migrated.state(now)
    assert state["budget"] == 500
    assert state["spent"] == 450
    assert state["daily_spent"] == 450
    assert state["remaining"] == 50
    assert float(_meta_value(path, "budget_since")) == 86400.0
    assert _meta_value(path, "legacy_armed_at") == "96000.0"

    restarted = _quota(path, budget=500, hours=8, rate=4, daily=500)
    assert restarted.state(now)["spent"] == 450
    assert restarted.state(now)["daily_spent"] == 450


def test_migrate_preserves_old_history_and_current_day_separately(tmp_path):
    path = tmp_path / "vt.db"
    now = 100000.0
    _legacy_state(path, [(80000.0, "committed"), (now - 1.0, "committed")])
    migrated = _quota(path, budget=500, hours=8, rate=4, daily=500)
    summary = migrated.adopt_legacy(now)
    assert summary["committed"] == 2
    assert _row_counts(path).get("committed") == 2
    state = migrated.state(now)
    assert state["daily_spent"] == 1
    assert state["spent"] == 1


def test_migrate_preserves_rolling_window_history(tmp_path):
    path = tmp_path / "vt.db"
    now = 100000.0
    _legacy_state(path, [(now - 10.0, "committed"), (now - 20.0, "committed")])
    migrated = _quota(path, budget=500, hours=8, rate=4, daily=500)
    migrated.adopt_legacy(now)
    assert migrated.state(now)["rate_spent"] == 2


def test_migrate_resolves_stale_pending_and_keeps_recent_pending(tmp_path):
    path = tmp_path / "vt.db"
    now = 100000.0
    _legacy_state(path, [(now - 400.0, "pending"), (now - 10.0, "pending")])
    migrated = _quota(path, budget=500, hours=8, rate=4, daily=500)
    summary = migrated.adopt_legacy(now)
    assert summary["stale_promoted"] == 1
    assert summary["committed"] == 1
    assert summary["pending"] == 1
    state = migrated.state(now)
    assert state["committed"] == 1
    assert state["pending"] == 1


def test_migrate_preserves_future_cooldown(tmp_path):
    path = tmp_path / "vt.db"
    now = 100000.0
    _legacy_state(path, [(now - 1.0, "committed")], cooldown=now + 120.0)
    migrated = _quota(path, budget=500, hours=8, rate=4, daily=500)
    migrated.adopt_legacy(now)
    with pytest.raises(VirusTotalQuotaError) as error:
        migrated.reserve(now)
    assert error.value.kind == "cooldown"
    assert error.value.retry_after_seconds and error.value.retry_after_seconds > 100


@pytest.mark.parametrize("rows,armed_at,cooldown", [
    ([(100000.0, "bogus")], 96000.0, 0.0),
    ([("not-a-time", "committed")], 96000.0, 0.0),
    ([(100000.0, "committed")], 0.0, 0.0),
    ([(100000.0, "committed")], 96000.0, "bad"),
])
def test_migrate_rejects_malformed_legacy_state(tmp_path, rows, armed_at, cooldown):
    path = tmp_path / "vt.db"
    _legacy_state(path, rows, armed_at=armed_at, cooldown=cooldown)
    migrated = _quota(path, budget=500, hours=8, rate=4, daily=500)
    with pytest.raises(VirusTotalQuotaError) as error:
        migrated.adopt_legacy(100000.0)
    assert error.value.kind == "state_corrupt"
    assert _meta_value(path, "version") == "1"
    assert _meta_value(path, "policy_version") is None


def test_migrate_refuses_missing_state_and_current_schema(tmp_path):
    missing = tmp_path / "missing.db"
    with pytest.raises(VirusTotalQuotaError) as error:
        _quota(missing).adopt_legacy(100000.0)
    assert error.value.kind == "state_missing"
    assert not missing.exists()

    current = tmp_path / "current.db"
    _init(current)
    with pytest.raises(VirusTotalQuotaError) as error:
        _quota(current).adopt_legacy(100000.0)
    assert error.value.kind == "state_exists"


def test_migrate_cli_requires_confirmation(tmp_path, capsys):
    path = tmp_path / "vt.db"
    now = time.time()
    _legacy_state(path, [(now - 1.0, "committed")], armed_at=now - 3600.0)
    base = ["migrate", "--state", str(path), "--budget", "500",
            "--hours", "8", "--rate", "4", "--daily", "500"]
    assert main(base) == 2
    assert _meta_value(path, "version") == "1"
    assert main([*base, "--confirm"]) == 0
    assert _meta_value(path, "version") == "2"
    output = capsys.readouterr().out
    assert "committed" in output


def test_new_state_directory_is_private(tmp_path):
    import stat
    path = tmp_path / "private" / "vt.db"
    _quota(path).initialize(1000.0)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700


def test_state_directory_must_not_be_group_or_world_writable(tmp_path):
    parent = tmp_path / "open"
    parent.mkdir()
    os.chmod(parent, 0o777)
    path = parent / "vt.db"
    with pytest.raises(VirusTotalQuotaError) as error:
        _quota(path).initialize(1000.0)
    assert error.value.kind == "storage_unavailable"
    assert not path.exists()
