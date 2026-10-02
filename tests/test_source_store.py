#!/usr/bin/env python3
"""
Contract and regression tests for ``mcp_server.core.source_store`` and the
``config.source`` section. Imports happen inside helpers, so a missing module
or config section fails each test with an explicit contract message.
"""
from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import sqlite3
import time
import pytest
from mcp_server.core.config import config
from mcp_server.core.exceptions import BlueTeamMCPError

DAY = 86400.0


def _store_module():
    try:
        import mcp_server.core.source_store as mod
    except ImportError as exc:
        pytest.fail(f"contract missing: mcp_server.core.source_store ({exc})")
    return mod


def _source_config(monkeypatch, tmp_path):
    section = getattr(config, "source", None)
    if section is None:
        pytest.fail("contract missing: config.source (SourceForecastConfig)")
    path = tmp_path / "source.db"
    monkeypatch.setattr(section, "enabled", True)
    monkeypatch.setattr(section, "store_path", str(path))
    monkeypatch.setattr(section, "max_rows", 1000)
    monkeypatch.setattr(section, "retention_days", 365)
    return section, path


def _srow(ip, ts, country=None, tactic="Reconnaissance", netblock=None):
    return {"source_ip": ip, "netblock": netblock or "8.8.8.0/24",
            "country": country, "tactic": tactic, "observed_at": ts}


def test_save_load_round_trip_and_dedupe(monkeypatch, tmp_path):
    store = _store_module()
    _source_config(monkeypatch, tmp_path)
    rows = [_srow("8.8.8.8", 0.0), _srow("8.8.8.8", 1.0, country="US")]
    assert store.save_source_observations(rows) == 2
    assert store.save_source_observations(rows) == 0
    loaded = store.load_source_observations(0.0)
    assert [row["source_ip"] for row in loaded] == ["8.8.8.8", "8.8.8.8"]
    assert store.store_stats()["rows"] == 2


def test_load_window_is_half_open(monkeypatch, tmp_path):
    store = _store_module()
    _source_config(monkeypatch, tmp_path)
    store.save_source_observations([_srow("8.8.8.8", 0.0), _srow("1.1.1.1", DAY)])
    loaded = store.load_source_observations(0.0, until_ts=DAY)
    assert [row["source_ip"] for row in loaded] == ["8.8.8.8"]


def test_purge_removes_aged_rows(monkeypatch, tmp_path):
    store = _store_module()
    section, _path = _source_config(monkeypatch, tmp_path)
    monkeypatch.setattr(section, "retention_days", 1)
    store.save_source_observations([_srow("8.8.8.8", 0.0),
                                    _srow("1.1.1.1", time.time())])
    result = store.purge_expired()
    assert result["rows"] == 1
    assert [row["source_ip"] for row in store.load_source_observations(0.0)] == ["1.1.1.1"]


def test_row_cap_trims_oldest(monkeypatch, tmp_path):
    store = _store_module()
    section, _path = _source_config(monkeypatch, tmp_path)
    monkeypatch.setattr(section, "max_rows", 3)
    store.save_source_observations([_srow("8.8.8.8", float(index))
                                    for index in range(5)])
    stats = store.store_stats()
    assert stats["rows"] == 3
    loaded = store.load_source_observations(0.0)
    assert [row["observed_at"] for row in loaded] == [2.0, 3.0, 4.0]


def test_store_file_is_owner_only(monkeypatch, tmp_path):
    store = _store_module()
    _section, path = _source_config(monkeypatch, tmp_path)
    store.save_source_observations([_srow("8.8.8.8", 0.0)])
    assert (os.stat(path).st_mode & 0o777) == 0o600


def test_stats_never_returns_raw_sources(monkeypatch, tmp_path):
    store = _store_module()
    _source_config(monkeypatch, tmp_path)
    store.save_source_observations([_srow("8.8.8.8", 0.0, country="US")])
    stats = store.store_stats()
    assert "8.8.8.8" not in str(stats)
    assert stats["sources"] == 1


def test_stats_geo_coverage(monkeypatch, tmp_path):
    store = _store_module()
    _source_config(monkeypatch, tmp_path)
    store.save_source_observations([_srow("8.8.8.8", 0.0, country="US"),
                                    _srow("1.1.1.1", 1.0, country="DE"),
                                    _srow("9.9.9.9", 2.0, country=None)])
    stats = store.store_stats()
    assert stats["geo_coverage"] == pytest.approx(2 / 3, abs=1e-4)
    assert stats["first_observed_at"] == 0.0
    assert stats["last_observed_at"] == 2.0


def test_ingest_round_trip_and_latest(monkeypatch, tmp_path):
    store = _store_module()
    _source_config(monkeypatch, tmp_path)
    store.save_ingest("ing-1", 0.0, DAY, True, True, {"fetched_hits": 10})
    store.save_ingest("ing-2", DAY, 2 * DAY, False, False, {"fetched_hits": 3})
    assert store.load_ingest("ing-1")["window_complete"] is True
    latest = store.load_ingest()
    assert latest["ingest_id"] == "ing-2"
    assert latest["stats"]["fetched_hits"] == 3


def test_complete_ingest_covering_requires_completeness(monkeypatch, tmp_path):
    store = _store_module()
    _source_config(monkeypatch, tmp_path)
    store.save_ingest("complete", 0.0, 2 * DAY, True, True)
    store.save_ingest("incomplete", 0.0, 4 * DAY, False, False)
    assert store.complete_ingest_covering(0.0, 2 * DAY)["ingest_id"] == "complete"
    assert store.complete_ingest_covering(DAY, 2 * DAY)["ingest_id"] == "complete"
    assert store.complete_ingest_covering(0.0, 3 * DAY) is None
    assert store.complete_ingest_covering(-DAY, DAY) is None


def test_unconfigured_store_raises(monkeypatch, tmp_path):
    store = _store_module()
    section, _path = _source_config(monkeypatch, tmp_path)
    monkeypatch.setattr(section, "store_path", "")
    with pytest.raises(BlueTeamMCPError):
        store.load_source_observations(0.0)


def test_wal_and_shm_are_owner_only(monkeypatch, tmp_path):
    store = _store_module()
    _section, path = _source_config(monkeypatch, tmp_path)
    conn = store._connect()
    conn.execute("INSERT INTO source_observations"
                 " (source_ip, netblock, country, tactic, observed_at)"
                 " VALUES ('8.8.8.8','8.8.8.0/24','US','Recon',1.0)")
    for suffix in ("-wal", "-shm"):
        target = path.parent / (path.name + suffix)
        assert (os.stat(target).st_mode & 0o777) == 0o600
    conn.commit()
    conn.close()


def test_config_rejects_store_path_collision(tmp_path):
    from mcp_server.core.config import Config
    from mcp_server.core.exceptions import ConfigurationError
    cfg = Config.from_env()
    shared = str(tmp_path / "shared.db")
    cfg.source.enabled = True
    cfg.source.store_path = shared
    cfg.forecast.store_path = shared
    with pytest.raises(ConfigurationError):
        cfg.validate()
    cfg.forecast.store_path = str(tmp_path / "forecast.db")
    cfg.cluster.store_path = shared
    with pytest.raises(ConfigurationError):
        cfg.validate()
    cfg.cluster.store_path = str(tmp_path / "clusters.db")
    cfg.validate()


def test_empty_store_stats(monkeypatch, tmp_path):
    store = _store_module()
    _source_config(monkeypatch, tmp_path)
    stats = store.store_stats()
    assert stats["rows"] == 0
    assert stats["sources"] == 0
    assert stats["geo_coverage"] is None
    assert stats["first_observed_at"] is None
    assert store.load_source_observations(0.0) == []
    assert sqlite3.connect((tmp_path / "source.db").as_posix()).execute(
        "SELECT COUNT(*) FROM source_observations").fetchone()[0] == 0
