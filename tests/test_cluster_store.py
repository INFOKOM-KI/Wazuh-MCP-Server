#!/usr/bin/env python3
"""
Tests for mcp_server/core/cluster_store.py the SQLite fit/assignment store.
Covers the failure modes that make a store dangerous rather than merely broken:
an unconfigured path, a fit written under a different feature layout, and file
permissions on a store whose entity keys are source IPs.
"""
from __future__ import annotations
import os
import sqlite3
import time

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import pytest
from mcp_server.core.config import ClusterConfig, config
from mcp_server.core.exceptions import ConfigurationError
from mcp_server.core.cluster_store import (
    ClusterStoreError,
    get_assignment,
    load_fit,
    load_fit_history,
    pending_novelty_count,
    purge_expired,
    record_assignment,
    save_fit,
    store_stats,
)

CLUSTER = {"label": 0, "centroid": [1.0, 2.0], "medoid": [1.0, 1.0], "size": 3, "radius": 0.5}


@pytest.fixture
def store_path(tmp_path, monkeypatch):
    path = tmp_path / "clusters.db"
    monkeypatch.setattr(config.cluster, "store_path", str(path))
    monkeypatch.setattr(config.cluster, "enabled", True)
    monkeypatch.setattr(config.cluster, "ttl_seconds", 86400)
    monkeypatch.setattr(config.cluster, "store_max", 100)
    return path


def test_unconfigured_store_raises(monkeypatch):
    monkeypatch.setattr(config.cluster, "store_path", "")
    with pytest.raises(ClusterStoreError):
        load_fit()


def test_save_and_load_round_trip(store_path):
    save_fit("fit-1", {"min_cluster_size": 5}, [CLUSTER], entity_count=4, noise_count=1,
             window={"since": "2026-09-23T00:00:00Z", "until": "2026-09-23T01:00:00Z"})
    fit = load_fit()
    assert fit["fit_id"] == "fit-1"
    assert fit["entity_count"] == 4
    assert fit["noise_count"] == 1
    assert fit["clusters"][0]["centroid"] == [1.0, 2.0]
    assert fit["window"]["since"].startswith("2026-09-23")


def test_empty_store_returns_none(store_path):
    assert load_fit() is None


def test_load_fit_history_returns_oldest_first(store_path):
    save_fit("fit-1", {"min_cluster_size": 5}, [CLUSTER], entity_count=4, noise_count=1)
    time.sleep(0.02)
    save_fit("fit-2", {"min_cluster_size": 5}, [CLUSTER], entity_count=4, noise_count=1)
    assert [fit["fit_id"] for fit in load_fit_history()] == ["fit-1", "fit-2"]
    assert [fit["fit_id"] for fit in load_fit_history(limit=1)] == ["fit-2"]


def test_feature_version_mismatch_refuses(store_path):
    save_fit("fit-1", {}, [CLUSTER], entity_count=3, noise_count=0)
    with sqlite3.connect(store_path) as conn:
        conn.execute("UPDATE fits SET feature_version = 'v0' WHERE fit_id = 'fit-1'")
    with pytest.raises(ClusterStoreError):
        load_fit()


def test_store_file_is_owner_only(store_path):
    save_fit("fit-1", {}, [CLUSTER], entity_count=3, noise_count=0)
    assert (os.stat(store_path).st_mode & 0o777) == 0o600


def test_assignment_round_trip_and_novelty_count(store_path):
    save_fit("fit-1", {}, [CLUSTER], entity_count=3, noise_count=0)
    record_assignment("203.0.113.7", "fit-1", 0, 0.21, novelty=False)
    record_assignment("203.0.113.9", "fit-1", -1, 9.5, novelty=True)
    assignment = get_assignment("203.0.113.7")
    assert assignment["label"] == 0
    assert assignment["novelty"] is False
    assert pending_novelty_count("fit-1") == 1


def test_purge_expired_removes_old_fits(store_path, monkeypatch):
    save_fit("fit-1", {}, [CLUSTER], entity_count=3, noise_count=0)
    with sqlite3.connect(store_path) as conn:
        conn.execute("UPDATE fits SET created_at = 0")
    monkeypatch.setattr(config.cluster, "ttl_seconds", 60)
    assert purge_expired() == 1
    assert load_fit() is None


def test_stats_never_returns_entity_keys(store_path):
    save_fit("fit-1", {}, [CLUSTER], entity_count=3, noise_count=0)
    record_assignment("203.0.113.7", "fit-1", 0, 0.1, novelty=False)
    stats = store_stats()
    assert stats["fits"] == 1
    assert stats["entities"] == 1
    assert "203.0.113.7" not in str(stats)


def test_config_rejects_invalid_max_fits():
    with pytest.raises(ConfigurationError):
        ClusterConfig(max_fits=9).validate()
    with pytest.raises(ConfigurationError):
        ClusterConfig(max_fits=1001).validate()
    ClusterConfig().validate()


def test_config_max_fits_from_env(monkeypatch):
    monkeypatch.delenv("BLUETEAM_CLUSTER_MAX_FITS", raising=False)
    assert ClusterConfig.from_env().max_fits == 100
    monkeypatch.setenv("BLUETEAM_CLUSTER_MAX_FITS", "250")
    assert ClusterConfig.from_env().max_fits == 250
    monkeypatch.setenv("BLUETEAM_CLUSTER_MAX_FITS", "not-a-number")
    with pytest.raises(ValueError):
        ClusterConfig.from_env()


def test_max_fits_evicts_oldest_with_children(store_path, monkeypatch):
    monkeypatch.setattr(config.cluster, "max_fits", 3)
    for index in range(3):
        save_fit(f"fit-{index}", {}, [CLUSTER], entity_count=3, noise_count=0,
                 window={"since": f"2026-09-0{index + 1}T00:00:00Z",
                         "until": f"2026-09-0{index + 1}T01:00:00Z"})
    record_assignment("203.0.113.9", "fit-0", 0, 0.1, novelty=False)
    save_fit("fit-3", {}, [CLUSTER], entity_count=3, noise_count=0,
             window={"since": "2026-09-04T00:00:00Z", "until": "2026-09-04T01:00:00Z"})
    assert [fit["fit_id"] for fit in load_fit_history(limit=10)] == ["fit-1", "fit-2", "fit-3"]
    with sqlite3.connect(store_path) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM centroids WHERE fit_id='fit-0'").fetchone()[0] == 0
        assert conn.execute(
            "SELECT COUNT(*) FROM entities WHERE fit_id='fit-0'").fetchone()[0] == 0


def test_load_fit_history_orders_by_window_not_save_time(store_path):
    save_fit("live", {}, [CLUSTER], entity_count=3, noise_count=0,
             window={"since": "2026-09-10T00:00:00Z", "until": "2026-09-11T00:00:00Z"})
    time.sleep(0.02)
    save_fit("backfill", {}, [CLUSTER], entity_count=3, noise_count=0,
             window={"since": "2026-09-01T00:00:00Z", "until": "2026-09-02T00:00:00Z"})
    assert [fit["fit_id"] for fit in load_fit_history()] == ["backfill", "live"]
    assert load_fit()["fit_id"] == "live"


def test_load_fit_history_legacy_fit_falls_back_to_created_at(store_path):
    save_fit("legacy", {}, [CLUSTER], entity_count=3, noise_count=0)
    with sqlite3.connect(store_path) as conn:
        conn.execute("UPDATE fits SET created_at = 0 WHERE fit_id = 'legacy'")
    save_fit("windowed", {}, [CLUSTER], entity_count=3, noise_count=0,
             window={"since": "2026-09-01T00:00:00Z", "until": "2026-09-02T00:00:00Z"})
    assert [fit["fit_id"] for fit in load_fit_history()] == ["legacy", "windowed"]


def test_legacy_fit_without_window_is_newest_by_creation_time(store_path):
    save_fit("windowed", {}, [CLUSTER], entity_count=3, noise_count=0,
             window={"since": "2020-01-01T00:00:00Z", "until": "2020-01-02T00:00:00Z"})
    time.sleep(0.02)
    save_fit("legacy", {}, [CLUSTER], entity_count=3, noise_count=0)
    assert load_fit()["fit_id"] == "legacy"


def test_replacing_fit_id_clears_stale_entities(store_path):
    save_fit("fit-1", {}, [CLUSTER], entity_count=3, noise_count=0,
             window={"since": "2026-09-01T00:00:00Z", "until": "2026-09-02T00:00:00Z"})
    record_assignment("203.0.113.7", "fit-1", 0, 0.1, novelty=False)
    save_fit("fit-1", {"min_cluster_size": 9}, [CLUSTER], entity_count=3, noise_count=0,
             window={"since": "2026-09-01T00:00:00Z", "until": "2026-09-02T00:00:00Z"})
    assert get_assignment("203.0.113.7", "fit-1") is None
    with sqlite3.connect(store_path) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM entities WHERE fit_id='fit-1'").fetchone()[0] == 0


def test_failed_replacement_rolls_back_entity_cleanup(store_path):
    save_fit("det-id", {}, [CLUSTER], entity_count=3, noise_count=0,
             window={"since": "2026-09-01T00:00:00Z", "until": "2026-09-02T00:00:00Z"})
    record_assignment("203.0.113.7", "det-id", 0, 0.1, novelty=False)
    with pytest.raises(KeyError):
        save_fit("det-id", {}, [{"label": 0}], entity_count=3, noise_count=0,
                 window={"since": "2026-09-01T00:00:00Z", "until": "2026-09-02T00:00:00Z"})
    assert get_assignment("203.0.113.7", "det-id") is not None
    assert len(load_fit("det-id")["clusters"]) == 1


def test_replacing_fit_id_preserves_created_at(store_path):
    save_fit("fit-1", {}, [CLUSTER], entity_count=3, noise_count=0,
             window={"since": "2026-09-01T00:00:00Z", "until": "2026-09-02T00:00:00Z"})
    with sqlite3.connect(store_path) as conn:
        conn.execute("UPDATE fits SET created_at = 1000 WHERE fit_id = 'fit-1'")
    save_fit("fit-1", {"min_cluster_size": 9}, [CLUSTER], entity_count=3, noise_count=0,
             window={"since": "2026-09-01T00:00:00Z", "until": "2026-09-02T00:00:00Z"})
    fit = load_fit("fit-1")
    assert fit["created_at"] == 1000.0
    assert fit["params"]["min_cluster_size"] == 9
