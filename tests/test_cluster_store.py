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

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import pytest
from mcp_server.core.config import config
from mcp_server.core.cluster_store import (
    ClusterStoreError,
    get_assignment,
    load_fit,
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
