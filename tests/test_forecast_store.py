#!/usr/bin/env python3
"""
Tests for mcp_server/core/forecast_store.py the SQLite forecast corpus and model store.
The failure modes that matter here: an unconfigured path, a corpus re-ingest that
would inflate counts, a model written under a different tactic taxonomy, and a
corrupted matrix that must not be scored against.
"""
from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import json
import sqlite3
import time
import pytest
from mcp_server.core.config import config
from mcp_server.core.forecast_store import (
    ForecastStoreError,
    append_observations,
    load_counts,
    load_model,
    load_observations,
    purge_expired,
    save_model,
    store_stats,
    upsert_counts,
)
from mcp_server.correlation.forecast_core import (
    TACTIC_ORDER,
    TAXONOMY_VERSION,
    fit_markov_chain,
)

SEQUENCES = [
    ["Reconnaissance", "Initial Access", "Execution", "Command and Control"],
    ["Reconnaissance", "Initial Access", "Execution", "Command and Control"],
    ["Reconnaissance", "Initial Access", "Persistence", "Command and Control"],
    ["Discovery", "Lateral Movement", "Exfiltration"],
    ["Discovery", "Lateral Movement", "Exfiltration"],
    ["Discovery", "Credential Access", "Lateral Movement", "Exfiltration"],
]


@pytest.fixture
def store_path(tmp_path, monkeypatch):
    path = tmp_path / "forecast.db"
    monkeypatch.setattr(config.forecast, "store_path", str(path))
    monkeypatch.setattr(config.forecast, "enabled", True)
    monkeypatch.setattr(config.forecast, "store_max", 1000)
    monkeypatch.setattr(config.forecast, "retention_days", 365)
    return path


def _fit():
    fit = fit_markov_chain(SEQUENCES, alpha=1.0, min_sequences=5, min_transitions=10)
    assert fit["status"] == "ok"
    return fit


def test_unconfigured_store_raises(monkeypatch):
    monkeypatch.setattr(config.forecast, "store_path", "")
    with pytest.raises(ForecastStoreError):
        load_observations()


def test_append_is_idempotent_and_round_trips(store_path):
    rows = [("203.0.113.7", "Discovery", 1000.0), ("203.0.113.7", "Impact", 2000.0)]
    assert append_observations(rows) == 2
    assert append_observations(rows) == 0
    loaded = load_observations()
    assert [row["tactic"] for row in loaded] == ["Discovery", "Impact"]
    assert loaded[0]["observed_at"] == 1000.0


def test_load_observations_respects_start(store_path):
    append_observations([("a", "Discovery", 100.0), ("a", "Impact", 900.0)])
    assert len(load_observations(500.0)) == 1


def test_save_and_load_model_round_trip(store_path):
    fit = _fit()
    save_model("m1", "markov", {"alpha": 1.0}, fit["startprob"], fit["transmat"],
               row_support=fit["row_support"], n_sequences=6, n_transitions=16)
    model = load_model()
    assert model["model_id"] == "m1"
    assert model["kind"] == "markov"
    assert model["taxonomy_version"] == TAXONOMY_VERSION
    assert model["tactics"] == list(TACTIC_ORDER)
    assert len(model["transmat"]) == len(TACTIC_ORDER)
    assert sum(model["row_support"]) == 16


def test_newest_model_wins_and_id_lookup_works(store_path):
    fit = _fit()
    save_model("old", "markov", {}, fit["startprob"], fit["transmat"],
               row_support=fit["row_support"], n_sequences=6, n_transitions=16)
    time.sleep(0.02)
    save_model("new", "markov", {}, fit["startprob"], fit["transmat"],
               row_support=fit["row_support"], n_sequences=6, n_transitions=16)
    assert load_model("old")["model_id"] == "old"
    assert load_model()["model_id"] == "new"


def test_taxonomy_mismatch_refuses(store_path, monkeypatch):
    fit = _fit()
    save_model("m1", "markov", {}, fit["startprob"], fit["transmat"],
               row_support=fit["row_support"], n_sequences=6, n_transitions=16)
    # A stored model from an older build: same row, different taxonomy stamp.
    monkeypatch.setattr("mcp_server.core.forecast_store.TAXONOMY_VERSION", "v0:deadbeef")
    with pytest.raises(ForecastStoreError):
        load_model("m1")


def test_corrupt_matrix_is_refused_not_scored(store_path):
    fit = _fit()
    save_model("m1", "markov", {}, fit["startprob"], fit["transmat"],
               row_support=fit["row_support"], n_sequences=6, n_transitions=16)
    bad_row = json.dumps([[9.0] * len(TACTIC_ORDER)] * len(TACTIC_ORDER))
    with sqlite3.connect(store_path) as conn:
        conn.execute("UPDATE models SET transmat = ? WHERE model_id = 'm1'", (bad_row,))
    with pytest.raises(ForecastStoreError):
        load_model("m1")


def test_retention_purge_removes_old_rows(store_path):
    append_observations([("a", "Discovery", 0.0), ("a", "Impact", time.time())])
    result = purge_expired()
    assert result["observations"] == 1
    assert len(load_observations()) == 1


def test_model_cap_evicts_the_oldest(store_path, monkeypatch):
    monkeypatch.setattr("mcp_server.core.forecast_store._MAX_MODELS", 1)
    fit = _fit()
    save_model("old", "markov", {}, fit["startprob"], fit["transmat"],
               row_support=fit["row_support"], n_sequences=6, n_transitions=16)
    time.sleep(0.02)
    save_model("new", "markov", {}, fit["startprob"], fit["transmat"],
               row_support=fit["row_support"], n_sequences=6, n_transitions=16)
    assert load_model()["model_id"] == "new"
    assert load_model("old") is None


def test_store_file_is_owner_only(store_path):
    append_observations([("a", "Discovery", 1.0)])
    assert (store_path.stat().st_mode & 0o777) == 0o600


def test_stats_report_counts_without_entity_keys(store_path):
    append_observations([("203.0.113.7", "Discovery", 1.0)])
    stats = store_stats()
    assert stats["observations"] == 1
    assert stats["entities"] == 1
    assert "203.0.113.7" not in json.dumps(stats)


def test_upsert_counts_replaces_and_orders(store_path):
    assert upsert_counts([(2000.0, 5), (1000.0, 1)]) == 2
    assert upsert_counts([(1000.0, 3)]) == 1
    assert load_counts() == [3, 5]
    assert load_counts(1500.0) == [5]


def test_retention_purge_removes_old_counts(store_path):
    upsert_counts([(0.0, 1), (time.time(), 2)])
    result = purge_expired()
    assert result["counts"] == 1
    assert load_counts() == [2]


def test_stats_include_counts(store_path):
    upsert_counts([(1.0, 7)])
    assert store_stats()["counts"] == 1
