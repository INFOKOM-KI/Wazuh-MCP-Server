#!/usr/bin/env python3
"""
Tests for blueteam_alert_cluster mode="backfill".
The Indexer aggregation, HDBSCAN and the srcip-mapping probe are mocked, so the
suite pins window arithmetic, deterministic ids, completeness gating, capacity
behavior, provenance and live-mode regression without a live Indexer or
scikit-learn. Tool bodies run through ``__wrapped__``.
"""
from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import asyncio
import hashlib
import json
import math
from datetime import datetime, timedelta, timezone
import pytest
from mcp_server.core.config import config
from mcp_server.core.cluster_store import (
    ClusterStoreError,
    load_fit,
    load_fit_history,
    save_fit,
    store_stats,
)
from mcp_server.core.exceptions import BlueTeamMCPError
from mcp_server.tools import cluster

_run = asyncio.run
_tool = cluster.blueteam_alert_cluster.__wrapped__
_assign = cluster.blueteam_alert_cluster_assign.__wrapped__

PROFILES = {
    "203.0.113.7": {"tactics": {"Command and Control": 30.0}, "score_a": 0.0,
                    "score_b": 12.0, "score_c": 30.0, "total": 72.0, "alert_count": 5},
    "203.0.113.8": {"tactics": {"Discovery": 6.0}, "score_a": 6.0,
                    "score_b": 0.0, "score_c": 0.0, "total": 6.0, "alert_count": 2},
    "203.0.113.9": {"tactics": {"Impact": 8.0}, "score_a": 0.0,
                    "score_b": 3.0, "score_c": 4.0, "total": 12.5, "alert_count": 3},
}

_STORE_CLUSTER = {"label": 0, "centroid": [1.0, 0.0], "medoid": [1.0, 0.0],
                  "size": 2, "radius": 0.5}


def _fetch_result(**overrides) -> dict:
    result = {"profiles": {key: dict(value) for key, value in PROFILES.items()},
              "warnings": [], "failures": 0, "path_errors": 0,
              "partial_shards": 0, "fallback_paths": 0}
    result.update(overrides)
    return result


async def _fake_fetch(categories, since_iso, until_iso, use_mitre=True,
                      technique_tactics=None, category_techniques=None, srcip=None,
                      srcip_paths=None):
    _fake_fetch.calls.append({"since": since_iso, "until": until_iso,
                              "srcip_paths": srcip_paths})
    if _fake_fetch.results:
        return _fake_fetch.results.pop(0)
    return _fetch_result()


_fake_fetch.calls = []
_fake_fetch.results = []


def _fake_fit(vectors, min_cluster_size=5, min_samples=3, clusterer=None):
    members = vectors[:2]
    centroid = [sum(v[i] for v in members) / len(members) for i in range(len(members[0]))]
    radius = max(math.dist(centroid, member) for member in members)
    return {
        "status": "ok", "labels": [0] * 2 + [-1] * (len(vectors) - 2),
        "clusters": [{"label": 0, "centroid": centroid, "medoid": list(vectors[0]),
                      "size": 2, "radius": radius}],
        "entity_count": len(vectors), "noise_count": len(vectors) - 2,
        "noise_ratio": round((len(vectors) - 2) / len(vectors), 3),
        "params": {"min_cluster_size": min_cluster_size, "min_samples": min_samples,
                   "metric": "euclidean"},
    }


@pytest.fixture(autouse=True)
def _setup(tmp_path, monkeypatch):
    monkeypatch.setattr(config.cluster, "enabled", True)
    monkeypatch.setattr(config.cluster, "store_path", str(tmp_path / "clusters.db"))
    monkeypatch.setattr(config.cluster, "min_cluster_size", 2)
    monkeypatch.setattr(config.cluster, "min_samples", 1)
    monkeypatch.setattr(config.cluster, "max_fits", 100)
    _fake_fetch.calls = []
    _fake_fetch.results = []
    monkeypatch.setattr(cluster, "fetch_srcip_profiles", _fake_fetch)
    monkeypatch.setattr(cluster, "fit_clusters", _fake_fit)

    async def _paths(fields, index_pattern=None):
        return {path: "keyword" for path in fields}

    async def _no_tech():
        return {}

    monkeypatch.setattr(cluster, "_wazuh_indexer_field_caps", _paths)
    monkeypatch.setattr(cluster, "_load_mitre_technique_map", _no_tech)
    yield


def _params(**overrides):
    return cluster.AlertClusterInput(mode="backfill", response_format="json", **overrides)


def test_range_defaults_to_max_days_before_until():
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    until = today - timedelta(days=1)
    expected_since = until - timedelta(days=90)
    since, until_iso, windows = cluster._resolve_backfill_range(
        _params(until=until.strftime("%Y-%m-%d"), max_days=90))
    assert since == expected_since.strftime("%Y-%m-%dT%H:%M:%SZ")
    assert until_iso == until.strftime("%Y-%m-%dT%H:%M:%SZ")
    assert len(windows) == 90
    assert windows[0] == {"day": expected_since.strftime("%Y-%m-%d"),
                          "since": expected_since.strftime("%Y-%m-%dT%H:%M:%SZ"),
                          "until": (expected_since + timedelta(days=1)).strftime(
                              "%Y-%m-%dT%H:%M:%SZ")}
    assert windows[-1]["until"] == until_iso
    assert windows[1]["since"] == windows[0]["until"]


def test_range_uses_explicit_since_and_until():
    since, until, windows = cluster._resolve_backfill_range(
        _params(since="2026-09-01", until="2026-09-04"))
    assert (since, until) == ("2026-09-01T00:00:00Z", "2026-09-04T00:00:00Z")
    assert [window["day"] for window in windows] == ["2026-09-01", "2026-09-02", "2026-09-03"]


@pytest.mark.parametrize("overrides", [
    {"until": "2026-09-30T12:00:00Z"},
    {"since": "2026-09-29T12:00:00Z", "until": "2026-09-30"},
    {"since": "2026-09-30", "until": "2026-09-30"},
    {"since": "2026-01-01", "until": "2026-09-30", "max_days": 90},
    {"until": "not-a-date"},
])
def test_invalid_ranges_are_rejected(overrides):
    with pytest.raises(BlueTeamMCPError):
        cluster._resolve_backfill_range(_params(**overrides))


def test_current_or_future_until_is_rejected():
    tomorrow = (datetime.now(timezone.utc).replace(hour=0, minute=0, second=0,
                                                   microsecond=0) + timedelta(days=1))
    with pytest.raises(BlueTeamMCPError):
        cluster._resolve_backfill_range(_params(until=tomorrow.strftime("%Y-%m-%d")))


def test_backfill_rejects_non_daily_window():
    with pytest.raises(BlueTeamMCPError) as excinfo:
        _run(_tool(_params(time_window_minutes=10080)))
    assert "1440" in str(excinfo.value)


def test_backfill_fit_id_is_deterministic_and_window_scoped():
    since, until = "2026-09-01T00:00:00Z", "2026-09-02T00:00:00Z"
    expected = "bf-" + hashlib.sha256(f"{since}|{until}".encode("utf-8")).hexdigest()[:10]
    assert cluster._backfill_fit_id(since, until) == expected
    assert cluster._backfill_fit_id(since, until) == cluster._backfill_fit_id(since, until)
    assert cluster._backfill_fit_id(since, until) != cluster._backfill_fit_id(
        "2026-09-02T00:00:00Z", "2026-09-03T00:00:00Z")


def test_backfill_persists_days_oldest_first_with_provenance():
    payload = json.loads(_run(_tool(_params(since="2026-09-01", until="2026-09-04"))))
    assert payload["status"] == "ok"
    assert payload["days_fitted"] == 3
    assert [day["status"] for day in payload["days"]] == ["ok", "ok", "ok"]
    fits = load_fit_history()
    assert [fit["window"]["since"] for fit in fits] == [
        "2026-09-01T00:00:00Z", "2026-09-02T00:00:00Z", "2026-09-03T00:00:00Z"]
    assert [call["since"] for call in _fake_fetch.calls] == [
        fit["window"]["since"] for fit in fits]
    assert all(fit["params"]["origin"] == "backfill" for fit in fits)
    assert fits[0]["params"]["use_mitre"] is True
    assert fits[0]["params"]["window_minutes"] == 1440
    assert [fit["fit_id"] for fit in fits] == [
        cluster._backfill_fit_id(fit["window"]["since"], fit["window"]["until"])
        for fit in fits]


def test_rerun_is_idempotent_and_preserves_created_at():
    _run(_tool(_params(since="2026-09-01", until="2026-09-03")))
    before = load_fit_history()
    created = {fit["fit_id"]: fit["created_at"] for fit in before}
    payload = json.loads(_run(_tool(_params(since="2026-09-01", until="2026-09-03"))))
    assert payload["days_fitted"] == 2
    assert payload["capacity"]["net_new_days"] == 0
    assert store_stats()["fits"] == 2
    after = load_fit_history()
    assert {fit["fit_id"]: fit["created_at"] for fit in after} == created


@pytest.mark.parametrize("override,expected", [
    ({"failures": 1}, "category fetch failures"),
    ({"path_errors": 2}, "srcip path errors"),
    ({"partial_shards": 3}, "failed shards"),
    ({"fallback_paths": 1}, "srcip mapping fallbacks"),
])
def test_degraded_fetch_is_not_persisted(override, expected):
    _fake_fetch.results = [_fetch_result(**override)]
    payload = json.loads(_run(_tool(_params(since="2026-09-01", until="2026-09-02"))))
    assert payload["days_incomplete"] == 1
    assert payload["days"][0]["status"] == "incomplete"
    assert expected in payload["days"][0]["reason"]
    assert load_fit_history() == []


def test_empty_day_is_skipped_not_fabricated():
    _fake_fetch.results = [_fetch_result(profiles={})]
    payload = json.loads(_run(_tool(_params(since="2026-09-01", until="2026-09-02"))))
    assert payload["days_skipped"] == 1
    assert payload["days"][0]["status"] == "skipped"
    assert load_fit_history() == []


def test_fit_insufficient_is_skipped(monkeypatch):
    monkeypatch.setattr(cluster, "fit_clusters", lambda *args, **kwargs: {
        "status": "insufficient_data", "entity_count": 3, "reason": "3 entities < 2"})
    payload = json.loads(_run(_tool(_params(since="2026-09-01", until="2026-09-02"))))
    assert payload["days_skipped"] == 1
    assert load_fit_history() == []


def test_fit_unavailable_is_an_error(monkeypatch):
    monkeypatch.setattr(cluster, "fit_clusters", lambda *args, **kwargs: {
        "status": "unavailable", "reason": "scikit-learn is not installed"})
    payload = json.loads(_run(_tool(_params(since="2026-09-01", until="2026-09-02"))))
    assert payload["days_failed"] == 1
    assert payload["days"][0]["status"] == "error"
    assert load_fit_history() == []


def test_one_failed_day_does_not_abort_the_rest(monkeypatch):
    calls = {"n": 0}

    async def _flaky(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("indexer hiccup")
        return _fetch_result()

    monkeypatch.setattr(cluster, "fetch_srcip_profiles", _flaky)
    payload = json.loads(_run(_tool(_params(since="2026-09-01", until="2026-09-04"))))
    assert payload["days_fitted"] == 2
    assert payload["days_failed"] == 1
    assert store_stats()["fits"] == 2
    monkeypatch.setattr(cluster, "fetch_srcip_profiles", _fake_fetch)
    retry = json.loads(_run(_tool(_params(since="2026-09-01", until="2026-09-04"))))
    assert retry["days_fitted"] == 3
    assert store_stats()["fits"] == 3


def test_capacity_refusal_writes_nothing(monkeypatch):
    save_fit("live-1", {}, [_STORE_CLUSTER], entity_count=3, noise_count=0)
    monkeypatch.setattr(config.cluster, "max_fits", 2)
    payload = json.loads(_run(_tool(_params(since="2026-09-01", until="2026-09-03"))))
    assert payload["status"] == "insufficient_capacity"
    assert payload["capacity"]["available"] == 1
    assert payload["capacity"]["net_new_days"] == 2
    assert {fit["fit_id"] for fit in load_fit_history()} == {"live-1"}


def test_capacity_exact_fit_is_allowed(monkeypatch):
    save_fit("live-1", {}, [_STORE_CLUSTER], entity_count=3, noise_count=0)
    monkeypatch.setattr(config.cluster, "max_fits", 2)
    payload = json.loads(_run(_tool(_params(since="2026-09-01", until="2026-09-02"))))
    assert payload["days_fitted"] == 1
    assert store_stats()["fits"] == 2


def test_capacity_race_is_skipped_atomically(monkeypatch):
    save_fit("live-1", {}, [_STORE_CLUSTER], entity_count=3, noise_count=0)
    monkeypatch.setattr(config.cluster, "max_fits", 2)
    state = {"filled": False}

    async def _racing_fetch(*args, **kwargs):
        if not state["filled"]:
            save_fit("live-2", {}, [_STORE_CLUSTER], entity_count=3, noise_count=0)
            state["filled"] = True
        return _fetch_result()

    monkeypatch.setattr(cluster, "fetch_srcip_profiles", _racing_fetch)
    payload = json.loads(_run(_tool(_params(since="2026-09-01", until="2026-09-02"))))
    assert payload["days_capacity_skipped"] == 1
    assert payload["days"][0]["status"] == "capacity_skipped"
    assert payload["capacity"]["exhausted"] is True
    assert {fit["fit_id"] for fit in load_fit_history(limit=10)} == {"live-1", "live-2"}


def test_backfill_refuses_when_srcip_mapping_unresolved(monkeypatch):
    async def _no_caps(fields, index_pattern=None):
        return {}

    monkeypatch.setattr(cluster, "_wazuh_indexer_field_caps", _no_caps)
    payload = json.loads(_run(_tool(_params(since="2026-09-01", until="2026-09-02"))))
    assert payload["status"] == "srcip_mapping_degraded"
    assert load_fit_history() == []


def test_backfill_probes_caps_and_loads_mitre_once(monkeypatch):
    counters = {"caps": 0, "mitre": 0}

    async def _counting_caps(fields, index_pattern=None):
        counters["caps"] += 1
        return {path: "keyword" for path in fields}

    async def _counting_mitre():
        counters["mitre"] += 1
        return {}

    monkeypatch.setattr(cluster, "_wazuh_indexer_field_caps", _counting_caps)
    monkeypatch.setattr(cluster, "_load_mitre_technique_map", _counting_mitre)
    _run(_tool(_params(since="2026-09-01", until="2026-09-04")))
    assert counters == {"caps": 1, "mitre": 1}
    assert all(call["srcip_paths"] for call in _fake_fetch.calls)


def test_backfill_never_becomes_auto_assignment_target():
    _run(_tool(_params(since="2026-09-01", until="2026-09-03")))
    with pytest.raises(BlueTeamMCPError) as excinfo:
        _run(_assign(cluster.AlertClusterAssignInput(srcip="203.0.113.7")))
    assert "backfill" in str(excinfo.value)


def test_explicit_assignment_to_backfill_fit_is_allowed():
    payload = json.loads(_run(_tool(_params(since="2026-09-01", until="2026-09-02"))))
    fit_id = payload["days"][0]["fit_id"]
    result = json.loads(_run(_assign(cluster.AlertClusterAssignInput(
        srcip="203.0.113.7", fit_id=fit_id, response_format="json"))))
    assert result["status"] == "ok"
    assert result["fit_id"] == fit_id


def test_live_fit_stays_newest_after_backfill():
    save_fit("live-x", {"min_cluster_size": 2}, [_STORE_CLUSTER], entity_count=3,
             noise_count=0,
             window={"since": "2026-09-09T00:00:00Z", "until": "2026-09-10T00:00:00Z"})
    _run(_tool(_params(since="2026-09-01", until="2026-09-03")))
    assert load_fit()["fit_id"] == "live-x"


def test_live_mode_keeps_random_ids_and_no_origin():
    payload = json.loads(_run(_tool(cluster.AlertClusterInput(
        mode="fit", response_format="json"))))
    assert payload["status"] == "ok"
    assert len(payload["fit_id"]) == 12
    assert not payload["fit_id"].startswith("bf-")
    assert "origin" not in load_fit(payload["fit_id"])["params"]


def test_srcip_buckets_counts_path_errors_and_partial_shards(monkeypatch):
    from mcp_server.tools import correlation

    async def _post(body, index_pattern=None):
        field = body["aggs"]["unique_srcips"]["terms"]["field"]
        if field == "data.srcip":
            return {"error": "boom"}
        return {"aggregations": {"unique_srcips": {"buckets": [
            {"key": "203.0.113.7", "doc_count": 2}]}},
            "_partial": True, "_failed_shards": 1}

    async def _caps(fields, index_pattern=None):
        return {"data.srcip.keyword": "keyword", "data.srcip": "keyword"}

    monkeypatch.setattr(correlation, "_wazuh_indexer_post", _post)
    monkeypatch.setattr(correlation, "_wazuh_indexer_field_caps", _caps)
    buckets, _warnings, failed, meta = _run(correlation._srcip_buckets(
        {"match_all": {}}, {}, "recon"))
    assert [bucket["key"] for bucket in buckets] == ["203.0.113.7"]
    assert failed is False
    assert meta["path_errors"] == 1
    assert meta["partial_shards"] == 1


def test_srcip_buckets_flags_mapping_fallback(monkeypatch):
    from mcp_server.tools import correlation

    async def _post(body, index_pattern=None):
        return {"aggregations": {"unique_srcips": {"buckets": []}}}

    async def _caps(fields, index_pattern=None):
        return {}

    monkeypatch.setattr(correlation, "_wazuh_indexer_post", _post)
    monkeypatch.setattr(correlation, "_wazuh_indexer_field_caps", _caps)
    _buckets, warnings, _failed, meta = _run(correlation._srcip_buckets(
        {"match_all": {}}, {}, "recon"))
    assert meta["fallback_paths"] == 1
    assert any("fallback" in warning or "data.srcip" in warning for warning in warnings)


def test_store_level_capacity_guard_is_atomic(monkeypatch):
    monkeypatch.setattr(config.cluster, "max_fits", 2)
    save_fit("live-1", {}, [_STORE_CLUSTER], entity_count=3, noise_count=0)
    save_fit("live-2", {}, [_STORE_CLUSTER], entity_count=3, noise_count=0)
    with pytest.raises(ClusterStoreError):
        save_fit("new-fit", {}, [_STORE_CLUSTER], entity_count=3, noise_count=0,
                 enforce_capacity=True)
    assert {fit["fit_id"] for fit in load_fit_history()} == {"live-1", "live-2"}
    save_fit("live-1", {"min_cluster_size": 9}, [_STORE_CLUSTER], entity_count=3,
             noise_count=0, enforce_capacity=True)
    assert store_stats()["fits"] == 2
