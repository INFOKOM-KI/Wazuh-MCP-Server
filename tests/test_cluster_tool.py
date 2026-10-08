#!/usr/bin/env python3
"""Tests for tools/cluster.py fit / assign.
The Indexer aggregation and HDBSCAN are both monkeypatched, so the suite covers
the tool logic (disabled gate, insufficient population, store round-trip, cached
assignment, not-observed entity) without scikit-learn or a live Indexer. Tool
bodies run through ``__wrapped__``; the decorator pipeline has its own test.
"""
from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import asyncio
import json
import math
import pytest
from mcp_server.core.config import config
from mcp_server.core.cluster_store import load_fit
from mcp_server.core.exceptions import BlueTeamMCPError
from mcp_server.tools import cluster


def _run(coro):
    return asyncio.run(coro)


_fit = cluster.blueteam_alert_cluster.__wrapped__
_assign = cluster.blueteam_alert_cluster_assign.__wrapped__

PROFILES = {
    "203.0.113.7": {"tactics": {"Command and Control": 30.0}, "score_a": 0.0,
                    "score_b": 12.0, "score_c": 30.0, "total": 72.0, "alert_count": 5},
    "203.0.113.8": {"tactics": {"Discovery": 6.0}, "score_a": 6.0,
                    "score_b": 0.0, "score_c": 0.0, "total": 6.0, "alert_count": 2},
    "203.0.113.9": {"tactics": {"Impact": 8.0}, "score_a": 0.0,
                    "score_b": 3.0, "score_c": 4.0, "total": 12.5, "alert_count": 3},
}


async def _fake_fetch(categories, since_iso, until_iso, use_mitre=True,
                      technique_tactics=None, category_techniques=None, srcip=None):
    _fake_fetch.calls.append(srcip)
    profiles = PROFILES if not srcip else {k: v for k, v in PROFILES.items() if k == srcip}
    return {"profiles": dict(profiles), "warnings": [], "failures": 0}


_fake_fetch.calls = []


def _fake_fit(vectors, min_cluster_size=5, min_samples=3, clusterer=None):
    members = vectors[:2]
    centroid = [sum(v[i] for v in members) / len(members) for i in range(len(members[0]))]
    # Real `fit_clusters` derives the radius from member distances; a hardcoded
    # small radius would make the assignment test assert on the fixture, not the tool.
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
    config.cluster.enabled = True
    config.cluster.store_path = str(tmp_path / "clusters.db")
    config.cluster.min_cluster_size = 2
    config.cluster.min_samples = 1
    config.cluster.assign_factor = 1.0
    _fake_fetch.calls = []
    monkeypatch.setattr(cluster, "fetch_srcip_profiles", _fake_fetch)
    monkeypatch.setattr(cluster, "fit_clusters", _fake_fit)
    yield
    config.cluster.enabled = False
    config.cluster.store_path = ""


def _fit_params(**overrides):
    return cluster.AlertClusterInput(**overrides)


def test_disabled_tool_raises_enable_hint():
    config.cluster.enabled = False
    with pytest.raises(BlueTeamMCPError):
        _run(_fit(_fit_params()))


def test_fit_persists_and_reports_clusters():
    payload = json.loads(_run(_fit(_fit_params(response_format="json"))))
    assert payload["status"] == "ok"
    assert payload["entity_count"] == 3
    assert payload["clusters"][0]["label"] == 0
    assert payload["clusters"][0]["top_tactics"] == ["Command and Control"]
    assert load_fit(payload["fit_id"])["feature_version"] == payload["feature_version"]


def test_fit_without_entities_is_insufficient_not_empty(monkeypatch):
    async def _empty(categories, since_iso, until_iso, **kwargs):
        return {"profiles": {}, "warnings": [], "failures": 0}
    monkeypatch.setattr(cluster, "fetch_srcip_profiles", _empty)
    payload = json.loads(_run(_fit(_fit_params(response_format="json"))))
    assert payload["status"] == "insufficient_data"


def test_unavailable_clusterer_is_reported(monkeypatch):
    monkeypatch.setattr(cluster, "fit_clusters", lambda *a, **k: {
        "status": "unavailable", "entity_count": 3, "reason": "scikit-learn is not installed"})
    payload = json.loads(_run(_fit(_fit_params(response_format="json"))))
    assert payload["status"] == "unavailable"
    assert "scikit-learn" in payload["reason"]


def test_status_before_and_after_fit():
    assert json.loads(_run(_fit(_fit_params(mode="status", response_format="json"))))["status"] == "no_fit"
    _run(_fit(_fit_params()))
    status = json.loads(_run(_fit(_fit_params(mode="status", response_format="json"))))
    assert status["status"] == "ok"
    assert status["cluster_count"] == 1


def test_assign_uncached_labels_entity():
    _run(_fit(_fit_params()))
    payload = json.loads(_run(_assign(cluster.AlertClusterAssignInput(
        srcip="203.0.113.7", response_format="json"))))
    assert payload["status"] == "ok"
    assert payload["assignment"]["label"] == 0
    assert payload["assignment"]["novelty"] is False
    assert payload["assignment"]["cached"] is False


def test_assign_cached_skips_the_indexer():
    _run(_fit(_fit_params()))
    _run(_assign(cluster.AlertClusterAssignInput(srcip="203.0.113.7")))
    before = len(_fake_fetch.calls)
    payload = json.loads(_run(_assign(cluster.AlertClusterAssignInput(
        srcip="203.0.113.7", response_format="json"))))
    assert payload["assignment"]["cached"] is True
    assert len(_fake_fetch.calls) == before


def test_assign_not_observed_is_explicit():
    _run(_fit(_fit_params()))
    payload = json.loads(_run(_assign(cluster.AlertClusterAssignInput(
        srcip="198.51.100.4", response_format="json"))))
    assert payload["status"] == "not_observed"


def test_assign_without_fit_raises():
    with pytest.raises(BlueTeamMCPError):
        _run(_assign(cluster.AlertClusterAssignInput(srcip="203.0.113.7")))


def test_fit_stamps_the_window_it_scored_in():
    payload = json.loads(_run(_fit(_fit_params(
        time_window_minutes=1440, response_format="json"))))
    window = load_fit(payload["fit_id"])["window"]
    assert window["since"] and window["until"]


def test_assign_refuses_a_window_the_fit_did_not_score_in():
    payload = json.loads(_run(_fit(_fit_params(
        time_window_minutes=1440, response_format="json"))))
    with pytest.raises(BlueTeamMCPError):
        _run(_assign(cluster.AlertClusterAssignInput(
            srcip="203.0.113.7", fit_id=payload["fit_id"], time_window_minutes=10080)))


def test_assign_refuses_a_window_mismatch_before_reading_the_cache():
    """A cache hit must not bypass the guard: the stored label was computed in
    the fit's space, so it is exactly as wrong as a fresh one.
    """
    payload = json.loads(_run(_fit(_fit_params(
        time_window_minutes=1440, response_format="json"))))
    _run(_assign(cluster.AlertClusterAssignInput(
        srcip="203.0.113.7", fit_id=payload["fit_id"], time_window_minutes=1440)))
    with pytest.raises(BlueTeamMCPError):
        _run(_assign(cluster.AlertClusterAssignInput(
            srcip="203.0.113.7", fit_id=payload["fit_id"], time_window_minutes=10080,
            use_cached=True)))


# fetch health: `_degraded` is orthogonal to `status`


def _fetch_payload(profiles, **counters):
    return {"profiles": dict(profiles), "warnings": [], "failures": 0, **counters}


def test_fit_empty_with_degraded_fetch_is_not_reported_as_an_empty_window(monkeypatch):
    async def _empty(categories, since_iso, until_iso, **kwargs):
        return _fetch_payload({}, failures=3, path_errors=1)

    monkeypatch.setattr(cluster, "fetch_srcip_profiles", _empty)
    payload = json.loads(_run(_fit(_fit_params(response_format="json"))))
    assert payload["status"] == "insufficient_data"
    assert payload["_degraded"] is True
    assert payload["fetch"]["failures"] == 3
    assert "fetch degraded" in payload["reason"]
    assert "hint" not in payload


def test_fit_empty_with_healthy_fetch_keeps_the_population_hint(monkeypatch):
    async def _empty(categories, since_iso, until_iso, **kwargs):
        return _fetch_payload({})

    monkeypatch.setattr(cluster, "fetch_srcip_profiles", _empty)
    payload = json.loads(_run(_fit(_fit_params(response_format="json"))))
    assert payload["status"] == "insufficient_data"
    assert payload["fetch"]["degraded"] is False
    assert "_degraded" not in payload
    assert "No srcip entities" in payload["hint"]
    assert "reason" not in payload


@pytest.mark.parametrize("counters", [{"failures": 1}, {"path_errors": 2},
                                      {"partial_shards": 4}, {"fallback_paths": 1}])
def test_fit_on_partial_fetch_is_marked_degraded_and_still_persisted(monkeypatch, counters):
    async def _partial(categories, since_iso, until_iso, **kwargs):
        return _fetch_payload(PROFILES, **counters)

    monkeypatch.setattr(cluster, "fetch_srcip_profiles", _partial)
    payload = json.loads(_run(_fit(_fit_params(response_format="json"))))
    assert payload["status"] == "ok"
    assert payload["_degraded"] is True
    for key, value in counters.items():
        assert payload["fetch"][key] == value
    assert load_fit(payload["fit_id"])["entity_count"] == 3


def test_fit_with_healthy_fetch_carries_no_degraded_marker():
    payload = json.loads(_run(_fit(_fit_params(response_format="json"))))
    assert payload["status"] == "ok"
    assert payload["fetch"]["degraded"] is False
    assert "_degraded" not in payload


def test_degraded_fit_markdown_names_the_incomplete_fetch(monkeypatch):
    async def _partial(categories, since_iso, until_iso, **kwargs):
        return _fetch_payload(PROFILES, failures=1)

    monkeypatch.setattr(cluster, "fetch_srcip_profiles", _partial)
    out = _run(_fit(_fit_params()))
    assert "Data fetch degraded" in out


def test_assign_not_observed_with_degraded_fetch_reports_unknown(monkeypatch):
    _run(_fit(_fit_params()))

    async def _degraded(categories, since_iso, until_iso, **kwargs):
        return _fetch_payload({}, failures=3)

    monkeypatch.setattr(cluster, "fetch_srcip_profiles", _degraded)
    payload = json.loads(_run(_assign(cluster.AlertClusterAssignInput(
        srcip="198.51.100.4", response_format="json", use_cached=False))))
    assert payload["status"] == "not_observed"
    assert payload["_degraded"] is True
    assert "may be unobserved" in payload["reason"]
    assert "hint" not in payload
    out = _run(_assign(cluster.AlertClusterAssignInput(
        srcip="198.51.100.4", use_cached=False)))
    assert "`_degraded`" in out


def test_assign_not_observed_with_healthy_fetch_keeps_the_plain_hint():
    _run(_fit(_fit_params()))
    payload = json.loads(_run(_assign(cluster.AlertClusterAssignInput(
        srcip="198.51.100.4", response_format="json", use_cached=False))))
    assert payload["status"] == "not_observed"
    assert payload["fetch"]["degraded"] is False
    assert "_degraded" not in payload
    assert "No alert for this entity" in payload["hint"]


def test_below_min_fit_with_degraded_fetch_markdown_shows_both_reasons(monkeypatch):
    async def _partial(categories, since_iso, until_iso, **kwargs):
        return _fetch_payload(PROFILES, failures=1)

    monkeypatch.setattr(cluster, "fetch_srcip_profiles", _partial)
    monkeypatch.setattr(cluster, "fit_clusters", lambda *a, **k: {
        "status": "insufficient_data", "entity_count": 3,
        "reason": "3 entities < min_cluster_size 5"})
    out = _run(_fit(_fit_params()))
    assert "3 entities < min_cluster_size 5" in out
    assert "Data fetch degraded" in out


def test_below_min_fit_with_healthy_fetch_markdown_is_unchanged(monkeypatch):
    monkeypatch.setattr(cluster, "fit_clusters", lambda *a, **k: {
        "status": "insufficient_data", "entity_count": 3,
        "reason": "3 entities < min_cluster_size 5"})
    out = _run(_fit(_fit_params()))
    assert out == ("# Alert Entity Clustering\n\n**Status**: `insufficient_data`\n\n"
                   "3 entities < min_cluster_size 5")
