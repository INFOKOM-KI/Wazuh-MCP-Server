#!/usr/bin/env python3
"""
Contract and regression tests for ``source_core.evaluate_rolling`` and the
metric helpers, using the same deferred-import guard as ``test_source_core.py``.
"""
from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import pytest

DAY = 86400.0


def _core():
    try:
        import mcp_server.correlation.source_core as mod
    except ImportError as exc:
        pytest.fail(f"contract missing: mcp_server.correlation.source_core ({exc})")
    return mod


def _obs(ip, day, country):
    return {"source_ip": ip, "observed_at": day * DAY,
            "tactic": "Reconnaissance", "country": country}


OBS = [_obs("A", 0, "US"), _obs("B", 1, "DE"), _obs("A", 3, "US"), _obs("B", 4, "DE")]


def _evaluate(core, observations, cutoffs=[2 * DAY, 4 * DAY], **overrides):
    params = {"horizon_seconds": 2 * DAY, "history_seconds": 30 * DAY,
              "min_observations": 1, "min_transitions": 1}
    params.update(overrides)
    return core.evaluate_rolling(observations, cutoffs, **params)


def _point(result, cutoff):
    return next(point for point in result["points"] if point["cutoff_ts"] == cutoff)


def test_rolling_cutoffs_and_targets():
    core = _core()
    result = _evaluate(core, OBS)
    assert len(result["points"]) == 2
    assert [point["target_source"] for point in result["points"]] == ["A", "B"]
    assert all(point["target_status"] == "ok" for point in result["points"])


def test_training_is_strictly_before_cutoff():
    core = _core()
    result = _evaluate(core, OBS)
    for point in result["points"]:
        assert point["max_training_observed_at"] < point["cutoff_ts"]
    assert _point(result, 2 * DAY)["max_training_observed_at"] == DAY


def test_target_outside_horizon_is_not_selected():
    core = _core()
    observations = OBS + [_obs("C", 6, "SG")]
    result = _evaluate(core, observations)
    assert _point(result, 4 * DAY)["target_source"] == "B"


def test_future_observations_do_not_leak():
    core = _core()
    baseline = _evaluate(core, OBS)
    augmented = _evaluate(core, OBS + [_obs("Z", 5, "ZZ")])
    for cutoff in (2 * DAY, 4 * DAY):
        assert _point(baseline, cutoff)["models"] == _point(augmented, cutoff)["models"]


def test_persistence_baseline_is_independent():
    core = _core()
    result = _evaluate(core, OBS)
    assert _point(result, 2 * DAY)["models"]["persistence"] == {
        "source": "B", "country": "DE"}
    assert _point(result, 4 * DAY)["models"]["persistence"]["source"] == "A"


def test_frequency_baseline_and_tiebreak():
    core = _core()
    result = _evaluate(core, OBS)
    assert _point(result, 4 * DAY)["models"]["frequency"]["source"] == "A"
    assert _point(result, 2 * DAY)["models"]["frequency"]["source"] == "A"


def test_no_target_is_counted_and_excluded():
    core = _core()
    result = _evaluate(core, OBS, cutoffs=[2 * DAY, 6 * DAY])
    assert _point(result, 6 * DAY)["target_status"] == "no_target"
    assert result["counts"]["no_target"] == 1
    assert result["counts"]["evaluated"] == 1


def test_insufficient_history_is_counted():
    core = _core()
    result = _evaluate(core, OBS, cutoffs=[0.5 * DAY], min_observations=5)
    point = _point(result, 0.5 * DAY)
    assert point["status"] == "insufficient_history"
    assert result["counts"]["insufficient_history"] == 1


def test_metrics_match_point_hits():
    core = _core()
    result = _evaluate(core, OBS)
    evaluated = [point for point in result["points"]
                 if point["status"] == "ok" and point["target_status"] == "ok"]
    expected = sum(point["hits"]["full_model_source_top1"] for point in evaluated) / len(evaluated)
    assert result["metrics"]["full_model"]["source_top1"] == pytest.approx(expected)
    assert result["metrics"]["persistence"]["country_top1"] == pytest.approx(
        sum(point["hits"]["persistence_country_top1"] for point in evaluated) / len(evaluated))


def test_model_minus_persistence_delta():
    core = _core()
    result = _evaluate(core, OBS)
    full = result["metrics"]["full_model"]["country_top1"]
    persistence = result["metrics"]["persistence"]["country_top1"]
    assert result["metrics"]["model_minus_persistence"]["country_top1"] == pytest.approx(
        full - persistence)


def test_coverage_and_unique_candidates():
    core = _core()
    result = _evaluate(core, OBS)
    evaluated = result["counts"]["evaluated"]
    assert result["metrics"]["full_model"]["coverage"] == pytest.approx(
        evaluated / result["counts"]["cutoffs"])
    assert result["metrics"]["full_model"]["unique_candidates"] >= 1


def test_evaluation_is_reproducible():
    core = _core()
    assert _evaluate(core, OBS) == _evaluate(core, OBS)


def test_asn_is_marked_unavailable():
    core = _core()
    result = _evaluate(core, OBS)
    assert "asn" in result["metrics"]["unavailable"]
    assert "asn_top1" not in result["metrics"]["full_model"]


def test_every_point_records_training_cutoff():
    core = _core()
    result = _evaluate(core, OBS)
    for point in result["points"]:
        assert "training_cutoff" in point
        assert point["training_cutoff"] == point["cutoff_ts"]
