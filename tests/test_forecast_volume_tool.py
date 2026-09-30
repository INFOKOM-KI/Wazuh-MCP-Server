#!/usr/bin/env python3
"""
Tests for tools/forecast.py volume path (blueteam_volume_forecast).
The Indexer aggregation is monkeypatched and the optional hmmlearn fitter is
injected as a hand-built two-regime model, so train, store round-trip and the
pure-arithmetic predict path all run on a host without hmmlearn. The guards are
exercised against the real fitter where no library is needed (thin, all-zero,
constant series).
"""
from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import asyncio
import json
import time
import pytest
from mcp_server.core.config import config
from mcp_server.core.exceptions import BlueTeamMCPError
from mcp_server.core.forecast_store import load_model, save_model, store_stats
from mcp_server.correlation.forecast_core import fit_poisson_hmm as real_fit
from mcp_server.tools import forecast

_run = asyncio.run
_volume = forecast.blueteam_volume_forecast.__wrapped__

# 24 hourly buckets: 12 quiet, 12 busy. The last four (the predict context) are
# all in the busy regime, so the posterior is deterministic enough to assert on.
BUCKETS = [2, 3, 1, 4, 2, 3, 1, 2, 4, 3, 2, 1] + [20, 25, 18, 22, 24, 21, 23, 19, 26, 20, 22, 24]
_BASE = time.time() - 23 * 3600.0


async def _fake_buckets(since_iso, until_iso, bucket_interval):
    _fake_buckets.calls.append(bucket_interval)
    return {"buckets": [{"ts": _BASE + index * 3600.0, "count": count}
                        for index, count in enumerate(BUCKETS)],
            "error": None, "warnings": []}


_fake_buckets.calls = []


def _fake_fit(counts, n_components=3, min_buckets=48, seed=42, n_iter=50):
    _fake_fit.calls.append((len(counts), n_components, min_buckets))
    return {"status": "ok", "kind": forecast.VOLUME_KIND, "lambdas": [1.0, 10.0],
            "startprob": [0.5, 0.5], "transmat": [[0.9, 0.1], [0.1, 0.9]],
            "n_buckets": len(counts), "n_components": int(n_components),
            "seed": int(seed), "n_iter": int(n_iter)}


_fake_fit.calls = []


@pytest.fixture(autouse=True)
def _setup(tmp_path, monkeypatch):
    config.forecast.enabled = True
    config.forecast.store_path = str(tmp_path / "forecast.db")
    config.forecast.store_max = 1000
    config.forecast.retention_days = 365
    config.forecast.volume_min_buckets = 8
    config.forecast.volume_components = 2
    config.forecast.volume_horizon_buckets = 4
    config.forecast.volume_context_buckets = 4
    config.forecast.hmm_seed = 42
    config.forecast.hmm_iter = 10
    _fake_buckets.calls = []
    _fake_fit.calls = []
    monkeypatch.setattr(forecast, "_fetch_volume_buckets", _fake_buckets)
    monkeypatch.setattr(forecast, "fit_poisson_hmm", _fake_fit)
    yield
    config.forecast.enabled = False
    config.forecast.store_path = ""


def _params(**overrides):
    return forecast.VolumeForecastInput(mode="train", time_window_minutes=2880,
                                        response_format="json", **overrides)


def test_disabled_tool_raises_enable_hint():
    config.forecast.enabled = False
    with pytest.raises(BlueTeamMCPError):
        _run(_volume(forecast.VolumeForecastInput(mode="status")))


def test_train_persists_a_volume_model():
    payload = json.loads(_run(_volume(_params())))
    assert payload["status"] == "ok"
    assert payload["kind"] == "poisson_hmm"
    assert payload["n_buckets"] == len(BUCKETS)
    assert payload["lambdas"] == [1.0, 10.0]
    assert payload["bucket_interval"] == "1h"
    stored = load_model(payload["model_id"])
    assert stored["kind"] == "poisson_hmm"
    assert stored["lambdas"] == [1.0, 10.0]


def test_train_is_idempotent_over_the_same_buckets():
    first = json.loads(_run(_volume(_params())))
    second = json.loads(_run(_volume(_params())))
    assert first["model_id"] == second["model_id"]
    assert store_stats()["counts"] == len(BUCKETS)


def test_train_without_buckets_is_insufficient(monkeypatch):
    async def _empty(since_iso, until_iso, bucket_interval):
        return {"buckets": [], "error": None, "warnings": []}

    monkeypatch.setattr(forecast, "_fetch_volume_buckets", _empty)
    payload = json.loads(_run(_volume(_params())))
    assert payload["status"] == "insufficient_data"


def test_train_all_zero_series_is_insufficient(monkeypatch):
    async def _zeros(since_iso, until_iso, bucket_interval):
        return {"buckets": [{"ts": _BASE + index * 3600.0, "count": 0}
                            for index in range(len(BUCKETS))],
                "error": None, "warnings": []}

    monkeypatch.setattr(forecast, "_fetch_volume_buckets", _zeros)
    monkeypatch.setattr(forecast, "fit_poisson_hmm", real_fit)
    payload = json.loads(_run(_volume(_params())))
    assert payload["status"] == "insufficient_data"
    assert "zero" in payload["reason"]


def test_train_constant_series_is_insufficient(monkeypatch):
    async def _constant(since_iso, until_iso, bucket_interval):
        return {"buckets": [{"ts": _BASE + index * 3600.0, "count": 5}
                            for index in range(len(BUCKETS))],
                "error": None, "warnings": []}

    monkeypatch.setattr(forecast, "_fetch_volume_buckets", _constant)
    monkeypatch.setattr(forecast, "fit_poisson_hmm", real_fit)
    payload = json.loads(_run(_volume(_params())))
    assert payload["status"] == "insufficient_data"
    assert "constant" in payload["reason"]


def test_train_reports_unavailable_when_hmmlearn_is_missing(monkeypatch):
    monkeypatch.setattr(forecast, "fit_poisson_hmm",
                        lambda *a, **k: {"status": "unavailable", "reason": "hmmlearn is not installed"})
    payload = json.loads(_run(_volume(_params())))
    assert payload["status"] == "unavailable"
    assert "hmmlearn" in payload["reason"]


def test_predict_rolls_the_horizon_from_the_stored_model():
    _run(_volume(_params()))
    payload = json.loads(_run(_volume(forecast.VolumeForecastInput(
        mode="predict", horizon_buckets=2, response_format="json"))))
    assert payload["status"] == "ok"
    assert payload["horizon_seconds"] == 7200
    assert payload["context_buckets_used"] == 4
    prediction = payload["prediction"]
    # Context is all busy buckets, so the posterior sits on the high regime:
    # step 1 = 0.1*1 + 0.9*10, step 2 = 0.18*1 + 0.82*10.
    assert prediction["expected_counts"] == pytest.approx([9.1, 8.38], abs=1e-2)
    assert prediction["peak_probability"] == 1.0
    assert prediction["posterior_fallback"] is False


def test_predict_respects_context_buckets():
    _run(_volume(_params()))
    payload = json.loads(_run(_volume(forecast.VolumeForecastInput(
        mode="predict", context_buckets=1, horizon_buckets=1, response_format="json"))))
    assert payload["context_buckets_used"] == 1


def test_predict_without_a_model_raises():
    with pytest.raises(BlueTeamMCPError):
        _run(_volume(forecast.VolumeForecastInput(mode="predict", response_format="json")))


def test_predict_refuses_a_tactic_model(monkeypatch):
    """An explicit model_id naming a tactic fit is refused, not scored."""
    monkeypatch.setattr(forecast, "load_model",
                        lambda model_id=None, kinds=None: {"kind": "markov", "model_id": "m1"})
    with pytest.raises(BlueTeamMCPError):
        _run(_volume(forecast.VolumeForecastInput(mode="predict", model_id="m1",
                                                  response_format="json")))


def test_predict_ignores_a_newer_tactic_fit():
    """Regression: the unnamed lookup resolved the newest row of any kind, so a
    newer tactic fit made predict raise instead of forecasting."""
    trained = json.loads(_run(_volume(_params())))
    time.sleep(0.02)
    save_model("hmm-newest", "hmm", {}, [1.0], [[1.0]], n_sequences=1, n_transitions=1)
    assert load_model()["model_id"] == "hmm-newest"
    payload = json.loads(_run(_volume(forecast.VolumeForecastInput(
        mode="predict", response_format="json"))))
    assert payload["model"] == trained["model_id"]
    assert payload["prediction"]["status"] != "error"


def test_predict_markdown_summarises_long_horizons():
    _run(_volume(_params()))
    # Exercises the >24-row truncation branch in the markdown renderer.
    result = _run(_volume(forecast.VolumeForecastInput(mode="predict", horizon_buckets=30)))
    assert "more buckets" in result


def test_status_before_and_after_train():
    before = json.loads(_run(_volume(forecast.VolumeForecastInput(
        mode="status", response_format="json"))))
    assert before["status"] == "no_model"
    assert before["store"]["counts"] == 0
    _run(_volume(_params()))
    after = json.loads(_run(_volume(forecast.VolumeForecastInput(
        mode="status", response_format="json"))))
    assert after["status"] == "ok"
    assert after["store"]["counts"] == len(BUCKETS)
    assert after["model"]["kind"] == "poisson_hmm"
