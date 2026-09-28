#!/usr/bin/env python3
"""
Tests for tools/forecast.py train / predict / status.
The Indexer fetch is monkeypatched, so the suite covers the tool logic (disabled
gate, insufficient corpus, store round-trip, per-entity sequence rebuild,
uniform fallback) without a live Indexer or hmmlearn. Tool bodies run through
``__wrapped__``; the decorator pipeline has its own test.
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
from mcp_server.core.forecast_store import load_model
from mcp_server.tools import forecast

_run = asyncio.run
_forecast = forecast.blueteam_tactic_forecast.__wrapped__

CORPUS = {
    "203.0.113.7": ["Reconnaissance", "Initial Access", "Execution", "Command and Control"],
    "203.0.113.8": ["Reconnaissance", "Initial Access", "Execution", "Command and Control"],
    "203.0.113.9": ["Reconnaissance", "Initial Access", "Persistence", "Command and Control"],
    "198.51.100.4": ["Discovery", "Lateral Movement", "Exfiltration"],
    "198.51.100.5": ["Discovery", "Lateral Movement", "Exfiltration"],
    "198.51.100.6": ["Discovery", "Credential Access", "Lateral Movement", "Exfiltration"],
}


async def _fake_fetch(srcip, since_iso, until_iso):
    _fake_fetch.calls.append(srcip)
    rows = []
    for entity, tactics in CORPUS.items():
        if srcip and srcip != entity:
            continue
        rows += [{"entity_key": entity, "tactic": tactic,
                  "observed_at": _FAKE_BASE + offset * 10.0}
                 for offset, tactic in enumerate(tactics)]
    return {"rows": rows, "warnings": [], "truncated": False, "skipped_no_entity": 0}


_FAKE_BASE = time.time() - 300.0
_fake_fetch.calls = []


@pytest.fixture(autouse=True)
def _setup(tmp_path, monkeypatch):
    config.forecast.enabled = True
    config.forecast.store_path = str(tmp_path / "forecast.db")
    config.forecast.min_sequences = 5
    config.forecast.min_transitions = 10
    config.forecast.min_support = 2
    config.forecast.alpha = 1.0
    config.forecast.hmm_components = 2
    config.forecast.hmm_min_sequences = 5
    _fake_fetch.calls = []
    monkeypatch.setattr(forecast, "_fetch_tactic_observations", _fake_fetch)
    yield
    config.forecast.enabled = False
    config.forecast.store_path = ""


def _train_params(**overrides):
    return forecast.TacticForecastInput(mode="train", response_format="json", **overrides)


def test_disabled_tool_raises_enable_hint():
    config.forecast.enabled = False
    with pytest.raises(BlueTeamMCPError):
        _run(_forecast(forecast.TacticForecastInput(mode="status")))


def test_train_persists_a_markov_model():
    payload = json.loads(_run(_forecast(_train_params())))
    assert payload["status"] == "ok"
    assert payload["kind"] == "markov"
    assert payload["entity_count"] == 6
    assert payload["n_sequences"] == 6
    assert payload["top_transitions"][0]["count"] >= 1
    assert load_model(payload["model_id"])["model_id"] == payload["model_id"]


def test_train_output_carries_no_entity_keys():
    result = _run(_forecast(forecast.TacticForecastInput(mode="train")))
    assert "203.0.113.7" not in result


def test_train_is_idempotent_by_content_hash():
    first = json.loads(_run(_forecast(_train_params())))
    second = json.loads(_run(_forecast(_train_params())))
    assert first["model_id"] == second["model_id"]
    assert second["observations_appended"] == 0


def test_train_without_rows_is_insufficient(monkeypatch):
    async def _empty(srcip, since_iso, until_iso):
        return {"rows": [], "warnings": [], "truncated": False, "skipped_no_entity": 0}

    monkeypatch.setattr(forecast, "_fetch_tactic_observations", _empty)
    payload = json.loads(_run(_forecast(_train_params())))
    assert payload["status"] == "insufficient_data"


def test_train_below_sample_floor_is_insufficient_not_empty(monkeypatch):
    async def _one_entity(srcip, since_iso, until_iso):
        return {"rows": [{"entity_key": "203.0.113.7", "tactic": "Discovery",
                          "observed_at": time.time() - 60.0}],
                "warnings": [], "truncated": False, "skipped_no_entity": 0}

    monkeypatch.setattr(forecast, "_fetch_tactic_observations", _one_entity)
    payload = json.loads(_run(_forecast(_train_params())))
    assert payload["status"] == "insufficient_data"
    assert "minimum" in payload["reason"]


def test_predict_from_current_tactic():
    _run(_forecast(_train_params()))
    payload = json.loads(_run(_forecast(forecast.TacticForecastInput(
        mode="predict", current_tactic="Reconnaissance", top_k=3, response_format="json"))))
    assert payload["status"] == "ok"
    assert payload["prediction"]["predictions"][0]["tactic"] == "Initial Access"
    assert payload["prediction"]["support"] == 3
    assert payload["prediction"]["low_support"] is False


def test_predict_srcip_rebuilds_sequence_and_reports_anomaly():
    _run(_forecast(_train_params()))
    payload = json.loads(_run(_forecast(forecast.TacticForecastInput(
        mode="predict", srcip="203.0.113.7", response_format="json"))))
    assert payload["status"] == "ok"
    assert payload["prediction"]["current_tactic"] == "Command and Control"
    assert payload["anomaly"]["status"] == "ok"
    assert payload["prediction"]["escalation_probability"] > 0


def test_predict_srcip_not_observed():
    _run(_forecast(_train_params()))
    payload = json.loads(_run(_forecast(forecast.TacticForecastInput(
        mode="predict", srcip="192.0.2.99", response_format="json"))))
    assert payload["status"] == "not_observed"


def test_predict_unseen_tactic_is_uniform_with_flag():
    _run(_forecast(_train_params()))
    payload = json.loads(_run(_forecast(forecast.TacticForecastInput(
        mode="predict", current_tactic="not-a-tactic", response_format="json"))))
    assert payload["prediction"]["uniform_fallback"] is True


def test_predict_without_anchor_raises():
    _run(_forecast(_train_params()))
    with pytest.raises(BlueTeamMCPError):
        _run(_forecast(forecast.TacticForecastInput(mode="predict")))


def test_hmm_kind_reports_unavailable_or_fits():
    payload = json.loads(_run(_forecast(_train_params(kind="hmm"))))
    if payload["status"] == "unavailable":
        assert "hmmlearn" in payload["reason"]
    else:
        assert payload["status"] == "ok"
        assert payload["kind"] == "hmm"
        assert payload["n_components"] == 2


def test_status_before_and_after_train():
    before = json.loads(_run(_forecast(forecast.TacticForecastInput(
        mode="status", response_format="json"))))
    assert before["status"] == "no_model"
    _run(_forecast(_train_params()))
    after = json.loads(_run(_forecast(forecast.TacticForecastInput(
        mode="status", response_format="json"))))
    assert after["status"] == "ok"
    assert after["model"]["kind"] == "markov"
    assert after["store"]["observations"] >= 6
