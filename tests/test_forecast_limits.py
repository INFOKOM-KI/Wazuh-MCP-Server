#!/usr/bin/env python3
"""
Limit tests for the forecast subsystem (tests only, no behavior changes).
Pins the tactic/volume observation-window boundaries, the volume bucket math at
the 25-day interval switch, the max_hits truncation path, a 30-day paged sweep,
and the estimators' independence from calendar-day parameters.
"""
from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import asyncio
import inspect
from datetime import datetime, timedelta, timezone
import pytest
from pydantic import ValidationError
from mcp_server.core.config import config
from mcp_server.correlation.forecast_core import (
    fit_categorical_hmm,
    fit_markov_chain,
    fit_poisson_hmm,
)
from mcp_server.tools import forecast
from mcp_server.wazuh.time_utils import _auto_bucket_interval

_run = asyncio.run

_TACTICS = ["Reconnaissance", "Initial Access", "Execution", "Command and Control"]


class _FakeIndexer:
    """Serves ``_wazuh_indexer_post`` pages newest-first plus exact-count probes."""

    def __init__(self, hits, *, verify_total=None):
        self.hits = sorted(hits, key=lambda item: (item["sort"][0], item["sort"][1]),
                           reverse=True)
        self.verify_total = verify_total
        self.calls = []

    async def __call__(self, body, index_pattern=None):
        self.calls.append(body)
        if int(body.get("size") or 0) == 0 and body.get("track_total_hits"):
            total = self.verify_total if self.verify_total is not None else len(self.hits)
            return {"hits": {"total": {"value": total, "relation": "eq"}, "hits": []}}
        after = body.get("search_after")
        use_id = any("_id" in field for field in body.get("sort") or [])
        candidates = self.hits
        if after:
            if use_id:
                key = (after[0], after[1])
                candidates = [h for h in self.hits
                              if (h["sort"][0], h["sort"][1]) < key]
            else:
                candidates = [h for h in self.hits if h["sort"][0] < after[0]]
        page = [dict(h) for h in candidates[:int(body.get("size") or 0)]]
        return {"hits": {"hits": page}}


def _hit(index: int, when: datetime, entity: str, tactic: str) -> dict:
    hit_id = f"doc-{index:04d}"
    return {
        "_id": hit_id,
        "_source": {"@timestamp": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "data": {"srcip": entity},
                    "rule": {"mitre": {"tactic": tactic}}},
        "sort": [int(when.timestamp() * 1000), hit_id],
    }


def _varying(count: int) -> list[int]:
    return [1 + (index % 3) for index in range(count)]


def test_tactic_window_boundary_and_default():
    assert forecast.TacticForecastInput().time_window_minutes == 10080
    assert forecast.TacticForecastInput(time_window_minutes=43200).time_window_minutes == 43200
    with pytest.raises(ValidationError):
        forecast.TacticForecastInput(time_window_minutes=43201)
    with pytest.raises(ValidationError):
        forecast.TacticForecastInput(time_window_minutes=4)


def test_volume_window_bucket_consistency_at_25_days():
    assert _auto_bucket_interval(36000) == "6h"
    assert 36000 // 360 == 100
    result = fit_poisson_hmm(_varying(100), n_components=3, min_buckets=48)
    assert result["status"] != "insufficient_data"


def test_volume_window_bucket_consistency_over_25_days():
    assert _auto_bucket_interval(36001) == "1d"
    assert 36001 // 1440 == 25
    result = fit_poisson_hmm(_varying(25), n_components=3, min_buckets=48)
    assert result["status"] == "insufficient_data"
    assert "below the configured minimum" in result["reason"]


def test_volume_cap_accepts_thirty_days_but_default_floor_rejects_it():
    assert forecast.VolumeForecastInput(time_window_minutes=43200).time_window_minutes == 43200
    with pytest.raises(ValidationError):
        forecast.VolumeForecastInput(time_window_minutes=43201)
    assert _auto_bucket_interval(43200) == "1d"
    assert 43200 // 1440 == 30 < 48
    result = fit_poisson_hmm(_varying(30), n_components=3, min_buckets=48)
    assert result["status"] == "insufficient_data"


def test_dense_window_beyond_max_hits_is_marked_incomplete(monkeypatch):
    monkeypatch.setattr(config.forecast, "fetch_page_size", 2)
    monkeypatch.setattr(config.forecast, "max_hits", 5)
    base = datetime(2026, 8, 1, tzinfo=timezone.utc)
    hits = [_hit(i, base + timedelta(minutes=i), "203.0.113.7", "Reconnaissance")
            for i in range(8)]
    monkeypatch.setattr(forecast, "_wazuh_indexer_post", _FakeIndexer(hits))
    result = _run(forecast._fetch_tactic_observations(
        None, "2026-08-01T00:00:00Z", "2026-08-02T00:00:00Z"))
    assert result["window_complete"] is False
    assert result["truncated"] is True
    assert result["stop_reason"] == "max_hits"
    assert result["missing_portion"] == "oldest"
    assert result["fetched_hits"] == 5
    assert result["verified_count"] == 8
    assert result["snapshot_consistent"] is False
    assert any("oldest" in warning for warning in result["warnings"])
    observed = {row["observed_at"] for row in result["rows"]}
    assert observed == {(base + timedelta(minutes=i)).timestamp() for i in range(3, 8)}
    block = forecast._corpus_block(result, result["rows"], {"entities": 1, "sequences": []},
                                   {"n_transitions": 0},
                                   "2026-08-01T00:00:00Z", "2026-08-02T00:00:00Z")
    assert block["fetch"]["stop_reason"] == "max_hits"
    assert block["fit"]["complete"] is False
    assert "fetch_max_hits" in block["fit"]["incomplete_reasons"]


def test_thirty_day_tactic_sweep_pages_and_verifies(monkeypatch):
    monkeypatch.setattr(config.forecast, "fetch_page_size", 50)
    monkeypatch.setattr(config.forecast, "max_hits", 1000)
    start = datetime(2026, 7, 3, tzinfo=timezone.utc)
    entities = ["203.0.113.7", "203.0.113.8", "198.51.100.4"]
    hits = [_hit(i, start + timedelta(days=i / 4), entities[i % 3], _TACTICS[i % 4])
            for i in range(120)]
    monkeypatch.setattr(forecast, "_wazuh_indexer_post", _FakeIndexer(hits))
    result = _run(forecast._fetch_tactic_observations(
        None, "2026-07-03T00:00:00Z", "2026-08-02T00:00:00Z"))
    assert result["window_complete"] is True
    assert result["snapshot_consistent"] is True
    assert result["stop_reason"] == "exhausted"
    assert result["pages"] == 3
    assert result["fetched_hits"] == 120
    assert result["verified_count"] == 120
    assert len(result["rows"]) == 120
    sequences = forecast.build_sequences(result["rows"])["sequences"]
    assert len(sequences) == 3
    fit = fit_markov_chain(sequences, min_sequences=2, min_transitions=1)
    assert fit["status"] == "ok"


def test_estimators_take_no_calendar_parameters():
    forbidden = {"days", "day", "window", "window_minutes", "time_window_minutes",
                 "since", "until"}
    for func in (fit_markov_chain, fit_categorical_hmm, fit_poisson_hmm):
        names = set(inspect.signature(func).parameters)
        assert not names & forbidden, (func.__name__, sorted(names))


def test_estimators_operate_on_observations_not_days():
    sequences = [["Reconnaissance", "Initial Access", "Execution"],
                 ["Reconnaissance", "Initial Access", "Command and Control"]]
    chain = fit_markov_chain(sequences, alpha=1.0, min_sequences=2, min_transitions=2)
    assert chain["status"] == "ok"
    hmm = fit_categorical_hmm(sequences, n_components=2, min_sequences=2)
    assert hmm["status"] in ("ok", "unavailable")
    volume = fit_poisson_hmm(_varying(60), n_components=3, min_buckets=48)
    assert volume["status"] in ("ok", "unavailable")
