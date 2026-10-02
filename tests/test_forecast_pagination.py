#!/usr/bin/env python3
"""
Pagination and corpus-completeness tests for tools/forecast.py.
The Indexer is faked at ``_wazuh_indexer_post``, so the paging loop
(search_after cursors, tiebreaker fallback, hit cap, shard partials, mid-sweep
errors, timestamp collisions) runs without a live cluster. Tool-level tests
monkeypatch ``_fetch_tactic_observations`` to cover strict-mode refusal and
the persisted corpus stamp.
"""
from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import asyncio
import json
import time as _time
from datetime import datetime, timedelta, timezone
import pytest
from mcp_server.core.config import ForecastConfig, config
from mcp_server.core.exceptions import ConfigurationError
from mcp_server.core.forecast_store import load_model
from mcp_server.tools import forecast

_run = asyncio.run
_forecast = forecast.blueteam_tactic_forecast.__wrapped__
_SINCE = "2026-08-01T00:00:00Z"
_UNTIL = "2026-09-10T00:00:00Z"
_BASE = datetime(2026, 9, 1, tzinfo=timezone.utc)


def _hit(index, tactic="Reconnaissance", entity="203.0.113.7", stamp=None):
    when = stamp if stamp is not None else _BASE + timedelta(seconds=index)
    hit_id = f"doc-{index:05d}"
    return {
        "_id": hit_id,
        "_source": {"@timestamp": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "data": {"srcip": entity},
                    "rule": {"mitre": {"tactic": tactic}}},
        "sort": [int(when.timestamp() * 1000), hit_id],
    }


class FakeIndexer:
    """Serves ``_wazuh_indexer_post`` pages from a fixed hit list, newest first."""

    def __init__(self, hits, *, reject_id_sort=False, fail_page=None,
                 partial_page=None, missing_sort_page=None, verify_total=None,
                 verify_error=False, dup_page=None):
        self.hits = sorted(hits, key=lambda item: (item["sort"][0], item["sort"][1]),
                           reverse=True)
        self.reject_id_sort = reject_id_sort
        self.fail_page = fail_page
        self.partial_page = partial_page
        self.missing_sort_page = missing_sort_page
        self.verify_total = verify_total
        self.verify_error = verify_error
        self.dup_page = dup_page
        self._served = []
        self.calls = []

    async def __call__(self, body, index_pattern=None):
        self.calls.append(body)
        page_no = len(self.calls)
        if self.reject_id_sort and any("_id" in field for field in body.get("sort") or []):
            return {"error": "Indexer API error: 400",
                    "detail": "Fielddata access on the _id field is disallowed"}
        if int(body.get("size") or 0) == 0 and body.get("track_total_hits"):
            if self.verify_error:
                return {"error": "Indexer API error: 503", "detail": "count probe unavailable"}
            total = self.verify_total if self.verify_total is not None else len(self.hits)
            return {"hits": {"total": {"value": total, "relation": "eq"}, "hits": []}}
        use_id = any("_id" in field for field in body.get("sort") or [])
        candidates = self.hits
        after = body.get("search_after")
        if after:
            if use_id:
                key = (after[0], after[1])
                candidates = [h for h in self.hits
                              if (h["sort"][0], h["sort"][1]) < key]
            else:
                candidates = [h for h in self.hits if h["sort"][0] < after[0]]
        if self.fail_page == page_no:
            return {"error": "Indexer API error: 503", "detail": "service unavailable"}
        page = [dict(h) for h in candidates[:int(body.get("size") or 0)]]
        self._served.extend(page)
        if self.dup_page == page_no and self._served:
            page = [dict(self._served[0])] + page
        if self.missing_sort_page == page_no:
            page = [{key: value for key, value in h.items() if key != "sort"} for h in page]
        out = {"hits": {"hits": page}}
        if self.partial_page == page_no:
            out["_partial"] = True
            out["_failed_shards"] = 1
        return out


@pytest.fixture(autouse=True)
def _setup(tmp_path, monkeypatch):
    monkeypatch.setattr(config.forecast, "enabled", True)
    monkeypatch.setattr(config.forecast, "store_path", str(tmp_path / "forecast.db"))
    yield


def _fetch(monkeypatch, fake, **overrides):
    monkeypatch.setattr(forecast, "_wazuh_indexer_post", fake)
    for field, value in overrides.items():
        monkeypatch.setattr(config.forecast, field, value)
    return _run(forecast._fetch_tactic_observations(None, _SINCE, _UNTIL))


def _rows_corpus():
    base = _time.time() - 600.0
    corpus = {
        "203.0.113.7": ["Reconnaissance", "Initial Access", "Execution",
                        "Command and Control"],
        "203.0.113.8": ["Reconnaissance", "Initial Access", "Persistence",
                        "Command and Control"],
    }
    rows = []
    for entity, tactics in corpus.items():
        for offset, tactic in enumerate(tactics):
            rows.append({"entity_key": entity, "tactic": tactic,
                         "observed_at": base + offset * 10.0})
    return rows


def _stub_fetch(result: dict):
    async def _fake(srcip, since_iso, until_iso):
        return result
    return _fake


def _lower_floors(monkeypatch):
    monkeypatch.setattr(config.forecast, "min_sequences", 2)
    monkeypatch.setattr(config.forecast, "min_transitions", 1)
    monkeypatch.setattr(config.forecast, "min_support", 1)


def test_config_rejects_bad_fetch_limits():
    with pytest.raises(ConfigurationError):
        ForecastConfig(fetch_page_size=10).validate()
    with pytest.raises(ConfigurationError):
        ForecastConfig(fetch_page_size=1000, max_hits=500).validate()
    ForecastConfig().validate()


def test_single_short_page_is_complete(monkeypatch):
    fake = FakeIndexer([_hit(i) for i in range(3)])
    result = _fetch(monkeypatch, fake)
    assert result["window_complete"] is True
    assert result["truncated"] is False
    assert result["stop_reason"] == "exhausted"
    assert result["pages"] == 1
    assert result["fetched_hits"] == 3
    assert len(result["rows"]) == 3
    assert result["verified_count"] == 3
    assert result["snapshot_consistent"] is True


def test_count_mismatch_marks_corpus_incomplete(monkeypatch):
    hits = [_hit(i) for i in range(3)]
    fake = FakeIndexer(hits, verify_total=len(hits) + 1)
    result = _fetch(monkeypatch, fake)
    assert result["window_complete"] is False
    assert result["snapshot_consistent"] is False
    assert result["stop_reason"] == "count_mismatch"
    assert result["verified_count"] == 4
    assert any("Count verification" in warning for warning in result["warnings"])


def test_max_hits_with_exact_count_is_rescued_to_complete(monkeypatch):
    hits = [_hit(i) for i in range(4)]
    fake = FakeIndexer(hits, verify_total=4)
    result = _fetch(monkeypatch, fake, fetch_page_size=2, max_hits=4)
    assert result["stop_reason"] == "max_hits"
    assert result["window_complete"] is True
    assert result["snapshot_consistent"] is True
    assert result["missing_portion"] is None


def test_verification_failure_marks_corpus_incomplete(monkeypatch):
    fake = FakeIndexer([_hit(i) for i in range(3)], verify_error=True)
    result = _fetch(monkeypatch, fake)
    assert result["stop_reason"] == "verification_failed"
    assert result["window_complete"] is False
    assert result["verified_count"] is None
    assert any("Count verification failed" in warning for warning in result["warnings"])


def test_duplicate_hit_marks_corpus_incomplete(monkeypatch):
    fake = FakeIndexer([_hit(i) for i in range(6)], dup_page=2)
    result = _fetch(monkeypatch, fake, fetch_page_size=2)
    assert result["stop_reason"] == "duplicate_hits"
    assert result["window_complete"] is False
    assert result["snapshot_consistent"] is False
    assert result["duplicates_dropped"] == 1
    observed = [row["observed_at"] for row in result["rows"]]
    assert len(set(observed)) == len(observed)


def test_multi_page_preserves_order_and_advances_cursor(monkeypatch):
    hits = [_hit(i) for i in range(5)]
    fake = FakeIndexer(hits)
    result = _fetch(monkeypatch, fake, fetch_page_size=2)
    assert result["pages"] == 3
    assert result["fetched_hits"] == 5
    assert result["window_complete"] is True
    ordered = sorted(hits, key=lambda h: (h["sort"][0], h["sort"][1]), reverse=True)
    assert "search_after" not in fake.calls[0]
    assert fake.calls[1]["search_after"] == ordered[1]["sort"]
    assert fake.calls[2]["search_after"] == ordered[3]["sort"]
    observed = [row["observed_at"] for row in result["rows"]]
    assert observed == sorted(observed, reverse=True)


def test_exact_page_then_empty_confirms_complete(monkeypatch):
    fake = FakeIndexer([_hit(i) for i in range(2)])
    result = _fetch(monkeypatch, fake, fetch_page_size=2)
    assert result["pages"] == 2
    assert result["window_complete"] is True
    assert result["stop_reason"] == "exhausted"


def test_max_hits_stop_is_incomplete_and_oldest_missing(monkeypatch):
    fake = FakeIndexer([_hit(i) for i in range(6)])
    result = _fetch(monkeypatch, fake, fetch_page_size=2, max_hits=4)
    assert result["window_complete"] is False
    assert result["truncated"] is True
    assert result["stop_reason"] == "max_hits"
    assert result["missing_portion"] == "oldest"
    assert result["fetched_hits"] == 4
    assert "oldest" in result["warnings"][0]


def test_error_mid_pagination_keeps_fetched_rows(monkeypatch):
    fake = FakeIndexer([_hit(i) for i in range(6)], fail_page=2)
    result = _fetch(monkeypatch, fake, fetch_page_size=2)
    assert result["pages"] == 1
    assert len(result["rows"]) == 2
    assert result["window_complete"] is False
    assert result["stop_reason"] == "error"
    assert "page 2" in result["warnings"][0]


def test_timestamp_collision_across_boundary_keeps_every_document(monkeypatch):
    fake = FakeIndexer([_hit(i, stamp=_BASE) for i in range(4)])
    result = _fetch(monkeypatch, fake, fetch_page_size=2)
    assert result["window_complete"] is True
    assert result["fetched_hits"] == 4
    assert len(result["rows"]) == 4


def test_id_sort_rejection_marks_corpus_incomplete(monkeypatch):
    fake = FakeIndexer([_hit(i) for i in range(2)], reject_id_sort=True)
    result = _fetch(monkeypatch, fake)
    assert result["sort_mode"] == "timestamp_only"
    assert result["window_complete"] is False
    assert result["truncated"] is True
    assert result["stop_reason"] == "tiebreaker_unavailable"
    assert len(fake.calls) == 2
    assert len(result["rows"]) == 2
    assert result["verified_count"] is None
    assert result["snapshot_consistent"] is False
    assert "_id" in result["warnings"][0]


def test_partial_shards_mark_corpus_incomplete(monkeypatch):
    fake = FakeIndexer([_hit(i) for i in range(2)], partial_page=1)
    result = _fetch(monkeypatch, fake)
    assert result["stop_reason"] == "shard_partial"
    assert result["partial_shards"] == 1
    assert result["window_complete"] is False


def test_missing_sort_key_stops_pagination(monkeypatch):
    fake = FakeIndexer([_hit(i) for i in range(4)], missing_sort_page=1)
    result = _fetch(monkeypatch, fake, fetch_page_size=2)
    assert result["stop_reason"] == "no_sort_key"
    assert result["window_complete"] is False
    assert len(result["rows"]) == 2


def test_corpus_block_flags_store_row_cap(monkeypatch):
    monkeypatch.setattr(config.forecast, "store_max", 3)
    stored = [{"entity_key": "a", "tactic": "Reconnaissance", "observed_at": 1.0},
              {"entity_key": "a", "tactic": "Initial Access", "observed_at": 2.0},
              {"entity_key": "a", "tactic": "Execution", "observed_at": 3.0}]
    built = {"entities": 1,
             "sequences": [["Reconnaissance", "Initial Access", "Execution"]]}
    fetched = {"rows": stored, "warnings": [], "truncated": False,
               "window_complete": True, "stop_reason": "exhausted", "pages": 1,
               "fetched_hits": 3, "skipped_no_entity": 0, "sort_mode": "timestamp_id",
               "missing_portion": None, "partial_shards": 0, "page_size": 1000,
               "max_hits": 100000}
    block = forecast._corpus_block(fetched, stored, built, {"n_transitions": 2},
                                   _SINCE, _UNTIL)
    assert block["store"]["at_row_cap"] is True
    assert block["fetch"]["window_complete"] is True
    assert block["fetch"]["snapshot_consistent"] is True
    assert block["fit"]["complete"] is False
    assert "store_row_cap" in block["fit"]["incomplete_reasons"]


def test_train_persists_complete_corpus_stamp(monkeypatch):
    monkeypatch.setattr(forecast, "_fetch_tactic_observations",
                        _stub_fetch({"rows": _rows_corpus(), "warnings": [],
                                     "truncated": False, "skipped_no_entity": 0}))
    _lower_floors(monkeypatch)
    payload = json.loads(_run(_forecast(forecast.TacticForecastInput(
        mode="train", response_format="json"))))
    assert payload["status"] == "ok"
    assert payload["corpus"]["fit"]["complete"] is True
    assert payload["corpus"]["fetch"]["fetched_hits"] == 8
    stamp = load_model(payload["model_id"])["params"]["corpus"]
    assert stamp["fit"]["complete"] is True
    assert stamp["fit"]["incomplete_reasons"] == []


def test_strict_mode_refuses_truncated_corpus(monkeypatch):
    monkeypatch.setattr(forecast, "_fetch_tactic_observations",
                        _stub_fetch({"rows": _rows_corpus(), "warnings": [],
                                     "truncated": True, "window_complete": False,
                                     "stop_reason": "max_hits", "fetched_hits": 8,
                                     "missing_portion": "oldest", "pages": 1,
                                     "skipped_no_entity": 0}))
    monkeypatch.setattr(config.forecast, "require_complete_corpus", True)
    _lower_floors(monkeypatch)
    payload = json.loads(_run(_forecast(forecast.TacticForecastInput(
        mode="train", response_format="json"))))
    assert payload["status"] == "corpus_incomplete"
    assert "fetch_max_hits" in payload["incomplete_reasons"]
    assert load_model() is None


def test_strict_mode_refuses_unverified_corpus(monkeypatch):
    monkeypatch.setattr(forecast, "_fetch_tactic_observations",
                        _stub_fetch({"rows": _rows_corpus(), "warnings": [],
                                     "truncated": True, "window_complete": False,
                                     "stop_reason": "verification_failed",
                                     "snapshot_consistent": False, "fetched_hits": 8,
                                     "missing_portion": "unknown", "pages": 1,
                                     "skipped_no_entity": 0}))
    monkeypatch.setattr(config.forecast, "require_complete_corpus", True)
    _lower_floors(monkeypatch)
    payload = json.loads(_run(_forecast(forecast.TacticForecastInput(
        mode="train", response_format="json"))))
    assert payload["status"] == "corpus_incomplete"
    assert "verification_failed" in payload["incomplete_reasons"]
    assert load_model() is None


def test_prediction_and_status_do_not_rewrite_model_stamp(monkeypatch):
    monkeypatch.setattr(forecast, "_fetch_tactic_observations",
                        _stub_fetch({"rows": _rows_corpus(), "warnings": [],
                                     "truncated": True, "window_complete": False,
                                     "stop_reason": "max_hits", "fetched_hits": 8,
                                     "snapshot_consistent": False,
                                     "missing_portion": "oldest", "pages": 1,
                                     "skipped_no_entity": 0}))
    _lower_floors(monkeypatch)
    trained = json.loads(_run(_forecast(forecast.TacticForecastInput(
        mode="train", response_format="json"))))
    before = load_model(trained["model_id"])["params"]["corpus"]
    _run(_forecast(forecast.TacticForecastInput(
        mode="predict", current_tactic="Reconnaissance", response_format="json")))
    _run(_forecast(forecast.TacticForecastInput(mode="status", response_format="json")))
    after = load_model(trained["model_id"])["params"]["corpus"]
    assert after == before


def test_predict_reports_partial_corpus_model(monkeypatch):
    monkeypatch.setattr(forecast, "_fetch_tactic_observations",
                        _stub_fetch({"rows": _rows_corpus(), "warnings": [],
                                     "truncated": True, "window_complete": False,
                                     "stop_reason": "max_hits", "fetched_hits": 8,
                                     "missing_portion": "oldest", "pages": 1,
                                     "skipped_no_entity": 0}))
    _lower_floors(monkeypatch)
    trained = json.loads(_run(_forecast(forecast.TacticForecastInput(
        mode="train", response_format="json"))))
    assert trained["status"] == "ok"
    markdown = _run(_forecast(forecast.TacticForecastInput(
        mode="predict", current_tactic="Reconnaissance", response_format="markdown")))
    assert "partial corpus" in markdown
    payload = json.loads(_run(_forecast(forecast.TacticForecastInput(
        mode="predict", current_tactic="Reconnaissance", response_format="json"))))
    assert payload["model"]["corpus"]["fit"]["complete"] is False


def test_train_over_paged_corpus_stamps_page_count(monkeypatch):
    _lower_floors(monkeypatch)
    monkeypatch.setattr(config.forecast, "fetch_page_size", 3)
    corpus = {"203.0.113.7": ["Reconnaissance", "Initial Access", "Execution",
                              "Command and Control"],
              "203.0.113.8": ["Reconnaissance", "Initial Access", "Persistence",
                              "Command and Control"]}
    hits = []
    index = 0
    recent = datetime.now(timezone.utc) - timedelta(minutes=10)
    for entity, tactics in corpus.items():
        for tactic in tactics:
            hits.append(_hit(index, tactic=tactic, entity=entity,
                             stamp=recent + timedelta(seconds=index)))
            index += 1
    fake = FakeIndexer(hits)
    monkeypatch.setattr(forecast, "_wazuh_indexer_post", fake)
    payload = json.loads(_run(_forecast(forecast.TacticForecastInput(
        mode="train", response_format="json"))))
    assert payload["status"] == "ok"
    assert payload["corpus"]["fetch"]["pages"] == 3
    assert payload["corpus"]["fetch"]["fetched_hits"] == 8
    assert payload["corpus"]["fit"]["complete"] is True
