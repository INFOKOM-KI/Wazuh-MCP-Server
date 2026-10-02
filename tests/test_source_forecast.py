#!/usr/bin/env python3
"""
Contract and regression tests for blueteam_source_forecast and
blueteam_attack_forecast: tool API, response schema, retrieval integrity.
Imports happen inside helpers, so a missing module fails each test by name.
"""
from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import asyncio
import json
import time
from datetime import datetime, timezone
import pytest
from mcp_server.core.config import config
from mcp_server.core.exceptions import BlueTeamMCPError

DAY = 86400.0
NOW = time.time()


def _tool():
    try:
        import mcp_server.tools.source_forecast as mod
    except ImportError as exc:
        pytest.fail(f"contract missing: mcp_server.tools.source_forecast ({exc})")
    return mod


def _store():
    try:
        import mcp_server.core.source_store as mod
    except ImportError as exc:
        pytest.fail(f"contract missing: mcp_server.core.source_store ({exc})")
    return mod


def _section(monkeypatch, tmp_path, **overrides):
    section = getattr(config, "source", None)
    if section is None:
        pytest.fail("contract missing: config.source (SourceForecastConfig)")
    defaults = {"enabled": True, "store_path": str(tmp_path / "source.db"),
                "history_days": 2, "max_rows": 10000, "retention_days": 365,
                "min_observations": 2, "min_transitions": 1, "half_life_days": 14.0,
                "max_candidates": 10, "netblock_v4_prefix": 24, "netblock_v6_prefix": 64,
                "include_internal": False, "min_geo_coverage": 0.0,
                "require_complete_corpus": True,
                "eval_horizon_minutes": 1440, "eval_step_days": 1,
                "eval_min_train_observations": 1}
    defaults.update(overrides)
    for key, value in defaults.items():
        monkeypatch.setattr(section, key, value)
    return section


def _iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fetch_result(rows, *, complete=True, snapshot=True, fetched=None, skipped=0):
    return {"rows": rows, "warnings": [], "truncated": not complete,
            "skipped_no_entity": skipped, "pages": 1,
            "fetched_hits": fetched if fetched is not None else len(rows),
            "window_complete": complete,
            "verified_count": len(rows) if complete else None,
            "snapshot_consistent": snapshot,
            "stop_reason": "exhausted" if complete else "max_hits",
            "sort_mode": "timestamp_id", "missing_portion": None,
            "partial_shards": 0, "duplicates_dropped": 0,
            "page_size": 1000, "max_hits": 100000}


def _fake_fetch(result):
    async def _fetch(srcip, since_iso, until_iso, include_geo=False):
        _fetch.calls.append(include_geo)
        return result
    _fetch.calls = []
    return _fetch


def _row(ip, ts, country="US", tactic="Reconnaissance"):
    return {"entity_key": ip, "tactic": tactic, "observed_at": ts, "country": country}


def _srow(ip, ts, country="US", netblock="8.8.8.0/24"):
    return {"source_ip": ip, "netblock": netblock, "country": country,
            "tactic": "Reconnaissance", "observed_at": ts}


def _seed(store, rows, *, complete=True):
    store.save_source_observations(rows)
    store.save_ingest("ing-test", 0.0, NOW + 1, complete, complete,
                      {"fetched_hits": len(rows)})


def _predict(mod, **overrides):
    params = {"mode": "predict", "as_of": _iso(NOW), "response_format": "json"}
    params.update(overrides)
    return json.loads(asyncio.run(
        mod.blueteam_source_forecast.__wrapped__(mod.SourceForecastInput(**params))))


def test_disabled_tool_raises(monkeypatch, tmp_path):
    mod = _tool()
    _section(monkeypatch, tmp_path, enabled=False)
    with pytest.raises(BlueTeamMCPError):
        asyncio.run(mod.blueteam_source_forecast.__wrapped__(mod.SourceForecastInput()))


def test_ingest_persists_verified_corpus(monkeypatch, tmp_path):
    mod = _tool()
    store = _store()
    _section(monkeypatch, tmp_path)
    fetch = _fake_fetch(_fetch_result([_row("8.8.8.8", NOW - DAY)]))
    monkeypatch.setattr(mod, "_fetch_tactic_observations", fetch)
    payload = json.loads(asyncio.run(mod.blueteam_source_forecast.__wrapped__(
        mod.SourceForecastInput(mode="ingest", since=_iso(NOW - 2 * DAY),
                                until=_iso(NOW), response_format="json"))))
    assert payload["status"] == "ok"
    assert payload["rows_persisted"] == 1
    assert payload["corpus"]["window_complete"] is True
    assert store.store_stats()["rows"] == 1
    assert store.load_ingest()["window_complete"] is True
    assert store.load_ingest()["stats"]["geo_rows"] == 1
    assert fetch.calls == [True]


def test_ingest_strict_refuses_incomplete(monkeypatch, tmp_path):
    mod = _tool()
    store = _store()
    _section(monkeypatch, tmp_path, require_complete_corpus=True)
    monkeypatch.setattr(mod, "_fetch_tactic_observations",
                        _fake_fetch(_fetch_result([_row("8.8.8.8", NOW - DAY)],
                                                  complete=False)))
    payload = json.loads(asyncio.run(mod.blueteam_source_forecast.__wrapped__(
        mod.SourceForecastInput(mode="ingest", since=_iso(NOW - 2 * DAY),
                                until=_iso(NOW), response_format="json"))))
    assert payload["status"] == "incomplete_corpus"
    assert payload["rows_persisted"] == 0
    assert store.store_stats()["rows"] == 0


def test_ingest_allowed_incomplete_is_degraded(monkeypatch, tmp_path):
    mod = _tool()
    store = _store()
    _section(monkeypatch, tmp_path, require_complete_corpus=False)
    monkeypatch.setattr(mod, "_fetch_tactic_observations",
                        _fake_fetch(_fetch_result([_row("8.8.8.8", NOW - DAY)],
                                                  complete=False)))
    payload = json.loads(asyncio.run(mod.blueteam_source_forecast.__wrapped__(
        mod.SourceForecastInput(mode="ingest", since=_iso(NOW - 2 * DAY),
                                until=_iso(NOW), response_format="json"))))
    assert payload["status"] == "degraded"
    assert payload["corpus"]["window_complete"] is False
    assert store.store_stats()["rows"] == 1
    assert store.load_ingest()["window_complete"] is False


def test_ingest_count_mismatch_is_incomplete(monkeypatch, tmp_path):
    mod = _tool()
    _section(monkeypatch, tmp_path, require_complete_corpus=False)
    monkeypatch.setattr(mod, "_fetch_tactic_observations",
                        _fake_fetch(_fetch_result([_row("8.8.8.8", NOW - DAY)],
                                                  complete=True, snapshot=False)))
    payload = json.loads(asyncio.run(mod.blueteam_source_forecast.__wrapped__(
        mod.SourceForecastInput(mode="ingest", since=_iso(NOW - 2 * DAY),
                                until=_iso(NOW), response_format="json"))))
    assert payload["status"] == "degraded"
    assert payload["corpus"]["snapshot_consistent"] is False


def test_ingest_without_sources_reports_no_sources(monkeypatch, tmp_path):
    mod = _tool()
    _section(monkeypatch, tmp_path)
    monkeypatch.setattr(mod, "_fetch_tactic_observations",
                        _fake_fetch(_fetch_result([], skipped=2)))
    payload = json.loads(asyncio.run(mod.blueteam_source_forecast.__wrapped__(
        mod.SourceForecastInput(mode="ingest", since=_iso(NOW - 2 * DAY),
                                until=_iso(NOW), response_format="json"))))
    assert payload["status"] == "no_sources"
    assert payload["rows_persisted"] == 0


def test_predict_returns_candidates_with_attribution_status(monkeypatch, tmp_path):
    mod = _tool()
    store = _store()
    _section(monkeypatch, tmp_path)
    _seed(store, [_srow("8.8.8.8", NOW - 2 * DAY), _srow("1.1.1.1", NOW - DAY),
                  _srow("8.8.8.8", NOW - 0.5 * DAY)])
    payload = _predict(mod)
    assert payload["status"] == "ok"
    assert payload["attribution_status"] == "not_established"
    assert payload["training_cutoff"]
    candidates = payload["candidates"]["ip"]
    assert candidates and candidates[0]["rank"] == 1
    assert {"value", "model_score", "score_kind", "components", "first_seen",
            "last_seen", "occurrence_count", "netblock",
            "observed_source_country"} <= set(candidates[0])
    assert payload["candidates"]["asn"] == []
    assert payload["asn_status"] == "unavailable"
    assert payload["baselines"]["persistence_source"]


def test_predict_insufficient_history(monkeypatch, tmp_path):
    mod = _tool()
    _section(monkeypatch, tmp_path)
    payload = _predict(mod)
    assert payload["status"] == "insufficient_history"
    assert payload["candidates"]["ip"] == []


def test_predict_unverified_history_refused_or_degraded(monkeypatch, tmp_path):
    mod = _tool()
    store = _store()
    _section(monkeypatch, tmp_path)
    store.save_source_observations([_srow("8.8.8.8", NOW - DAY),
                                    _srow("1.1.1.1", NOW - 0.5 * DAY)])
    refused = _predict(mod)
    assert refused["status"] == "corpus_unverified"
    allowed = _predict(mod, allow_unverified_history=True)
    assert allowed["status"] == "degraded"


def test_predict_country_insufficient_geo(monkeypatch, tmp_path):
    mod = _tool()
    store = _store()
    _section(monkeypatch, tmp_path, min_geo_coverage=0.5)
    _seed(store, [_srow("8.8.8.8", NOW - DAY, country=None),
                  _srow("1.1.1.1", NOW - 0.5 * DAY, country=None)])
    payload = _predict(mod)
    assert payload["status"] == "ok"
    assert payload["country_status"] == "insufficient_geo"
    assert payload["candidates"]["country"] == []


def test_predict_excludes_internal_sources(monkeypatch, tmp_path):
    mod = _tool()
    store = _store()
    _section(monkeypatch, tmp_path)
    _seed(store, [_srow("10.0.0.1", NOW - DAY, netblock="10.0.0.0/24")])
    payload = _predict(mod)
    values = {candidate["value"] for candidate in payload["candidates"]["ip"]}
    assert "10.0.0.1" not in values


def test_predict_ipv6_netblock(monkeypatch, tmp_path):
    mod = _tool()
    store = _store()
    _section(monkeypatch, tmp_path)
    _seed(store, [_srow("2606:4700::1111", NOW - DAY, netblock="2606:4700::/64"),
                  _srow("2606:4700::2222", NOW - 0.5 * DAY, netblock="2606:4700::/64")])
    payload = _predict(mod)
    candidate = payload["candidates"]["ip"][0]
    assert candidate["value"].startswith("2606:")
    assert candidate["netblock"].endswith("/64")


def test_predict_respects_max_candidates(monkeypatch, tmp_path):
    mod = _tool()
    store = _store()
    _section(monkeypatch, tmp_path, max_candidates=2, min_observations=1)
    _seed(store, [_srow(f"10.0.{index}.1", NOW - DAY + index, netblock=f"10.0.{index}.0/24",
                        country=None) for index in range(5)])
    payload = _predict(mod)
    assert len(payload["candidates"]["ip"]) <= 2


def test_predict_rejects_future_as_of(monkeypatch, tmp_path):
    mod = _tool()
    _section(monkeypatch, tmp_path)
    with pytest.raises(BlueTeamMCPError):
        _predict(mod, as_of=_iso(NOW + 3600))


def test_response_never_labels_sources_malicious(monkeypatch, tmp_path):
    mod = _tool()
    store = _store()
    _section(monkeypatch, tmp_path)
    _seed(store, [_srow("8.8.8.8", NOW - DAY), _srow("1.1.1.1", NOW - 0.5 * DAY)])
    payload = _predict(mod)
    rendered = json.dumps(payload)
    for forbidden in ("attacker_ip", "attacker_country", "malicious", "is_attacker"):
        assert forbidden not in rendered


def test_status_reports_store_depth(monkeypatch, tmp_path):
    mod = _tool()
    store = _store()
    _section(monkeypatch, tmp_path)
    _seed(store, [_srow("8.8.8.8", NOW - DAY), _srow("1.1.1.1", NOW - 0.5 * DAY)])
    payload = json.loads(asyncio.run(mod.blueteam_source_forecast.__wrapped__(
        mod.SourceForecastInput(mode="status", response_format="json"))))
    assert payload["status"] == "ok"
    assert payload["store"]["rows"] == 2
    assert payload["last_ingest"]["ingest_id"] == "ing-test"


def test_ingest_purges_expired_rows(monkeypatch, tmp_path):
    mod = _tool()
    store = _store()
    _section(monkeypatch, tmp_path, retention_days=1)
    store.save_source_observations([_srow("9.9.9.9", 0.0)])
    monkeypatch.setattr(mod, "_fetch_tactic_observations",
                        _fake_fetch(_fetch_result([_row("8.8.8.8", NOW - 100)])))
    payload = json.loads(asyncio.run(mod.blueteam_source_forecast.__wrapped__(
        mod.SourceForecastInput(mode="ingest", since=_iso(NOW - 2 * DAY),
                                until=_iso(NOW), response_format="json"))))
    assert payload["status"] == "ok"
    assert payload["purged_rows"] == 1
    assert store.store_stats()["sources"] == 1


def test_evaluate_mode_runs_over_stored_observations(monkeypatch, tmp_path):
    mod = _tool()
    store = _store()
    _section(monkeypatch, tmp_path, eval_min_train_observations=1,
             eval_horizon_minutes=1440, eval_step_days=1)
    base = NOW - 4 * DAY
    _seed(store, [_srow("8.8.8.8", base + 0.1 * DAY),
                  _srow("1.1.1.1", base + 1.1 * DAY),
                  _srow("8.8.8.8", base + 2.1 * DAY),
                  _srow("1.1.1.1", base + 3.1 * DAY)])
    payload = json.loads(asyncio.run(mod.blueteam_source_forecast.__wrapped__(
        mod.SourceForecastInput(mode="evaluate", since=_iso(base), until=_iso(NOW),
                                response_format="json"))))
    assert payload["status"] == "ok"
    evaluation = payload["evaluation"]
    assert evaluation["status"] == "ok"
    assert evaluation["counts"]["cutoffs"] >= 2
    assert evaluation["counts"]["evaluated"] >= 1
    assert evaluation["metrics"]["unavailable"] == ["asn"]
    assert "model_minus_persistence" in evaluation["metrics"]
    assert all("training_cutoff" in point for point in evaluation["points"])


def test_attack_forecast_composes_both_layers(monkeypatch, tmp_path):
    mod = _tool()
    _section(monkeypatch, tmp_path)

    async def _tactic(params):
        return json.dumps({"status": "ok", "prediction": {"predictions": []}})

    async def _source(params):
        return json.dumps({"status": "ok", "attribution_status": "not_established",
                           "candidates": {"ip": []}})

    monkeypatch.setattr(mod, "blueteam_tactic_forecast", _tactic)
    monkeypatch.setattr(mod, "blueteam_source_forecast", _source)
    payload = json.loads(asyncio.run(mod.blueteam_attack_forecast.__wrapped__(
        mod.AttackForecastInput(srcip="8.8.8.8", response_format="json"))))
    assert payload["behavioral"]["status"] == "ok"
    assert payload["sources"]["attribution_status"] == "not_established"
