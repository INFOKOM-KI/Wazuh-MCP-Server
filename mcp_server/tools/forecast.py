#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Tactic-sequence forecasting: train a transition model over MITRE tactic chains and predict the next tactic for an entity.
Pipeline position
blueteam_tactic_forecast(mode="train")   -> ingest alert tactics + fit model
blueteam_tactic_forecast(mode="predict") -> next-tactic distribution for one srcip
blueteam_tactic_forecast(mode="status")  -> corpus + newest model metadata

Sequences are built from ``rule.mitre.tactic`` on Wazuh alerts, ordered by
timestamp per source IP, with consecutive duplicates collapsed. Two estimators:
a Laplace smoothed first-order Markov chain (default) and an optional
``CategoricalHMM`` whose hidden states are campaign phases. The escalation
probability is the mass the next-step distribution places on Command and
Control, Exfiltration, Impact and Lateral Movement.

Gating: disabled by default. ``BLUETEAM_FORECAST_ENABLED=false`` makes the tool
raise an enable hint instead of returning an empty corpus, which would read as
"no history exists" when the truth is "forecasting is off".

NOTE: No ``from __future__ import annotations`` deferred annotation evaluation
      (PEP 563) breaks @blueteam_tool type resolution.
"""
import asyncio
import hashlib
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Literal, Optional
from pydantic import BaseModel, ConfigDict, Field
from mcp_server import WAZUH_INDEXER_PASSWORD, WAZUH_INDEXER_URL
from mcp_server.core.cluster_features import normalize_entity_key
from mcp_server.core.config import config
from mcp_server.core.exceptions import BlueTeamMCPError
from mcp_server.core.forecast_store import (
    append_observations,
    load_counts,
    load_model,
    load_observations,
    purge_expired,
    save_model,
    store_stats,
    upsert_counts,
)
from mcp_server.core.tool_decorator import blueteam_tool
from mcp_server.correlation.forecast_core import (
    TACTIC_ORDER,
    VOLUME_KIND,
    build_sequences,
    fit_categorical_hmm,
    fit_markov_chain,
    fit_poisson_hmm,
    normalize_tactics,
    predict_next_hmm,
    predict_next_markov,
    predict_volume,
    sequence_logprob,
)
from mcp_server.wazuh.indexer import _SRCIP_FIELD_PATHS, _wazuh_indexer_post
from mcp_server.wazuh.time_utils import _auto_bucket_interval

logger = logging.getLogger("blue_team_mcp.forecast")

_HIT_CAP = 5000
_OBSERVATION_FIELDS = ["@timestamp", "rule.mitre.tactic"] + _SRCIP_FIELD_PATHS


def _require_enabled() -> None:
    if not config.forecast.enabled:
        raise BlueTeamMCPError(
            "Tactic forecasting is disabled. Set BLUETEAM_FORECAST_ENABLED=true and "
            "BLUETEAM_FORECAST_STORE=/abs/path/forecast.db, then restart the server. "
            "The optional HMM estimator also needs hmmlearn "
            "(setup.sh BLUETEAM_INSTALL_FORECAST=1); the Markov chain does not."
        )


def _window(minutes: int) -> tuple[str, str]:
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    until = datetime.utcnow()
    return (until - timedelta(minutes=minutes)).strftime(fmt), until.strftime(fmt)


def _epoch(value) -> Optional[float]:
    """Parse an ISO-8601 ``@timestamp`` into epoch seconds. Python 3.9/3.10
    ``fromisoformat`` rejects the trailing ``Z`` that Wazuh emits, so normalise
    it first; an unparseable row is skipped, never guessed."""
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _source_value(source: dict, path: str):
    value = source
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


async def _fetch_tactic_observations(srcip: Optional[str], since_iso: str,
                                     until_iso: str) -> dict:
    """Pull MITRE annotated alerts and flatten them to observation rows.
    One search, capped at ``_HIT_CAP`` hits sorted oldest-first. There is no
    pagination: ``truncated`` in the result tells the caller the window was
    clipped, and repeating the call for a shorter window is the honest remedy.
    Alerts with no source IP are counted but cannot join a per-entity sequence.
    """
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return {"rows": [], "warnings": ["WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set."],
                "truncated": False, "skipped_no_entity": 0}
    filters: list[dict] = [
        {"range": {"@timestamp": {"gte": since_iso, "lt": until_iso,
                                  "format": "strict_date_optional_time"}}},
        {"exists": {"field": "rule.mitre.tactic"}},
    ]
    if srcip:
        should = [{"match": {path: srcip}} for path in _SRCIP_FIELD_PATHS]
        should.append({"match_phrase": {"full_log": srcip}})
        filters.append({"bool": {"should": should, "minimum_should_match": 1}})
    body = {
        "size": _HIT_CAP,
        "sort": [{"@timestamp": {"order": "asc"}}],
        "query": {"bool": {"filter": filters}},
        "_source": _OBSERVATION_FIELDS,
    }
    raw = await _wazuh_indexer_post(body)
    if "error" in raw:
        return {"rows": [], "warnings": [f"Indexer query failed: {raw['error']}"],
                "truncated": False, "skipped_no_entity": 0}
    hits = raw.get("hits", {}).get("hits", [])
    rows: list[dict] = []
    skipped_no_entity = 0
    for hit in hits:
        source = hit.get("_source", hit)
        key = ""
        for path in _SRCIP_FIELD_PATHS:
            value = _source_value(source, path)
            if value:
                key = str(value)
                break
        observed_at = _epoch(source.get("@timestamp"))
        if not key or observed_at is None:
            skipped_no_entity += 1
            continue
        rows.append({"entity_key": normalize_entity_key(key),
                     "tactic": _source_value(source, "rule.mitre.tactic"),
                     "observed_at": observed_at})
    warnings: list[str] = []
    truncated = len(hits) >= _HIT_CAP
    if truncated:
        warnings.append(
            f"Hit cap reached ({_HIT_CAP} alerts); the oldest part of the window is "
            "missing. Narrow time_window_minutes for an untruncated fit.")
    return {"rows": rows, "warnings": warnings, "truncated": truncated,
            "skipped_no_entity": skipped_no_entity}


def _model_id(fit: dict) -> str:
    """Content-addressed id: identical parameters replace their row, so a
    repeated train over the same corpus is idempotent instead of churning the
    model cap."""
    canonical = json.dumps(
        {key: fit.get(key) for key in ("kind", "startprob", "transmat", "emissionprob", "lambdas")},
        sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]


def _top_transitions(fit: dict, limit: int = 8) -> list[dict]:
    counts = fit.get("counts")
    if not counts:
        return []
    pairs = [(int(counts[current][following]), TACTIC_ORDER[current], TACTIC_ORDER[following])
             for current in range(len(TACTIC_ORDER))
             for following in range(len(TACTIC_ORDER)) if counts[current][following]]
    pairs.sort(key=lambda item: (-item[0], item[1], item[2]))
    return [{"from": source, "to": target, "count": count} for count, source, target in pairs[:limit]]


def _fit_params_summary(model: dict) -> dict:
    return {"model_id": model["model_id"], "kind": model["kind"],
            "taxonomy_version": model["taxonomy_version"],
            "n_sequences": model["n_sequences"], "n_transitions": model["n_transitions"],
            "created_at": model["created_at"]}


def _train_markdown(payload: dict) -> str:
    lines = [
        f"# Tactic Forecast - model `{payload['model_id']}`",
        "",
        f"**Kind**: `{payload['kind']}` | **Taxonomy**: `{payload['taxonomy_version']}`",
        f"**Window**: `{payload['window']['since']}` -> `{payload['window']['until']}`",
        f"**Entities**: {payload['entity_count']} | **Sequences**: {payload['n_sequences']} "
        f"| **Transitions**: {payload['n_transitions']}",
        f"**Observations appended**: {payload['observations_appended']} "
        f"| **Dropped**: {payload['dropped_unknown']} unknown tactic, "
        f"{payload['dropped_short']} single-tactic sequences, "
        f"{payload['dropped_no_entity']} without entity",
        "",
    ]
    if payload.get("top_transitions"):
        lines += ["| From | To | Count |", "|------|----|-------|"]
        lines += [f"| {item['from']} | {item['to']} | {item['count']} |"
                  for item in payload["top_transitions"]]
    if payload.get("warnings"):
        lines += ["", "**Indexer notes**"] + [f"- {warning}" for warning in payload["warnings"]]
    return "\n".join(lines)


def _predict_markdown(payload: dict) -> str:
    prediction = payload["prediction"]
    model = payload["model"]
    lines = [
        f"# Tactic Forecast model `{model['model_id']}` (`{model['kind']}`)",
        "",
        f"**Input**: {payload['input_label']} | **Current tactic**: "
        f"`{prediction.get('current_tactic') or '-'}`",
        f"**Escalation probability**: {prediction['escalation_probability']:.0%}"
        + (f" | **Support**: {prediction.get('support')} transitions"
           if prediction.get("support") is not None else ""),
        "",
        "| Next tactic | Probability |",
        "|-------------|-------------|",
    ]
    lines += [f"| {item['tactic']} | {item['probability']:.1%} |"
              for item in prediction["predictions"]]
    if prediction.get("uniform_fallback"):
        lines += ["", f"**Uniform fallback**: {prediction.get('reason') or 'no anchor in the corpus'}."]
    if prediction.get("low_support"):
        lines += ["", "**Low support**: too few observed transitions on this row to trust the "
                      "ranking treat it as a hint, not a score."]
    anomaly = payload.get("anomaly") or {}
    if anomaly.get("status") == "ok":
        lines += ["", f"**Chain mean log-likelihood**: {anomaly['mean_logprob']} "
                      f"over {anomaly['steps']} transitions (lower = less like the training corpus)."]
    return "\n".join(lines)


def _status_markdown(payload: dict) -> str:
    lines = ["# Tactic Forecast status", "",
             f"**Status**: `{payload['status']}`",
             f"**Corpus**: {payload['store']['observations']} observations from "
             f"{payload['store']['entities']} entities | **Models**: {payload['store']['models']}"]
    if payload.get("model"):
        model = payload["model"]
        lines += ["", f"**Newest model**: `{model['model_id']}` (`{model['kind']}`, "
                      f"{model['n_sequences']} sequences / {model['n_transitions']} transitions)"]
    if payload.get("hint"):
        lines += ["", payload["hint"]]
    return "\n".join(lines)


class TacticForecastInput(BaseModel):
    """Input model for blueteam_tactic_forecast."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    mode: Literal["train", "predict", "status"] = Field(
        default="predict",
        description="'train' ingests the window and fits a model; 'predict' scores one "
                    "entity or tactic; 'status' reads the corpus and newest model.")
    kind: Literal["markov", "hmm"] = Field(
        default="markov",
        description="Estimator for mode='train'. 'markov' is the Laplace-smoothed chain "
                    "(no extra dependency); 'hmm' is the CategoricalHMM and needs hmmlearn.")
    srcip: Optional[str] = Field(default=None, min_length=1, max_length=64,
        description="Source IP whose tactic sequence is rebuilt for mode='predict'.")
    current_tactic: Optional[str] = Field(default=None, max_length=64,
        description="Predict from this tactic alone when no entity sequence is available.")
    model_id: Optional[str] = Field(default=None, max_length=32,
        description="Model to load; newest fit when omitted.")
    time_window_minutes: int = Field(default=10080, ge=5, le=43200,
        description="Window for training ingestion or entity-sequence rebuild.")
    min_sequences: Optional[int] = Field(default=None, ge=2, le=100000)
    min_transitions: Optional[int] = Field(default=None, ge=1, le=1000000)
    n_components: Optional[int] = Field(default=None, ge=2, le=8,
        description="Hidden states for kind='hmm'; default from config.")
    top_k: int = Field(default=3, ge=1, le=16,
        description="Number of next-tactic candidates to return.")
    response_format: Literal["markdown", "json"] = Field(default="markdown")


@blueteam_tool(
    name="blueteam_tactic_forecast",
    annotations={"readOnlyHint": False, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
    audit=True, truncate=True, redact=True,
)
async def blueteam_tactic_forecast(params: TacticForecastInput) -> str:
    """Fit and query a MITRE tactic transition model over Wazuh alert sequences.
    Two estimators share one corpus format (per-entity tactic chains from
    ``rule.mitre.tactic``, ordered by timestamp, consecutive duplicates
    collapsed). ``markov`` is a Laplace-smoothed first-order chain with raw
    support counts per row interpretable and dependency-free. ``hmm`` is a
    CategoricalHMM (hidden campaign phase -> observed tactic) for when tactics
    are a noisy proxy for the underlying phase. Predictions report how much
    observed evidence backs them; a tactic the corpus never produced is never
    assigned a fabricated probability.

    Args:
        params.mode: 'train', 'predict' (default) or 'status'.
        params.kind: 'markov' (default) or 'hmm' for training.
        params.srcip: Entity to rebuild a sequence for when predicting.
        params.current_tactic: Single-tactic anchor when no entity is given.
        params.model_id: Model to use; newest when omitted.
        params.time_window_minutes: 5 minutes to 30 days.
        params.min_sequences: Minimum per-entity sequences to fit.
        params.min_transitions: Minimum transitions to fit.
        params.n_components: HMM hidden states (2-8).
        params.top_k: Next-tactic candidates to return.
        params.response_format: 'markdown' (default) or 'json'.

    Returns:
        markdown or json. Train: model id, corpus counts, truncated-window
        warnings, and (Markov) the strongest observed transitions. Predict: the
        top-k next tactics with probabilities, the escalation probability, a
        ``low_support``/``uniform_fallback`` flag where applicable, and the
        chains mean log-likelihood against the training corpus (Markov models;
        an HMM reports ``not_applicable``). Status: corpus and newest-model metadata.

    Worked Examples:
        1. Weekly Markov fit -> ``blueteam_tactic_forecast(mode="train",
           kind="markov", time_window_minutes=10080)``
        2. Fitted HMM over a month -> ``blueteam_tactic_forecast(mode="train",
           kind="hmm", n_components=4, time_window_minutes=43200)``
        3. Next tactic for one IP -> ``blueteam_tactic_forecast(mode="predict",
           srcip="203.0.113.7", top_k=5, response_format="json")``

    Permissions: read on the Wazuh Indexer; read/write on BLUETEAM_FORECAST_STORE.
    Rate limits: one Indexer search per train or entity predict, capped at 5000
    alerts (the response flags truncation); no external network calls.
    """
    _require_enabled()
    since_iso, until_iso = _window(params.time_window_minutes)

    if params.mode == "status":
        store = await asyncio.to_thread(store_stats)
        model = None
        try:
            loaded = await asyncio.to_thread(load_model, params.model_id)
        except BlueTeamMCPError as exc:
            payload = {"status": "error", "store": store, "reason": str(exc)}
            if params.response_format == "json":
                return json.dumps(payload, indent=2, ensure_ascii=False)
            return _status_markdown(payload)
        if loaded is not None:
            model = _fit_params_summary(loaded)
        payload = {"status": "ok" if model else "no_model", "store": store, "model": model,
                   "hint": None if model else "Run mode='train' first to fit a model."}
        if params.response_format == "json":
            return json.dumps(payload, indent=2, ensure_ascii=False)
        return _status_markdown(payload)

    if params.mode == "predict":
        loaded = await asyncio.to_thread(load_model, params.model_id, ("markov", "hmm"))
        if loaded is None:
            raise BlueTeamMCPError(
                "No stored forecast model. Run blueteam_tactic_forecast mode='train' first.")
        if loaded["kind"] not in ("markov", "hmm"):
            raise BlueTeamMCPError(
                f"Stored model {loaded['model_id']} is a '{loaded['kind']}' model, not a "
                "tactic model. Train one with blueteam_tactic_forecast mode='train'.")
        sequence: list[str] = []
        anomaly = None
        warnings: list[str] = []
        if params.srcip:
            fetched = await _fetch_tactic_observations(
                normalize_entity_key(params.srcip), since_iso, until_iso)
            warnings = fetched["warnings"]
            built = build_sequences(fetched["rows"])
            if built["sequences"]:
                sequence = built["sequences"][0]
            if not sequence:
                payload = {"status": "not_observed", "model": _fit_params_summary(loaded),
                           "srcip": normalize_entity_key(params.srcip),
                           "window": {"since": since_iso, "until": until_iso},
                           "warnings": fetched["warnings"],
                           "hint": "No MITRE-annotated sequence for this entity in the "
                                   "window; widen it or predict from current_tactic."}
                if params.response_format == "json":
                    return json.dumps(payload, indent=2, ensure_ascii=False)
                return (f"# Tactic Forecast\n\n**Status**: `not_observed` no tactic sequence "
                        f"for `{payload['srcip']}` in `{since_iso}` -> `{until_iso}`.\n")
            input_label = f"srcip `{normalize_entity_key(params.srcip)}`"
            anomaly = sequence_logprob(loaded, sequence)
        elif params.current_tactic:
            sequence = [params.current_tactic]
            input_label = f"current tactic `{params.current_tactic}`"
        else:
            raise BlueTeamMCPError(
                "mode='predict' requires exactly one of srcip or current_tactic.")

        if loaded["kind"] == "hmm":
            prediction = predict_next_hmm(loaded, sequence, params.top_k)
        else:
            prediction = predict_next_markov(
                loaded, sequence, params.top_k, config.forecast.min_support)
        payload = {"status": prediction.get("status", "ok"),
                   "model": _fit_params_summary(loaded), "input_label": input_label,
                   "prediction": prediction, "anomaly": anomaly,
                   "warnings": warnings}
        if params.response_format == "json":
            return json.dumps(payload, indent=2, ensure_ascii=False)
        return _predict_markdown(payload)

    # mode == "train"
    fetched = await _fetch_tactic_observations(None, since_iso, until_iso)
    if not fetched["rows"]:
        payload = {"status": "insufficient_data", "entity_count": 0,
                   "window": {"since": since_iso, "until": until_iso},
                   "warnings": fetched["warnings"],
                   "hint": "No MITRE-annotated alerts in the window. Check that the Wazuh "
                           "ruleset populates rule.mitre.tactic, or widen the window."}
        if params.response_format == "json":
            return json.dumps(payload, indent=2, ensure_ascii=False)
        return (f"# Tactic Forecast\n\n**Status**: `insufficient_data` - no MITRE-annotated "
                f"alerts in `{since_iso}` -> `{until_iso}`.\n")

    observations: list[tuple[str, str, float]] = []
    for row in fetched["rows"]:
        for tactic in normalize_tactics(row["tactic"]):
            observations.append((row["entity_key"], tactic, row["observed_at"]))
    purged = await asyncio.to_thread(purge_expired)
    appended = await asyncio.to_thread(append_observations, observations)
    since_ts = time.time() - params.time_window_minutes * 60
    stored = await asyncio.to_thread(load_observations, since_ts)
    built = build_sequences(stored)

    min_sequences = params.min_sequences or config.forecast.min_sequences
    min_transitions = params.min_transitions or config.forecast.min_transitions
    if params.kind == "hmm":
        fit = fit_categorical_hmm(
            built["sequences"], n_components=params.n_components or config.forecast.hmm_components,
            min_sequences=max(min_sequences, config.forecast.hmm_min_sequences),
            seed=config.forecast.hmm_seed, n_iter=config.forecast.hmm_iter)
    else:
        fit = fit_markov_chain(built["sequences"], alpha=config.forecast.alpha,
                               min_sequences=min_sequences, min_transitions=min_transitions)

    if fit["status"] != "ok":
        payload = {"status": fit["status"], "reason": fit.get("reason"),
                   "entity_count": built["entities"],
                   "n_sequences": fit.get("n_sequences"), "n_transitions": fit.get("n_transitions"),
                   "window": {"since": since_iso, "until": until_iso},
                   "warnings": fetched["warnings"]}
        if params.response_format == "json":
            return json.dumps(payload, indent=2, ensure_ascii=False)
        return (f"# Tactic Forecast\n\n**Status**: `{fit['status']}`\n\n{fit.get('reason') or ''}")

    model_id = _model_id(fit)
    fit_params = (
        {"n_components": fit["n_components"], "seed": fit["seed"], "n_iter": fit["n_iter"],
         "min_sequences": max(min_sequences, config.forecast.hmm_min_sequences)}
        if params.kind == "hmm" else
        {"alpha": fit["alpha"], "min_sequences": min_sequences,
         "min_transitions": min_transitions})
    await asyncio.to_thread(
        save_model, model_id, fit["kind"], fit_params, fit["startprob"],
        fit["transmat"], fit.get("emissionprob"), fit.get("row_support"),
        fit["n_sequences"], fit["n_transitions"])

    payload = {
        "status": "ok", "model_id": model_id, "kind": fit["kind"],
        "taxonomy_version": fit["taxonomy_version"],
        "window": {"since": since_iso, "until": until_iso},
        "entity_count": built["entities"], "n_sequences": fit["n_sequences"],
        "n_transitions": fit["n_transitions"],
        "observations_appended": appended, "observations_in_window": len(stored),
        "dropped_unknown": built["dropped_unknown"], "dropped_no_entity": built["dropped_no_entity"],
        "dropped_short": built["dropped_short"],
        "top_transitions": _top_transitions(fit),
        "n_components": fit.get("n_components"),
        "purged_observations": purged.get("observations", 0),
        "warnings": fetched["warnings"],
    }
    if params.response_format == "json":
        return json.dumps(payload, indent=2, ensure_ascii=False)
    return _train_markdown(payload)


def _interval_seconds(value) -> Optional[float]:
    """Seconds in a ``fixed_interval`` string (``1m``, ``6h``, ``1d``). ``None``
    for anything else, so the caller reports buckets without a fabricated span."""
    text = str(value or "").strip().lower()
    units = {"s": 1.0, "m": 60.0, "h": 3600.0, "d": 86400.0}
    if len(text) < 2 or text[-1] not in units:
        return None
    try:
        return float(text[:-1]) * units[text[-1]]
    except ValueError:
        return None


async def _fetch_volume_buckets(since_iso: str, until_iso: str, bucket_interval: str) -> dict:
    """Date-histogram of alert counts. ``min_doc_count: 0`` is required: an
    empty bucket is a zero count, which is the signal Poisson regimes are fit
    to. Without it the series has holes and the HMM reads the gaps as missing
    time. ``extended_bounds`` keeps the first and last partial buckets present.
    """
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return {"buckets": [], "error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set.",
                "warnings": []}
    body = {
        "size": 0,
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": since_iso, "lt": until_iso,
                                      "format": "strict_date_optional_time"}}},
        ]}},
        "aggs": {"over_time": {"date_histogram": {
            "field": "@timestamp", "fixed_interval": bucket_interval,
            "min_doc_count": 0,
            "extended_bounds": {"min": since_iso, "max": until_iso}}}},
    }
    raw = await _wazuh_indexer_post(body)
    if "error" in raw:
        return {"buckets": [], "error": str(raw["error"]),
                "warnings": [f"Indexer query failed: {raw['error']}"]}
    hits_buckets = raw.get("aggregations", {}).get("over_time", {}).get("buckets", [])
    buckets: list[dict] = []
    for bucket in hits_buckets:
        ts = _epoch(bucket.get("key_as_string"))
        if ts is None:
            key = bucket.get("key")
            ts = float(key) / 1000.0 if isinstance(key, (int, float)) else None
        if ts is None:
            continue
        buckets.append({"ts": ts, "count": int(bucket.get("doc_count", 0) or 0)})
    return {"buckets": buckets, "error": None, "warnings": []}


def _volume_train_markdown(payload: dict) -> str:
    lines = [
        f"# Volume Forecast - model `{payload['model_id']}`",
        "",
        f"**Kind**: `{payload['kind']}` | **Bucket interval**: `{payload['bucket_interval']}` "
        f"| **Buckets**: {payload['n_buckets']} | **Alerts in window**: {payload['total_alerts']}",
        f"**Window**: `{payload['window']['since']}` -> `{payload['window']['until']}`",
        f"**Expected alerts per bucket (lambda per regime)**: "
        + ", ".join(f"`{value}`" for value in payload["lambdas"]),
        "",
        "A lambda is the mean alerts per bucket while that regime is active. The model says "
        "which regime is likely next, not which alert counts are acceptable.",
    ]
    if payload.get("warnings"):
        lines += ["", "**Indexer notes**"] + [f"- {warning}" for warning in payload["warnings"]]
    return "\n".join(lines)


def _volume_predict_markdown(payload: dict) -> str:
    prediction = payload["prediction"]
    if prediction.get("status") != "ok":
        return (f"# Volume Forecast model `{payload['model']}`\n\n"
                f"**Status**: `{prediction.get('status')}`\n\n{prediction.get('reason') or ''}")
    lines = [
        f"# Volume Forecast - model `{payload['model']}`",
        "",
        f"**Horizon**: {payload['horizon_buckets']} buckets at `{payload['bucket_interval']}` "
        f"| **Context**: {payload['context_buckets_used']} observed buckets",
        f"**Expected total**: {prediction['expected_total']} alerts | "
        f"**Mean per bucket**: {prediction['mean_per_bucket']} | "
        f"**Peak probability**: {prediction['peak_probability']:.0%} "
        f"(states {prediction['peak_states']})",
        "",
        "| Step | Expected alerts |",
        "|------|-----------------|",
    ]
    shown = prediction["expected_counts"][:24]
    lines += [f"| +{index + 1} | {value} |" for index, value in enumerate(shown)]
    if len(prediction["expected_counts"]) > len(shown):
        lines.append(f"| ... | {len(prediction['expected_counts']) - len(shown)} more buckets "
                     f"(expected total listed above) |")
    if prediction.get("posterior_fallback"):
        lines += ["", "**Posterior fallback**: the context posterior collapsed, so the prior "
                      "distribution was used. Do not quote this as a fitted forecast."]
    return "\n".join(lines)


def _volume_status_markdown(payload: dict) -> str:
    lines = ["# Volume Forecast status", "",
             f"**Status**: `{payload['status']}`",
             f"**Corpus**: {payload['store']['counts']} bucketed counts, "
             f"{payload['store']['observations']} tactic observations | "
             f"**Models**: {payload['store']['models']}"]
    if payload.get("model"):
        model = payload["model"]
        lines += ["", f"**Newest model**: `{model['model_id']}` (`{model['kind']}`, "
                      f"{model['n_sequences']} buckets)"]
    if payload.get("hint"):
        lines += ["", payload["hint"]]
    return "\n".join(lines)


class VolumeForecastInput(BaseModel):
    """Input model for blueteam_volume_forecast."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    mode: Literal["train", "predict", "status"] = Field(
        default="predict",
        description="'train' ingests the bucketed alert series and fits a PoissonHMM; "
                    "'predict' forecasts the next buckets; 'status' reads the corpus and model.")
    horizon_buckets: Optional[int] = Field(default=None, ge=1, le=336,
        description="Buckets to forecast; default from config (24).")
    context_buckets: Optional[int] = Field(default=None, ge=1, le=336,
        description="Most recent observed buckets used to filter the regime posterior.")
    n_components: Optional[int] = Field(default=None, ge=2, le=6,
        description="Poisson regimes (default 3: quiet/normal/burst).")
    min_buckets: Optional[int] = Field(default=None, ge=8, le=100000,
        description="Minimum buckets required to fit; default from config (48).")
    model_id: Optional[str] = Field(default=None, max_length=32,
        description="Model to load; newest fit when omitted.")
    time_window_minutes: int = Field(default=10080, ge=60, le=43200,
        description="Training window in minutes; the bucket interval is derived from it.")
    response_format: Literal["markdown", "json"] = Field(default="markdown")


@blueteam_tool(
    name="blueteam_volume_forecast",
    annotations={"readOnlyHint": False, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
    audit=True, truncate=True, redact=True,
)
async def blueteam_volume_forecast(params: VolumeForecastInput) -> str:
    """Fit and query a PoissonHMM over per-bucket Wazuh alert counts.
    The series comes from a ``date_histogram`` with empty buckets included, so a
    quiet hour is a real zero. The HMM's hidden states are volume regimes; each
    state carries its own Poisson mean (lambda), and the forecast rolls the
    regime distribution forward over the requested horizon. Output is an
    expected count per bucket, an expected total, and the exact probability that
    a maximum-lambda regime is active at least once in the horizon.

    Args:
        params.mode: 'train', 'predict' (default) or 'status'.
        params.horizon_buckets: Future buckets to forecast (1-336).
        params.context_buckets: Recent buckets used to filter the posterior.
        params.n_components: Poisson regimes (2-6).
        params.min_buckets: Minimum observed buckets to fit.
        params.model_id: Model to use; newest when omitted.
        params.time_window_minutes: 1 hour to 30 days for training.
        params.response_format: 'markdown' (default) or 'json'.

    Returns:
        markdown or json. Train: model id, bucket interval, per-regime lambdas,
        window and alert total. Predict: expected counts, expected total,
        peak probability and the final regime distribution. Status: corpus and
        newest-model metadata.

    Worked Examples:
        1. Weekly fit -> ``blueteam_volume_forecast(mode="train",
           time_window_minutes=10080, response_format="json")``
        2. Next day on the newest model -> ``blueteam_volume_forecast(
           mode="predict", horizon_buckets=24)``
        3. Tighter fit over a month -> ``blueteam_volume_forecast(mode="train",
           time_window_minutes=43200, n_components=4, min_buckets=120)``

    Permissions: read on the Wazuh Indexer; read/write on BLUETEAM_FORECAST_STORE.
    Rate limits: one size-0 aggregation per train; predict is store-only. The
    optional hmmlearn package is required to train, never to predict.
    """
    _require_enabled()
    since_iso, until_iso = _window(params.time_window_minutes)

    if params.mode == "status":
        store = await asyncio.to_thread(store_stats)
        model_summary = None
        try:
            loaded = await asyncio.to_thread(load_model, params.model_id)
        except BlueTeamMCPError as exc:
            payload = {"status": "error", "store": store, "model": None, "reason": str(exc),
                       "hint": None}
            if params.response_format == "json":
                return json.dumps(payload, indent=2, ensure_ascii=False)
            return _volume_status_markdown(payload)
        if loaded is not None:
            model_summary = _fit_params_summary(loaded)
        payload = {"status": "ok" if model_summary else "no_model", "store": store,
                   "model": model_summary,
                   "hint": None if model_summary else "Run mode='train' first to fit a volume model."}
        if params.response_format == "json":
            return json.dumps(payload, indent=2, ensure_ascii=False)
        return _volume_status_markdown(payload)

    if params.mode == "predict":
        loaded = await asyncio.to_thread(load_model, params.model_id, (VOLUME_KIND,))
        if loaded is None:
            raise BlueTeamMCPError(
                "No stored volume model. Run blueteam_volume_forecast mode='train' first.")
        if loaded["kind"] != VOLUME_KIND:
            raise BlueTeamMCPError(
                f"Stored model {loaded['model_id']} is a '{loaded['kind']}' model, not a "
                "volume model. Train one with blueteam_volume_forecast mode='train'.")
        context_size = params.context_buckets or config.forecast.volume_context_buckets
        horizon = params.horizon_buckets or config.forecast.volume_horizon_buckets
        all_counts = await asyncio.to_thread(load_counts)
        context = [int(count) for count in all_counts[-context_size:]]
        prediction = predict_volume(loaded, context, horizon)
        bucket_interval = loaded["params"].get("bucket_interval")
        interval_seconds = _interval_seconds(bucket_interval)
        payload = {
            "status": prediction.get("status", "ok"),
            "model": loaded["model_id"], "kind": loaded["kind"],
            "bucket_interval": bucket_interval,
            "horizon_buckets": horizon,
            "horizon_seconds": (None if interval_seconds is None
                                else round(interval_seconds * horizon, 1)),
            "context_buckets_used": len(context),
            "prediction": prediction,
        }
        if params.response_format == "json":
            return json.dumps(payload, indent=2, ensure_ascii=False)
        return _volume_predict_markdown(payload)

    bucket_interval = _auto_bucket_interval(params.time_window_minutes)
    fetched = await _fetch_volume_buckets(since_iso, until_iso, bucket_interval)
    if fetched["error"]:
        payload = {"status": "error", "reason": fetched["error"],
                   "bucket_interval": bucket_interval, "warnings": fetched["warnings"]}
        if params.response_format == "json":
            return json.dumps(payload, indent=2, ensure_ascii=False)
        return (f"# Volume Forecast\n\n**Status**: `error`\n\n{fetched['error']}")
    if not fetched["buckets"]:
        payload = {"status": "insufficient_data", "n_buckets": 0,
                   "bucket_interval": bucket_interval,
                   "window": {"since": since_iso, "until": until_iso},
                   "hint": "The aggregation returned no buckets; check the window and Indexer "
                           "connectivity.", "warnings": fetched["warnings"]}
        if params.response_format == "json":
            return json.dumps(payload, indent=2, ensure_ascii=False)
        return (f"# Volume Forecast\n\n**Status**: `insufficient_data` - no buckets in "
                f"`{since_iso}` -> `{until_iso}`.\n")

    await asyncio.to_thread(
        upsert_counts, [(bucket["ts"], bucket["count"]) for bucket in fetched["buckets"]])
    purged = await asyncio.to_thread(purge_expired)
    since_ts = time.time() - params.time_window_minutes * 60
    stored = await asyncio.to_thread(load_counts, since_ts)
    counts = [int(count) for count in stored]
    floor_buckets = params.min_buckets or config.forecast.volume_min_buckets
    components = params.n_components or config.forecast.volume_components
    fit = fit_poisson_hmm(counts, n_components=components, min_buckets=floor_buckets,
                          seed=config.forecast.hmm_seed, n_iter=config.forecast.hmm_iter)
    if fit["status"] != "ok":
        payload = {"status": fit["status"], "reason": fit.get("reason"),
                   "n_buckets": len(counts), "bucket_interval": bucket_interval,
                   "window": {"since": since_iso, "until": until_iso},
                   "warnings": fetched["warnings"]}
        if params.response_format == "json":
            return json.dumps(payload, indent=2, ensure_ascii=False)
        return (f"# Volume Forecast\n\n**Status**: `{fit['status']}`\n\n"
                f"{fit.get('reason') or ''}")

    model_id = _model_id(fit)
    fit_params = {"lambdas": fit["lambdas"], "n_components": fit["n_components"],
                  "seed": fit["seed"], "n_iter": fit["n_iter"],
                  "bucket_interval": bucket_interval, "min_buckets": floor_buckets}
    await asyncio.to_thread(
        save_model, model_id, fit["kind"], fit_params, fit["startprob"], fit["transmat"],
        None, None, fit["n_buckets"], 0)
    payload = {
        "status": "ok", "model_id": model_id, "kind": fit["kind"],
        "bucket_interval": bucket_interval,
        "window": {"since": since_iso, "until": until_iso},
        "n_buckets": fit["n_buckets"], "total_alerts": int(sum(counts)),
        "mean_per_bucket": round(sum(counts) / len(counts), 3) if counts else 0.0,
        "lambdas": fit["lambdas"], "n_components": fit["n_components"],
        "buckets_appended": len(fetched["buckets"]),
        "purged_counts": purged.get("counts", 0),
        "warnings": fetched["warnings"],
    }
    if params.response_format == "json":
        return json.dumps(payload, indent=2, ensure_ascii=False)
    return _volume_train_markdown(payload)
