#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Observed-source forecasting: rank candidate next-observed source IPs,
netblocks and observed source countries. Forecasts observed source
infrastructure, never attacker identity; every response carries
``attribution_status="not_established"``.
Gating: disabled by default. ``BLUETEAM_SOURCE_FORECAST_ENABLED=false`` raises an
enable hint, never an empty candidate set that would read as "no sources".
NOTE: No ``from __future__ import annotations`` deferred annotation evaluation
      (PEP 563) breaks @blueteam_tool type resolution.
"""
import asyncio
import hashlib
import json
import logging
import time
from datetime import datetime, timezone
from typing import Literal, Optional
from pydantic import BaseModel, ConfigDict, Field
from mcp_server.core import source_store
from mcp_server.core.config import config
from mcp_server.core.exceptions import BlueTeamMCPError
from mcp_server.core.tool_decorator import blueteam_tool
from mcp_server.correlation import source_core
from mcp_server.tools.forecast import (
    TacticForecastInput,
    _fetch_tactic_observations,
    blueteam_tactic_forecast,
)
from mcp_server.wazuh.time_utils import _parse_time_window

logger = logging.getLogger("blue_team_mcp.source_forecast")

_ATTRIBUTION_STATUS = "not_established"
_ASN_STATUS = "unavailable"


def _require_enabled() -> None:
    if not getattr(config.source, "enabled", False):
        raise BlueTeamMCPError(
            "Source forecasting is disabled. Set BLUETEAM_SOURCE_FORECAST_ENABLED=true "
            "and BLUETEAM_SOURCE_STORE=/abs/path/source.db, then restart the server."
        )


def _iso(timestamp: float) -> str:
    return datetime.fromtimestamp(float(timestamp), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _epoch(value: Optional[str]) -> Optional[float]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError as exc:
        raise BlueTeamMCPError(f"invalid timestamp {value!r}; use ISO-8601 UTC") from exc


def _as_of(value: Optional[str]) -> float:
    timestamp = _epoch(value) if value else time.time()
    if timestamp is None:
        timestamp = time.time()
    if timestamp > time.time():
        raise BlueTeamMCPError("as_of must not be in the future")
    return timestamp


def _render(params, payload: dict) -> str:
    if params.response_format == "json":
        return json.dumps(payload, indent=2, ensure_ascii=False)
    return _markdown(payload)


def _markdown(payload: dict) -> str:
    lines = [f"# Source forecast - `{payload.get('status')}`", ""]
    if payload.get("attribution_status"):
        lines.append(f"**Attribution status**: `{payload['attribution_status']}` "
                     "(candidates are observed-source estimates, not attribution)")
    candidates = (payload.get("candidates") or {}).get("ip") or []
    if candidates:
        lines += ["", "| Rank | Candidate source | Model score | Score kind | Netblock "
                      "| Observed country |", "|------|------------------|-------------|"
                      "------------|----------|------------------|"]
        lines += [f"| {item['rank']} | `{item['value']}` | {item['model_score']} "
                  f"| {item.get('score_kind') or '-'} | `{item.get('netblock') or '-'}` "
                  f"| {item.get('observed_source_country') or '-'} |" for item in candidates]
    if payload.get("status") not in ("ok",):
        lines += ["", payload.get("reason") or payload.get("hint") or ""]
    if payload.get("warnings"):
        lines += ["", "**Notes**"] + [f"- {warning}" for warning in payload["warnings"]]
    return "\n".join(lines)


def _normalize(fetched_rows: list[dict], section) -> tuple[list[dict], dict]:
    normalized: list[dict] = []
    stats = {"skipped_malformed": 0, "skipped_internal": 0, "skipped_missing": 0,
             "geo_rows": 0}
    for row in fetched_rows:
        source = row.get("entity_key")
        classification = source_core.classify_source(
            source, v4_prefix=int(section.netblock_v4_prefix),
            v6_prefix=int(section.netblock_v6_prefix))
        if not classification["valid"]:
            stats["skipped_missing" if not source else "skipped_malformed"] += 1
            continue
        if classification["is_internal"] and not section.include_internal:
            stats["skipped_internal"] += 1
            continue
        observed_at = row.get("observed_at")
        try:
            observed_at = float(observed_at)
        except (TypeError, ValueError):
            stats["skipped_missing"] += 1
            continue
        country = row.get("country")
        country = country.strip() if isinstance(country, str) and country.strip() else None
        if country:
            stats["geo_rows"] += 1
        tactics = source_core.normalize_tactics(row.get("tactic")) or [""]
        for tactic in tactics:
            normalized.append({"source_ip": classification["normalized"],
                               "netblock": classification["netblock"],
                               "country": country, "tactic": tactic,
                               "observed_at": observed_at})
    return normalized, stats


async def _ingest(params) -> dict:
    since_iso, until_iso = _parse_time_window(params.since or "24h", params.until)
    fetched = await _fetch_tactic_observations(None, since_iso, until_iso, include_geo=True)
    complete = bool(fetched.get("window_complete")) and bool(fetched.get("snapshot_consistent"))
    section = config.source
    rows, stats = _normalize(fetched.get("rows") or [], section)
    corpus = {"window_complete": bool(fetched.get("window_complete")),
              "snapshot_consistent": bool(fetched.get("snapshot_consistent")),
              "verified": complete,
              "fetched_hits": fetched.get("fetched_hits"),
              "rows": len(rows),
              "geo_coverage": (round(stats["geo_rows"] / len(rows), 4) if rows else None)}
    warnings = list(fetched.get("warnings") or [])
    if not complete and section.require_complete_corpus:
        return {"status": "incomplete_corpus", "mode": "ingest", "corpus": corpus,
                "rows_persisted": 0, "warnings": warnings,
                "hint": "Set BLUETEAM_SOURCE_REQUIRE_COMPLETE_CORPUS=false to ingest "
                        "a visibly degraded corpus."}
    if not rows:
        return {"status": "no_sources", "mode": "ingest", "corpus": corpus,
                "rows_persisted": 0, "warnings": warnings}
    persisted = await asyncio.to_thread(source_store.save_source_observations, rows)
    ingest_id = "si-" + hashlib.sha256(f"{since_iso}|{until_iso}".encode("utf-8")).hexdigest()[:10]
    await asyncio.to_thread(
        source_store.save_ingest, ingest_id, float(_epoch(since_iso)), float(_epoch(until_iso)),
        bool(fetched.get("window_complete")), bool(fetched.get("snapshot_consistent")),
        {"fetched_hits": fetched.get("fetched_hits"), "usable_rows": len(rows),
         "geo_rows": stats["geo_rows"], "skipped_internal": stats["skipped_internal"],
         "skipped_malformed": stats["skipped_malformed"],
         "skipped_missing": stats["skipped_missing"]})
    if stats["skipped_internal"]:
        warnings.append(f"{stats['skipped_internal']} internal/non-routable sources excluded")
    if stats["skipped_malformed"]:
        warnings.append(f"{stats['skipped_malformed']} malformed sources skipped")
    purged = await asyncio.to_thread(source_store.purge_expired)
    return {"status": "ok" if complete else "degraded", "mode": "ingest",
            "ingest_id": ingest_id, "rows_persisted": persisted,
            "purged_rows": purged.get("rows", 0),
            "corpus": corpus, "warnings": warnings}


def _filter_internal(rows: list[dict], section) -> list[dict]:
    if section.include_internal:
        return rows
    kept = []
    for row in rows:
        classified = source_core.classify_source(
            row.get("source_ip"), v4_prefix=int(section.netblock_v4_prefix),
            v6_prefix=int(section.netblock_v6_prefix))
        if classified["valid"] and not classified["is_internal"]:
            kept.append(row)
    return kept


def _corpus_block(start: float, cutoff: float, rows: list[dict], unverified: bool) -> dict:
    covering = None if unverified else source_store.complete_ingest_covering(start, cutoff)
    geo = sum(1 for row in rows if row.get("country"))
    return {"verified": covering is not None,
            "window_complete": bool(covering and covering["window_complete"]),
            "snapshot_consistent": bool(covering and covering["snapshot_consistent"]),
            "rows": len(rows),
            "geo_coverage": (round(geo / len(rows), 4) if rows else None)}


def _context_tactics(rows: list[dict], cutoff: float, window_minutes: int) -> list[str]:
    floor = cutoff - max(1, int(window_minutes)) * 60.0
    tactics: list[str] = []
    for row in rows:
        if float(row["observed_at"]) < floor:
            continue
        tactics.extend(source_core.normalize_tactics(row.get("tactic")))
    return sorted(set(tactics))


def _predict(params) -> dict:
    section = config.source
    as_of = _as_of(params.as_of)
    history_days = int(params.history_days or section.history_days)
    start = as_of - history_days * 86400.0
    rows = _filter_internal(
        source_store.load_source_observations(start, as_of), section)
    if len(rows) < int(section.min_observations):
        return {"status": "insufficient_history", "mode": "predict",
                "as_of": _iso(as_of), "training_cutoff": _iso(as_of),
                "attribution_status": _ATTRIBUTION_STATUS,
                "reason": (f"{len(rows)} observations in the last {history_days} days; "
                           f"need at least {section.min_observations}"),
                "corpus": _corpus_block(start, as_of, rows, True),
                "candidates": {"ip": [], "netblock": [], "asn": [], "country": []},
                "country_status": "insufficient_geo", "asn_status": _ASN_STATUS,
                "baselines": {"persistence_source": None, "persistence_country": None},
                "warnings": []}

    unverified = source_store.complete_ingest_covering(start, as_of) is None
    if unverified and not params.allow_unverified_history:
        return {"status": "corpus_unverified", "mode": "predict",
                "as_of": _iso(as_of), "training_cutoff": _iso(as_of),
                "attribution_status": _ATTRIBUTION_STATUS,
                "reason": "no complete ingest covers the training window; rerun "
                          "mode='ingest' or set allow_unverified_history=true",
                "corpus": _corpus_block(start, as_of, rows, True),
                "candidates": {"ip": [], "netblock": [], "asn": [], "country": []},
                "country_status": "insufficient_geo", "asn_status": _ASN_STATUS,
                "baselines": {"persistence_source": None, "persistence_country": None},
                "warnings": ["training history has no verified ingest"]}

    source_timeline = source_core.build_timeline(rows, as_of)
    country_timeline = source_core.build_country_timeline(rows, as_of)
    entries = [{"value": entry["value"], "observed_at": entry["observed_at"],
                "country": entry["country"], "tactics": entry["tactics"]}
               for entry in source_timeline]
    context = _context_tactics(rows, as_of, params.context_window_minutes)
    scored = source_core.score_sequence(
        entries, context, as_of, half_life_days=section.half_life_days, alpha=0.5,
        min_transitions=section.min_transitions,
        max_candidates=int(params.max_candidates or section.max_candidates),
        history_seconds=history_days * 86400.0)
    netblocks = {row["source_ip"]: row["netblock"] for row in rows}

    ip_candidates: list[dict] = []
    for candidate in scored["candidates"]:
        ip_candidates.append({
            "rank": candidate["rank"], "value": candidate["value"],
            "model_score": candidate["model_score"], "score_kind": candidate["score_kind"],
            "components": candidate["components"],
            "transition_probability": candidate["transition_probability"],
            "transition_support": candidate["transition_support"],
            "first_seen": candidate["first_seen"], "last_seen": candidate["last_seen"],
            "occurrence_count": candidate["occurrence_count"],
            "tactics": candidate["tactics"],
            "netblock": netblocks.get(candidate["value"]),
            "observed_source_country": candidate["country"]})

    grouped: dict[str, dict] = {}
    if params.include_netblock:
        for candidate in ip_candidates:
            key = candidate["netblock"]
            if not key:
                continue
            item = grouped.setdefault(key, {"value": key, "model_score": 0.0,
                                            "occurrence_count": 0})
            item["model_score"] = round(item["model_score"] + candidate["model_score"], 6)
            item["occurrence_count"] += candidate["occurrence_count"]
    netblock_candidates = sorted(grouped.values(),
                                 key=lambda item: (-item["model_score"], item["value"]))
    for index, item in enumerate(netblock_candidates, start=1):
        item["rank"] = index

    corpus = _corpus_block(start, as_of, rows, unverified)
    geo_coverage = corpus["geo_coverage"] or 0.0
    country_candidates: list[dict] = []
    if not params.include_country:
        country_status = "disabled"
    elif geo_coverage < float(section.min_geo_coverage):
        country_status = "insufficient_geo"
    else:
        country_status = "ok"
        country_entries = [{"value": entry["value"], "observed_at": entry["observed_at"],
                            "country": entry["country"], "tactics": entry["tactics"]}
                           for entry in country_timeline]
        country_scored = source_core.score_sequence(
            country_entries, context, as_of, half_life_days=section.half_life_days,
            alpha=0.5, min_transitions=section.min_transitions,
            max_candidates=int(params.max_candidates or section.max_candidates),
            history_seconds=history_days * 86400.0)
        country_candidates = [
            {"rank": item["rank"], "value": item["value"],
             "model_score": item["model_score"], "score_kind": item["score_kind"],
             "occurrence_count": item["occurrence_count"],
             "first_seen": item["first_seen"], "last_seen": item["last_seen"]}
            for item in country_scored["candidates"]]

    warnings: list[str] = []
    if unverified:
        warnings.append("training history has no verified ingest; result is degraded")
    return {"status": "degraded" if unverified else "ok", "mode": "predict",
            "as_of": _iso(as_of), "training_cutoff": _iso(as_of),
            "attribution_status": _ATTRIBUTION_STATUS,
            "corpus": corpus, "country_status": country_status, "asn_status": _ASN_STATUS,
            "candidates": {"ip": ip_candidates, "netblock": netblock_candidates,
                           "asn": [], "country": country_candidates},
            "baselines": {
                "persistence_source": source_timeline[-1]["value"] if source_timeline else None,
                "persistence_country": (country_timeline[-1]["value"]
                                        if country_timeline else None)},
            "warnings": warnings}


def _day_cutoffs(start_epoch: float, end_epoch: float, step_days: int) -> list[float]:
    first = datetime.fromtimestamp(start_epoch, timezone.utc)
    first = first.replace(hour=0, minute=0, second=0, microsecond=0)
    cutoffs: list[float] = []
    current = first.timestamp()
    step = max(1, int(step_days)) * 86400.0
    while current < end_epoch:
        cutoffs.append(current)
        current += step
    return cutoffs


def _evaluate(params) -> dict:
    section = config.source
    since_iso, until_iso = _parse_time_window(params.since or "30d", params.until)
    end = float(_epoch(until_iso))
    history_days = int(params.history_days or section.history_days)
    horizon = float(params.horizon_minutes or section.eval_horizon_minutes) * 60.0
    observations = source_store.load_source_observations(
        float(_epoch(since_iso)) - history_days * 86400.0, end + horizon)
    cutoffs = _day_cutoffs(float(_epoch(since_iso)), end, section.eval_step_days)
    evaluation = source_core.evaluate_rolling(
        observations, cutoffs, horizon_seconds=horizon,
        history_seconds=history_days * 86400.0, half_life_days=section.half_life_days,
        alpha=0.5, min_transitions=section.min_transitions,
        max_candidates=section.max_candidates,
        min_observations=section.eval_min_train_observations)
    return {"status": "ok", "mode": "evaluate", "evaluation": evaluation}


class SourceForecastInput(BaseModel):
    """Input model for blueteam_source_forecast."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    mode: Literal["predict", "ingest", "evaluate", "status"] = Field(
        default="predict",
        description="'predict' ranks candidate next-observed sources; 'ingest' fills the "
                    "source store from a verified paged fetch; 'evaluate' runs the "
                    "rolling-origin comparison; 'status' reads store depth.")
    as_of: Optional[str] = Field(default=None, max_length=40,
        description="Prediction cutoff (ISO-8601 UTC); default now. Must not be in the future.")
    since: Optional[str] = Field(default=None, max_length=40,
        description="Ingest/evaluate window start (ISO-8601 or relative like '30d').")
    until: Optional[str] = Field(default=None, max_length=40,
        description="Ingest/evaluate window end (ISO-8601 or relative).")
    history_days: Optional[int] = Field(default=None, ge=1, le=365,
        description="Training history in days; default from config (90).")
    horizon_minutes: Optional[int] = Field(default=None, ge=1, le=10080,
        description="Evaluation target horizon in minutes; default from config (1440).")
    max_candidates: Optional[int] = Field(default=None, ge=1, le=50,
        description="Candidate ceiling; default from config (10).")
    context_window_minutes: int = Field(default=60, ge=1, le=1440,
        description="Tactic context window before the cutoff.")
    include_netblock: bool = Field(default=True,
        description="Aggregate candidate IPs into netblock candidates.")
    include_country: bool = Field(default=True,
        description="Rank candidate observed source countries when GeoIP coverage allows.")
    allow_unverified_history: bool = Field(default=False,
        description="Allow prediction from history without a complete ingest stamp; the "
                    "result is marked degraded.")
    response_format: Literal["markdown", "json"] = Field(default="markdown")
    bypass_redaction: bool = Field(default=False)


@blueteam_tool(
    name="blueteam_source_forecast",
    annotations={"readOnlyHint": False, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
    audit=True, truncate=True, redact=True,
)
async def blueteam_source_forecast(params: SourceForecastInput) -> str:
    """Forecast the next observed source infrastructure for a Wazuh deployment.
    Candidates are estimates over *observed* sources, not attacker attribution:
    every response carries ``attribution_status="not_established"``. IP
    candidates are ranked by a documented scoring model with per-component
    evidence; ``transition_probability`` is a smoothed empirical estimate with
    its support, while ``model_score`` is a ranking heuristic, not a calibrated
    probability. Netblocks aggregate candidate scores; ASN is unavailable in v1
    because the Wazuh index exposes no deterministic ASN field; countries come
    from ``GeoLocation.country_name`` and are reported as observed source
    countries.

    Args:
        params.mode: 'predict' (default), 'ingest', 'evaluate', or 'status'.
        params.as_of: Prediction cutoff; must not be in the future.
        params.since/params.until: Ingest/evaluate window.
        params.history_days: Training history (1-365; default from config, 90).
        params.horizon_minutes: Evaluation target horizon.
        params.max_candidates: Candidate ceiling (1-50).
        params.context_window_minutes: Tactic context window.
        params.include_netblock/params.include_country: Candidate families to emit.
        params.allow_unverified_history: Accept an unstamped corpus as degraded.
        params.response_format: 'markdown' (default) or 'json'.

    Returns:
        markdown or json. Predict: ranked candidate IPs/netblocks/countries with
        model scores, components, transition support and evidence; corpus
        completeness; baselines; warnings. Ingest: rows persisted and the
        corpus completeness stamp. Evaluate: rolling-origin metrics with
        persistence and frequency baselines. Status: store depth and last ingest.

    Worked Examples:
        1. Ingest yesterday -> ``blueteam_source_forecast(mode="ingest",
           since="<yesterday>", until="<today>", response_format="json")``
        2. Predict now -> ``blueteam_source_forecast(mode="predict",
           history_days=90, response_format="json")``
        3. Rolling evaluation -> ``blueteam_source_forecast(mode="evaluate",
           since="30d", response_format="json")``

    Permissions: read on the Wazuh Indexer and the source store; write on ingest.
    Rate limits: one paged fetch per ingest; predictions are store-only.
    """
    _require_enabled()
    if params.mode == "status":
        return _render(params, {"status": "ok", "mode": "status",
                                "store": await asyncio.to_thread(source_store.store_stats),
                                "last_ingest": await asyncio.to_thread(source_store.load_ingest)})
    if params.mode == "ingest":
        return _render(params, await _ingest(params))
    if params.mode == "evaluate":
        return _render(params, await asyncio.to_thread(_evaluate, params))
    return _render(params, await asyncio.to_thread(_predict, params))


class AttackForecastInput(BaseModel):
    """Input model for blueteam_attack_forecast."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    srcip: Optional[str] = Field(default=None, max_length=64,
        description="Entity for the behavioral tactic forecast; optional.")
    current_tactic: Optional[str] = Field(default=None, max_length=64,
        description="Tactic anchor when no entity is given.")
    as_of: Optional[str] = Field(default=None, max_length=40,
        description="Prediction cutoff passed to the source layer.")
    history_days: Optional[int] = Field(default=None, ge=1, le=365)
    response_format: Literal["markdown", "json"] = Field(default="markdown")


@blueteam_tool(
    name="blueteam_attack_forecast",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
    audit=True, truncate=True, redact=True,
)
async def blueteam_attack_forecast(params: AttackForecastInput) -> str:
    """Combine the behavioral tactic forecast and the source forecast in one call.
    The behavioral layer predicts the next ATT&CK tactic for an entity; the source
    layer ranks candidate next-observed source infrastructure. The layers stay
    separate in the response; source candidates are never presented as attacker
    attribution (``attribution_status="not_established"``).
    """
    _require_enabled()
    behavioral = json.loads(await blueteam_tactic_forecast(TacticForecastInput(
        mode="predict", srcip=params.srcip, current_tactic=params.current_tactic,
        response_format="json")))
    sources = json.loads(await blueteam_source_forecast(SourceForecastInput(
        mode="predict", as_of=params.as_of, history_days=params.history_days,
        response_format="json")))
    payload = {"status": "ok", "behavioral": behavioral, "sources": sources,
               "attribution_status": _ATTRIBUTION_STATUS}
    if params.response_format == "json":
        return json.dumps(payload, indent=2, ensure_ascii=False)
    return "\n".join([_markdown(sources), "", "## Behavioral layer", "",
                      json.dumps(behavioral, indent=2, ensure_ascii=False)])
