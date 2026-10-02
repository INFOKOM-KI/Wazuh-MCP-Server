#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Alert-entity clustering: fit HDBSCAN over srcip feature profiles and assign a
live entity to a stored cluster.
Pipeline position
blueteam_alert_cluster         -> fit + persist (centroids, medoids, radii)
blueteam_alert_cluster_assign  -> real-time label for one srcip

The population comes from the same MITRE-first aggregation the 3-Sum engine
uses (``fetch_srcip_profiles``), so an entity's cluster is derived from the
scores that already drive detection. Assignment is nearest-centroid, not
inductive prediction: the pinned scikit-learn HDBSCAN exposes ``fit_predict``
only.

Gating: disabled by default. ``BLUETEAM_CLUSTER_ENABLED=false`` makes both tools
raise an enable hint instead of returning empty clusters, which would read as
"no clusters exist" when the truth is "clustering is off".

NOTE: No ``from __future__ import annotations`` deferred annotation evaluation
      (PEP 563) breaks @blueteam_tool type resolution.
"""
import asyncio
import hashlib
import json
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal, Optional
from pydantic import BaseModel, ConfigDict, Field
from mcp_server.core.cluster_features import FEATURE_VERSION, build_vector, normalize_entity_key
from mcp_server.core.cluster_store import (
    ClusterStoreError,
    get_assignment,
    load_fit,
    load_fit_history,
    pending_novelty_count,
    record_assignment,
    save_fit,
    store_stats,
)
from mcp_server.core.config import config
from mcp_server.core.exceptions import BlueTeamMCPError
from mcp_server.core.tool_decorator import blueteam_tool
from mcp_server.correlation.cluster_core import assign_vector, fit_clusters
from mcp_server.correlation.three_sum_core import build_category_techniques
from mcp_server.tools.correlation import _load_mitre_technique_map, fetch_srcip_profiles
from mcp_server.wazuh.indexer import _SRCIP_FIELD_PATHS, _wazuh_indexer_field_caps

logger = logging.getLogger("blue_team_mcp.cluster")

_PENDING_REFIT_AT = 20

_DEFAULT_A_GROUPS = ["web", "attack", "scan", "recon", "accesslog"]
_DEFAULT_B_GROUPS = ["authentication_failures", "bruteforce", "blocklist",
                     "zimbra", "spam", "postfix"]
_DEFAULT_C_GROUPS = ["firewall_drop", "exfiltration", "overflow", "opencti",
                     "backdoor", "defacement"]

_BACKFILL_ID_PREFIX = "bf-"
_DAY_SECONDS = 86400


def _require_enabled() -> None:
    if not config.cluster.enabled:
        raise BlueTeamMCPError(
            "Alert clustering is disabled. Set BLUETEAM_CLUSTER_ENABLED=true and "
            "BLUETEAM_CLUSTER_STORE=/abs/path/clusters.db, install scikit-learn "
            "(setup.sh BLUETEAM_INSTALL_CLUSTER=1), then restart the server."
        )


_WINDOW_FMT = "%Y-%m-%dT%H:%M:%SZ"


def _window(minutes: int) -> tuple[str, str]:
    until = datetime.utcnow()
    return ((until - timedelta(minutes=minutes)).strftime(_WINDOW_FMT),
            until.strftime(_WINDOW_FMT))


def _window_minutes(window: dict) -> Optional[float]:
    """Duration of a stored fit window. ``None`` when the fit carries no usable
    stamp, which leaves the scale of its entity vectors unverifiable."""
    since, until = (window or {}).get("since"), (window or {}).get("until")
    if not since or not until:
        return None
    try:
        span = (datetime.strptime(until, _WINDOW_FMT)
                - datetime.strptime(since, _WINDOW_FMT))
    except ValueError:
        return None
    return span.total_seconds() / 60.0


def _categories(params) -> list[tuple[str, str, list[str]]]:
    return [("A", "recon", params.category_a_groups),
            ("B", "access", params.category_b_groups),
            ("C", "c2_exfil", params.category_c_groups)]


def _utc_midnight(value: Optional[str], field: str) -> datetime:
    """Parse a UTC date or ISO timestamp into a naive midnight.
    Non-midnight values are rejected: a backfill window is a whole UTC day.
    """
    text = (value or "").strip()
    try:
        parsed = (datetime.strptime(text, "%Y-%m-%d") if len(text) == 10
                  else datetime.fromisoformat(text.replace("Z", "+00:00")))
    except ValueError as exc:
        raise BlueTeamMCPError(
            f"{field} must be YYYY-MM-DD or ISO-8601 UTC (got {value!r})") from exc
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    if (parsed.hour, parsed.minute, parsed.second, parsed.microsecond) != (0, 0, 0, 0):
        raise BlueTeamMCPError(f"{field} must be UTC midnight (got {value!r})")
    return parsed


def _resolve_backfill_range(params) -> tuple[str, str, list[dict]]:
    """Resolve the previous completed UTC days, oldest first.
    ``until`` defaults to today 00:00 UTC and may not pass it, so the current
    partial day is never fitted. ``since`` defaults to ``max_days`` before
    ``until``.
    """
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0,
                                               microsecond=0, tzinfo=None)
    until_dt = _utc_midnight(params.until, "until") if params.until else today
    if until_dt > today:
        raise BlueTeamMCPError(
            "until must not be later than today's UTC midnight; backfill never "
            "fits the current partial day")
    since_dt = (_utc_midnight(params.since, "since") if params.since
                else until_dt - timedelta(days=params.max_days))
    if since_dt >= until_dt:
        raise BlueTeamMCPError("since must be earlier than until")
    span_seconds = (until_dt - since_dt).total_seconds()
    if span_seconds % _DAY_SECONDS:
        raise BlueTeamMCPError("since and until must span a whole number of UTC days")
    days = int(span_seconds // _DAY_SECONDS)
    if days > params.max_days:
        raise BlueTeamMCPError(f"requested {days} days exceeds max_days={params.max_days}")
    windows: list[dict] = []
    for index in range(days):
        start = since_dt + timedelta(days=index)
        windows.append({
            "day": start.strftime("%Y-%m-%d"),
            "since": start.strftime(_WINDOW_FMT),
            "until": (start + timedelta(days=1)).strftime(_WINDOW_FMT),
        })
    return windows[0]["since"], windows[-1]["until"], windows


def _backfill_fit_id(since_iso: str, until_iso: str) -> str:
    """One fit per UTC day: the window is the identity, so a parameter change
    replaces that day's fit instead of creating a second version of it. The
    ``bf-`` prefix cannot collide with a random hex live id.
    """
    digest = hashlib.sha256(f"{since_iso}|{until_iso}".encode("utf-8")).hexdigest()
    return f"{_BACKFILL_ID_PREFIX}{digest[:10]}"


def _backfill_markdown(payload: dict) -> str:
    lines = [
        "# Cluster backfill",
        "",
        f"**Window**: `{payload['window']['since']}` -> `{payload['window']['until']}`",
        f"**Fitted**: {payload.get('days_fitted', 0)} | **Skipped**: "
        f"{payload.get('days_skipped', 0)} | **Incomplete**: {payload.get('days_incomplete', 0)} "
        f"| **Failed**: {payload.get('days_failed', 0)} | **Capacity skipped**: "
        f"{payload.get('days_capacity_skipped', 0)}",
    ]
    if payload.get("status") != "ok":
        lines += ["", f"**Status**: `{payload['status']}`", "", payload.get("reason") or ""]
        return "\n".join(lines)
    lines += ["", "| Day | Status | Entities | Clusters | Noise | Note |",
              "|-----|--------|----------|----------|-------|------|"]
    for day in payload["days"]:
        entities = day.get("entity_count")
        clusters = day.get("cluster_count")
        noise = day.get("noise_count")
        lines.append(
            f"| {day['day']} | {day['status']} "
            f"| {entities if entities is not None else '-'} "
            f"| {clusters if clusters is not None else '-'} "
            f"| {noise if noise is not None else '-'} "
            f"| {day.get('reason') or '-'} |")
    if payload.get("warnings"):
        lines += ["", "**Notes**"] + [f"- {warning}" for warning in payload["warnings"]]
    return "\n".join(lines)


async def _backfill_one_day(params, window: dict, technique_tactics,
                            category_techniques, srcip_paths: list[str]) -> dict:
    """Fetch, gate and fit one UTC day.
    The day reaches ``save_fit`` only when every completeness counter is zero;
    degraded or empty data is reported, never fabricated into a fit.
    """
    since_iso, until_iso = window["since"], window["until"]
    row = {"day": window["day"], "window": {"since": since_iso, "until": until_iso},
           "fit_id": _backfill_fit_id(since_iso, until_iso), "status": "ok",
           "entity_count": None, "cluster_count": None, "noise_count": None,
           "noise_ratio": None, "reason": None}
    fetched = await fetch_srcip_profiles(
        _categories(params), since_iso, until_iso, use_mitre=params.use_mitre,
        technique_tactics=technique_tactics, category_techniques=category_techniques,
        srcip_paths=srcip_paths)
    degraded = []
    if fetched.get("failures"):
        degraded.append(f"{fetched['failures']} category fetch failures")
    if fetched.get("path_errors"):
        degraded.append(f"{fetched['path_errors']} srcip path errors")
    if fetched.get("partial_shards"):
        degraded.append(f"{fetched['partial_shards']} failed shards")
    if fetched.get("fallback_paths"):
        degraded.append(f"{fetched['fallback_paths']} srcip mapping fallbacks")
    if degraded:
        row["status"] = "incomplete"
        row["reason"] = "degraded fetch: " + ", ".join(degraded)
        return row
    profiles = fetched.get("profiles") or {}
    if not profiles:
        row["status"] = "skipped"
        row["reason"] = "no srcip entities in the day"
        return row
    entity_keys = sorted(profiles)
    vectors = [build_vector(profiles[key], 1440) for key in entity_keys]
    min_size = params.min_cluster_size or config.cluster.min_cluster_size
    min_samples = params.min_samples or config.cluster.min_samples
    result = await asyncio.to_thread(fit_clusters, vectors, min_size, min_samples)
    if result["status"] != "ok":
        row["status"] = "skipped" if result["status"] == "insufficient_data" else "error"
        row["reason"] = result.get("reason")
        return row
    fit_params = dict(result["params"])
    fit_params.update({"origin": "backfill", "use_mitre": params.use_mitre,
                       "window_minutes": 1440})
    try:
        await asyncio.to_thread(
            save_fit, row["fit_id"], fit_params, result["clusters"],
            result["entity_count"], result["noise_count"],
            {"since": since_iso, "until": until_iso}, enforce_capacity=True)
    except ClusterStoreError as exc:
        row["status"] = "capacity_skipped"
        row["reason"] = str(exc)[:200]
        return row
    row.update({"entity_count": result["entity_count"],
                "cluster_count": len(result["clusters"]),
                "noise_count": result["noise_count"],
                "noise_ratio": result.get("noise_ratio")})
    return row


async def _run_backfill(params) -> str:
    """Fit every completed UTC day in the resolved range, oldest first.
    Best-effort: one degraded or failed day does not discard the others. The
    capacity precheck is advisory - another writer can consume a slot between
    days, so capacity is re-read before each net-new write and a full store is
    reported as ``capacity_skipped`` instead of evicting a live fit.
    """
    since_iso, until_iso, windows = _resolve_backfill_range(params)
    planned = [_backfill_fit_id(window["since"], window["until"]) for window in windows]
    existing = await asyncio.to_thread(load_fit_history, config.cluster.max_fits)
    existing_ids = {fit["fit_id"] for fit in existing}
    net_new = sum(1 for fit_id in planned if fit_id not in existing_ids)
    max_fits = int(config.cluster.max_fits)
    stats = await asyncio.to_thread(store_stats)
    current = int(stats.get("fits") or 0)
    capacity = {"max_fits": max_fits, "existing_fits": current,
                "net_new_days": net_new, "available": max(0, max_fits - current),
                "exhausted": False}
    if net_new > capacity["available"]:
        payload = {"status": "insufficient_capacity", "mode": "backfill",
                   "window": {"since": since_iso, "until": until_iso},
                   "days_requested": len(windows), "capacity": capacity,
                   "reason": (f"{net_new} net-new backfill fits exceed "
                              f"{capacity['available']} available of "
                              f"BLUETEAM_CLUSTER_MAX_FITS={max_fits}; raise the ceiling "
                              "or shrink the range")}
        if params.response_format == "json":
            return json.dumps(payload, indent=2, ensure_ascii=False)
        return _backfill_markdown(payload)

    caps = await _wazuh_indexer_field_caps(_SRCIP_FIELD_PATHS)
    live_paths = [path for path in _SRCIP_FIELD_PATHS if path in caps]
    if not live_paths:
        payload = {"status": "srcip_mapping_degraded", "mode": "backfill",
                   "window": {"since": since_iso, "until": until_iso},
                   "days_requested": len(windows), "capacity": capacity,
                   "reason": ("no mapped srcip field path; refusing to build historical "
                              "fits from a fallback field. Check the Indexer mapping "
                              "with blueteam_index_schema.")}
        if params.response_format == "json":
            return json.dumps(payload, indent=2, ensure_ascii=False)
        return _backfill_markdown(payload)

    technique_tactics = None
    category_techniques = None
    if params.use_mitre:
        technique_tactics = await _load_mitre_technique_map()
        category_techniques = build_category_techniques(technique_tactics or {})

    days: list[dict] = []
    counts = {"ok": 0, "skipped": 0, "incomplete": 0, "error": 0, "capacity_skipped": 0}
    warnings: list[str] = []
    for window in windows:
        fit_id = _backfill_fit_id(window["since"], window["until"])
        row = None
        if fit_id not in existing_ids:
            # Capacity is re-read per net-new day: the precheck above is advisory,
            # not a reservation against another writer. The save itself re-checks
            # inside the write transaction, so a race cannot evict a live fit.
            stats = await asyncio.to_thread(store_stats)
            if int(stats.get("fits") or 0) >= max_fits:
                row = {"day": window["day"],
                       "window": {"since": window["since"], "until": window["until"]},
                       "fit_id": fit_id, "status": "capacity_skipped",
                       "entity_count": None, "cluster_count": None,
                       "noise_count": None, "noise_ratio": None,
                       "reason": "store reached BLUETEAM_CLUSTER_MAX_FITS"}
        if row is None:
            try:
                row = await _backfill_one_day(params, window, technique_tactics,
                                              category_techniques, live_paths)
            except BlueTeamMCPError as exc:
                row = {"day": window["day"],
                       "window": {"since": window["since"], "until": window["until"]},
                       "fit_id": fit_id, "status": "error", "entity_count": None,
                       "cluster_count": None, "noise_count": None, "noise_ratio": None,
                       "reason": str(exc)[:200]}
            except Exception as exc:
                row = {"day": window["day"],
                       "window": {"since": window["since"], "until": window["until"]},
                       "fit_id": fit_id, "status": "error", "entity_count": None,
                       "cluster_count": None, "noise_count": None, "noise_ratio": None,
                       "reason": f"{type(exc).__name__}: {exc}"[:200]}
        if row["status"] == "capacity_skipped" and not capacity["exhausted"]:
            warnings.append(
                "capacity was reached mid-run; remaining net-new days were skipped. "
                "Raise BLUETEAM_CLUSTER_MAX_FITS and rerun to fill the gaps.")
            capacity["exhausted"] = True
        days.append(row)
        counts[row["status"]] = counts.get(row["status"], 0) + 1

    payload = {
        "status": "ok", "mode": "backfill",
        "window": {"since": since_iso, "until": until_iso},
        "days_requested": len(windows), "days_fitted": counts["ok"],
        "days_skipped": counts["skipped"], "days_incomplete": counts["incomplete"],
        "days_failed": counts["error"],
        "days_capacity_skipped": counts["capacity_skipped"],
        "capacity": capacity, "days": days, "warnings": warnings,
    }
    if params.response_format == "json":
        return json.dumps(payload, indent=2, ensure_ascii=False)
    if params.response_format == "toon":
        return payload
    return _backfill_markdown(payload)


def _cluster_records(result: dict, entity_keys: list[str], vectors: list[list[float]],
                     profiles: dict) -> list[dict]:
    """Describe each cluster by size, radius and its medoid entity. Member IPs
    stay out of the response: the caller gets the shape of the cluster, not a
    list of third-party indicators."""
    records: list[dict] = []
    for cluster in result["clusters"]:
        try:
            index = vectors.index(cluster["medoid"])
        except ValueError:
            index = -1
        key = entity_keys[index] if 0 <= index < len(entity_keys) else None
        profile = profiles.get(key or "", {})
        top_tactics = sorted((profile.get("tactics") or {}).items(),
                             key=lambda item: item[1], reverse=True)[:3]
        records.append({
            "label": int(cluster["label"]),
            "size": int(cluster["size"]),
            "radius": round(float(cluster["radius"]), 3),
            "medoid": key,
            "top_tactics": [tactic for tactic, _ in top_tactics],
        })
    return records


def _fit_markdown(payload: dict) -> str:
    lines = [
        f"# Alert Entity Clustering - fit `{payload['fit_id']}`",
        "",
        f"**Window**: `{payload['window']['since']}` -> `{payload['window']['until']}`",
        f"**Entities**: {payload['entity_count']} | **Clusters**: {len(payload['clusters'])} "
        f"| **Noise**: {payload['noise_count']} ({payload['noise_ratio']:.0%})",
        f"**Feature version**: `{payload['feature_version']}` | **Params**: "
        f"`min_cluster_size={payload['params']['min_cluster_size']}, "
        f"min_samples={payload['params']['min_samples']}`",
        "",
    ]
    if payload["clusters"]:
        lines += ["| Cluster | Size | Radius | Medoid | Top tactics |",
                  "|---------|------|--------|--------|-------------|"]
        for cluster in payload["clusters"]:
            lines.append(
                f"| {cluster['label']} | {cluster['size']} | {cluster['radius']} "
                f"| `{cluster['medoid']}` | {', '.join(cluster['top_tactics']) or '-'} |"
            )
    else:
        lines.append("No cluster reached the minimum size; every entity is noise.")
    if payload.get("warnings"):
        lines += ["", "**Indexer notes**"] + [f"- {w}" for w in payload["warnings"]]
    lines += ["", "Noise (`-1`) is a result, not a failure: it marks entities the "
                  "current window does not resemble. Assignment is nearest-centroid "
                  "with a per-cluster radius, so `novel` means the stored fit no "
                  "longer describes this entity."]
    return "\n".join(lines)


class AlertClusterInput(BaseModel):
    """Input model for blueteam_alert_cluster."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    mode: Literal["fit", "status", "backfill"] = Field(
        default="fit", description="'fit' clusters the window and persists the result; "
                                   "'status' reads the stored fit; 'backfill' fits each "
                                   "completed UTC day in the requested range.")
    time_window_minutes: int = Field(default=1440, ge=5, le=20160)
    since: Optional[str] = Field(default=None, max_length=40,
        description="Backfill start, inclusive UTC midnight (YYYY-MM-DD or ISO-8601).")
    until: Optional[str] = Field(default=None, max_length=40,
        description="Backfill end, exclusive UTC midnight; default today 00:00 UTC.")
    max_days: int = Field(default=90, ge=1, le=120,
        description="Backfill span in days; used as the default range and as a hard cap.")
    min_cluster_size: Optional[int] = Field(default=None, ge=2, le=200,
        description="Override BLUETEAM_CLUSTER_MIN_SIZE for this fit.")
    min_samples: Optional[int] = Field(default=None, ge=1, le=200,
        description="Override BLUETEAM_CLUSTER_MIN_SAMPLES for this fit.")
    use_mitre: bool = Field(default=True,
        description="Classify alerts from rule.mitre.tactic / rule.mitre.id; "
                    "rule.groups is fallback-only for alerts with no MITRE data.")
    category_a_groups: list[str] = Field(default=_DEFAULT_A_GROUPS)
    category_b_groups: list[str] = Field(default=_DEFAULT_B_GROUPS)
    category_c_groups: list[str] = Field(default=_DEFAULT_C_GROUPS)
    response_format: Literal["markdown", "json", "toon"] = Field(default="markdown")


@blueteam_tool(
    name="blueteam_alert_cluster",
    annotations={"readOnlyHint": False, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
    audit=True, truncate=True, redact=True,
)
async def blueteam_alert_cluster(params: AlertClusterInput) -> str:
    """Cluster srcip entities in a Wazuh alert window with HDBSCAN.
    Entities are built from the same MITRE-first aggregation the 3-Sum engine
    scores: 16 tactic level-sum dimensions plus the A/B/C category scores. The
    fit persists centroids, medoids and per-cluster radii, which
    ``blueteam_alert_cluster_assign`` then uses for real-time assignment.
    Use this to answer "which kinds of activity exist in this window", not
    "which IP is malicious": the label says an entity resembles a cluster, never
    that it is confirmed.

    Args:
        params.mode: 'fit' (default), 'status', or 'backfill'.
        params.time_window_minutes: Analysis window, 5 minutes to 14 days; must be 1440 in backfill mode.
        params.since: Backfill start (inclusive UTC midnight); default until minus max_days.
        params.until: Backfill end (exclusive UTC midnight); default today 00:00 UTC.
        params.max_days: Backfill span (1-120 days).
        params.min_cluster_size: Entities needed to form a cluster (default from config).
        params.min_samples: HDBSCAN conservativeness (default from config).
        params.use_mitre: MITRE-first classification with rule.groups fallback.
        params.category_*_groups: Fallback rule.groups tokens per category.
        params.response_format: 'markdown' (default), 'json', or 'toon'.

    Returns:
        markdown or json with the fit id, window, entity/noise counts, cluster
        table (size, radius, medoid, top tactics) and indexer warnings. A
        population below min_cluster_size returns ``insufficient_data``, never an
        empty cluster list. Backfill returns per-day status rows: a day reaches
        the store only when fetched data is complete, and degraded or empty days
        are reported as ``incomplete`` or ``skipped``.

    Worked Examples:
        1. Daily fit -> ``blueteam_alert_cluster(mode="fit", time_window_minutes=1440)``
        2. Tighter clusters over a week -> ``blueteam_alert_cluster(mode="fit",
           time_window_minutes=10080, min_cluster_size=10)``
        3. Backfill the previous 90 completed UTC days -> ``blueteam_alert_cluster(
           mode="backfill", max_days=90)``
        4. Check what is stored -> ``blueteam_alert_cluster(mode="status",
           response_format="json")``

    Permissions: read on the Wazuh Indexer, write on BLUETEAM_CLUSTER_STORE.
    Requires scikit-learn (setup.sh BLUETEAM_INSTALL_CLUSTER=1).
    Rate limits: one aggregation per category per call; a 14-day window is a
    heavy query, so prefer the 24h default for routine runs. A backfill issues
    three aggregations per mapped srcip path per day and runs sequentially.
    """
    _require_enabled()
    if params.mode == "status":
        fit = await asyncio.to_thread(load_fit)
        if fit is None:
            payload = {"status": "no_fit", "store": await asyncio.to_thread(store_stats),
                       "hint": "Run blueteam_alert_cluster with mode='fit' first."}
        else:
            payload = {
                "status": "ok", "fit_id": fit["fit_id"],
                "feature_version": fit["feature_version"], "window": fit["window"],
                "entity_count": fit["entity_count"], "noise_count": fit["noise_count"],
                "cluster_count": len(fit["clusters"]), "params": fit["params"],
                "pending_novelty": await asyncio.to_thread(pending_novelty_count, fit["fit_id"]),
                "store": await asyncio.to_thread(store_stats),
            }
        if params.response_format == "json":
            return json.dumps(payload, indent=2, ensure_ascii=False)
        if params.response_format == "toon":
            return payload
        return (f"# Cluster store status\n\n"
                f"**Status**: `{payload['status']}`\n\n"
                f"```json\n{json.dumps(payload, indent=2, ensure_ascii=False)}\n```")

    if params.mode == "backfill":
        if params.time_window_minutes != 1440:
            raise BlueTeamMCPError(
                "mode='backfill' fits whole UTC days; time_window_minutes must be 1440.")
        return await _run_backfill(params)

    since_iso, until_iso = _window(params.time_window_minutes)
    fetched = await fetch_srcip_profiles(_categories(params), since_iso, until_iso,
                                         use_mitre=params.use_mitre)
    profiles = fetched["profiles"]
    if not profiles:
        payload = {"status": "insufficient_data", "entity_count": 0,
                   "window": {"since": since_iso, "until": until_iso},
                   "warnings": fetched["warnings"],
                   "hint": "No srcip entities in the window; widen it or check the "
                           "category fallback groups."}
    else:
        entity_keys = sorted(profiles)
        vectors = [build_vector(profiles[key], params.time_window_minutes)
                   for key in entity_keys]
        min_size = params.min_cluster_size or config.cluster.min_cluster_size
        min_samples = params.min_samples or config.cluster.min_samples
        result = await asyncio.to_thread(fit_clusters, vectors, min_size, min_samples)
        if result["status"] != "ok":
            payload = {"status": result["status"], "entity_count": result.get("entity_count", 0),
                       "reason": result.get("reason"), "window": {"since": since_iso, "until": until_iso},
                       "warnings": fetched["warnings"]}
        else:
            fit_id = uuid.uuid4().hex[:12]
            await asyncio.to_thread(
                save_fit, fit_id, result["params"], result["clusters"],
                result["entity_count"], result["noise_count"],
                {"since": since_iso, "until": until_iso})
            payload = {
                "status": "ok", "fit_id": fit_id, "feature_version": FEATURE_VERSION,
                "window": {"since": since_iso, "until": until_iso},
                "entity_count": result["entity_count"], "noise_count": result["noise_count"],
                "noise_ratio": result["noise_ratio"], "params": result["params"],
                "clusters": _cluster_records(result, entity_keys, vectors, profiles),
                "warnings": fetched["warnings"],
            }
    if params.response_format == "json":
        return json.dumps(payload, indent=2, ensure_ascii=False)
    if params.response_format == "toon":
        return payload
    if payload.get("status") != "ok":
        return (f"# Alert Entity Clustering\n\n**Status**: `{payload['status']}`\n\n"
                f"{payload.get('reason') or payload.get('hint') or ''}")
    return _fit_markdown(payload)


class AlertClusterAssignInput(BaseModel):
    """Input model for blueteam_alert_cluster_assign."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    srcip: str = Field(..., min_length=1, max_length=64,
        description="Source IP to assign to the stored clusters.")
    fit_id: Optional[str] = Field(default=None, max_length=32,
        description="Fit to assign against; newest fit when omitted.")
    use_cached: bool = Field(default=True,
        description="Return the stored assignment for this fit without re-querying.")
    assign_factor: Optional[float] = Field(default=None, gt=0, le=10,
        description="Radius multiplier for acceptance; default from config.")
    time_window_minutes: int = Field(default=1440, ge=5, le=20160,
        description="Window used to rebuild the entity profile; must equal the "
                    "window the fit was built over.")
    use_mitre: bool = True
    category_a_groups: list[str] = Field(default=_DEFAULT_A_GROUPS)
    category_b_groups: list[str] = Field(default=_DEFAULT_B_GROUPS)
    category_c_groups: list[str] = Field(default=_DEFAULT_C_GROUPS)
    response_format: Literal["markdown", "json", "toon"] = Field(default="markdown")


@blueteam_tool(
    name="blueteam_alert_cluster_assign",
    annotations={"readOnlyHint": False, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
    audit=True, truncate=True, redact=True,
)
async def blueteam_alert_cluster_assign(params: AlertClusterAssignInput) -> str:
    """Assign one srcip to the stored clusters (nearest centroid, per-cluster radius).
    Real-time path for a live alert: the entity's current profile is rebuilt from
    the Indexer, then matched against the persisted fit. ``label=-1`` with
    ``novelty=true`` means the entity falls outside every stored radius - it is an
    outlier against the fit, not a confirmed malicious IP.
    Args:
        params.srcip: Entity to assign.
        params.fit_id: Fit to use; newest when omitted. Auto-selection refuses a backfill-origin fit.
        params.use_cached: Reuse an assignment already stored for this fit.
        params.assign_factor: Radius multiplier for acceptance.
        params.time_window_minutes: Window used to rebuild the entity profile; must match the fits window.
        params.use_mitre: MITRE-first classification with rule.groups fallback.
        params.category_*_groups: Fallback rule.groups tokens per category.
        params.response_format: 'markdown' (default), 'json', or 'toon'.
    Returns:
        markdown or json with ``label``, ``distance``, ``limit``, ``nearest_label``,
        ``novelty``, ``pending_novelty``, and a ``pending_refit`` flag once enough
        novel entities accumulate to justify an operator-run refit.
    Worked Examples:
        1. Label a live alert -> ``blueteam_alert_cluster_assign(srcip="45.194.92.25")``
        2. Looser acceptance -> ``blueteam_alert_cluster_assign(srcip="45.194.92.25",
           assign_factor=1.5)``
        3. Force a re-query -> ``blueteam_alert_cluster_assign(srcip="45.194.92.25",
           use_cached=False, response_format="json")``
    Permissions: read on the Wazuh Indexer, write on BLUETEAM_CLUSTER_STORE.
    Rate limits: three category aggregations per uncached call; the cached path
    performs no Indexer query.
    """
    _require_enabled()
    key = normalize_entity_key(params.srcip)
    if not key:
        raise BlueTeamMCPError("srcip must not be empty.")
    fit = await asyncio.to_thread(load_fit, params.fit_id)
    if fit is None:
        raise BlueTeamMCPError(
            "No stored cluster fit to assign against. Run blueteam_alert_cluster "
            "with mode='fit' first."
        )
    if params.fit_id is None and (fit.get("params") or {}).get("origin") == "backfill":
        raise BlueTeamMCPError(
            "The newest stored fit is a historical backfill fit; assignment targets "
            "the live window. Run blueteam_alert_cluster mode='fit' first, or pass an "
            "explicit fit_id to assign against the backfill fit."
        )
    fit_minutes = _window_minutes(fit.get("window") or {})
    if fit_minutes is None:
        raise BlueTeamMCPError(
            f"Fit {fit['fit_id']} carries no window, so the scale of its entity "
            "vectors cannot be verified. Re-run blueteam_alert_cluster mode='fit'."
        )
    if round(fit_minutes) != params.time_window_minutes:
        raise BlueTeamMCPError(
            f"Fit {fit['fit_id']} was built over {round(fit_minutes)} minutes; this "
            f"assignment asks for {params.time_window_minutes}. Entity vectors are "
            "rates per day, so scoring across windows measures the window, not the "
            "entity. Refit with the same time_window_minutes, or pass the fit's."
        )
    assignment = None
    if params.use_cached:
        assignment = await asyncio.to_thread(get_assignment, key, fit["fit_id"])
    if assignment is None:
        since_iso, until_iso = _window(params.time_window_minutes)
        fetched = await fetch_srcip_profiles(_categories(params), since_iso, until_iso,
                                             use_mitre=params.use_mitre, srcip=key)
        profile = fetched["profiles"].get(key)
        if profile is None:
            payload = {"status": "not_observed", "fit_id": fit["fit_id"], "srcip": key,
                       "window": {"since": since_iso, "until": until_iso},
                       "hint": "No alert for this entity in the window; nothing to assign."}
            if params.response_format == "json":
                return json.dumps(payload, indent=2, ensure_ascii=False)
            if params.response_format == "toon":
                return payload
            return (f"# Cluster assignment\n\n**Status**: `not_observed` - no alert for "
                    f"`{key}` in `{since_iso}` -> `{until_iso}`.\n")
        factor = params.assign_factor or config.cluster.assign_factor
        outcome = assign_vector(build_vector(profile, params.time_window_minutes),
                                fit["clusters"], factor)
        await asyncio.to_thread(record_assignment, key, fit["fit_id"],
                                outcome["label"], outcome["distance"], outcome["novelty"])
        assignment = {"label": outcome["label"], "distance": outcome["distance"],
                      "novelty": outcome["novelty"], "nearest_label": outcome["nearest_label"],
                      "limit": outcome["limit"], "cached": False}
    else:
        assignment = dict(assignment)
        assignment["limit"] = None
        assignment["cached"] = True
        # The store keeps no nearest_label; a non-novel row's label is by
        # definition the cluster it matched.
        assignment["nearest_label"] = (assignment["label"]
                                       if assignment["label"] >= 0 else None)
    pending = await asyncio.to_thread(pending_novelty_count, fit["fit_id"])
    payload = {"status": "ok", "fit_id": fit["fit_id"], "srcip": key,
               "feature_version": fit["feature_version"], "assignment": assignment,
               "pending_novelty": pending, "pending_refit": pending >= _PENDING_REFIT_AT}
    if params.response_format == "json":
        return json.dumps(payload, indent=2, ensure_ascii=False)
    if params.response_format == "toon":
        return payload
    label = assignment["label"]
    verdict = ("cluster %d" % label) if label >= 0 else "noise (novel)"
    lines = [
        f"# Cluster assignment - `{key}`",
        "",
        f"**Fit**: `{fit['fit_id']}` ({fit['feature_version']}) | "
        f"**Result**: {verdict} | **Cached**: {assignment['cached']}",
        f"**Distance**: {assignment['distance']} | **Nearest cluster**: "
        f"{assignment['nearest_label']} | **Novelty**: {assignment['novelty']}",
        f"**Pending novel entities**: {pending}"
        + (" - enough to justify a refit (`blueteam_alert_cluster mode='fit'`)."
           if pending >= _PENDING_REFIT_AT else ""),
    ]
    return "\n".join(lines)
