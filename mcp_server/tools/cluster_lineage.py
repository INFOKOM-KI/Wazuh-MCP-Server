#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Cluster lineage: stable campaign identity across HDBSCAN fits, plus per-lineage
behavior shifts (size, novelty pressure, tactic composition) against the
lineage's own history.
Pipeline position
blueteam_alert_cluster          -> persists a fit (fit-scoped labels)
blueteam_cluster_lineage       -> matches fits into lineages, flags shifts
The tool reads the cluster store only. It never refits, never writes, and never
returns entity keys or member lists; lineage output carries sizes, radii and
tactic names. A lineage is a resemblance across windows, not a confirmed
campaign. Gating: the cluster subsystem flag. ``BLUETEAM_CLUSTER_ENABLED=false`` raises
the same enable hint blueteam_alert_cluster raises, because lineage without a
stored fit history has nothing to read.
NOTE: No ``from __future__ import annotations`` deferred annotation evaluation
      (PEP 563) breaks @blueteam_tool type resolution.
"""
import asyncio
import json
import logging
from typing import Literal, Optional
from pydantic import BaseModel, ConfigDict, Field
from mcp_server.core.cluster_store import (
    load_fit_history,
    pending_novelty_count,
    store_stats,
)
from mcp_server.core.config import config
from mcp_server.core.tool_decorator import blueteam_tool
from mcp_server.correlation.lineage_core import build_lineages, lineage_behavior
from mcp_server.tools.cluster import _require_enabled

logger = logging.getLogger("blue_team_mcp.cluster_lineage")


def _novelty_by_fit(fits: list[dict]) -> dict:
    """Assignment novelty rate per fit: novel entities / entity_count.
    A live fit with no assignments is a true zero; a backfilled fit has no
    assignment history, so its rate is None rather than a synthetic zero.
    """
    rates: dict[str, Optional[float]] = {}
    for fit in fits:
        if (fit.get("params") or {}).get("origin") == "backfill":
            rates[fit["fit_id"]] = None
            continue
        novel = pending_novelty_count(fit["fit_id"])
        rates[fit["fit_id"]] = round(novel / max(1, int(fit["entity_count"])), 4)
    return rates


def _lineage_markdown(payload: dict) -> str:
    lines = [
        f"# Cluster lineage - {payload['fit_count']} fits",
        "",
        f"**Match factor**: {payload['match_factor']} | **New in latest**: "
        f"{len(payload['born_in_latest'])} | **Ended**: {len(payload['ended_lineages'])}",
        "",
        "| Lineage | Steps | First fit | Last fit | Active | Latest size | Top tactics |",
        "|---------|-------|-----------|----------|--------|-------------|-------------|",
    ]
    for lineage in payload["lineages"]:
        lines.append(
            f"| {lineage['id']} | {lineage['step_count']} | `{lineage['first_seen']}` "
            f"| `{lineage['last_seen']}` | {lineage['active']} | {lineage['latest_size']} "
            f"| {', '.join(lineage['latest_top_tactics']) or '-'} |")
    lines += ["", "A lineage id is stable across fits but is only as good as the match: "
                  "a cluster that drifts outside the previous radius starts a new lineage."]
    return "\n".join(lines)


def _behavior_markdown(payload: dict) -> str:
    lines = [
        f"# Cluster behavior shifts - {payload['fit_count']} fits",
        "",
        f"**Match factor**: {payload['match_factor']} | **Min points**: {payload['min_points']} "
        f"| **Shift z**: {payload['shift_z']}",
        "",
        "| Lineage | Steps | Size | Trend | Novelty z | Tactic L1 | Risk | Signals |",
        "|---------|-------|------|-------|-----------|-----------|------|---------|",
    ]
    for lineage in payload["lineages"]:
        novelty_z = "-" if lineage["novelty_z"] is None else f"{lineage['novelty_z']}"
        tactic_l1 = "-" if lineage["tactic_l1"] is None else f"{lineage['tactic_l1']}"
        signals = ", ".join(lineage["signals"]) or "-"
        lines.append(
            f"| {lineage['id']} | {lineage['step_count']} | {lineage['latest_size']} "
            f"| {lineage['size_direction']} | {novelty_z} | {tactic_l1} "
            f"| {lineage['behavior_risk']} | {signals} |")
    lines += ["",
              "`insufficient_history` means the lineage has fewer steps than min_points; no "
              "shift is claimed. `elevated` means at least one signal crossed its threshold, "
              "`watch` means a rising size trend without a crossing. All of it is advisory: a "
              "rising cluster is a campaign to look at, not a prediction of an attack."]
    return "\n".join(lines)


class ClusterLineageInput(BaseModel):
    """Input model for blueteam_cluster_lineage."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    mode: Literal["lineage", "behavior", "status"] = Field(
        default="behavior",
        description="'lineage' is the structural table across stored fits; 'behavior' adds "
                    "per-lineage series and shift flags; 'status' reads the store depth.")
    min_fits: Optional[int] = Field(default=None, ge=2, le=50,
        description="Fits with clusters required to build lineage; default from config (2).")
    match_factor: Optional[float] = Field(default=None, gt=0.0, le=10.0,
        description="Multiplier on the previous cluster's radius when matching; default 1.5.")
    min_points: Optional[int] = Field(default=None, ge=2, le=50,
        description="Steps a lineage needs before a behavior verdict; default 3.")
    shift_z: Optional[float] = Field(default=None, gt=0.0, le=10.0,
        description="Z-score threshold for a size or novelty jump; default 2.5.")
    response_format: Literal["markdown", "json"] = Field(default="markdown")


@blueteam_tool(
    name="blueteam_cluster_lineage",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
    audit=True, truncate=True, redact=True,
)
async def blueteam_cluster_lineage(params: ClusterLineageInput) -> str:
    """Track HDBSCAN clusters across fits and flag behavior shifts over time.
    A fit's labels are scoped to that fit, so a refit can relabel the same
    campaign. This tool matches each cluster to the nearest unclaimed cluster of
    the previous fit inside that cluster's radius, giving a stable lineage id.
    Behavior mode then reads each lineage as a series (size, radius, novelty
    rate, tactic composition from the centroid) and flags size jumps, novelty
    jumps and tactic-composition shifts against the lineage's own history.

    Args:
        params.mode: 'lineage', 'behavior' (default) or 'status'.
        params.min_fits: Fits required before lineage is attempted.
        params.match_factor: Radius multiplier for a cross-fit match.
        params.min_points: Steps required before a behavior verdict.
        params.shift_z: Z threshold for a size or novelty jump.
        params.response_format: 'markdown' (default) or 'json'.

    Returns:
        markdown or json. Lineage: one row per lineage with steps, first/last
        fit, active flag and latest size. Behavior: lineage rows with size
        slope and direction, novelty z, tactic L1 shift, the signals that fired
        and the advisory risk level. Status: store depth and fit count.

    Worked Examples:
        1. Structure across stored fits -> ``blueteam_cluster_lineage(mode="lineage")``
        2. Shift report -> ``blueteam_cluster_lineage(mode="behavior",
           response_format="json")``
        3. Looser cross-fit matching -> ``blueteam_cluster_lineage(mode="behavior",
           match_factor=2.0)``

    Permissions: read on BLUETEAM_CLUSTER_STORE only; no Indexer query, no write.
    Rate limits: one SQLite read per stored fit (max BLUETEAM_CLUSTER_MAX_FITS,
    default 100); no external calls.
    """
    _require_enabled()

    if params.mode == "status":
        fits = await asyncio.to_thread(load_fit_history, config.cluster.max_fits)
        payload = {"status": "ok", "fits": len(fits),
                   "store": await asyncio.to_thread(store_stats),
                   "hint": None if len(fits) >= 2 else
                           "Fewer than two fits stored; run blueteam_alert_cluster "
                           "mode='fit' again after the next window."}
        if params.response_format == "json":
            return json.dumps(payload, indent=2, ensure_ascii=False)
        return (f"# Cluster lineage status\n\n**Stored fits**: {payload['fits']}\n\n"
                f"{payload['hint'] or ''}")

    fits = await asyncio.to_thread(load_fit_history, config.cluster.max_fits)
    floor_fits = params.min_fits or config.cluster.lineage_min_fits
    if len(fits) < floor_fits:
        payload = {"status": "insufficient_data", "fit_count": len(fits),
                   "reason": f"{len(fits)} stored fits, need at least {floor_fits}. "
                             "Run blueteam_alert_cluster mode='fit' once per window.",
                   "store": await asyncio.to_thread(store_stats)}
        if params.response_format == "json":
            return json.dumps(payload, indent=2, ensure_ascii=False)
        return (f"# Cluster lineage\n\n**Status**: `insufficient_data`\n\n{payload['reason']}")

    factor = params.match_factor or config.cluster.lineage_match_factor
    result = build_lineages(fits, factor)
    if result["status"] != "ok":
        payload = {"status": result["status"], "fit_count": result.get("fit_count", len(fits)),
                   "reason": result.get("reason")}
        if params.response_format == "json":
            return json.dumps(payload, indent=2, ensure_ascii=False)
        return (f"# Cluster lineage\n\n**Status**: `{result['status']}`\n\n"
                f"{result.get('reason') or ''}")

    if params.mode == "lineage":
        payload = {
            "status": "ok", "mode": "lineage", "fit_count": result["fit_count"],
            "match_factor": factor,
            "lineages": [{"id": record["id"], "step_count": record["step_count"],
                          "first_seen": record["first_seen"], "last_seen": record["last_seen"],
                          "active": record["active"],
                          "latest_size": record["steps"][-1]["size"],
                          "latest_radius": record["steps"][-1]["radius"],
                          "latest_top_tactics": record["steps"][-1]["top_tactics"]}
                         for record in result["lineages"]],
            "born_in_latest": result["born_in_latest"],
            "ended_lineages": result["ended_lineages"],
        }
        if params.response_format == "json":
            return json.dumps(payload, indent=2, ensure_ascii=False)
        return _lineage_markdown(payload)

    points_floor = params.min_points or config.cluster.lineage_min_points
    z_floor = params.shift_z or config.cluster.lineage_shift_z
    novelty_rates = await asyncio.to_thread(_novelty_by_fit, fits)
    behaviors = lineage_behavior(
        result["lineages"], novelty_rates, min_points=points_floor, shift_z=z_floor,
        tactic_shift_threshold=config.cluster.lineage_tactic_shift)
    payload = {"status": "ok", "mode": "behavior", "fit_count": result["fit_count"],
               "match_factor": factor, "min_points": points_floor, "shift_z": z_floor,
               "lineages": behaviors, "born_in_latest": result["born_in_latest"],
               "ended_lineages": result["ended_lineages"]}
    if params.response_format == "json":
        return json.dumps(payload, indent=2, ensure_ascii=False)
    return _behavior_markdown(payload)
