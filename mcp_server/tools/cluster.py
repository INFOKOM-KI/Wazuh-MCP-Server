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
import json
import logging
import time
import uuid
from datetime import datetime, timedelta
from typing import Literal, Optional
from pydantic import BaseModel, ConfigDict, Field
from mcp_server.core.cluster_features import FEATURE_VERSION, build_vector, normalize_entity_key
from mcp_server.core.cluster_store import (
    get_assignment,
    load_fit,
    pending_novelty_count,
    record_assignment,
    save_fit,
    store_stats,
)
from mcp_server.core.config import config
from mcp_server.core.exceptions import BlueTeamMCPError
from mcp_server.core.tool_decorator import blueteam_tool
from mcp_server.correlation.cluster_core import assign_vector, fit_clusters
from mcp_server.tools.correlation import fetch_srcip_profiles

logger = logging.getLogger("blue_team_mcp.cluster")

_PENDING_REFIT_AT = 20

_DEFAULT_A_GROUPS = ["web", "attack", "scan", "recon", "accesslog"]
_DEFAULT_B_GROUPS = ["authentication_failures", "bruteforce", "blocklist",
                     "zimbra", "spam", "postfix"]
_DEFAULT_C_GROUPS = ["firewall_drop", "exfiltration", "overflow", "opencti",
                     "backdoor", "defacement"]


def _require_enabled() -> None:
    if not config.cluster.enabled:
        raise BlueTeamMCPError(
            "Alert clustering is disabled. Set BLUETEAM_CLUSTER_ENABLED=true and "
            "BLUETEAM_CLUSTER_STORE=/abs/path/clusters.db, install scikit-learn "
            "(setup.sh BLUETEAM_INSTALL_CLUSTER=1), then restart the server."
        )


def _window(minutes: int) -> tuple[str, str]:
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    until = datetime.utcnow()
    return (until - timedelta(minutes=minutes)).strftime(fmt), until.strftime(fmt)


def _categories(params) -> list[tuple[str, str, list[str]]]:
    return [("A", "recon", params.category_a_groups),
            ("B", "access", params.category_b_groups),
            ("C", "c2_exfil", params.category_c_groups)]


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
    mode: Literal["fit", "status"] = Field(
        default="fit", description="'fit' clusters the window and persists the result; 'status' reads the stored fit.")
    time_window_minutes: int = Field(default=1440, ge=5, le=20160)
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
    response_format: Literal["markdown", "json"] = Field(default="markdown")


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
        params.mode: 'fit' (default) or 'status'.
        params.time_window_minutes: Analysis window, 5 minutes to 14 days.
        params.min_cluster_size: Entities needed to form a cluster (default from config).
        params.min_samples: HDBSCAN conservativeness (default from config).
        params.use_mitre: MITRE-first classification with rule.groups fallback.
        params.category_*_groups: Fallback rule.groups tokens per category.
        params.response_format: 'markdown' (default) or 'json'.

    Returns:
        markdown or json with the fit id, window, entity/noise counts, cluster
        table (size, radius, medoid, top tactics) and indexer warnings. A
        population below min_cluster_size returns ``insufficient_data``, never an
        empty cluster list.

    Worked Examples:
        1. Daily fit -> ``blueteam_alert_cluster(mode="fit", time_window_minutes=1440)``
        2. Tighter clusters over a week -> ``blueteam_alert_cluster(mode="fit",
           time_window_minutes=10080, min_cluster_size=10)``
        3. Check what is stored -> ``blueteam_alert_cluster(mode="status",
           response_format="json")``

    Permissions: read on the Wazuh Indexer, write on BLUETEAM_CLUSTER_STORE.
    Requires scikit-learn (setup.sh BLUETEAM_INSTALL_CLUSTER=1).
    Rate limits: one aggregation per category per call; a 14-day window is a
    heavy query, so prefer the 24h default for routine runs.
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
        return (f"# Cluster store status\n\n"
                f"**Status**: `{payload['status']}`\n\n"
                f"```json\n{json.dumps(payload, indent=2, ensure_ascii=False)}\n```")

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
        vectors = [build_vector(profiles[key]) for key in entity_keys]
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
    time_window_minutes: int = Field(default=1440, ge=5, le=20160)
    use_mitre: bool = True
    category_a_groups: list[str] = Field(default=_DEFAULT_A_GROUPS)
    category_b_groups: list[str] = Field(default=_DEFAULT_B_GROUPS)
    category_c_groups: list[str] = Field(default=_DEFAULT_C_GROUPS)
    response_format: Literal["markdown", "json"] = Field(default="markdown")


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
        params.fit_id: Fit to use; newest when omitted.
        params.use_cached: Reuse an assignment already stored for this fit.
        params.assign_factor: Radius multiplier for acceptance.
        params.time_window_minutes: Window used to rebuild the entity profile.
        params.use_mitre: MITRE-first classification with rule.groups fallback.
        params.category_*_groups: Fallback rule.groups tokens per category.
        params.response_format: 'markdown' (default) or 'json'.
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
            return (f"# Cluster assignment\n\n**Status**: `not_observed` - no alert for "
                    f"`{key}` in `{since_iso}` -> `{until_iso}`.\n")
        factor = params.assign_factor or config.cluster.assign_factor
        outcome = assign_vector(build_vector(profile), fit["clusters"], factor)
        await asyncio.to_thread(record_assignment, key, fit["fit_id"],
                                outcome["label"], outcome["distance"], outcome["novelty"])
        assignment = {"label": outcome["label"], "distance": outcome["distance"],
                      "novelty": outcome["novelty"], "nearest_label": outcome["nearest_label"],
                      "limit": outcome["limit"], "cached": False}
    else:
        assignment = dict(assignment)
        assignment["limit"] = None
        assignment["cached"] = True
    pending = await asyncio.to_thread(pending_novelty_count, fit["fit_id"])
    payload = {"status": "ok", "fit_id": fit["fit_id"], "srcip": key,
               "feature_version": fit["feature_version"], "assignment": assignment,
               "pending_novelty": pending, "pending_refit": pending >= _PENDING_REFIT_AT}
    if params.response_format == "json":
        return json.dumps(payload, indent=2, ensure_ascii=False)
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
