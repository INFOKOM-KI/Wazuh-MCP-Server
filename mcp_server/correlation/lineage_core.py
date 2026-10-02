#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Cluster lineage and behavior-shift analysis over stored HDBSCAN fits.
A fit's cluster labels are scoped to that fit: a refit can relabel the same
campaign. Lineage rebuilds identity across fits by matching each
cluster to the nearest unclaimed cluster of the previous fit inside that
previous cluster's radius x match factor. That is the same acceptance contract
the real-time assign path uses, so "the same campaign" means the same thing on
both paths. Behavior reads one lineage as a series (size, radius, novelty rate, tactic
composition from the centroid's tactic block) and flags shifts with z-scores
against the lineage's own history, never against another lineage. Pure stdlib
arithmetic over fit records; the caller loads them from cluster_store.
"""
from __future__ import annotations
import math
from typing import Any, Optional
from mcp_server.core.cluster_features import TACTIC_ORDER

DEFAULT_MATCH_FACTOR = 1.5
DEFAULT_MIN_POINTS = 3
DEFAULT_SHIFT_Z = 2.5
DEFAULT_TACTIC_SHIFT = 0.25
_STDDEV_EPSILON = 1e-9


def _distance(left: list[float], right: list[float]) -> float:
    return math.dist(left, right)


def tactic_shares(centroid: list[float]) -> dict[str, float]:
    """Tactic composition of one centroid, normalised to shares of the tactic block.
    The centroid layout is 16 tactic level sums followed by the four engine
    scores, so the block is a slice of the vector. An all-zero tactic block
    returns ``{}`` rather than dividing by zero: an entity set whose alerts
    carry no MITRE annotation has no composition to report.
    """
    values = []
    for raw in list(centroid)[:len(TACTIC_ORDER)]:
        try:
            value = float(raw)
        except (TypeError, ValueError):
            value = 0.0
        values.append(value if math.isfinite(value) and value > 0 else 0.0)
    total = sum(values)
    if total <= 0:
        return {}
    return {tactic: round(value / total, 4)
            for tactic, value in zip(TACTIC_ORDER, values) if value > 0}


def top_tactics(shares: dict[str, float], limit: int = 3) -> list[str]:
    return [tactic for tactic, _ in sorted(shares.items(), key=lambda item: (-item[1], item[0]))[:limit]]


def _l1(left: dict[str, float], right: dict[str, float]) -> float:
    """L1 distance between two share maps. Range [0, 2]: disjoint compositions
    score 2, identical score 0. Missing tactics count as zero mass."""
    keys = set(left) | set(right)
    return round(sum(abs(float(left.get(key, 0.0)) - float(right.get(key, 0.0)))
                     for key in keys), 4)


def _zscore(latest: float, history: list[float]) -> Optional[float]:
    """Z-score of the newest point against its own history.
    ``None`` below two historical points, because one point defines no spread.
    A zero-variance history yields 0.0 rather than a division by zero, the same
    guard ``three_sum_core.evaluate_baseline_drift`` applies.
    """
    if len(history) < 2:
        return None
    mean = sum(history) / len(history)
    variance = sum((value - mean) ** 2 for value in history) / len(history)
    stddev = variance ** 0.5
    if stddev <= _STDDEV_EPSILON:
        return 0.0
    return round((float(latest) - mean) / stddev, 3)


def _slope(values: list[float]) -> float:
    """Least-squares slope per fit step. Zero for fewer than two points."""
    count = len(values)
    if count < 2:
        return 0.0
    mean_x = (count - 1) / 2.0
    mean_y = sum(values) / count
    numerator = sum((index - mean_x) * (value - mean_y) for index, value in enumerate(values))
    denominator = sum((index - mean_x) ** 2 for index in range(count))
    if denominator <= 0:
        return 0.0
    return round(numerator / denominator, 4)


def build_lineages(fits: list[dict], match_factor: float = DEFAULT_MATCH_FACTOR) -> dict:
    """Assign stable lineage ids across fits, oldest fit first.
    Matching is greedy over all cluster pairs sorted by how far inside the
    previous radius they sit, so one previous cluster claims at most one new
    cluster and vice versa. A cluster with no match starts a new lineage; a
    lineage whose last step is not the newest fit is ``active: false``.
    Fewer than two fits with clusters returns ``insufficient_data``: one
    snapshot has nothing to match against, and an invented lineage would be a
    fabricated identity.
    """
    usable = [fit for fit in fits if fit.get("clusters")]
    if len(usable) < 2:
        return {"status": "insufficient_data", "fit_count": len(usable),
                "reason": f"{len(usable)} fits with clusters, need at least 2 to build lineage"}
    lineages: dict[str, dict] = {}
    next_index = 1
    previous: list[dict] = []
    for fit in usable:
        clusters = fit.get("clusters") or []
        pairs: list[tuple[float, float, int, int]] = []
        for cluster_index, cluster in enumerate(clusters):
            for previous_index, prior in enumerate(previous):
                distance = _distance(cluster["centroid"], prior["centroid"])
                limit = max(float(prior["radius"]), _STDDEV_EPSILON) * float(match_factor)
                if distance <= limit:
                    pairs.append((distance / limit, distance, cluster_index, previous_index))
        pairs.sort(key=lambda item: (item[0], item[1]))
        claimed: dict[int, tuple[str, float]] = {}
        claimed_previous: set[int] = set()
        for _ratio, distance, cluster_index, previous_index in pairs:
            if cluster_index in claimed or previous_index in claimed_previous:
                continue
            claimed[cluster_index] = (previous[previous_index]["lineage_id"], round(distance, 4))
            claimed_previous.add(previous_index)

        current: list[dict] = []
        for cluster_index, cluster in enumerate(clusters):
            if cluster_index in claimed:
                lineage_id, distance = claimed[cluster_index]
            else:
                lineage_id = f"L{next_index}"
                next_index += 1
                distance = None
            shares = tactic_shares(cluster["centroid"])
            step = {
                "fit_id": fit["fit_id"], "created_at": fit.get("created_at"),
                "origin": (fit.get("params") or {}).get("origin", "live"),
                "label": int(cluster.get("label", -1)), "size": int(cluster["size"]),
                "radius": round(float(cluster["radius"]), 3),
                "distance_from_previous": distance,
                "top_tactics": top_tactics(shares), "tactic_shares": shares,
            }
            record = lineages.setdefault(lineage_id, {"id": lineage_id, "steps": []})
            record["steps"].append(step)
            current.append({"lineage_id": lineage_id, "centroid": cluster["centroid"],
                            "radius": cluster["radius"]})
        previous = current

    newest_fit_id = usable[-1]["fit_id"]
    records = []
    for record in lineages.values():
        steps = record["steps"]
        records.append({
            "id": record["id"], "first_seen": steps[0]["fit_id"],
            "last_seen": steps[-1]["fit_id"], "step_count": len(steps),
            "active": steps[-1]["fit_id"] == newest_fit_id, "steps": steps,
        })
    records.sort(key=lambda item: int(item["id"][1:]))
    return {
        "status": "ok", "fit_count": len(usable), "lineages": records,
        "born_in_latest": [record["id"] for record in records
                           if record["first_seen"] == newest_fit_id],
        "ended_lineages": [record["id"] for record in records if not record["active"]],
    }


def lineage_behavior(lineages: list[dict], novelty_by_fit: dict[str, float],
                     min_points: int = DEFAULT_MIN_POINTS, shift_z: float = DEFAULT_SHIFT_Z,
                     tactic_shift_threshold: float = DEFAULT_TACTIC_SHIFT) -> list[dict]:
    """Per-lineage trajectory with shift flags against its own history.
    Metrics that need more history than exists return ``None``, never a
    fabricated zero. Below ``min_points`` steps the verdict is
    ``insufficient_history`` regardless of the numbers: two snapshots do not
    make a trend. ``elevated`` means at least one signal crossed its threshold;
    ``watch`` means a rising size trend without a crossing; everything else is
    ``stable``. A ``None`` novelty rate (no assignments recorded for a fit)
    drops that point from the novelty statistic rather than counting it as zero.
    """
    results: list[dict] = []
    for lineage in lineages:
        steps = lineage["steps"]
        sizes = [int(step["size"]) for step in steps]
        latest = steps[-1]
        prior = steps[:-1]
        size_z = _zscore(latest["size"], [step["size"] for step in prior])

        latest_novelty = novelty_by_fit.get(latest["fit_id"])
        prior_novelty = [novelty_by_fit[step["fit_id"]] for step in prior
                         if novelty_by_fit.get(step["fit_id"]) is not None]
        novelty_z = None
        if latest_novelty is not None and len(prior_novelty) >= 2:
            novelty_z = _zscore(latest_novelty, prior_novelty)

        slope = _slope(sizes)
        mean_size = sum(sizes) / len(sizes)
        deadband = 0.05 * mean_size
        direction = ("rising" if slope > deadband
                     else "falling" if slope < -deadband else "stable")

        tactic_l1 = None
        tactic_shift = None
        if prior:
            tactic_l1 = _l1(latest["tactic_shares"], prior[-1]["tactic_shares"])
            tactic_shift = tactic_l1 > float(tactic_shift_threshold)

        signals: list[str] = []
        if size_z is not None and size_z >= float(shift_z):
            signals.append("size_jump")
        if novelty_z is not None and novelty_z >= float(shift_z):
            signals.append("novelty_jump")
        if tactic_shift:
            signals.append("tactic_shift")

        if len(steps) < int(min_points):
            risk = "insufficient_history"
            signals = []
        elif signals:
            risk = "elevated"
        elif direction == "rising":
            risk = "watch"
        else:
            risk = "stable"

        results.append({
            "id": lineage["id"], "step_count": len(steps),
            "first_seen": lineage["first_seen"], "last_seen": lineage["last_seen"],
            "active": lineage["active"], "latest_size": latest["size"],
            "size_slope": slope, "size_direction": direction, "size_z": size_z,
            "novelty_rate": latest_novelty, "novelty_z": novelty_z,
            "tactic_l1": tactic_l1, "tactic_shift": tactic_shift,
            "top_tactics": latest["top_tactics"],
            "previous_top_tactics": prior[-1]["top_tactics"] if prior else [],
            "signals": signals, "behavior_risk": risk,
            "series": [{"fit_id": step["fit_id"], "size": step["size"],
                        "radius": step["radius"],
                        "novelty_rate": novelty_by_fit.get(step["fit_id"]),
                        "top_tactics": step["top_tactics"]}
                       for step in steps],
        })
    results.sort(key=lambda item: (item["behavior_risk"] != "elevated", int(item["id"][1:])))
    return results
