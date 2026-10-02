#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Source forecasting primitives: classification, timelines, weighted transitions
and candidate scoring for the next *observed* source/country. Pure stdlib,
no I/O; the store and tool layers wrap this module.
"""
from __future__ import annotations
import ipaddress
import math
from typing import Any, Optional
from mcp_server.correlation.forecast_core import normalize_tactics

DAY_SECONDS = 86400.0
DEFAULT_WEIGHTS = {"transition": 0.45, "recency": 0.20, "frequency": 0.15,
                   "context": 0.12, "recurrence": 0.08}
_COMPONENTS = ("transition", "recency", "frequency", "context", "recurrence")
_EPSILON = 1e-9


def _as_float(value: Any) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _invalid(reason: str) -> dict:
    return {"valid": False, "reason": reason, "version": None,
            "is_internal": False, "netblock": None, "normalized": None}


def classify_source(value: Any, v4_prefix: int = 24, v6_prefix: int = 64) -> dict:
    """Parse one source string into an address classification.
    Non-global addresses (private, loopback, link-local, reserved, multicast,
    shared, ULA) are ``is_internal``; bad input is invalid, not coerced.
    """
    text = str(value).strip() if value is not None else ""
    if not text:
        return _invalid("empty source")
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return _invalid("not an IP address")
    prefix = v4_prefix if address.version == 4 else v6_prefix
    try:
        network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
    except ValueError:
        return _invalid("invalid netblock prefix")
    return {"valid": True, "reason": None, "version": address.version,
            "is_internal": bool(address.is_multicast or not address.is_global),
            "netblock": str(network), "normalized": str(address)}


def _collapse(ordered: list[tuple]) -> list[dict]:
    """Fold an ordered (ts, value, row) list into runs, collapsing consecutive
    duplicates so a repeated value is one timeline step, not a loop."""
    timeline: list[dict] = []
    for timestamp, value, row in ordered:
        tactics = sorted(set(normalize_tactics(row.get("tactic"))))
        country = row.get("country")
        country = country.strip() if isinstance(country, str) and country.strip() else None
        if timeline and timeline[-1]["value"] == value:
            run = timeline[-1]
            run["tactics"] = sorted(set(run["tactics"]) | set(tactics))
            if run["country"] is None and country:
                run["country"] = country
            continue
        timeline.append({"value": value, "observed_at": timestamp,
                         "country": country, "tactics": tactics})
    return timeline


def _ordered_rows(rows: list[dict], key: str, cutoff_ts: Optional[float]) -> list[tuple]:
    ordered: list[tuple] = []
    cutoff = None if cutoff_ts is None else float(cutoff_ts)
    for row in rows or []:
        value = str(row.get(key) or "").strip()
        timestamp = _as_float(row.get("observed_at"))
        if not value or timestamp is None:
            continue
        if cutoff is not None and timestamp >= cutoff:
            continue
        ordered.append((timestamp, value, row))
    ordered.sort(key=lambda item: (item[0], item[1]))
    return ordered


def build_timeline(rows: list[dict], cutoff_ts: Optional[float] = None) -> list[dict]:
    """Source timeline ordered by ``(observed_at, source_ip)``.
    The cutoff is exclusive, so raw rows cannot leak a post-cutoff observation.
    """
    return _collapse(_ordered_rows(rows, "source_ip", cutoff_ts))


def build_country_timeline(rows: list[dict],
                           cutoff_ts: Optional[float] = None) -> list[dict]:
    """Country timeline from ``GeoLocation``-derived rows; unknown countries are
    skipped, not replaced with a placeholder."""
    ordered = _ordered_rows(rows, "country", cutoff_ts)
    return _collapse(ordered)


def recency_weight(age_seconds: float, half_life_days: float) -> float:
    """Exponential decay: ``2 ** (-age_days / half_life_days)``."""
    if half_life_days is None or float(half_life_days) <= 0:
        return 0.0
    age_days = max(0.0, float(age_seconds)) / DAY_SECONDS
    return 2.0 ** (-age_days / float(half_life_days))


def weighted_transitions(timeline: list[dict], half_life_days: float,
                         cutoff_ts: float) -> dict[str, dict[str, dict]]:
    """Recency-weighted consecutive transitions: ``{previous: {next: {...}}}``.
    Only observed pairs are stored; memory grows with transitions, not squared
    vocabulary.
    """
    transitions: dict[str, dict[str, dict]] = {}
    for previous, following in zip(timeline, timeline[1:]):
        weight = recency_weight(float(cutoff_ts) - following["observed_at"], half_life_days)
        row = transitions.setdefault(previous["value"], {})
        bucket = row.setdefault(following["value"], {"weight": 0.0, "count": 0})
        bucket["weight"] += weight
        bucket["count"] += 1
    return transitions


def transition_probability(transitions: dict, previous: str, candidate: str,
                           alpha: float = 0.5) -> dict:
    """Smoothed empirical ``P(next=candidate | previous)`` with support.
    Unseen candidates get ``alpha / (row_weight + alpha * K)``; an unknown
    previous row returns ``probability=None``, never a fabricated distribution.
    """
    row = transitions.get(previous)
    if not row:
        return {"probability": None, "support": 0, "row_total_weight": 0.0,
                "candidates_in_row": 0}
    total = sum(bucket["weight"] for bucket in row.values())
    k = len(row)
    bucket = row.get(candidate)
    return {"probability": ((bucket["weight"] if bucket else 0.0) + alpha)
                           / (total + alpha * k),
            "support": int(bucket["count"]) if bucket else 0,
            "row_total_weight": total, "candidates_in_row": k}


def component_context(source_tactics: dict, context_tactics: list) -> float:
    """Cosine similarity between a source's tactic shares and the current
    context's distinct tactics (each context tactic weight 1)."""
    context = {str(tactic) for tactic in (context_tactics or []) if str(tactic)}
    if not context or not source_tactics:
        return 0.0
    norm = math.sqrt(sum(float(value) ** 2 for value in source_tactics.values()))
    if norm <= _EPSILON:
        return 0.0
    numerator = sum(float(source_tactics.get(tactic, 0.0)) for tactic in context)
    value = numerator / (norm * math.sqrt(len(context)))
    return round(min(1.0, max(0.0, value)), 6)


def component_recurrence(timestamps: list) -> float:
    """Gap regularity of a source's sightings: 1.0 for perfectly regular gaps,
    falling toward 0 as the latest gap deviates. Needs three sightings."""
    values = sorted(value for value in (_as_float(ts) for ts in timestamps)
                    if value is not None)
    if len(values) < 3:
        return 0.0
    gaps = [following - previous for previous, following in zip(values, values[1:])]
    mean = sum(gaps) / len(gaps)
    variance = sum((gap - mean) ** 2 for gap in gaps) / len(gaps)
    stddev = math.sqrt(variance)
    if stddev <= _EPSILON:
        return 1.0
    return round(1.0 / (1.0 + abs(gaps[-1] - mean) / stddev), 6)


def normalize_max(values: dict) -> dict:
    """Max-normalize a component across candidates; an all-zero vector stays zero."""
    top = max((float(value) for value in values.values()), default=0.0)
    if top <= 0.0:
        return {key: 0.0 for key in values}
    return {key: float(value) / top for key, value in values.items()}


def _collapse_entries(prepared: list[tuple]) -> list[dict]:
    timeline: list[dict] = []
    for timestamp, value, entry in prepared:
        tactics = sorted({str(tactic) for tactic in (entry.get("tactics") or []) if str(tactic)})
        country = entry.get("country")
        if timeline and timeline[-1]["value"] == value:
            run = timeline[-1]
            run["tactics"] = sorted(set(run["tactics"]) | set(tactics))
            if run["country"] is None and country:
                run["country"] = country
            continue
        timeline.append({"value": value, "observed_at": timestamp,
                         "country": country, "tactics": tactics})
    return timeline


def score_sequence(entries: list[dict], context_tactics: list, cutoff_ts: float, *,
                   half_life_days: float = 14.0, alpha: float = 0.5,
                   min_transitions: int = 5, max_candidates: int = 10,
                   history_seconds: Optional[float] = None,
                   weights: Optional[dict] = None) -> dict:
    """Rank next-value candidates from a value timeline.
    Components are max-normalized across candidates; below ``min_transitions``
    the transition weight is dropped and the rest re-normalized. ``model_score``
    is a ranking heuristic, not a probability.
    """
    cutoff = float(cutoff_ts)
    floor_ts = None if history_seconds is None else cutoff - float(history_seconds)
    prepared: list[tuple] = []
    for entry in entries or []:
        value = str(entry.get("value") or "").strip()
        timestamp = _as_float(entry.get("observed_at"))
        if not value or timestamp is None or timestamp >= cutoff:
            continue
        if floor_ts is not None and timestamp < floor_ts:
            continue
        prepared.append((timestamp, value, entry))
    prepared.sort(key=lambda item: (item[0], item[1]))
    timeline = _collapse_entries(prepared)
    if not timeline:
        return {"score_kind": "model_score", "previous_value": None,
                "vocabulary_size": 0, "transition_entries": 0, "candidates": []}

    stats: dict[str, dict] = {}
    for entry in timeline:
        value = entry["value"]
        item = stats.setdefault(value, {"count": 0, "first": entry["observed_at"],
                                        "last": entry["observed_at"], "tactics": {},
                                        "timestamps": [], "country": None})
        item["count"] += 1
        item["first"] = min(item["first"], entry["observed_at"])
        item["last"] = max(item["last"], entry["observed_at"])
        item["timestamps"].append(entry["observed_at"])
        for tactic in entry["tactics"]:
            item["tactics"][tactic] = item["tactics"].get(tactic, 0) + 1
        if item["country"] is None and entry["country"]:
            item["country"] = entry["country"]

    transitions = weighted_transitions(timeline, half_life_days, cutoff)
    previous = timeline[-1]["value"]
    transition_entries = sum(len(row) for row in transitions.values())
    active_weights = dict(DEFAULT_WEIGHTS if weights is None else weights)
    row = transitions.get(previous)
    row_support = sum(bucket["count"] for bucket in row.values()) if row else 0
    fallback = row is None or row_support < int(min_transitions)
    if fallback:
        active_weights.pop("transition", None)
        total = sum(active_weights.values())
        active_weights = ({name: value / total for name, value in active_weights.items()}
                          if total > 0 else {})

    raw: dict[str, dict] = {}
    probabilities: dict[str, Optional[float]] = {}
    supports: dict[str, int] = {}
    for value, item in stats.items():
        estimate = transition_probability(transitions, previous, value, alpha)
        probabilities[value] = estimate["probability"]
        supports[value] = estimate["support"]
        raw[value] = {
            "transition": estimate["probability"] if estimate["probability"] is not None else 0.0,
            "recency": recency_weight(cutoff - item["last"], half_life_days),
            "frequency": float(item["count"]),
            "context": component_context({tactic: float(count)
                                          for tactic, count in item["tactics"].items()},
                                         context_tactics or []),
            "recurrence": component_recurrence(item["timestamps"]),
        }
    normalized = {name: normalize_max({value: raw[value][name] for value in raw})
                  for name in _COMPONENTS}

    candidates: list[dict] = []
    for value, item in stats.items():
        components = {name: normalized[name][value] for name in _COMPONENTS}
        if fallback:
            components["transition"] = 0.0
        score = sum(active_weights.get(name, 0.0) * components[name]
                    for name in _COMPONENTS)
        candidates.append({
            "value": value, "model_score": round(score, 6),
            "score_kind": "fallback_frequency" if fallback else "model_score",
            "components": components,
            "transition_probability": probabilities[value],
            "transition_support": supports[value],
            "occurrence_count": item["count"],
            "first_seen": item["first"], "last_seen": item["last"],
            "tactics": sorted(item["tactics"]), "country": item["country"],
        })
    candidates.sort(key=lambda candidate: (-candidate["model_score"], candidate["value"]))
    for index, candidate in enumerate(candidates, start=1):
        candidate["rank"] = index
    return {"score_kind": "model_score", "previous_value": previous,
            "vocabulary_size": len(stats), "transition_entries": transition_entries,
            "candidates": candidates[:max(1, int(max_candidates))]}


def top_k_hit(candidates: list, target: Optional[str], k: int) -> bool:
    if target is None:
        return False
    return target in list(candidates)[:max(0, int(k))]


def reciprocal_rank(candidates: list, target: Optional[str]) -> float:
    if target is None:
        return 0.0
    for index, value in enumerate(candidates, start=1):
        if value == target:
            return 1.0 / index
    return 0.0


def _most_frequent(rows: list[dict], key: str) -> Optional[str]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(key) or "").strip()
        if value:
            counts[value] = counts.get(value, 0) + 1
    if not counts:
        return None
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[0][0]


def _transition_candidates(timeline: list[dict], max_candidates: int) -> list[str]:
    vocabulary = sorted({entry["value"] for entry in timeline})
    if not timeline:
        return []
    ordered: list[str] = []
    if len(timeline) >= 2:
        transitions = weighted_transitions(timeline, 14.0, timeline[-1]["observed_at"] + 1.0)
        row = transitions.get(timeline[-1]["value"], {})
        ordered = [value for value, _ in sorted(row.items(), key=lambda item: (-item[1]["weight"], item[0]))]
    for value in vocabulary:
        if value not in ordered:
            ordered.append(value)
    return ordered[:max(1, int(max_candidates))]


def _target_rows(observations: list[dict], cutoff: float,
                 horizon_seconds: float) -> list[dict]:
    selected = []
    for row in observations:
        timestamp = _as_float(row.get("observed_at"))
        if timestamp is None or not (cutoff <= timestamp < cutoff + horizon_seconds):
            continue
        selected.append(row)
    selected.sort(key=lambda row: (float(row["observed_at"]),
                                   str(row.get("source_ip") or "")))
    return selected


def evaluate_rolling(observations: list[dict], cutoffs: list, *,
                     horizon_seconds: float = DAY_SECONDS,
                     history_seconds: float = 365 * DAY_SECONDS,
                     half_life_days: float = 14.0, alpha: float = 0.5,
                     min_transitions: int = 5, max_candidates: int = 10,
                     min_observations: int = 20,
                     weights: Optional[dict] = None) -> dict:
    """Rolling-origin evaluation over explicit cutoffs; no random split.
    Training uses ``observed_at < cutoff``; the target is the first qualifying
    observation in ``[cutoff, cutoff + horizon)``; every point records its cutoff.
    """
    points: list[dict] = []
    for cutoff_ts in cutoffs:
        cutoff = float(cutoff_ts)
        training = [row for row in observations
                    if (_as_float(row.get("observed_at")) is not None
                        and float(row["observed_at"]) < cutoff)]
        max_training = max((float(row["observed_at"]) for row in training), default=None)
        targets = _target_rows(observations, cutoff, float(horizon_seconds))
        target_source = None
        target_country = None
        for row in targets:
            if target_source is None:
                target_source = str(row.get("source_ip") or "") or None
            country = row.get("country")
            if target_country is None and isinstance(country, str) and country.strip():
                target_country = country.strip()
        target_status = "ok" if targets else "no_target"

        source_timeline = build_timeline(training, cutoff)
        country_timeline = build_country_timeline(training, cutoff)
        persistence = {
            "source": source_timeline[-1]["value"] if source_timeline else None,
            "country": country_timeline[-1]["value"] if country_timeline else None}
        frequency = {
            "source": _most_frequent(training, "source_ip"),
            "country": _most_frequent([row for row in training
                                       if str(row.get("country") or "").strip()], "country")}
        transition_only = {
            "source_candidates": _transition_candidates(source_timeline, max_candidates),
            "country_candidates": _transition_candidates(country_timeline, max_candidates)}

        full = score_sequence(
            [{"value": entry["value"], "observed_at": entry["observed_at"],
              "country": entry["country"], "tactics": entry["tactics"]}
             for entry in source_timeline], [], cutoff,
            half_life_days=half_life_days, alpha=alpha,
            min_transitions=min_transitions, max_candidates=max_candidates,
            history_seconds=history_seconds, weights=weights)
        full_country = score_sequence(
            [{"value": entry["value"], "observed_at": entry["observed_at"],
              "country": entry["country"], "tactics": entry["tactics"]}
             for entry in country_timeline], [], cutoff,
            half_life_days=half_life_days, alpha=alpha,
            min_transitions=min_transitions, max_candidates=max_candidates,
            history_seconds=history_seconds, weights=weights)
        full_values = [candidate["value"] for candidate in full["candidates"]]
        full_country_values = [candidate["value"] for candidate in full_country["candidates"]]
        status = "ok" if len(training) >= int(min_observations) else "insufficient_history"

        hits = {
            "persistence_source_top1": persistence["source"] == target_source,
            "persistence_country_top1": persistence["country"] == target_country,
            "frequency_source_top1": frequency["source"] == target_source,
            "frequency_country_top1": frequency["country"] == target_country,
            "transition_only_source_top1": top_k_hit(
                transition_only["source_candidates"], target_source, 1),
            "transition_only_source_top5": top_k_hit(
                transition_only["source_candidates"], target_source, 5),
            "transition_only_country_top1": top_k_hit(
                transition_only["country_candidates"], target_country, 1),
            "full_model_source_top1": top_k_hit(full_values, target_source, 1),
            "full_model_source_top5": top_k_hit(full_values, target_source, 5),
            "full_model_source_rr": reciprocal_rank(full_values, target_source),
            "full_model_country_top1": top_k_hit(full_country_values, target_country, 1),
            "full_model_country_top5": top_k_hit(full_country_values, target_country, 5),
        }
        points.append({
            "cutoff_ts": cutoff, "training_cutoff": cutoff,
            "max_training_observed_at": max_training,
            "training_observations": len(training), "status": status,
            "target_status": target_status, "target_source": target_source,
            "target_country": target_country,
            "models": {"persistence": persistence, "frequency": frequency,
                       "transition_only": transition_only,
                       "full_model": {"source_candidates": full_values,
                                      "country_candidates": full_country_values}},
            "hits": hits})

    evaluated = [point for point in points
                 if point["status"] == "ok" and point["target_status"] == "ok"]

    def rate(key: str) -> Optional[float]:
        if not evaluated:
            return None
        return sum(1 for point in evaluated if point["hits"][key]) / len(evaluated)

    def mean_reciprocal(target_key: str) -> Optional[float]:
        if not evaluated:
            return None
        return sum(point["hits"][target_key] for point in evaluated) / len(evaluated)

    metrics = {
        "full_model": {
            "source_top1": rate("full_model_source_top1"),
            "source_top5": rate("full_model_source_top5"),
            "source_mrr": mean_reciprocal("full_model_source_rr"),
            "country_top1": rate("full_model_country_top1"),
            "country_topk": rate("full_model_country_top5"),
            "coverage": (len(evaluated) / len(points)) if points else None,
            "unique_candidates": len({value for point in evaluated
                                      for value in point["models"]["full_model"]["source_candidates"]}),
            "cutoffs": len(evaluated)},
        "persistence": {"source_top1": rate("persistence_source_top1"),
                        "country_top1": rate("persistence_country_top1")},
        "frequency": {"source_top1": rate("frequency_source_top1"),
                      "country_top1": rate("frequency_country_top1")},
        "transition_only": {"source_top1": rate("transition_only_source_top1"),
                            "source_top5": rate("transition_only_source_top5"),
                            "country_top1": rate("transition_only_country_top1")},
        "model_minus_persistence": {
            "source_top1": (rate("full_model_source_top1") - rate("persistence_source_top1")
                            if evaluated else None),
            "country_top1": (rate("full_model_country_top1") - rate("persistence_country_top1")
                             if evaluated else None)},
        "unavailable": ["asn"],
    }
    counts = {"cutoffs": len(points), "evaluated": len(evaluated),
              "no_target": sum(1 for point in points
                               if point["target_status"] == "no_target"),
              "insufficient_history": sum(1 for point in points
                                          if point["status"] == "insufficient_history")}
    return {"status": "ok", "points": points, "metrics": metrics, "counts": counts}
