#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
3-Sum APT detection — pure computation module (stdlib only)
Hard Rule 11 (CLAUDE.md): this module MUST remain pure-computation — ``math``,
``typing``, ``ipaddress`` only. Never import ``httpx``, ``pydantic``, ``mcp``,
or ``logging``. All API/orchestration logic lives in ``engine.py`` and
``investigation.py``.
"""
from __future__ import annotations
import ipaddress
from typing import Any

# Default thresholds (conservative — per CLAUDE.md Hard Rule 10)
DEFAULT_THRESHOLD_SCORE: int = 10
DEFAULT_Z_THRESHOLD: float = 2.5
DEFAULT_WINDOW_MINUTES: int = 10080  # 7 days

# Non-networked decoder fallback IPs (syscheck, auditd, vulnerability-detector)
_EXCLUDE_IP_FALLBACKS: set[str] = {"0.0.0.0", "unknown", ""}

# Active Response wrapper rule IDs — these duplicate the underlying alert
_DEDUP_WRAPPER_RULES: set[str] = {"606029", "651"}


def normalize_srcip_to_cidr(ip: str, prefix: int = 24) -> str:
    """Normalize an IP to its /24 CIDR network (opt-in grouping).

    Args:
        ip: IPv4 or IPv6 address string.
        prefix: CIDR prefix length (default 24 for IPv4).

    Returns:
        CIDR network string (e.g. ``"10.0.0.0/24"``) or the original IP string
        if it cannot be parsed.
    """
    try:
        net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        return str(net)
    except ValueError:
        return ip


def evaluate_engine_a(
    srcips_a: list[tuple[str, int]],
    srcips_b: list[tuple[str, int]],
    srcips_c: list[tuple[str, int]],
    threshold_score: int = DEFAULT_THRESHOLD_SCORE,
    exclude_srcips: list[str] | None = None,
    cidr_normalize: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Engine A — Multi-IoC Risk Thresholding.

    Finds source IPs appearing in all 3 alert categories, sums their per-category
    risk scores, and returns those exceeding ``threshold_score``.

    Args:
        srcips_a: Category A (recon) entries as ``[(ip, score), ...]``.
        srcips_b: Category B (access anomaly) entries.
        srcips_c: Category C (c2/exfil) entries.
        threshold_score: Minimum combined score to trigger (default 10).
        exclude_srcips: Operational suppression list — IPs to skip.
        cidr_normalize: If True, group IPs by /24 before intersection.

    Returns:
        ``(triggers, stats)`` where *triggers* is a list of dicts with keys
        ``ip``, ``score_a``, ``score_b``, ``score_c``, ``total`` and *stats*
        is a dict with ``total_unique_a``, ``total_unique_b``, ``total_unique_c``,
        ``intersection_count``, ``triggers_count``.
    """
    exclude_set: set[str] = set(exclude_srcips or []) | _EXCLUDE_IP_FALLBACKS

    def _normalize(ip: str) -> str:
        if cidr_normalize:
            return normalize_srcip_to_cidr(ip)
        return ip

    # Build per-category dicts: {normalized_ip: max_score}
    def _build_map(entries: list[tuple[str, int]]) -> dict[str, int]:
        result: dict[str, int] = {}
        for ip, score in entries:
            if ip in exclude_set:
                continue
            norm = _normalize(ip)
            result[norm] = max(result.get(norm, 0), score)
        return result

    map_a = _build_map(srcips_a)
    map_b = _build_map(srcips_b)
    map_c = _build_map(srcips_c)

    # 3-way intersection
    common_ips = set(map_a) & set(map_b) & set(map_c)

    triggers: list[dict[str, Any]] = []
    for ip in sorted(common_ips):
        score_a = map_a.get(ip, 0)
        score_b = map_b.get(ip, 0)
        score_c = map_c.get(ip, 0)
        total = score_a + score_b + score_c
        if total >= threshold_score:
            triggers.append({
                "ip": ip,
                "score_a": score_a,
                "score_b": score_b,
                "score_c": score_c,
                "total": total,
            })

    stats = {
        "total_unique_a": len(map_a),
        "total_unique_b": len(map_b),
        "total_unique_c": len(map_c),
        "intersection_count": len(common_ips),
        "triggers_count": len(triggers),
    }
    return triggers, stats


def evaluate_engine_b(
    buckets_a: list[dict[str, Any]],
    buckets_b: list[dict[str, Any]],
    buckets_c: list[dict[str, Any]],
    z_score_threshold: float = DEFAULT_Z_THRESHOLD,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Engine B — 3-Source Volumetric Z-Score.

    Computes rolling μ/σ across three time-bucketed alert sources and flags
    buckets where all three simultaneously exceed the Z-threshold.

    Args:
        buckets_a: Category A (recon) time buckets with ``doc_count``.
        buckets_b: Category B (access anomaly) time buckets.
        buckets_c: Category C (c2/exfil) time buckets.
        z_score_threshold: Z threshold (default 2.5).

    Returns:
        ``(anomalies, stats)`` where *anomalies* is a list of dicts with
        ``timestamp``, ``z_a``, ``z_b``, ``z_c`` and *stats* has per-source
        μ/σ/bucket counts.
    """
    def _compute(values: list[int]) -> dict[str, Any]:
        n = len(values)
        if n < 2:
            return {"mean": values[0] if values else 0.0, "stddev": 0.0, "buckets": n}
        mean = sum(values) / n
        variance = sum((v - mean) ** 2 for v in values) / n
        stddev = variance ** 0.5
        return {"mean": mean, "stddev": stddev, "buckets": n}

    def _z_scores(values: list[int], stats: dict[str, Any]) -> list[float]:
        mean = stats["mean"]
        stddev = stats["stddev"]
        if stddev <= 0.0001:
            return [0.0] * len(values)
        return [(v - mean) / stddev for v in values]

    counts_a = [b.get("doc_count", 0) for b in buckets_a]
    counts_b = [b.get("doc_count", 0) for b in buckets_b]
    counts_c = [b.get("doc_count", 0) for b in buckets_c]

    stats_a = _compute(counts_a)
    stats_b = _compute(counts_b)
    stats_c = _compute(counts_c)

    z_a = _z_scores(counts_a, stats_a)
    z_b = _z_scores(counts_b, stats_b)
    z_c = _z_scores(counts_c, stats_c)

    # Find buckets where ALL THREE Z-scores exceed threshold simultaneously
    min_len = min(len(z_a), len(z_b), len(z_c))
    timestamps = [b.get("key_as_string", b.get("key", f"b{i}"))
                  for i, b in enumerate(buckets_a[:min_len])]

    anomalies: list[dict[str, Any]] = []
    for i in range(min_len):
        if z_a[i] >= z_score_threshold and z_b[i] >= z_score_threshold and z_c[i] >= z_score_threshold:
            anomalies.append({
                "timestamp": timestamps[i] if i < len(timestamps) else f"b{i}",
                "z_a": round(z_a[i], 2),
                "z_b": round(z_b[i], 2),
                "z_c": round(z_c[i], 2),
                "count_a": counts_a[i] if i < len(counts_a) else 0,
                "count_b": counts_b[i] if i < len(counts_b) else 0,
                "count_c": counts_c[i] if i < len(counts_c) else 0,
            })

    stats = {
        "source_a": {"label": "recon", "mean": round(stats_a["mean"], 2),
                      "stddev": round(stats_a["stddev"], 2), "buckets": stats_a["buckets"]},
        "source_b": {"label": "access_anomaly", "mean": round(stats_b["mean"], 2),
                      "stddev": round(stats_b["stddev"], 2), "buckets": stats_b["buckets"]},
        "source_c": {"label": "c2_exfil", "mean": round(stats_c["mean"], 2),
                      "stddev": round(stats_c["stddev"], 2), "buckets": stats_c["buckets"]},
        "anomaly_count": len(anomalies),
    }
    return anomalies, stats


def format_evaluation_dict(
    since_iso: str,
    until_iso: str,
    engine_a_results: tuple[list[dict[str, Any]], dict[str, Any]] | None = None,
    engine_b_results: tuple[list[dict[str, Any]], dict[str, Any]] | None = None,
    evaluation_time_ms: float = 0.0,
) -> dict[str, Any]:
    """Format combined Engine A + B results into a unified output dict.

    Args:
        since_iso: ISO 8601 window start.
        until_iso: ISO 8601 window end.
        engine_a_results: ``(triggers, stats)`` from :func:`evaluate_engine_a`.
        engine_b_results: ``(anomalies, stats)`` from :func:`evaluate_engine_b`.
        evaluation_time_ms: Wall-clock evaluation time in milliseconds.

    Returns:
        Structured dict with ``window``, ``engine_a``, ``engine_b``,
        ``unified_scoring``, and ``meta`` keys. Safe to serialize via ``json.dumps``.
    """
    result: dict[str, Any] = {
        "window": {"since": since_iso, "until": until_iso},
        "meta": {"evaluation_time_ms": round(evaluation_time_ms, 1)},
    }

    # Engine A
    if engine_a_results is not None:
        triggers, stats = engine_a_results
        result["engine_a"] = {"triggers": triggers, "stats": stats}
    else:
        result["engine_a"] = {"triggers": [], "stats": {}, "status": "disabled"}

    # Engine B
    if engine_b_results is not None:
        anomalies, stats = engine_b_results
        result["engine_b"] = {"anomalies": anomalies, "stats": stats}
    else:
        result["engine_b"] = {"anomalies": [], "stats": {}, "status": "disabled"}

    # Unified scoring: compute overlap and severity
    e_a_triggers = len(result["engine_a"].get("triggers", []))
    e_b_anomalies = len(result["engine_b"].get("anomalies", []))
    overlap_bonus = 1 if (e_a_triggers > 0 and e_b_anomalies > 0) else 0
    unified_score = min(e_a_triggers + e_b_anomalies + overlap_bonus, 10)

    if unified_score == 0:
        severity = "NONE"
    elif unified_score <= 2:
        severity = "LOW"
    elif unified_score <= 5:
        severity = "MEDIUM"
    elif unified_score <= 8:
        severity = "HIGH"
    else:
        severity = "CRITICAL"

    result["unified_scoring"] = {
        "engine_a_triggers": e_a_triggers,
        "engine_b_anomalies": e_b_anomalies,
        "overlap_bonus": overlap_bonus,
        "unified_score": unified_score,
        "severity": severity,
    }

    return result


def compute_time_decay_weight(
    first_seen_iso: str,
    last_seen_iso: str,
    half_life_hours: float = 168.0,
) -> float:
    """Compute a time-decay weight for an IOC based on recency.

    Uses exponential decay: weight = 2 ^ (-age / half_life).
    Recent IOCs weight closer to 1.0; IOCs older than several half-lives
    approach 0.0. Default half-life is 168 hours (7 days).

    Args:
        first_seen_iso: ISO 8601 timestamp of first observation.
        last_seen_iso: ISO 8601 timestamp of last observation (or None).
        half_life_hours: Hours after which weight halves (default 168).

    Returns:
        Float weight in [0.0, 1.0]. Returns 1.0 if timestamps cannot be parsed.
    """
    from datetime import datetime, timezone
    try:
        ts_str = last_seen_iso or first_seen_iso
        if not ts_str:
            return 1.0
        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00").rstrip("Z"))
        now = datetime.now(timezone.utc)
        age_hours = (now - ts).total_seconds() / 3600.0
        if age_hours <= 0:
            return 1.0
        return 2.0 ** (-age_hours / half_life_hours)
    except (ValueError, TypeError):
        return 1.0
