#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Baseline profiling + calendar heatmap tools
"""
from __future__ import annotations
import json, math, os, re
from datetime import datetime, timedelta
from typing import Optional, Literal
from collections import Counter
from pydantic import BaseModel, ConfigDict, Field
from mcp_server import (mcp, WAZUH_INDEXER_URL, WAZUH_INDEXER_PASSWORD,
                        _BYPASS_REDACTION_DESC, _INVESTIGATION_HISTORY_FILE)
from mcp_server.core.audit import _audit_log, _truncate_if_needed
from mcp_server.correlation.engine import response_pipeline
from mcp_server.wazuh.indexer import _wazuh_indexer_post, _WAZUH_INDEX_PATTERNS
from mcp_server.wazuh.time_utils import _parse_time_window
from mcp_server.core.validators import ValidAgentName, ValidRuleGroups, ValidKeyword

class BaselineProfileInput(BaseModel):
    """Input model for blueteam_baseline_profile."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    agent_name: Optional[str] = Field(default=None, max_length=64,
        description="Target agent for per-agent baselining.")
    rule_groups: Optional[list[str]] = Field(default=None,
        description="Filter by rule groups for per-rule-type baselining.")
    metric: Literal["alert_volume", "unique_ips", "high_severity"] = Field(
        default="alert_volume",
        description="Baseline metric: alert_volume, unique_ips, or high_severity (L10+).")
    window: str = Field(default="7d", max_length=30,
        description="Historical window for baseline computation.")
    granularity: str = Field(default="1h", max_length=10,
        description="Bucket granularity: 15m, 1h, 6h, 1d.")
    response_format: Literal["markdown", "json"] = Field(
        default="markdown", description="'markdown' or 'json'.")


@response_pipeline("blueteam_baseline_profile")
@mcp.tool(
    name="blueteam_baseline_profile",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
)
async def blueteam_baseline_profile(params: BaselineProfileInput) -> str:
    """Compute statistical baselines for alert volume, unique IPs, or severity.

    Queries historical alert data and returns mean (μ), standard deviation (σ),
    and per-bucket Z-scores so the LLM can answer: "Is this normal?"

    **Required Permissions**: Wazuh Indexer read access.

    **Worked Examples**

    1. *Is current alert volume normal for thezoo-prod?*:
       ``blueteam_baseline_profile(agent_name="thezoo-prod", metric="alert_volume", window="7d")``

    2. *High-severity baseline across all agents*:
       ``blueteam_baseline_profile(metric="high_severity", window="30d", granularity="6h")``

    3. *Unique IP baseline for recon alerts*:
       ``blueteam_baseline_profile(rule_groups=["recon","scan"], metric="unique_ips", window="7d")``
    """
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return {"error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set."}

    since_iso, until_iso = _parse_time_window(params.window, None)

    filter_clauses: list[dict] = [
        {"range": {"@timestamp": {"gte": since_iso, "lt": until_iso,
                                   "format": "strict_date_optional_time"}}},
    ]
    if params.agent_name:
        filter_clauses.append({"match": {"agent.name": params.agent_name.strip()}})
    if params.rule_groups:
        filter_clauses.append({"bool": {"should": [
            {"terms": {"rule.groups": params.rule_groups}},
            {"terms": {"rule.groups.keyword": params.rule_groups}},
        ], "minimum_should_match": 1}})
    if params.metric == "high_severity":
        filter_clauses.append({"range": {"rule.level": {"gte": 10}}})

    aggs: dict = {}
    if params.metric == "unique_ips":
        aggs["metric_value"] = {"cardinality": {"field": "data.srcip.keyword",
                                                 "precision_threshold": 40000}}
    else:
        aggs["metric_value"] = {"value_count": {"field": "_id"}}

    body = {
        "size": 0,
        "query": {"bool": {"filter": filter_clauses}},
        "aggs": {
            "over_time": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": params.granularity,
                    "min_doc_count": 0,
                    "extended_bounds": {"min": since_iso, "max": until_iso},
                },
                "aggs": aggs,
            }
        },
    }
    raw = await _wazuh_indexer_post(body)
    if "error" in raw:
        return raw

    buckets = raw.get("aggregations", {}).get("over_time", {}).get("buckets", [])
    values = [
        (b.get("metric_value", {}).get("value", 0) if params.metric == "unique_ips"
         else b.get("doc_count", 0))
        for b in buckets
    ]
    n = len(values)
    if n < 2:
        return {"baseline": {"mean": values[0] if values else 0, "stddev": 0.0,
                "buckets": n, "verdict": "insufficient_data"}}

    mean_val = sum(values) / n
    variance = sum((v - mean_val) ** 2 for v in values) / n
    stddev = math.sqrt(variance)

    # Current value = most recent bucket
    current = values[-1] if values else 0
    z_current = (current - mean_val) / stddev if stddev > 0.0001 else 0.0

    max_val = max(values)
    max_z = (max_val - mean_val) / stddev if stddev > 0.0001 else 0.0
    peak_at = buckets[values.index(max_val)]["key_as_string"] if values else None

    verdict = (
        "critical_anomaly" if abs(z_current) >= 3.0 else
        "significant" if abs(z_current) >= 2.0 else
        "elevated" if abs(z_current) >= 1.0 else
        "normal"
    )

    if params.response_format == "json":
        result = {
            "window": {"since": since_iso, "until": until_iso},
            "granularity": params.granularity,
            "metric": params.metric,
            "baseline": {"mean": round(mean_val, 2), "stddev": round(stddev, 2),
                        "buckets": n},
            "current": {"value": current, "z_score": round(z_current, 2),
                       "verdict": verdict},
            "peak": {"value": max_val, "z_score": round(max_z, 2), "at": peak_at},
        }
        return _truncate_if_needed(json.dumps(result, indent=2, ensure_ascii=False))

    label = params.metric.replace("_", " ").title()
    lines = [
        f"# 📊 Baseline Profile — {label}",
        "",
        f"**Window**: `{since_iso}` → `{until_iso}` ({params.granularity} buckets)",
        "",
        f"| Statistic | Value |",
        f"|-----------|-------|",
        f"| Mean (μ) | {mean_val:.1f} |",
        f"| StdDev (σ) | {stddev:.1f} |",
        f"| Current | **{current}** |",
        f"| Current Z-score | **{z_current:+.1f}σ** |",
        f"| Verdict | {verdict.replace('_',' ').title()} |",
        f"| Peak | {max_val} at {peak_at or '?'} ({max_z:+.1f}σ) |",
        "",
    ]
    if abs(z_current) >= 2.0:
        lines.append(f"⚠️ Current value is **{abs(z_current):.1f}σ** from mean — investigate.")
    else:
        lines.append("✅ Current value is within normal range.")

    lines.append("")
    lines.append("## Per-Bucket Breakdown")
    lines.append("```")
    for i, (b, v) in enumerate(zip(buckets, values)):
        ts = b.get("key_as_string", f"b{i}")[:16]
        z = (v - mean_val) / stddev if stddev > 0.0001 else 0.0
        bar = "█" * min(30, int(abs(z) * 8)) if abs(z) > 0.5 else "▁"
        marker_flag = " ← current" if i == n - 1 else ""
        lines.append(f"  {ts}  {v:>6.0f}  Z:{z:+.1f}  {bar}{marker_flag}")
    lines.append("```")

    return "\n".join(lines)



# AUL Adjust - CAT-B: Calendar Heatmap (Periodicity Detection)
class CalendarHeatmapInput(BaseModel):
    """Input model for blueteam_calendar_heatmap."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    srcip: Optional[str] = Field(default=None, max_length=45,
        description="Source IP to analyze. If omitted, aggregates all IPs.")
    days: int = Field(default=30, ge=7, le=90,
        description="Number of days to analyze (7-90). Default 30.")
    response_format: Literal["markdown", "json"] = Field(
        default="markdown", description="'markdown' or 'json'.")


@mcp.tool(
    name="blueteam_calendar_heatmap",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
)
async def blueteam_calendar_heatmap(params: CalendarHeatmapInput) -> str:
    """Detect scheduled attack patterns via day×hour heatmap analysis.

    Queries 7-90 days of alert data and builds a day-of-week x hour-of-day
    matrix. High-density cells reveal periodic attack schedules - the
    hallmark of automated C2 beaconing, cron-job exploitation, or
    scheduled scanning campaigns.

    **Required Permissions**: Wazuh Indexer read access.

    **Worked Examples**

    1. *Check if an IP attacks on a schedule*:
       ``blueteam_calendar_heatmap(srcip="103.107.116.202", days=30)``

    2. *Global attack pattern across all IPs*:
       ``blueteam_calendar_heatmap(days=14)``

    3. *Extended 90-day analysis*:
       ``blueteam_calendar_heatmap(srcip="185.220.101.1", days=90)``
    """
    _audit_log("blueteam_calendar_heatmap", {"srcip": params.srcip, "days": params.days})
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return json.dumps({"error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set."}, indent=2)

    since_dt = datetime.utcnow() - timedelta(days=params.days)
    until_dt = datetime.utcnow()
    since_iso = since_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    until_iso = until_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    must_clauses: list[dict] = [
        {"range": {"@timestamp": {"gte": since_iso, "lt": until_iso,
                                   "format": "strict_date_optional_time"}}},
    ]
    if params.srcip:
        must_clauses.append({"bool": {"should": [
            {"match": {"data.srcip": params.srcip.strip()}},
            {"match_phrase": {"full_log": params.srcip.strip()}},
        ], "minimum_should_match": 1}})

    body = {
        "size": 0,
        "query": {"bool": {"must": must_clauses}},
        "aggs": {
            "by_hour": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "1h",
                    "min_doc_count": 0,
                    "extended_bounds": {"min": since_iso, "max": until_iso},
                },
            },
        },
    }
    raw = await _wazuh_indexer_post(body)
    if "error" in raw:
        return json.dumps(raw, indent=2)

    buckets = raw.get("aggregations", {}).get("by_hour", {}).get("buckets", [])

    # Build day x hour matrix (Mon-Sun rows, 0-23 hour columns)
    days_of_week = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    matrix: list[list[int]] = [[0] * 24 for _ in range(7)]
    total_alerts = 0

    for b in buckets:
        ts = b.get("key_as_string", "")
        count = b.get("doc_count", 0)
        total_alerts += count
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            dow = dt.weekday()  # 0=Mon, 6=Sun
            hour = dt.hour
            matrix[dow][hour] += count
        except (ValueError, TypeError):
            continue

    # Find peak cell and compute statistics
    max_val = max(max(row) for row in matrix)
    flat = [v for row in matrix for v in row]
    n_cells = len(flat)
    mean_val = sum(flat) / n_cells if n_cells > 0 else 0.0
    variance = sum((v - mean_val) ** 2 for v in flat) / n_cells if n_cells > 0 else 0.0
    stddev = math.sqrt(variance)

    # Find peak day and hour
    peak_day_idx, peak_hour = 0, 0
    for d in range(7):
        for h in range(24):
            if matrix[d][h] > matrix[peak_day_idx][peak_hour]:
                peak_day_idx, peak_hour = d, h

    # Detect strongly periodic patterns (Z > 2.5 in any cell)
    periodic_cells = []
    for d in range(7):
        for h in range(24):
            z = (matrix[d][h] - mean_val) / stddev if stddev > 0.001 else 0.0
            if z >= 2.5:
                periodic_cells.append((days_of_week[d], h, matrix[d][h], round(z, 1)))

    verdict = (
        "strong_periodicity" if len(periodic_cells) >= 3 else
        "possible_periodicity" if periodic_cells else
        "no_periodicity"
    )

    if params.response_format == "json":
        return _truncate_if_needed(json.dumps({
            "window": {"since": since_iso, "until": until_iso, "days": params.days},
            "srcip": params.srcip,
            "total_alerts": total_alerts,
            "stats": {"mean_per_cell": round(mean_val, 1), "stddev": round(stddev, 1)},
            "peak": {"day": days_of_week[peak_day_idx], "hour": peak_hour,
                    "count": matrix[peak_day_idx][peak_hour]},
            "verdict": verdict,
            "periodic_cells": [{"day": d, "hour": h, "count": c, "z": z}
                              for d, h, c, z in periodic_cells],
            "matrix": {days_of_week[d]: {str(h): matrix[d][h] for h in range(24)}
                      for d in range(7)},
        }, indent=2, ensure_ascii=False))

    # ASCII heatmap
    lines = [
        f"# 📅 Calendar Heatmap — {params.srcip or 'All IPs'}",
        "",
        f"**Window**: {params.days} days ({since_iso[:10]} → {until_iso[:10]})",
        f"**Total alerts**: {total_alerts:,}",
        f"**Verdict**: {verdict.replace('_', ' ').title()}",
        "",
    ]

    if periodic_cells:
        lines.append("## ⚠️ Periodic Hotspots (Z ≥ 2.5)")
        lines.append("")
        for d, h, c, z in periodic_cells[:8]:
            lines.append(f"- **{d} {h:02d}:00** — {c:,} alerts ({z:+.1f}σ)")
        lines.append("")

    lines.append(f"## Day × Hour Matrix  (peak: {days_of_week[peak_day_idx]} {peak_hour:02d}:00 = {matrix[peak_day_idx][peak_hour]:,})")
    lines.append("")
    # Header
    lines.append("```")
    header = "     " + "".join(f"{h:>4}" for h in range(24))
    lines.append(header)
    lines.append("    " + "-" * 96)

    for d in range(7):
        row_vals = matrix[d]
        # Find max in this row for scaling
        row_max = max(row_vals) if max(row_vals) > 0 else 1
        # Build ASCII bar row
        bars = ""
        for h in range(24):
            v = row_vals[h]
            if v == 0:
                bars += "   ·"
            else:
                intensity = int(v / row_max * 3)
                chars = ["░", "▒", "▓", "█"]
                bars += f"  {chars[min(intensity, 3)]}"
        marker = " ◀" if d == peak_day_idx else ""
        lines.append(f" {days_of_week[d]} {bars}{marker}")
    lines.append("```")
    lines.append("")
    lines.append("_· = 0   ░ = low   ▒ = medium   ▓ = high   █ = peak_")
    lines.append("")
    lines.append(f"**Peak**: {days_of_week[peak_day_idx]} at {peak_hour:02d}:00 UTC "
                 f"({matrix[peak_day_idx][peak_hour]:,} alerts)")

    return _truncate_if_needed("\n".join(lines))
