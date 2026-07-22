#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Investigation history + false positive tracker + summary tools
"""
from __future__ import annotations
import json, os
from datetime import datetime, timedelta
from typing import Optional, Literal
from collections import Counter
from pydantic import field_validator, BaseModel, ConfigDict, Field

from mcp_server import (mcp, _INVESTIGATION_HISTORY_FILE)
from mcp_server.core.audit import _audit_log, _truncate_if_needed

_INVESTIGATION_HISTORY_MAX_ENTRIES = int(os.environ.get("BLUETEAM_INVESTIGATION_HISTORY_MAX_ENTRIES", "10000"))

class MarkInvestigatedInput(BaseModel):
    """Input model for blueteam_mark_investigated."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    srcip: str = Field(..., min_length=7, max_length=45,
        description="Source IP being investigated.")
    verdict: Literal["true_positive", "false_positive", "suspicious", "clean", "unknown"] = Field(
        ..., description="Investigation verdict.")
    notes: str = Field(default="", max_length=1024,
        description="Analyst notes (max 1024 chars).")


@mcp.tool(
    name="blueteam_mark_investigated",
    annotations={"readOnlyHint": False, "destructiveHint": False,
                 "idempotentHint": False, "openWorldHint": False},
)
async def blueteam_mark_investigated(params: MarkInvestigatedInput) -> str:
    """Record an IP investigation verdict in the persistent JSONL history.

    Appends a timestamped entry to BLUETEAM_INVESTIGATION_HISTORY. This is the
    only tool that writes investigation state — all other tools (curated reports,
    threat cards, beacon detection) are read-only.

    **Required**: BLUETEAM_INVESTIGATION_HISTORY env var set to a writable path.

    **Worked Examples**

    1. *Mark malicious*:
       ``blueteam_mark_investigated(srcip="103.107.116.202", verdict="true_positive", notes="CrowdSec confirmed — C2 beaconing")``

    2. *Mark false positive*:
       ``blueteam_mark_investigated(srcip="8.8.8.8", verdict="false_positive", notes="Google DNS — scanner noise")``
    """
    _audit_log("blueteam_mark_investigated", {"srcip": params.srcip, "verdict": params.verdict})
    if not _INVESTIGATION_HISTORY_FILE:
        return json.dumps({"error": "BLUETEAM_INVESTIGATION_HISTORY env var not set.",
                           "detail": "Set this to a writable JSONL file path for investigation persistence."}, indent=2)
    entry = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "srcip": params.srcip.strip(),
        "verdict": params.verdict,
        "notes": params.notes[:1024],
    }
    try:
        with open(_INVESTIGATION_HISTORY_FILE, "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return json.dumps({"status": "recorded", "entry": entry}, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Failed to write history: {e}"}, indent=2)


class FalsePositiveTrackerInput(BaseModel):
    """Input model for blueteam_false_positive_tracker."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    rule_id: str = Field(..., max_length=16,
        description="Wazuh rule ID to check, e.g. '600029'.")
    since: Optional[str] = Field(default="30d", max_length=30,
        description="Time window. ISO 8601 or relative ('7d', '30d').")
    response_format: Literal["markdown", "json"] = Field(
        default="markdown", description="'markdown' or 'json'.")


@mcp.tool(
    name="blueteam_false_positive_tracker",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
)
async def blueteam_false_positive_tracker(params: FalsePositiveTrackerInput) -> str:
    """Count how often a Wazuh rule fired but was later marked false-positive.

    Parses BLUETEAM_INVESTIGATION_HISTORY to find IPs investigated with
    verdict="false_positive", then cross-references rule_id from investigation
    summaries. Helps SOC tune noisy Wazuh rules.

    **Worked Examples**

    1. *Check rule 600029*:
       ``blueteam_false_positive_tracker(rule_id="600029", since="30d")``
    """
    _audit_log("blueteam_false_positive_tracker", {"rule_id": params.rule_id})
    if not _INVESTIGATION_HISTORY_FILE:
        return json.dumps({"error": "BLUETEAM_INVESTIGATION_HISTORY not set."}, indent=2)
    since_dt = datetime.utcnow() - timedelta(days=30 if params.since == "30d" else 7)
    history = _read_history()
    fp_ips = {ip for ip, e in history.items()
              if e.get("verdict") == "false_positive"
              and e.get("ts", "") >= since_dt.strftime("%Y-%m-%d")}
    # Cross-reference: count rule_id mentions in FP summaries
    fp_count = 0
    fp_ips_list: list[str] = []
    for ip, e in history.items():
        if ip not in fp_ips:
            continue
        summary = e.get("summary", {})
        rules = summary.get("rules", [])
        if isinstance(rules, list):
            for r in rules:
                if isinstance(r, dict) and str(r.get("id", "")) == params.rule_id:
                    fp_count += 1
                    fp_ips_list.append(ip)
                    break
    if params.response_format == "json":
        return json.dumps({"rule_id": params.rule_id, "false_positive_count": fp_count,
                           "ips": fp_ips_list[:50]}, indent=2)
    return (f"# False Positive Tracker — Rule `{params.rule_id}`\n\n"
            f"- **False positive verdicts**: {fp_count}\n"
            f"- **IPs flagged**: {', '.join(f'`{ip}`' for ip in fp_ips_list[:10]) if fp_ips_list else 'none'}\n"
            f"- **Window**: since {since_dt.strftime('%Y-%m-%d')}\n")


class InvestigationSummaryInput(BaseModel):
    """Input model for blueteam_investigation_summary."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    since: Optional[str] = Field(default="7d", max_length=30,
        description="Time window. ISO 8601 or relative.")
    response_format: Literal["markdown", "json"] = Field(
        default="markdown", description="'markdown' or 'json'.")


@mcp.tool(
    name="blueteam_investigation_summary",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
)
async def blueteam_investigation_summary(params: InvestigationSummaryInput) -> str:
    """Dashboard: unique IPs investigated, verdict breakdown, analyst notes.

    Reads BLUETEAM_INVESTIGATION_HISTORY and aggregates recent investigations.
    Prevents redundant re-analysis by showing which IPs already have verdicts.

    **Worked Examples**

    1. *Last 7 days*:
       ``blueteam_investigation_summary()``

    2. *Last 30 days*:
       ``blueteam_investigation_summary(since="30d")``
    """
    _audit_log("blueteam_investigation_summary", {"since": params.since})
    if not _INVESTIGATION_HISTORY_FILE:
        return json.dumps({"error": "BLUETEAM_INVESTIGATION_HISTORY not set."}, indent=2)
    since_dt = datetime.utcnow() - timedelta(days=7 if params.since == "7d" else 30)
    history = _read_history()
    recent = {ip: e for ip, e in history.items()
              if e.get("ts", "")[:10] >= since_dt.strftime("%Y-%m-%d")}
    verdicts: Counter[str] = Counter()
    for e in recent.values():
        verdicts[e.get("verdict", "unknown")] += 1

    if params.response_format == "json":
        return json.dumps({
            "window_since": since_dt.strftime("%Y-%m-%d"),
            "total_investigated": len(recent),
            "verdicts": dict(verdicts),
            "ips": sorted(recent.keys()),
        }, indent=2)

    lines = [
        f"# Investigation Summary - Since {since_dt.strftime('%Y-%m-%d')}",
        "",
        f"**Total IPs investigated**: {len(recent)}",
        "",
        "| Verdict | Count |",
        "|---------|-------|",
    ]
    for v, c in verdicts.most_common():
        lines.append(f"| {v} | {c} |")
    if recent:
        lines.append("")
        lines.append("## Recent Investigations")
        for ip, e in sorted(recent.items(), key=lambda x: x[1].get("ts", ""), reverse=True)[:15]:
            ts = e.get("ts", "?")[:19]
            v = e.get("verdict", "?")
            notes = (e.get("notes", "") or "")[:60]
            lines.append(f"- `[{ts}]` `{ip}` — {v}" + (f" ({notes})" if notes else ""))
    return _truncate_if_needed("\n".join(lines))


# Investigation History read/write helpers (shared across tools)
def _read_history() -> dict[str, dict]:
    """Read investigation history from JSONL file. Returns {ip: latest_entry}."""
    if not _INVESTIGATION_HISTORY_FILE:
        return {}
    history: dict[str, dict] = {}
    try:
        with open(_INVESTIGATION_HISTORY_FILE) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                ip = entry.get("srcip", "")
                if ip:
                    history[ip] = entry
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return history


def _write_history(srcip: str, verdict: str, summary: dict) -> None:
    """Append an investigation entry to the history file."""
    if not _INVESTIGATION_HISTORY_FILE:
        return
    try:
        entry = {"ts": datetime.utcnow().isoformat() + "Z", "srcip": srcip,
                 "verdict": verdict, "summary": summary}
        with open(_INVESTIGATION_HISTORY_FILE, "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        # Tail-truncate if over max entries
        if _INVESTIGATION_HISTORY_MAX_ENTRIES > 0:
            with open(_INVESTIGATION_HISTORY_FILE) as f:
                lines = f.readlines()
            if len(lines) > _INVESTIGATION_HISTORY_MAX_ENTRIES:
                with open(_INVESTIGATION_HISTORY_FILE, "w") as f:
                    f.writelines(lines[-_INVESTIGATION_HISTORY_MAX_ENTRIES:])
    except Exception:
        pass


class InvestigationHistoryInput(BaseModel):
    """Input model for blueteam_investigation_history."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    srcip: str = Field(..., min_length=7, max_length=45,
        description="Source IP to check investigation history for.")
    response_format: Literal["markdown", "json"] = Field(
        default="markdown", description="'markdown' or 'json'.")


@mcp.tool(
    name="blueteam_investigation_history",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
)
async def blueteam_investigation_history(params: InvestigationHistoryInput) -> str:
    """Check if an IP was previously investigated and what the verdict was.

    Reads from BLUETEAM_INVESTIGATION_HISTORY (JSONL file). Returns the last
    investigation entry for the IP with timestamp, verdict, and summary.

    **Required**: BLUETEAM_INVESTIGATION_HISTORY env var pointing to a writable
    JSONL file. Without it, returns empty history.

    **Worked Examples**

    1. *Check prior investigation*:
       ``blueteam_investigation_history(srcip="103.107.116.202")``

    2. *Verify if IP is new*:
       ``blueteam_investigation_history(srcip="185.220.101.1")``
    """
    _audit_log("blueteam_investigation_history", {"srcip": params.srcip})
    history = _read_history()
    entry = history.get(params.srcip.strip())

    if params.response_format == "json":
        return json.dumps({
            "srcip": params.srcip,
            "previously_investigated": entry is not None,
            "last_entry": entry,
        }, indent=2, ensure_ascii=False)

    if entry:
        ts = entry.get("ts", "?")[:19]
        verdict = entry.get("verdict", "unknown")
        summary = entry.get("summary", {})
        return (
            f"# Investigation History — `{params.srcip}`\n\n"
            f"- **Last analyzed**: {ts}\n"
            f"- **Verdict**: {verdict}\n"
            f"- **Summary**: {json.dumps(summary, indent=2)}\n\n"
            f"_History file: {_INVESTIGATION_HISTORY_FILE}_"
        )
    return (
        f"# Investigation History — `{params.srcip}`\n\n"
        f"**No prior investigation found**. This IP has not been analyzed before.\n\n"
        f"_History file: {_INVESTIGATION_HISTORY_FILE or '(not configured)'}_"
    )


# Wazuh Indexer index patterns (OpenSearch)
# Correlation tools (hand-migrated)
import json, asyncio, time, math
from datetime import datetime, timedelta
from pydantic import BaseModel, ConfigDict, Field, field_validator
from mcp_server import (WAZUH_INDEXER_URL, WAZUH_INDEXER_PASSWORD, _WAZUH_INDEXER_MAX_SIZE,
                        CROWDSEC_API_KEY_ENV, ARGUS_API_KEY_ENV, _INVESTIGATION_HISTORY_FILE)
from mcp_server.core.audit import _audit_log, _truncate_if_needed, _escape_md_table
from mcp_server.core.http_client import _api_call, _handle_api_error
from mcp_server.core.constants import MITRE_TACTIC_TO_CATEGORY, _last_eval_time, _last_eval_result
from mcp_server.core.validators import ValidAgentName, ValidRuleGroups, ValidKeyword
from mcp_server.wazuh.indexer import _wazuh_indexer_post, _wazuh_indexer_msearch, _WAZUH_INDEX_PATTERNS, _KEYWORD_SEARCH_FIELDS, _SRCIP_FIELD_PATHS
from mcp_server.wazuh.time_utils import _parse_time_window, _auto_bucket_interval, _duration_minutes
from mcp_server.threat_intel.crowdsec import _crowdsec_request
from mcp_server.correlation.engine import response_pipeline
from mcp_server.correlation.three_sum_core import (evaluate_engine_a, evaluate_engine_b, format_evaluation_dict,
    normalize_srcip_to_cidr, DEFAULT_THRESHOLD_SCORE, DEFAULT_Z_THRESHOLD, DEFAULT_WINDOW_MINUTES)


# Aggregate Analysis
class AggregateAnalysisInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    mode: str = Field(default="summary")
    since: Optional[str] = Field(default="24h", max_length=30)
    until: Optional[str] = Field(default=None, max_length=30)
    agent_name: ValidAgentName = Field(default=None, max_length=64)
    rule_groups: ValidRuleGroups = Field(default=None)
    rule_level_min: Optional[int] = Field(default=None, ge=1, le=16)
    keyword: ValidKeyword = Field(default=None, max_length=1024)
    top_n: int = Field(default=10, ge=3, le=50)
    response_format: str = Field(default="markdown")
    bypass_redaction: bool = Field(default=False)

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v):
        if v.strip().lower() not in ("topology","anomaly","correlation","trend","summary"):
            raise ValueError("mode must be: topology, anomaly, correlation, trend, summary. "
                             "For top rules/srcips/agents by keyword, use blueteamWazuhIndexerSearch "
                             "or wazuhAlertFocusedCrawl instead.")
        return v.strip().lower()


@mcp.tool(
    name="wazuh_alert_aggregate_analysis",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}
)
async def wazuh_alert_aggregate_analysis(params: AggregateAnalysisInput) -> str:
    """Zero-doc statistical analysis of Wazuh alerts across the full index."""
    _audit_log("wazuh_alert_aggregate_analysis", {"mode": params.mode})
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return json.dumps({"error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set."}, indent=2)
    since_str, until_str = _parse_time_window(params.since, params.until)
    filters = [{"range": {"@timestamp": {"gte": since_str, "lt": until_str, "format": "strict_date_optional_time"}}}]
    if params.agent_name: filters.append({"match": {"agent.name": params.agent_name}})
    if params.rule_groups:
        groups = [g.strip() for g in params.rule_groups.split(",") if g.strip()]
        if groups: filters.append({"terms": {"rule.groups": groups}})
    if params.rule_level_min is not None: filters.append({"range": {"rule.level": {"gte": params.rule_level_min}}})
    if params.keyword:
        k = params.keyword.strip()
        parts = [f'{f}: ({k})^{b}' if b else f'{f}: ({k})' for f, b in _KEYWORD_SEARCH_FIELDS[:8]]
        filters.append({"query_string": {"query": " OR ".join(parts), "default_operator": "AND", "lenient": True}})
    body = {"size": 0, "query": {"bool": {"filter": filters}},
            "aggs": {"top_srcips": {"terms": {"field": "data.srcip.keyword", "size": params.top_n}},
                     "top_rules": {"terms": {"field": "rule.id.keyword", "size": params.top_n}},
                     "top_agents": {"terms": {"field": "agent.name.keyword", "size": params.top_n}},
                     "severity_bands": {"range": {"field": "rule.level",
                         "ranges": [{"key":"low","to":5},{"key":"medium","from":5,"to":10},{"key":"high","from":10}]}}}}
    raw = await _wazuh_indexer_post(body)
    if "error" in raw: return json.dumps(raw, indent=2)
    aggs = raw.get("aggregations", {})
    total = raw.get("hits", {}).get("total", {}).get("value", 0)
    if params.response_format == "json":
        return _truncate_if_needed(json.dumps({"total": total, "aggregations": aggs}, indent=2))
    sev = {b["key"]: b["doc_count"] for b in aggs.get("severity_bands", {}).get("buckets", [])}
    lines = [f"# Aggregate Analysis ({params.mode})", "", f"**Total alerts**: {total:,}", "",
             "## Severity", f"- Low: {sev.get('low',0):,}", f"- Medium: {sev.get('medium',0):,}",
             f"- High: {sev.get('high',0):,}", "", "## Top Source IPs"]
    for b in aggs.get("top_srcips", {}).get("buckets", [])[:10]:
        lines.append(f"- `{b['key']}`: {b['doc_count']:,}")
    return _truncate_if_needed("\n".join(lines))


# Three-Sum Correlation
class ThreeSumCorrelationInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    engine_a_enabled: bool = Field(default=True)
    engine_b_enabled: bool = Field(default=True)
    time_window_minutes: int = Field(default=DEFAULT_WINDOW_MINUTES, ge=5)
    threshold_score: int = Field(default=DEFAULT_THRESHOLD_SCORE, ge=6, le=30)
    z_score_threshold: float = Field(default=DEFAULT_Z_THRESHOLD, ge=1.0, le=5.0)
    response_format: str = Field(default="markdown")
    throttle: int = Field(default=0, ge=0)
    use_mitre: bool = Field(default=False)
    category_a_groups: list[str] = Field(default=["web","attack","scan","recon","accesslog"])
    category_b_groups: list[str] = Field(default=["authentication_failures","bruteforce","blocklist","zimbra","spam","postfix"])
    category_c_groups: list[str] = Field(default=["firewall_drop","exfiltration","overflow","opencti","backdoor","defacement"])
    category_a_label: str = Field(default="recon")
    category_b_label: str = Field(default="access_anomaly")
    category_c_label: str = Field(default="c2_exfil")
    category_a_score: int = Field(default=3, ge=1, le=10)
    category_b_score: int = Field(default=4, ge=1, le=10)
    category_c_score: int = Field(default=4, ge=1, le=10)
    cidr_normalize: bool = Field(default=False)
    exclude_srcips: list[str] = Field(default=[])
    follow_up: str = Field(default="none")
    multi_resolution: bool = Field(default=False)
    cross_agent: bool = Field(
        default=False,
        description="When true, correlate alerts by (srcip × agent.name) instead of srcip only. "
                    "Detects lateral movement where same IP targets multiple agents.",
    )


_three_sum_global_throttle = {"time": 0.0, "result": None}


@response_pipeline("three_sum_correlation")
@mcp.tool(
    name="three_sum_correlation",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def three_sum_correlation(data: ThreeSumCorrelationInput) -> dict:
    """Evaluate 3-Sum APT detection across 3 Wazuh alert categories.

    **Engine A — Multi-IoC Risk Thresholding**: Finds source IPs appearing in
    all 3 alert categories, sums per-category risk scores, and flags those
    exceeding ``threshold_score``.

    **Engine B — 3-Source Volumetric Z-Score**: Queries per-minute alert
    counts for all 3 categories, computes rolling μ/σ, and flags buckets
    where all 3 simultaneously exceed ``z_score_threshold``.

    **follow_up**: When set to ``"threat_intel"``, automatically enriches
    the top 10 trigger IPs with CrowdSec and ThreatFox lookups.
    """
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return {"error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set."}
    start_time = time.monotonic()

    # Throttle gate
    if data.throttle > 0 and _three_sum_global_throttle["time"] > 0:
        elapsed = start_time - _three_sum_global_throttle["time"]
        if elapsed < data.throttle:
            return dict(_three_sum_global_throttle["result"] or {})

    # Feedback loop: auto-exclude FP-verified IPs from investigation history
    exclude_set: set[str] = set(data.exclude_srcips or [])
    if _INVESTIGATION_HISTORY_FILE:
        try:
            history = _read_history()
            for ip, entry in history.items():
                if entry.get("verdict") == "false_positive":
                    exclude_set.add(ip)
        except Exception:
            pass

    # Time window
    since_dt = datetime.utcnow() - timedelta(minutes=data.time_window_minutes)
    until_dt = datetime.utcnow()
    since_iso = since_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    until_iso = until_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    labels = [(data.category_a_label, data.category_a_groups, data.category_a_score),
              (data.category_b_label, data.category_b_groups, data.category_b_score),
              (data.category_c_label, data.category_c_groups, data.category_c_score)]

    # Shared query builder (Engine A + B)
    def _build_filter(groups: list[str]) -> dict:
        return {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": since_iso, "lt": until_iso,
                                       "format": "strict_date_optional_time"}}},
            {"bool": {"should": [
                {"terms": {"rule.groups": groups}},
                {"terms": {"rule.groups.keyword": groups}},
            ], "minimum_should_match": 1}},
        ]}}

    engine_a_results = None
    engine_b_results = None

    # ENGINE A - Multi-IoC Risk Thresholding
    if data.engine_a_enabled:
        async def _fetch_srcips(label, groups, score):
            body = {"size": 0, "query": _build_filter(groups),
                    "aggs": {"unique_srcips": {
                        "multi_terms": {"terms": [{"field": f} for f in _SRCIP_FIELD_PATHS],
                                         "size": 10000}}}}
            raw = await _wazuh_indexer_post(body)
            if "error" in raw:
                return (label, [])
            buckets = raw.get("aggregations", {}).get("unique_srcips", {}).get("buckets", [])
            entries = []
            for b in buckets:
                key = b["key"]
                ip = next((v for v in key if v is not None), "0.0.0.0") if isinstance(key, list) else key
                entries.append((ip, score))
            return (label, entries)

        fetched = await asyncio.gather(*[_fetch_srcips(l, g, s) for l, g, s in labels])
        srcips_by_label = {l: e for l, e in fetched}

        triggers, stats = evaluate_engine_a(
            srcips_by_label.get(data.category_a_label, []),
            srcips_by_label.get(data.category_b_label, []),
            srcips_by_label.get(data.category_c_label, []),
            threshold_score=data.threshold_score,
            exclude_srcips=list(exclude_set) if exclude_set else None,
            cidr_normalize=data.cidr_normalize,
        )
        engine_a_results = (triggers, stats)

    # ENGINE B - 3-Source Volumetric Z-Score
    if data.engine_b_enabled:
        # Compute auto-bucket interval: target ~60 buckets
        dur_minutes = data.time_window_minutes
        if dur_minutes <= 60:
            bucket_interval = "1m"
        elif dur_minutes <= 360:
            bucket_interval = "5m"
        elif dur_minutes <= 1440:
            bucket_interval = "15m"
        else:
            bucket_interval = "1h"

        async def _fetch_time_buckets(groups):
            body = {"size": 0, "query": _build_filter(groups),
                    "aggs": {"over_time": {"date_histogram": {
                        "field": "@timestamp", "fixed_interval": bucket_interval,
                        "min_doc_count": 0,
                        "extended_bounds": {"min": since_iso, "max": until_iso}}}}}
            raw = await _wazuh_indexer_post(body)
            if "error" in raw:
                return []
            return raw.get("aggregations", {}).get("over_time", {}).get("buckets", [])

        buckets_a, buckets_b, buckets_c = await asyncio.gather(
            _fetch_time_buckets(data.category_a_groups),
            _fetch_time_buckets(data.category_b_groups),
            _fetch_time_buckets(data.category_c_groups),
        )

        anomalies, b_stats = evaluate_engine_b(
            buckets_a, buckets_b, buckets_c,
            z_score_threshold=data.z_score_threshold,
        )
        engine_b_results = (anomalies, b_stats)

    # UNIFIED SCORING
    result = format_evaluation_dict(
        since_iso, until_iso,
        engine_a_results=engine_a_results,
        engine_b_results=engine_b_results,
        evaluation_time_ms=(time.monotonic() - start_time) * 1000,
    )

    # FOLLOW-UP ENRICHMENT - auto-enrich top triggers with threat intel
    if data.follow_up == "threat_intel" and engine_a_results:
        triggers, _ = engine_a_results
        top_ips = [t["ip"] for t in triggers[:10] if t.get("ip")]
        if top_ips:
            enrichment = await _enrich_ips(top_ips)
            result["enrichment"] = enrichment

    _three_sum_global_throttle["time"] = time.monotonic()
    _three_sum_global_throttle["result"] = result
    return result


async def _enrich_ips(ips: list[str]) -> dict[str, dict]:
    """Enrich a list of IPs with CrowdSec + ThreatFox concurrently.

    Best-effort — individual failures are surfaced inline but never block
    the overall enrichment pass.
    """
    async def _crowdsec_one(ip: str) -> dict | None:
        try:
            raw = await _crowdsec_request(f"/v2/smoke/{ip}")
            return {"reputation": raw.get("reputation", "unknown"),
                    "behaviors": [b.get("name", "?") for b in raw.get("behaviors", [])[:3]]}
        except Exception:
            return None

    async def _threatfox_one(ip: str) -> dict | None:
        try:
            from mcp_server.threat_intel.threatfox import _threatfox_request
            raw = await _threatfox_request(ip, False)
            items = raw.get("data", [])
            if not items:
                return None
            return {"malware": items[0].get("malware_printable", "?"),
                    "confidence": items[0].get("confidence_level", 0),
                    "threat_type": items[0].get("threat_type_desc", "?")}
        except Exception:
            return None

    tasks = []
    for ip in ips:
        tasks.append(_crowdsec_one(ip))
        tasks.append(_threatfox_one(ip))

    results = await asyncio.gather(*tasks)
    enriched: dict[str, dict] = {}
    for i, ip in enumerate(ips):
        cs = results[i * 2]
        tf = results[i * 2 + 1]
        entry: dict = {}
        if cs:
            entry["crowdsec"] = cs
        if tf:
            entry["threatfox"] = tf
        if entry:
            enriched[ip] = entry
    return enriched


# Cross-Tool IP Investigation
class InvestigateIpInput(BaseModel):
    """Input model for blueteam_investigate_ip."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    srcip: str = Field(..., min_length=7, max_length=45,
                       description="Source IP to investigate.")
    since: str | None = Field(default="24h", max_length=30,
                               description="Time window. ISO 8601 or relative ('24h', '7d').")
    response_format: Literal["markdown", "json"] = Field(
        default="markdown", description="'markdown' or 'json'.")


@mcp.tool(
    name="blueteam_investigate_ip",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
)
async def blueteam_investigate_ip(params: InvestigateIpInput) -> str:
    """Run a comprehensive IP investigation — alert profile, timeline, and geo.

    Combines three indexer queries in parallel:
    1. Alert count + top rules (like alert summarization)
    2. Hourly timeline (for pattern/beacon detection)
    3. Geo distribution (country-level attack origin)

    Use this as a first-look triage tool. For deeper analysis, follow up with
    ``blueteam_threat_card``, ``blueteam_attack_chain``, and ``blueteam_unified_threat_score``.

    **Worked Examples**

    1. *Quick triage of a suspicious IP*:
       ``blueteam_investigate_ip(srcip="103.107.116.202")``

    2. *7-day investigation*:
       ``blueteam_investigate_ip(srcip="185.220.101.1", since="7d")``

    3. *JSON output for automated processing*:
       ``blueteam_investigate_ip(srcip="10.0.0.55", response_format="json")``
    """
    _audit_log("blueteam_investigate_ip", {"srcip": params.srcip, "since": params.since})
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return json.dumps({"error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set."}, indent=2)

    since_iso, until_iso = _parse_time_window(params.since or "24h", None)
    srcip = params.srcip.strip()

    # Build shared filter
    base_filter = [
        {"range": {"@timestamp": {"gte": since_iso, "lt": until_iso,
                                   "format": "strict_date_optional_time"}}},
        {"bool": {"should": [
            {"match": {"data.srcip": srcip}},
            {"match_phrase": {"full_log": srcip}},
        ], "minimum_should_match": 1}},
    ]

    async def _fetch_summary():
        body = {"size": 0, "query": {"bool": {"filter": base_filter}},
                "aggs": {
                    "top_rules": {"terms": {"field": "rule.id.keyword", "size": 10}},
                    "top_agents": {"terms": {"field": "agent.name.keyword", "size": 10}},
                    "severity": {"range": {"field": "rule.level",
                        "ranges": [{"key": "low", "to": 5}, {"key": "medium", "from": 5, "to": 10},
                                   {"key": "high", "from": 10}]}},
                }}
        return await _wazuh_indexer_post(body)

    async def _fetch_timeline():
        body = {"size": 0, "query": {"bool": {"filter": base_filter}},
                "aggs": {"over_time": {"date_histogram": {
                    "field": "@timestamp", "fixed_interval": "1h",
                    "min_doc_count": 0,
                    "extended_bounds": {"min": since_iso, "max": until_iso}}}}}
        return await _wazuh_indexer_post(body)

    async def _fetch_geo():
        body = {"size": 0, "query": {"bool": {"filter": base_filter + [
                    {"exists": {"field": "GeoLocation.country_name"}}]}},
                "aggs": {"by_country": {"terms": {
                    "field": "GeoLocation.country_name", "size": 10}}}}
        return await _wazuh_indexer_post(body)

    summary_raw, timeline_raw, geo_raw = await asyncio.gather(
        _fetch_summary(), _fetch_timeline(), _fetch_geo())

    # Parse results
    total = summary_raw.get("hits", {}).get("total", {}).get("value", 0)
    s_aggs = summary_raw.get("aggregations", {})
    t_aggs = timeline_raw.get("aggregations", {})
    g_aggs = geo_raw.get("aggregations", {})

    if params.response_format == "json":
        return json.dumps({
            "srcip": srcip,
            "window": {"since": since_iso, "until": until_iso},
            "total_alerts": total,
            "top_rules": [{"id": b["key"], "count": b["doc_count"]}
                          for b in s_aggs.get("top_rules", {}).get("buckets", [])],
            "top_agents": [{"name": b["key"], "count": b["doc_count"]}
                           for b in s_aggs.get("top_agents", {}).get("buckets", [])],
            "severity": {b["key"]: b["doc_count"]
                         for b in s_aggs.get("severity", {}).get("buckets", [])},
            "timeline": [{"ts": b.get("key_as_string", "?")[:16],
                          "count": b.get("doc_count", 0)}
                         for b in t_aggs.get("over_time", {}).get("buckets", [])],
            "geo": [{"country": b["key"], "count": b["doc_count"]}
                    for b in g_aggs.get("by_country", {}).get("buckets", [])],
        }, indent=2, ensure_ascii=False)

    # Build markdown report
    lines = [
        f"# 🔎 IP Investigation — `{srcip}`",
        "",
        f"**Window**: `{since_iso}` → `{until_iso}`",
        f"**Total alerts**: {total:,}",
        "",
    ]

    # Severity breakdown
    sev = {b["key"]: b["doc_count"] for b in s_aggs.get("severity", {}).get("buckets", [])}
    if sev:
        lines.append("## Severity")
        lines.append(f"- 🔴 High (L10+): {sev.get('high', 0):,}")
        lines.append(f"- 🟡 Medium (L5-9): {sev.get('medium', 0):,}")
        lines.append(f"- 🟢 Low (L1-4): {sev.get('low', 0):,}")
        lines.append("")

    # Top rules
    top_rules = s_aggs.get("top_rules", {}).get("buckets", [])
    if top_rules:
        lines.append("## Top Rules")
        lines.append("| Rule ID | Alerts |")
        lines.append("|---------|--------|")
        for b in top_rules[:10]:
            lines.append(f"| `{b['key']}` | {b['doc_count']:,} |")
        lines.append("")

    # Timeline sparkline
    timeline_buckets = t_aggs.get("over_time", {}).get("buckets", [])
    if timeline_buckets:
        max_count = max((b.get("doc_count", 0) for b in timeline_buckets), default=1)
        lines.append("## Hourly Timeline")
        for b in timeline_buckets:
            ts = b.get("key_as_string", "?")[:16]
            count = b.get("doc_count", 0)
            bar_len = int(count / max(max_count, 1) * 30) if max_count > 0 else 0
            bar = "█" * bar_len if bar_len > 0 else "▁"
            lines.append(f"  `{ts}`  {count:>5,}  {bar}")
        lines.append("")

    # Geo
    geo_buckets = g_aggs.get("by_country", {}).get("buckets", [])
    if geo_buckets:
        lines.append("## Top Countries")
        lines.append("| Country | Alerts |")
        lines.append("|---------|--------|")
        for b in geo_buckets[:8]:
            lines.append(f"| {b['key']} | {b['doc_count']:,} |")
        lines.append("")

    # Target agents
    top_agents = s_aggs.get("top_agents", {}).get("buckets", [])
    if top_agents:
        lines.append("## Target Agents")
        for b in top_agents[:8]:
            lines.append(f"- `{b['key']}`: {b['doc_count']:,} alerts")
        lines.append("")

    if total == 0:
        lines.append("✅ **No alerts found** for this IP in the selected time window.")
    else:
        lines.append("---")
        lines.append(f"*Follow up with `blueteam_threat_card(srcip='{srcip}')` for threat intel enrichment,*")
        lines.append(f"*`blueteam_attack_chain(srcip='{srcip}')` for kill-chain analysis, or*")
        lines.append(f"*`blueteam_unified_threat_score(ip='{srcip}')` for multi-source scoring.*")

    return _truncate_if_needed("\n".join(lines))
