#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Alert enrichment tools — curated report, threat card, attack chain, beacon detect, summarize, compare
"""
from __future__ import annotations
import json, re, math, asyncio, os
from datetime import datetime, timedelta
from typing import Optional, Literal, Any
from collections import Counter
from pydantic import BaseModel, ConfigDict, Field, field_validator
from mcp_server import (mcp, WAZUH_INDEXER_URL, WAZUH_INDEXER_PASSWORD,
                        _WAZUH_INDEXER_MAX_SIZE, _BYPASS_REDACTION_DESC,
                        CROWDSEC_API_KEY_ENV, ARGUS_API_KEY_ENV,
                        ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY)
from mcp_server.core.audit import _audit_log, _truncate_if_needed, _escape_md_table
from mcp_server.core.redact import _redact_alert_data
from mcp_server.core.http_client import _api_call, _get_client
from mcp_server.core.validators import ValidAgentName, ValidKeyword, ValidRuleGroups
from mcp_server.wazuh.indexer import _wazuh_indexer_post, _WAZUH_INDEX_PATTERNS
from mcp_server.wazuh.time_utils import _parse_time_window, _duration_minutes

# F-1: Alert Summarization
class AlertSummarizeInput(BaseModel):
    """Input model for blueteam_wazuh_alert_summarize."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    srcip: str = Field(
        ...,
        min_length=7,
        max_length=45,
        description="Source IP to summarize alerts for (e.g. '103.107.116.202').",
    )
    agent_name: ValidAgentName = Field(
        default=None,
        max_length=64,
        description="Optional Wazuh agent name filter.",
    )
    since: Optional[str] = Field(
        default="24h",
        max_length=30,
        description="Start of time window. ISO 8601 or relative ('5m','1h','24h','7d','30d').",
    )
    until: Optional[str] = Field(
        default=None,
        max_length=30,
        description="End of time window. Defaults to now.",
    )
    limit: int = Field(
        default=200,
        ge=10,
        le=2000,
        description="Max alerts to fetch for summarization (default 200).",
    )
    response_format: Literal["markdown", "json"] = Field(
        default="markdown",
        description="Output format: 'markdown' (human-readable digest) or 'json'.",
    )
    bypass_redaction: bool = Field(
        default=False,
        description=_BYPASS_REDACTION_DESC,
    )


@mcp.tool(
    name="blueteam_wazuh_alert_summarize",
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def blueteam_wazuh_alert_summarize(params: AlertSummarizeInput) -> str:
    """Summarize Wazuh alerts for a source IP into a compact threat digest.

    Extracts IoCs (domains, URLs, user-agents), groups alerts by rule.id
    with counts, computes first_seen / last_seen per rule, and flags
    unusual user-agent strings (old browsers, scripted clients).

    Returns a markdown report or JSON with the structured digest — the LLM
    can reason about attack patterns from the summary without scanning
    raw alert documents.

    **Required Permissions**: Wazuh Indexer user with ``read`` access.

    **Worked Examples**

    1. *Basic IP summary*:
       ``blueteam_wazuh_alert_summarize(srcip="103.107.116.202")``

    2. *Focused time window*:
       ``blueteam_wazuh_alert_summarize(srcip="103.107.116.202", since="1h")``

    3. *Single agent only*:
       ``blueteam_wazuh_alert_summarize(srcip="103.107.116.202", agent_name="thezoo-prod")``
    """
    _audit_log("blueteam_wazuh_alert_summarize", {"srcip": params.srcip})
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return json.dumps({
            "error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set.",
        }, indent=2)

    since_iso, until_iso = _parse_time_window(params.since, params.until)

    must_clauses: list[dict] = [
        {"range": {"@timestamp": {"gte": since_iso, "lt": until_iso,
                                     "format": "strict_date_optional_time"}}},
        {"bool": {
            "should": [
                {"match": {"data.srcip": params.srcip.strip()}},
                {"match_phrase": {"full_log": params.srcip.strip()}},
            ],
            "minimum_should_match": 1,
        }},
    ]
    if params.agent_name:
        must_clauses.append({"match": {"agent.name": params.agent_name.strip()}})

    body = {
        "size": min(params.limit, _WAZUH_INDEXER_MAX_SIZE),
        "sort": [{"@timestamp": {"order": "asc"}}],
        "query": {"bool": {"must": must_clauses}},
        "_source": [
            "@timestamp", "agent.name", "rule.id", "rule.level",
            "rule.description", "rule.groups", "rule.mitre.tactic",
            "data.srcip", "data.domain", "data.url", "data.user_agent",
        ],
    }
    raw = await _wazuh_indexer_post(body)
    if "error" in raw:
        return json.dumps(raw, indent=2)

    hits = raw.get("hits", {}).get("hits", [])
    docs = [_redact_alert_data(h.get("_source", h), bypass=params.bypass_redaction)
            for h in hits]

    if not docs:
        result = {"srcip": params.srcip, "total_alerts": 0,
                  "summary": "No alerts found for this IP in the time window."}
        return json.dumps(result, indent=2) if params.response_format == "json" else (
            f"# Alert Digest - {params.srcip}\n\n**No alerts found** in window "
            f"`{since_iso}` -> `{until_iso}`.")

    # IoC extraction
    rule_counts: Counter[str] = Counter()
    rule_descriptions: dict[str, str] = {}
    rule_timestamps: dict[str, list[str]] = {}
    domains: set[str] = set()
    urls: list[dict[str, str]] = []
    uas: Counter[str] = Counter()
    unusual_uas: list[str] = []
    mitre_tactics: set[str] = set()
    first_ts = docs[0].get("@timestamp", "")
    last_ts = docs[-1].get("@timestamp", "")

    for d in docs:
        rid = str(d.get("rule", {}).get("id", "unknown"))
        rule_counts[rid] = rule_counts.get(rid, 0) + 1
        if rid not in rule_descriptions:
            rule_descriptions[rid] = str(d.get("rule", {}).get("description", rid))
        rule_timestamps.setdefault(rid, []).append(str(d.get("@timestamp", "")))

        data = d.get("data", {})
        if isinstance(data, dict):
            dom = str(data.get("domain", "")).strip()
            if dom and dom != "-":
                domains.add(dom)
            url = str(data.get("url", "")).strip()
            if url and url != "-":
                urls.append({"url": url, "ts": str(d.get("@timestamp", ""))})
            ua = str(data.get("user_agent", "")).strip()
            if ua and ua != "-":
                uas[ua] += 1

        mitre = d.get("rule", {}).get("mitre", {})
        if isinstance(mitre, dict):
            tactics = mitre.get("tactic", [])
            if isinstance(tactics, list):
                mitre_tactics.update(tactics)

    # Flag unusual UA
    _UA_SIGNALS = [
        (re.compile(r"Firefox/(?:[1-6]\d|7[0-7])\."), "Old Firefox (pre-78)"),
        (re.compile(r"Chrome/(?:[1-5]\d|6[0-9])\."), "Old Chrome (pre-70)"),
        (re.compile(r"curl|wget|python|go-http|libwww|Java/"), "Scripted/automated client"),
        (re.compile(r"zgrab|masscan|nmap|nikto|sqlmap|ffuf|burp"), "Scanner/exploitation tool"),
    ]
    for ua, _ in uas.most_common(20):
        for pat, label in _UA_SIGNALS:
            if pat.search(ua):
                unusual_uas.append(f"{label}: `{ua[:120]}`")
                break

    # Build response
    if params.response_format == "json":
        result = {
            "srcip": params.srcip,
            "window": {"since": since_iso, "until": until_iso},
            "total_alerts": len(docs),
            "first_seen": first_ts,
            "last_seen": last_ts,
            "rules": [
                {
                    "id": rid,
                    "count": cnt,
                    "description": rule_descriptions.get(rid, ""),
                    "first_seen": rule_timestamps[rid][0],
                    "last_seen": rule_timestamps[rid][-1],
                }
                for rid, cnt in rule_counts.most_common()
            ],
            "iocs": {
                "domains": sorted(domains),
                "urls": urls[:50],
                "top_user_agents": [{"ua": ua, "count": n}
                                    for ua, n in uas.most_common(5)],
            },
            "mitre_tactics": sorted(mitre_tactics),
            "unusual_user_agents": unusual_uas,
        }
        return _truncate_if_needed(json.dumps(result, indent=2, ensure_ascii=False))

    # Markdown digest
    lines = [
        f"# Alert Digest - `{params.srcip}`",
        "",
        f"- **Window**: `{since_iso}` -> `{until_iso}`",
        f"- **Total alerts**: {len(docs)} | **First seen**: `{first_ts}` | **Last seen**: `{last_ts}`",
        "",
        "## Rules Triggered",
        "",
        "| Rule ID | Count | Description | First → Last |",
        "|---------|-------|-------------|--------------|",
    ]
    for rid, cnt in rule_counts.most_common():
        desc = _escape_md_table(rule_descriptions.get(rid, ""))[:80]
        fst = rule_timestamps[rid][0][:19] if rule_timestamps[rid] else "-"
        lst = rule_timestamps[rid][-1][:19] if rule_timestamps[rid] else "-"
        lines.append(f"| {rid} | {cnt} | {desc} | {fst} → {lst} |")

    if domains:
        lines.append("")
        lines.append("## Target Domains")
        for d in sorted(domains):
            lines.append(f"- `{d}`")

    if urls:
        lines.append("")
        lines.append(f"## URLs Accessed ({len(urls)} total, showing first 15)")
        for u in urls[:15]:
            ts_short = u["ts"][:19] if len(u["ts"]) > 19 else u["ts"]
            lines.append(f"- `[{ts_short}]` `{u['url'][:100]}`")
        if len(urls) > 15:
            lines.append(f"- ... and {len(urls) - 15} more")

    if mitre_tactics:
        lines.append("")
        lines.append("## MITRE ATT&CK Tactics")
        for t in sorted(mitre_tactics):
            cat = MITRE_TACTIC_TO_CATEGORY.get(t, "?")
            lines.append(f"- {t} (3-Sum Cat: `{cat}`)")

    if unusual_uas:
        lines.append("")
        lines.append("## ⚠️ Unusual User-Agents Flagged")
        for ua_flag in unusual_uas:
            lines.append(f"- {ua_flag}")

    if uas:
        lines.append("")
        lines.append("## Top User-Agents")
        for ua, n in uas.most_common(3):
            lines.append(f"- ({n}×) `{ua[:100]}`")

    return _truncate_if_needed("\n".join(lines))


# F-2: Beacon Detection
class BeaconDetectInput(BaseModel):
    """Input model for blueteam_beacon_detect."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    srcip: str = Field(
        ...,
        min_length=7,
        max_length=45,
        description="Source IP to analyze for C2 beaconing patterns.",
    )
    since: Optional[str] = Field(
        default="24h",
        max_length=30,
        description="Start of time window. ISO 8601 or relative.",
    )
    until: Optional[str] = Field(
        default=None,
        max_length=30,
        description="End of time window. Defaults to now.",
    )
    cv_threshold: float = Field(
        default=0.35,
        ge=0.0,
        le=1.0,
        description="Coefficient of variation threshold. CV < threshold → regular beaconing. "
                    "Lower = stricter (0.15 for tight beacons, 0.35 for relaxed).",
    )
    min_events: int = Field(
        default=5,
        ge=3,
        le=1000,
        description="Minimum events required to compute beacon score.",
    )
    response_format: Literal["markdown", "json"] = Field(
        default="markdown",
        description="Output format: 'markdown' or 'json'.",
    )


@mcp.tool(
    name="blueteam_beacon_detect",
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def blueteam_beacon_detect(params: BeaconDetectInput) -> str:
    """Detect C2 beaconing patterns via inter-arrival time analysis.
    Fetches ``@timestamp`` for all alerts from a given source IP, computes
    inter-arrival gaps, and calculates the coefficient of variation (CV =
    σ/μ). A low CV with consistent intervals is the statistical signature
    of periodic beaconing — a hallmark of C2 callbacks.

    Returns beacon score (0.0–1.0), estimated period, gap statistics,
    and a timeline summary.

    **Required Permissions**: Wazuh Indexer user with ``read`` access.

    **Worked Examples**

    1. *Default 24h scan*:
       ``blueteam_beacon_detect(srcip="103.107.116.202")``

    2. *7-day window, stricter threshold*:
       ``blueteam_beacon_detect(srcip="103.107.116.202", since="7d", cv_threshold=0.15)``

    3. *Short window for rapid beaconing*:
       ``blueteam_beacon_detect(srcip="103.107.116.202", since="1h", min_events=10)``
    """
    _audit_log("blueteam_beacon_detect", {"srcip": params.srcip})
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return json.dumps({
            "error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set.",
        }, indent=2)

    since_iso, until_iso = _parse_time_window(params.since, params.until)

    body = {
        "size": 2000,
        "sort": [{"@timestamp": {"order": "asc"}}],
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": since_iso, "lt": until_iso,
                                             "format": "strict_date_optional_time"}}},
                    {"bool": {
                        "should": [
                            {"match": {"data.srcip": params.srcip.strip()}},
                            {"match_phrase": {"full_log": params.srcip.strip()}},
                        ],
                        "minimum_should_match": 1,
                    }},
                ]
            }
        },
        "_source": ["@timestamp"],
    }
    raw = await _wazuh_indexer_post(body)
    if "error" in raw:
        return json.dumps(raw, indent=2)

    hits = raw.get("hits", {}).get("hits", [])
    if len(hits) < params.min_events:
        result = {
            "srcip": params.srcip,
            "beacon_score": 0.0,
            "verdict": "insufficient_data",
            "detail": f"Only {len(hits)} events — need at least {params.min_events}.",
        }
        return json.dumps(result, indent=2) if params.response_format == "json" else (
            f"# Beacon Detection — `{params.srcip}`\n\n"
            f"**Insufficient data**: {len(hits)} events (need ≥{params.min_events}). "
            f"Expand the time window and retry.")

    # Parse timestamps into epoch seconds
    timestamps: list[float] = []
    for h in hits:
        ts = h.get("_source", {}).get("@timestamp", "")
        try:
            dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            timestamps.append(dt.timestamp())
        except (ValueError, TypeError):
            continue

    if len(timestamps) < params.min_events:
        result = {
            "srcip": params.srcip,
            "beacon_score": 0.0,
            "verdict": "unparseable_timestamps",
            "detail": f"Only {len(timestamps)} parseable timestamps from {len(hits)} hits.",
        }
        return json.dumps(result, indent=2) if params.response_format == "json" else (
            f"# Beacon Detection - `{params.srcip}`\n\n"
            f"**Could not parse enough timestamps**: {len(timestamps)} valid from {len(hits)} total.")

    # Inter-arrival analysis
    gaps = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
    n = len(gaps)
    mean_gap = sum(gaps) / n
    variance = sum((g - mean_gap) ** 2 for g in gaps) / n
    stddev = math.sqrt(variance)
    cv = stddev / mean_gap if mean_gap > 0 else float("inf")

    # Beacon score: 1.0 = perfect periodicity, 0.0 = random
    # clamp CV to [0, 1] range via sigmoid-like decay
    beacon_score = max(0.0, min(1.0, 1.0 - (cv / 0.5)))

    # Estimate period - use median for robustness against outliers
    sorted_gaps = sorted(gaps)
    median_gap = sorted_gaps[n // 2] if n > 0 else 0.0
    period_secs = round(median_gap)

    # Detect multiple period candidates (e.g. 60s + 300s harmonics)
    gap_counter: Counter[int] = Counter()
    for g in gaps:
        gap_counter[int(round(g))] += 1
    top_periods = gap_counter.most_common(3)

    verdict = (
        "strong_beacon" if beacon_score >= 0.8 else
        "likely_beacon" if beacon_score >= 0.5 else
        "possible_beacon" if beacon_score >= 0.25 else
        "no_beacon"
    )

    if params.response_format == "json":
        result = {
            "srcip": params.srcip,
            "window": {"since": since_iso, "until": until_iso},
            "total_events": len(timestamps),
            "gaps": {
                "count": n,
                "mean_seconds": round(mean_gap, 1),
                "median_seconds": round(median_gap, 1),
                "stddev_seconds": round(stddev, 1),
                "cv": round(cv, 3),
            },
            "beacon_score": round(beacon_score, 3),
            "verdict": verdict,
            "estimated_period_seconds": period_secs,
            "top_periods": [{"seconds": p, "count": c} for p, c in top_periods],
            "timeline_preview": [
                {"ts": datetime.utcfromtimestamp(t).isoformat() + "Z",
                 "gap_from_prev_s": round(gaps[i - 1], 1) if i > 0 else None}
                for i, t in enumerate(timestamps[:20])
            ],
        }
        return _truncate_if_needed(json.dumps(result, indent=2, ensure_ascii=False))

    # Markdown report Format
    verdict_icon = {"strong_beacon": "🔴", "likely_beacon": "🟠",
                     "possible_beacon": "🟡", "no_beacon": "🟢"}
    lines = [
        f"# Beacon Detection — `{params.srcip}`",
        "",
        f"- **Verdict**: {verdict_icon.get(verdict, '')} **{verdict.replace('_', ' ').title()}**",
        f"- **Beacon Score**: `{beacon_score:.3f}` (0.0 = random, 1.0 = perfect periodicity)",
        f"- **Events**: {len(timestamps)} over {since_iso} → {until_iso}",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Mean gap | {mean_gap:.1f}s |",
        f"| Median gap | {median_gap:.1f}s |",
        f"| StdDev | {stddev:.1f}s |",
        f"| CV (σ/μ) | {cv:.3f} |",
        "",
    ]
    if period_secs > 0:
        period_display = (
            f"{period_secs}s" if period_secs < 120 else
            f"{period_secs / 60:.1f}m" if period_secs < 3600 else
            f"{period_secs / 3600:.1f}h"
        )
        lines.append(f"**Estimated period**: ~{period_display}")

    if top_periods:
        lines.append("")
        lines.append("## Top Period Candidates")
        for secs, cnt in top_periods:
            d = f"{secs}s" if secs < 120 else f"{secs / 60:.1f}m"
            lines.append(f"- {d} — {cnt} occurrences")

    lines.append("")
    lines.append("## Gap Distribution (first 20 events)")
    lines.append("```")
    for i, t in enumerate(timestamps[:20]):
        ts_str = datetime.utcfromtimestamp(t).isoformat()[:19] + "Z"
        gap_str = f"+{gaps[i - 1]:.0f}s" if i > 0 else "start"
        bar = "█" * min(40, int(gaps[i - 1] / max(1, mean_gap) * 10)) if i > 0 else ""
        lines.append(f"  {ts_str}  {gap_str:>8s}  {bar}")
    if len(timestamps) > 20:
        lines.append(f"  ... and {len(timestamps) - 20} more events")
    lines.append("```")

    return _truncate_if_needed("\n".join(lines))


# F-3: Attack Chain Analysis
class AttackChainInput(BaseModel):
    """Input model for blueteam_attack_chain."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    srcip: str = Field(
        ...,
        min_length=7,
        max_length=45,
        description="Source IP to analyze for attack progression chains.",
    )
    since: Optional[str] = Field(
        default="24h",
        max_length=30,
        description="Start of time window.",
    )
    until: Optional[str] = Field(
        default=None,
        max_length=30,
        description="End of time window.",
    )
    min_transitions: int = Field(
        default=2,
        ge=2,
        le=100,
        description="Minimum rule transitions to consider a chain.",
    )
    response_format: Literal["markdown", "json"] = Field(
        default="markdown",
        description="Output format: 'markdown' or 'json'.",
    )


@mcp.tool(
    name="blueteam_attack_chain",
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def blueteam_attack_chain(params: AttackChainInput) -> str:
    """Analyze rule-to-rule transitions to reconstruct attack kill-chain progression.

    Fetches all alerts for a source IP ordered by timestamp, builds a
    Markov transition graph of ``rule.id`` sequences, and matches observed
    transitions against known attack chains (recon -> bruteforce -> access -> C2/response).

    Returns matched chains with confidence scores, the full transition
    matrix, and a timeline of key transitions.

    **Required Permissions**: Wazuh Indexer user with ``read`` access.

    **Worked Examples**

    1. *Default 24h*:
       ``blueteam_attack_chain(srcip="103.107.116.202")``

    2. *7-day forensic window*:
       ``blueteam_attack_chain(srcip="103.107.116.202", since="7d")``

    3. *Require 3+ transitions*:
       ``blueteam_attack_chain(srcip="103.107.116.202", min_transitions=3)``
    """
    _audit_log("blueteam_attack_chain", {"srcip": params.srcip})
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return json.dumps({
            "error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set.",
        }, indent=2)

    since_iso, until_iso = _parse_time_window(params.since, params.until)

    body = {
        "size": 2000,
        "sort": [{"@timestamp": {"order": "asc"}}],
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": since_iso, "lt": until_iso,
                                             "format": "strict_date_optional_time"}}},
                    {"bool": {
                        "should": [
                            {"match": {"data.srcip": params.srcip.strip()}},
                            {"match_phrase": {"full_log": params.srcip.strip()}},
                        ],
                        "minimum_should_match": 1,
                    }},
                ]
            }
        },
        "_source": ["@timestamp", "rule.id", "rule.description", "rule.level", "rule.mitre.tactic"],
    }
    raw = await _wazuh_indexer_post(body)
    if "error" in raw:
        return json.dumps(raw, indent=2)

    hits = raw.get("hits", {}).get("hits", [])
    docs = [h.get("_source", h) for h in hits]

    if len(docs) < params.min_transitions:
        result = {
            "srcip": params.srcip,
            "total_events": len(docs),
            "verdict": "insufficient_data",
            "detail": f"Need at least {params.min_transitions} rule transitions.",
        }
        return json.dumps(result, indent=2) if params.response_format == "json" else (
            f"# Attack Chain — `{params.srcip}`\n\n"
            f"**Insufficient data**: {len(docs)} events (need ≥{params.min_transitions} transitions).")

    # Build rule sequence and transition matrix
    rule_seq: list[str] = []
    rule_info: dict[str, dict[str, str]] = {}
    for d in docs:
        rid = str(d.get("rule", {}).get("id", "unknown"))
        rule_seq.append(rid)
        if rid not in rule_info:
            rule_info[rid] = {
                "description": str(d.get("rule", {}).get("description", rid)),
                "level": str(d.get("rule", {}).get("level", "?")),
            }

    # Compress consecutive duplicates (Aul Adjusted : same rule firing repeatedly = persistence, not a transition)
    compressed: list[str] = [rule_seq[0]]
    for rid in rule_seq[1:]:
        if rid != compressed[-1]:
            compressed.append(rid)

    transitions: list[tuple[str, str]] = []
    for i in range(len(compressed) - 1):
        transitions.append((compressed[i], compressed[i + 1]))

    # Count transitions
    trans_counter: Counter[tuple[str, str]] = Counter(transitions)

    # Match against known attack chains
    chain_matches: list[dict[str, Any]] = []
    for chain in _KNOWN_ATTACK_CHAINS:
        chain_ids = [rid for rid, _ in transitions]
        # Check if the compressed sequence contains the ordered pattern
        # Use a subsequence match: each phase must appear in order, not necessarily consecutive
        pattern = chain["pattern"]
        seq_idx = 0
        matched_ids: list[str] = []
        for rid in compressed:
            if seq_idx < len(pattern) and pattern[seq_idx].search(rid):
                matched_ids.append(rid)
                seq_idx += 1
        if seq_idx >= 2:  # at least 2 phases matched
            # Compute observed phase-by-phase transition details
            phase_detail: list[dict[str, Any]] = []
            for j in range(len(matched_ids) - 1):
                phase_detail.append({
                    "from_phase": chain["phases"][j],
                    "to_phase": chain["phases"][j + 1],
                    "from_rule": matched_ids[j],
                    "to_rule": matched_ids[j + 1],
                })
            adjusted_conf = chain["confidence"] * min(1.0, seq_idx / len(pattern))
            chain_matches.append({
                "chain_id": chain["id"],
                "description": chain["description"],
                "confidence": round(adjusted_conf, 2),
                "phases_matched": seq_idx,
                "phases_total": len(pattern),
                "matched_rules": matched_ids[:8],
                "phase_transitions": phase_detail,
            })
    chain_matches.sort(key=lambda c: c["confidence"], reverse=True)

    if params.response_format == "json":
        result = {
            "srcip": params.srcip,
            "window": {"since": since_iso, "until": until_iso},
            "total_events": len(docs),
            "unique_rules": len(rule_info),
            "transitions_observed": len(transitions),
            "compressed_sequence": compressed[:50],
            "rule_info": rule_info,
            "top_transitions": [
                {"from": f, "to": t, "count": c}
                for (f, t), c in trans_counter.most_common(15)
            ],
            "chain_matches": chain_matches,
        }
        return _truncate_if_needed(json.dumps(result, indent=2, ensure_ascii=False))

    # Markdown report
    lines = [
        f"# Attack Chain — `{params.srcip}`",
        "",
        f"- **Window**: `{since_iso}` → `{until_iso}`",
        f"- **Events**: {len(docs)} → {len(compressed)} distinct rule transitions",
        f"- **Unique rules triggered**: {len(rule_info)}",
        "",
    ]

    if chain_matches:
        lines.append("## 🎯 Matched Kill-Chain Patterns")
        lines.append("")
        for cm in chain_matches[:5]:
            conf_bar = "█" * int(cm["confidence"] * 10) + "░" * (10 - int(cm["confidence"] * 10))
            lines.append(f"### {cm['chain_id']} (confidence: {cm['confidence']:.2f})")
            lines.append(f"`[{conf_bar}]`")
            lines.append(f"{cm['description']}")
            lines.append(f"- **Phases matched**: {cm['phases_matched']}/{cm['phases_total']}")
            # Draw ASCII chain
            arrow_parts: list[str] = []
            for pt in cm.get("phase_transitions", []):
                arrow_parts.append(
                    f"`{pt['from_phase']}`[{pt['from_rule']}] → "
                    f"`{pt['to_phase']}`[{pt['to_rule']}]"
                )
            lines.append(f"- **Path**: {' → '.join(arrow_parts) if arrow_parts else '(see matched_rules)'}")
            lines.append("")
    else:
        lines.append("## No known attack chain matched")
        lines.append("")

    # Compressed sequence visualization
    lines.append("## Rule Transition Sequence")
    lines.append("")
    lines.append("```")
    for i, rid in enumerate(compressed[:30]):
        info = rule_info.get(rid, {})
        desc = info.get("description", "?")[:70]
        lvl = info.get("level", "?")
        arrow = " → " if i < len(compressed[:30]) - 1 else ""
        lines.append(f"  [{lvl}] {rid} ({desc}){arrow}")
    if len(compressed) > 30:
        lines.append(f"  ... and {len(compressed) - 30} more transitions")
    lines.append("```")

    # Top transitions table
    if trans_counter:
        lines.append("")
        lines.append("## Top Rule Transitions")
        lines.append("")
        lines.append("| From | To | Count |")
        lines.append("|------|----|-------|")
        for (f, t), c in trans_counter.most_common(10):
            lines.append(f"| `{f}` | `{t}` | {c} |")

    return _truncate_if_needed("\n".join(lines))


# F-5: Threat Card Generation (AUL Adjusted)
class ThreatCardInput(BaseModel):
    """Input model for blueteam_threat_card."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    srcip: str = Field(
        ...,
        min_length=7,
        max_length=45,
        description="Source IP to generate a comprehensive threat card for.",
    )
    since: Optional[str] = Field(
        default="24h",
        max_length=30,
        description="Start of time window.",
    )
    until: Optional[str] = Field(
        default=None,
        max_length=30,
        description="End of time window. Defaults to now.",
    )
    include_threat_intel: bool = Field(
        default=True,
        description="Include CrowdSec and GreyNoise reputation lookups (may add ~2s latency).",
    )
    bypass_redaction: bool = Field(
        default=False,
        description=_BYPASS_REDACTION_DESC,
    )
    response_format: Literal["markdown", "json"] = Field(
        default="markdown",
        description="'markdown' (default, human-readable) or 'json'.",
    )


@mcp.tool(
    name="blueteam_threat_card",
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def blueteam_threat_card(params: ThreatCardInput) -> str:
    """Generate a comprehensive threat card for a source IP.
    Collapses alert summarization, attack chain analysis, MITRE ATT&CK
    mapping, and threat intelligence (CrowdSec + GreyNoise) into a single
    structured report. Designed as the one-stop triage tool — the LLM can
    understand the full threat context in one call.

    **Required Permissions**: Wazuh Indexer ``read`` access.
    CrowdSec/GreyNoise lookups are best-effort (fail gracefully if keys
    are not configured).

    **Worked Examples**

    1. *Default 24h card*:
       ``blueteam_threat_card(srcip="103.107.116.202")``

    2. *7-day forensic card*:
       ``blueteam_threat_card(srcip="103.107.116.202", since="7d")``

    3. *Skip threat intel for speed*:
       ``blueteam_threat_card(srcip="103.107.116.202", include_threat_intel=false)``
    """
    _audit_log("blueteam_threat_card", {"srcip": params.srcip})
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return json.dumps({
            "error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set.",
        }, indent=2)

    since_iso, until_iso = _parse_time_window(params.since, params.until)

    # Fetch alerts for this IP
    body = {
        "size": 500,
        "sort": [{"@timestamp": {"order": "asc"}}],
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": since_iso, "lt": until_iso,
                                             "format": "strict_date_optional_time"}}},
                    {"bool": {
                        "should": [
                            {"match": {"data.srcip": params.srcip.strip()}},
                            {"match_phrase": {"full_log": params.srcip.strip()}},
                        ],
                        "minimum_should_match": 1,
                    }},
                ]
            }
        },
        "_source": [
            "@timestamp", "agent.name", "rule.id", "rule.level",
            "rule.description", "rule.groups", "rule.mitre.tactic",
            "data.srcip", "data.domain", "data.url", "data.user_agent",
        ],
    }

    # Fetch alerts + threat intel concurrently
    async def _fetch_alerts():
        raw = await _wazuh_indexer_post(body)
        if "error" in raw:
            return raw
        return [h.get("_source", h) for h in raw.get("hits", {}).get("hits", [])]

    async def _fetch_crowdsec():
        if not params.include_threat_intel or not os.environ.get(CROWDSEC_API_KEY_ENV):
            return None
        try:
            return await _crowdsec_request(f"/v2/smoke/{params.srcip}")
        except Exception:
            return None

    async def _fetch_greynoise():
        if not params.include_threat_intel:
            return None
        try:
            return await _greynoise_community_request(params.srcip)
        except Exception:
            return None

    docs, crowdsec_data, greynoise_data = await asyncio.gather(
        _fetch_alerts(), _fetch_crowdsec(), _fetch_greynoise(),
    )

    if isinstance(docs, dict) and "error" in docs:
        return json.dumps(docs, indent=2)

    docs = _redact_alert_data(docs, bypass=params.bypass_redaction)

    # Extract common data
    rule_counts: Counter[str] = Counter()
    rule_descs: dict[str, str] = {}
    mitre_tactics: set[str] = set()
    domains: set[str] = set()
    urls: list[str] = []
    levels: list[int] = []
    agents: set[str] = set()
    first_ts = str(docs[0].get("@timestamp", ""))[:19]
    last_ts = str(docs[-1].get("@timestamp", ""))[:19]

    for d in docs:
        r = d.get("rule", {})
        rid = str(r.get("id", "unknown"))
        rule_counts[rid] += 1
        if rid not in rule_descs:
            rule_descs[rid] = str(r.get("description", rid))
        lvl = r.get("level")
        if isinstance(lvl, (int, str)):
            try: levels.append(int(lvl))
            except (ValueError, TypeError): pass
        mitre = r.get("mitre", {})
        if isinstance(mitre, dict):
            tactics = mitre.get("tactic", [])
            if isinstance(tactics, list): mitre_tactics.update(tactics)
        data = d.get("data", {})
        if isinstance(data, dict):
            dom = str(data.get("domain", "")).strip()
            if dom and dom != "-": domains.add(dom)
            url = str(data.get("url", "")).strip()
            if url and url != "-": urls.append(url)
        ag = d.get("agent", {})
        if isinstance(ag, dict) and ag.get("name"): agents.add(str(ag["name"]))

    max_level = max(levels) if levels else 0
    avg_level = sum(levels) / len(levels) if levels else 0.0

    # Format output
    if params.response_format == "json":
        return _truncate_if_needed(json.dumps({
            "srcip": params.srcip,
            "window": {"since": since_iso, "until": until_iso},
            "total_events": len(docs),
            "first_seen": first_ts,
            "last_seen": last_ts,
            "max_level": max_level,
            "avg_level": round(avg_level, 1),
            "rules": [{"id": rid, "count": cnt, "description": rule_descs.get(rid, "")}
                      for rid, cnt in rule_counts.most_common(10)],
            "targeted_domains": sorted(domains),
            "urls_probed": list(set(urls))[:50],
            "mitre_tactics": sorted(mitre_tactics),
            "agents": sorted(agents),
            "threat_intel": {"crowdsec": crowdsec_data, "greynoise": greynoise_data},
        }, indent=2, ensure_ascii=False))

    # Markdown threat card
    lines = [
        f"# 🛡️ Threat Card — `{params.srcip}`",
        "",
        f"**Window**: `{since_iso}` → `{until_iso}` | **Total events**: {len(docs)}",
        "",
        "---",
        "",
    ]

    if not docs:
        lines.append("## No alerts found")
        lines.append(f"No Wazuh alerts for `{params.srcip}` in this time window.")
        return "\n".join(lines)

    # Section 1: Executive Summary
    lines.append("## 📊 Executive Summary")
    lines.append("")
    lines.append(f"| Field | Value |")
    lines.append(f"|-------|-------|")
    lines.append(f"| Total alerts | {len(docs)} |")
    lines.append(f"| Unique rules | {len(rule_counts)} |")
    lines.append(f"| Max rule level | {max_level} |")
    lines.append(f"| Avg rule level | {avg_level:.1f} |")
    lines.append(f"| Agents targeted | {len(agents)} ({', '.join(sorted(agents)[:3])}{"..." if len(agents) > 3 else ""}) |")
    lines.append(f"| First seen | `{first_ts}` |")
    lines.append(f"| Last seen | `{last_ts}` |")
    lines.append("")

    # Section 2: MITRE ATT&CK
    if mitre_tactics:
        lines.append("## 🎯 MITRE ATT&CK Tactics")
        lines.append("")
        lines.append("| Tactic | 3-Sum Category |")
        lines.append("|--------|---------------|")
        for t in sorted(mitre_tactics):
            cat = MITRE_TACTIC_TO_CATEGORY.get(t, "?")
            lines.append(f"| {t} | `{cat}` |")
        lines.append("")

    # Section 3: Rules Fired
    lines.append("## 🔥 Rules Triggered")
    lines.append("")
    lines.append("| Rule ID | Count | Description |")
    lines.append("|---------|-------|-------------|")
    for rid, cnt in rule_counts.most_common(10):
        desc = _escape_md_table(rule_descs.get(rid, ""))[:80]
        lines.append(f"| {rid} | {cnt} | {desc} |")
    lines.append("")

    # Section 4: Targeted Resources
    if domains:
        lines.append("## 🌐 Targeted Domains")
        for d in sorted(domains):
            lines.append(f"- `{d}`")
        lines.append("")
    if urls:
        lines.append(f"## 🔗 URLs Probed ({len(urls)} unique)")
        for u in sorted(set(urls))[:10]:
            lines.append(f"- `{u[:120]}`")
        if len(set(urls)) > 10:
            lines.append(f"- ... and {len(set(urls)) - 10} more")
        lines.append("")

    # Section 5: Threat Intelligence
    if crowdsec_data or greynoise_data:
        lines.append("## 🌍 External Threat Intelligence")
        lines.append("")
    if crowdsec_data:
        rep = crowdsec_data.get("reputation", "unknown")
        behaviors = [b.get("name", "") for b in crowdsec_data.get("behaviors", [])]
        lines.append(f"- **CrowdSec**: reputation `{rep}`")
        if behaviors:
            lines.append(f"  - Behaviors: {', '.join(behaviors[:5])}")
        cves = crowdsec_data.get("cves", [])
        if cves:
            lines.append(f"  - Related CVEs: {', '.join(cves[:5])}")
    if greynoise_data:
        noise = greynoise_data.get("noise")
        riot = greynoise_data.get("riot")
        classification = greynoise_data.get("classification", "unknown")
        lines.append(f"- **GreyNoise**: classification `{classification}`")
        if noise:
            lines.append(f"  - Internet scanner: ✅ (background noise)")
        if riot:
            lines.append(f"  - Known business service: ✅ (likely benign)")
    if crowdsec_data or greynoise_data:
        lines.append("")

    # Section 6: Recommended Actions
    lines.append("## 🛠️ Recommended Actions")
    lines.append("")

    # Heuristic recommendations based on alert patterns
    if max_level >= 12:
        lines.append("1. **🚨 IMMEDIATE**: Critical-severity alerts detected — initiate incident response")
        lines.append(f"2. Block `{params.srcip}` at perimeter firewall immediately")
    elif max_level >= 10:
        lines.append(f"1. **⚠️ HIGH**: Block `{params.srcip}` at perimeter firewall")
        lines.append("2. Review affected agent logs for signs of compromise")
    elif max_level >= 6:
        lines.append(f"1. **📋 MEDIUM**: Monitor `{params.srcip}` and add to watchlist")
        lines.append("2. Review web/app logs for suspicious request patterns")
    else:
        lines.append(f"1. **ℹ️ LOW**: `{params.srcip}` shows low-severity activity")
        lines.append("2. No immediate action required — continue monitoring")

    if crowdsec_data and crowdsec_data.get("reputation") == "malicious":
        lines.append("3. CrowdSec confirms malicious — escalate block priority")
    if len(agents) > 1:
        lines.append(f"4. IP targeted {len(agents)} agents — check for lateral movement")
    if len(mitre_tactics) >= 3:
        lines.append("5. Multiple MITRE tactics observed — full compromise assessment recommended")

    lines.append("")
    lines.append("---")
    lines.append(f"*Card generated by blue_team_mcp at {datetime.utcnow().isoformat()[:19]}Z*")

    return _truncate_if_needed("\n".join(lines))


# F-6: Alert Comparison
class AlertCompareInput(BaseModel):
    """Input model for blueteam_wazuh_alert_compare."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    srcip_a: str = Field(
        ...,
        min_length=7,
        max_length=45,
        description="First source IP to compare.",
    )
    srcip_b: str = Field(
        ...,
        min_length=7,
        max_length=45,
        description="Second source IP to compare.",
    )
    since: Optional[str] = Field(
        default="24h",
        max_length=30,
        description="Start of time window.",
    )
    until: Optional[str] = Field(
        default=None,
        max_length=30,
        description="End of time window. Defaults to now.",
    )
    response_format: Literal["markdown", "json"] = Field(
        default="markdown",
        description="Output format: 'markdown' (side-by-side) or 'json'.",
    )


@mcp.tool(
    name="blueteam_wazuh_alert_compare",
    annotations={
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def blueteam_wazuh_alert_compare(params: AlertCompareInput) -> str:
    """Compare alert profiles of two source IPs side-by-side.

    Fetches alert counts, top rules, max severity, MITRE tactics, and
    beacon scores for both IPs and returns a structured comparison with
    a verdict on which IP is more suspicious.

    Saves the LLM from orchestrating 4+ sequential calls to analyze two
    IPs independently.

    **Required Permissions**: Wazuh Indexer ``read`` access.

    **Worked Examples**

    1. *Compare two suspicious IPs*:
       ``blueteam_wazuh_alert_compare(srcip_a="103.107.116.202", srcip_b="185.220.101.1")``

    2. *7-day comparison*:
       ``blueteam_wazuh_alert_compare(srcip_a="10.0.0.5", srcip_b="10.0.0.99", since="7d")``
    """
    _audit_log("blueteam_wazuh_alert_compare",
               {"srcip_a": params.srcip_a, "srcip_b": params.srcip_b})
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return json.dumps({
            "error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set.",
        }, indent=2)

    since_iso, until_iso = _parse_time_window(params.since, params.until)

    async def _profile_ip(ip: str) -> dict[str, Any]:
        body = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": since_iso, "lt": until_iso,
                                                 "format": "strict_date_optional_time"}}},
                        {"bool": {
                            "should": [
                                {"match": {"data.srcip": ip.strip()}},
                                {"match_phrase": {"full_log": ip.strip()}},
                            ],
                            "minimum_should_match": 1,
                        }},
                    ]
                }
            },
            "aggs": {
                "top_rules": {"terms": {"field": "rule.id.keyword", "size": 5}},
                "by_level": {
                    "range": {
                        "field": "rule.level",
                        "ranges": [
                            {"key": "low", "to": 5},
                            {"key": "medium", "from": 5, "to": 10},
                            {"key": "high", "from": 10},
                        ],
                    }
                },
                "top_agents": {"terms": {"field": "agent.name.keyword", "size": 5}},
            },
        }
        raw = await _wazuh_indexer_post(body)
        if "error" in raw:
            return {"srcip": ip, "error": raw["error"]}
        total = raw.get("hits", {}).get("total", {})
        total_val = total.get("value", 0) if isinstance(total, dict) else total
        aggs = raw.get("aggregations", {})
        return {
            "srcip": ip,
            "total_alerts": total_val,
            "top_rules": [
                {"id": b["key"], "count": b["doc_count"]}
                for b in aggs.get("top_rules", {}).get("buckets", [])
            ],
            "severity": {
                b["key"]: b["doc_count"]
                for b in aggs.get("by_level", {}).get("buckets", [])
            },
            "agents": [
                {"name": b["key"], "count": b["doc_count"]}
                for b in aggs.get("top_agents", {}).get("buckets", [])
            ],
        }

    profile_a, profile_b = await asyncio.gather(
        _profile_ip(params.srcip_a), _profile_ip(params.srcip_b),
    )

    if params.response_format == "json":
        result = {
            "window": {"since": since_iso, "until": until_iso},
            "ip_a": profile_a,
            "ip_b": profile_b,
        }
        # Determine which is more suspicious
        a_score = profile_a.get("total_alerts", 0)
        b_score = profile_b.get("total_alerts", 0)
        if a_score > b_score * 2:
            result["verdict"] = f"{params.srcip_a} is significantly more active"
        elif b_score > a_score * 2:
            result["verdict"] = f"{params.srcip_b} is significantly more active"
        else:
            result["verdict"] = "Both IPs show comparable activity levels"
        return _truncate_if_needed(json.dumps(result, indent=2, ensure_ascii=False))

    # Markdown side-by-side
    a_total = profile_a.get("total_alerts", 0)
    b_total = profile_b.get("total_alerts", 0)
    a_rules = ", ".join(f"`{r['id']}`({r['count']})"
                         for r in profile_a.get("top_rules", [])[:3]) or "-"
    b_rules = ", ".join(f"`{r['id']}`({r['count']})"
                         for r in profile_b.get("top_rules", [])[:3]) or "-"
    a_sev = profile_a.get("severity", {})
    b_sev = profile_b.get("severity", {})
    a_high = a_sev.get("high", 0)
    b_high = b_sev.get("high", 0)
    a_agents = len(profile_a.get("agents", []))
    b_agents = len(profile_b.get("agents", []))

    # Verdict
    if a_total > b_total * 2 and a_high > b_high:
        verdict = f"🔴**{params.srcip_a}** is significantly more threatening"
    elif b_total > a_total * 2 and b_high > a_high:
        verdict = f"🔴**{params.srcip_b}** is significantly more threatening"
    elif a_total > b_total:
        verdict = f"🟡**{params.srcip_a}** has more activity - investigate first"
    elif b_total > a_total:
        verdict = f"🟡**{params.srcip_b}** has more activity - investigate first"
    else:
        verdict = "🟢Both IPs show comparable activity"

    lines = [
        f"# Alert Comparison",
        "",
        f"**Window**: `{since_iso}` → `{until_iso}`",
        "",
        f"| Metric | `{params.srcip_a}` | `{params.srcip_b}` |",
        f"|--------|{'-' * (len(params.srcip_a) + 4)}|{'-' * (len(params.srcip_b) + 4)}|",
        f"| Total alerts | **{a_total}** | **{b_total}** |",
        f"| High severity (L10+) | {a_high} | {b_high} |",
        f"| Medium severity (L5-9) | {a_sev.get('medium', 0)} | {b_sev.get('medium', 0)} |",
        f"| Low severity (L1-4) | {a_sev.get('low', 0)} | {b_sev.get('low', 0)} |",
        f"| Agents targeted | {a_agents} | {b_agents} |",
        f"| Top rules | {a_rules} | {b_rules} |",
        "",
        f"### Verdict",
        f"{verdict}",
    ]

    return _truncate_if_needed("\n".join(lines))


# Sprint 6: Geo-Aware Curated Threat Intelligence Pipeline (AUL Adjust)
# Composable filter specification - any combination of dimensions can be AND'd.
# Cross-source deduplication patterns (parent-child alert relationships).
# Each entry: (child_rule_id_regex, parent_rule_field_path_in_nested_alert)
# When deduplicate=True, child alerts matching these patterns are subtracted
# from aggregate counts to prevent double-counting.
_DEDUP_PATTERNS: list[tuple[str, str]] = [
    ("606029", "data.parameters.alert.rule.id"),  # Active Response wraps its trigger
    ("651",   "data.parameters.alert.rule.id"),   # Ossec agent-spawned alerts
]

# Maps directly to OpenSearch bool.must/filter clauses inside _build_curated_query().
class CuratedReportFilters(BaseModel):
    """Filter specification for blueteam_curated_threat_report. Every field is
    optional — only specified filters are applied. All filters are AND'd together.
    """
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    # Geo dimension
    geo_country: Optional[str] = Field(
        default=None, max_length=60,
        description="Exact match on GeoLocation.country_name, e.g. 'Indonesia'.")
    geo_country_pattern: Optional[str] = Field(
        default=None, max_length=60,
        description="Wildcard match, e.g. 'Indo*'.")

    # Domain dimension
    domain: Optional[str] = Field(
        default=None, max_length=253,
        description="Exact match on data.domain, e.g. 'bangjaka.tangerangkota.go.id'.")
    domain_pattern: Optional[str] = Field(
        default=None, max_length=253,
        description="Wildcard on data.domain, e.g. '*.tangerangkota.go.id'.")
    domain_contains: Optional[str] = Field(
        default=None, max_length=253,
        description="Substring match on data.domain, e.g. 'tangerangkota'.")

    # Rule dimension
    rule_ids: Optional[list[str]] = Field(default=None, max_length=30,
        description="Specific rule IDs, e.g. ['600029','606029'].")
    rule_level_min: Optional[int] = Field(default=None, ge=1, le=16,
        description="Minimum rule.level (severity floor).")
    rule_level_max: Optional[int] = Field(default=None, ge=1, le=16,
        description="Maximum rule.level (severity ceiling).")
    rule_groups: Optional[list[str]] = Field(default=None,
        description="Wazuh rule.groups tokens, e.g. ['recon','firewall_drop'].")
    mitre_tactics: Optional[list[str]] = Field(default=None,
        description="MITRE ATT&CK tactics, e.g. ['Discovery','Collection'].")
    mitre_techniques: Optional[list[str]] = Field(default=None,
        description="MITRE technique IDs, e.g. ['T1083','T1552'].")

    # Agent dimension
    agent_name: Optional[str] = Field(default=None, max_length=64,
        description="Target agent name, e.g. 'thezoo-prod'.")
    agent_ip: Optional[str] = Field(default=None, max_length=45,
        description="Target agent internal IP, e.g. '172.16.10.135'.")
    agent_id: Optional[str] = Field(default=None, max_length=32,
        description="Target agent ID, e.g. '227'.")
    decoder: Optional[str] = Field(default=None, max_length=64,
        description="Decoder name, e.g. 'web-accesslog', 'ar_log_json', 'sysmon'.")

    # HTTP dimension
    url_pattern: Optional[str] = Field(default=None, max_length=1024,
        description="Wildcard on data.url, e.g. '/.vscode/*'.")
    response_codes: Optional[list[str]] = Field(default=None,
        description="HTTP response codes, e.g. ['403','404'].")
    http_methods: Optional[list[str]] = Field(default=None,
        description="HTTP methods, e.g. ['POST','PUT'].")
    user_agent_contains: Optional[str] = Field(default=None, max_length=512,
        description="Substring in data.user_agent, e.g. 'Firefox'.")
    referrer_pattern: Optional[str] = Field(default=None, max_length=1024,
        description="Wildcard on data.referrer, e.g. '*tangerangkota*'.")
    response_size_min: Optional[int] = Field(default=None, ge=0,
        description="Minimum data.response_size in bytes (exfil indicator).")
    response_size_max: Optional[int] = Field(default=None, ge=0,
        description="Maximum data.response_size in bytes.")

    # Rule description dimension
    rule_desc_contains: Optional[str] = Field(default=None, max_length=512,
        description="Substring in rule.description, e.g. 'sensitive files'.")
    rule_firedtimes_min: Optional[int] = Field(default=None, ge=1,
        description="Minimum rule.firedtimes (persistence signal — rule triggered at least N times).")
    log_source_pattern: Optional[str] = Field(default=None, max_length=512,
        description="Wildcard on location field, e.g. '/containers/*/logs/*' to filter by log source path.")

    # Geo bounding box
    geo_bbox: Optional[str] = Field(default=None, max_length=80,
        description="Geo bounding box: 'lat1,lon1,lat2,lon2' (bottom-left, top-right). "
                    "Filters GeoLocation.location within box, e.g. '-7.0,106.5,-5.5,107.0' "
                    "for Jabodetabek area. Only alerts with GeoIP data are matched.")

    # IP dimension
    srcips: Optional[list[str]] = Field(default=None, max_length=25,
        description="Specific IPs to INCLUDE (max 25).")
    exclude_srcips: Optional[list[str]] = Field(default=None, max_length=25,
        description="IPs to EXCLUDE, e.g. known scanners.")

    # Threat intel pre-filter
    min_crowdsec_reputation: Optional[str] = Field(default=None,
        description="Pre-filter: only IPs with this CrowdSec reputation "
                    "('malicious','suspicious','safe','unknown'). "
                    "Requires CROWDSEC_API_KEY and adds per-IP API calls.")


def _build_curated_query(
    since_iso: str, until_iso: str, f: CuratedReportFilters,
) -> list[dict]:
    """Translate CuratedReportFilters into OpenSearch bool.must clauses.

    Each non-None filter field becomes an AND clause. Returns a list of
    OpenSearch query/filter dicts ready for a bool.must array.
    """
    clauses: list[dict] = [
        {"range": {"@timestamp": {"gte": since_iso, "lt": until_iso,
                                   "format": "strict_date_optional_time"}}},
    ]
    # Geo
    if f.geo_country:
        clauses.append({"term": {"GeoLocation.country_name": f.geo_country.strip()}})
    if f.geo_country_pattern:
        clauses.append({"wildcard": {"GeoLocation.country_name": f.geo_country_pattern.strip()}})

    # Domain
    if f.domain:
        clauses.append({"match": {"data.domain": f.domain.strip()}})
    if f.domain_pattern:
        clauses.append({"wildcard": {"data.domain.keyword": f.domain_pattern.strip()}})
    if f.domain_contains:
        clauses.append({"wildcard": {"data.domain.keyword": f"*{f.domain_contains.strip()}*"}})

    # Rule
    if f.rule_ids:
        clauses.append({"terms": {"rule.id.keyword": [r.strip() for r in f.rule_ids]}})
    if f.rule_level_min is not None:
        clauses.append({"bool": {"should": [
            {"range": {"rule.level": {"gte": f.rule_level_min}}},
        ], "minimum_should_match": 1}})
    if f.rule_level_max is not None:
        clauses.append({"bool": {"should": [
            {"range": {"rule.level": {"lte": f.rule_level_max}}},
        ], "minimum_should_match": 1}})
    if f.rule_groups:
        clauses.append({"bool": {"should": [
            {"terms": {"rule.groups": f.rule_groups}},
            {"terms": {"rule.groups.keyword": f.rule_groups}},
        ], "minimum_should_match": 1}})
    if f.mitre_tactics:
        clauses.append({"terms": {"rule.mitre.tactic": f.mitre_tactics}})
    if f.mitre_techniques:
        clauses.append({"terms": {"rule.mitre.id": f.mitre_techniques}})

    # Agent
    if f.agent_name:
        clauses.append({"match": {"agent.name": f.agent_name.strip()}})
    if f.agent_ip:
        clauses.append({"match": {"agent.ip": f.agent_ip.strip()}})
    if f.agent_id:
        clauses.append({"match": {"agent.id": f.agent_id.strip()}})
    if f.decoder:
        clauses.append({"term": {"decoder.name": f.decoder.strip()}})

    # HTTP
    if f.url_pattern:
        clauses.append({"wildcard": {"data.url.keyword": f.url_pattern.strip()}})
    if f.response_codes:
        clauses.append({"terms": {"data.response_code": f.response_codes}})
    if f.http_methods:
        clauses.append({"terms": {"data.method": f.http_methods}})
    if f.user_agent_contains:
        clauses.append({"wildcard": {"data.user_agent.keyword":
                                     f"*{f.user_agent_contains.strip()}*"}})
    if f.referrer_pattern:
        clauses.append({"wildcard": {"data.referrer.keyword": f.referrer_pattern.strip()}})
    if f.response_size_min is not None:
        clauses.append({"range": {"data.response_size": {"gte": f.response_size_min}}})
    if f.response_size_max is not None:
        clauses.append({"range": {"data.response_size": {"lte": f.response_size_max}}})

    # Rule description free-text
    if f.rule_desc_contains:
        clauses.append({"wildcard": {"rule.description.keyword":
                                     f"*{f.rule_desc_contains.strip()}*"}})
    if f.rule_firedtimes_min is not None:
        clauses.append({"range": {"rule.firedtimes": {"gte": f.rule_firedtimes_min}}})
    if f.log_source_pattern:
        clauses.append({"wildcard": {"location.keyword": f.log_source_pattern.strip()}})

    # Geo bounding box
    if f.geo_bbox:
        parts = [p.strip() for p in f.geo_bbox.split(",")]
        if len(parts) == 4:
            try:
                lat1, lon1, lat2, lon2 = float(parts[0]), float(parts[1]), float(parts[2]), float(parts[3])
                clauses.append({"bool": {"must": [
                    {"range": {"GeoLocation.location.lat": {"gte": min(lat1, lat2), "lte": max(lat1, lat2)}}},
                    {"range": {"GeoLocation.location.lon": {"gte": min(lon1, lon2), "lte": max(lon1, lon2)}}},
                ]}})
            except ValueError:
                pass  # invalid bbox -> skip filter silently

    # IP inclusion/exclusion
    if f.srcips:
        ip_clauses = []
        for ip in f.srcips:
            ip = ip.strip()
            if ip:
                ip_clauses.append({"bool": {"should": [
                    {"match": {"data.srcip": ip}},
                    {"match_phrase": {"full_log": ip}},
                ], "minimum_should_match": 1}})
        clauses.extend(ip_clauses)
    if f.exclude_srcips:
        for ip in f.exclude_srcips:
            ip = ip.strip()
            if ip:
                clauses.append({"bool": {"must_not": {"match": {"data.srcip": ip}}}})

    return clauses


# G-2: Geo Distribution
class CuratedThreatReportInput(BaseModel):
    """Input model for blueteam_curated_threat_report."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    since: Optional[str] = Field(default="24h", max_length=30)
    until: Optional[str] = Field(default=None, max_length=30)
    filters: CuratedReportFilters = Field(default_factory=CuratedReportFilters)
    include_threat_intel: bool = Field(default=True)
    max_entities: int = Field(default=50, ge=10, le=100)
    group_by: Literal["srcip", "domain", "rule.id", "agent"] = Field(default="srcip")
    response_format: Literal["markdown", "json"] = Field(default="markdown")
    bypass_redaction: bool = Field(default=False, description=_BYPASS_REDACTION_DESC)
    compare_since: Optional[str] = Field(default=None, max_length=30)
    investigation_depth: Literal["summary", "enriched", "deep"] = Field(default="enriched")
    deduplicate: bool = Field(default=False)
    time_decay: Literal["none", "linear", "exponential"] = Field(default="none")
    scoring_mode: Literal["volume", "diversity"] = Field(default="volume")


@mcp.tool(
    name="blueteam_curated_threat_report",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": True},
)
async def blueteam_curated_threat_report(params: CuratedThreatReportInput) -> str:
    """Generate a geo/domain/rule-filtered threat intelligence report in one call.

    Combines alert aggregation, IP extraction, and multi-source threat intel
    enrichment into a single structured report. Replace 8–12 sequential LLM
    tool calls with one.

    **Filter dimensions** (any combination, all AND'd):
      • geo_country / geo_country_pattern — GeoLocation.country_name
      • geo_bbox - bounding box "lat1,lon1,lat2,lon2" for area filtering
      • domain / domain_pattern / domain_contains — data.domain
      • rule_ids / rule_level_min / rule_level_max / rule_groups / rule_desc_contains — rule filtering
      • mitre_tactics / mitre_techniques — ATT&CK filtering
      • agent_name / agent_ip / agent_id — target agent
      • decoder - log decoder name (web-accesslog, sysmon, etc.)
      • url_pattern / referrer_pattern / response_codes / response_size_min / response_size_max / http_methods / user_agent_contains - HTTP layer
      • rule_firedtimes_min - persistence signal
      • log_source_pattern - wildcard on location field
      • srcips (include) / exclude_srcips — IP-level
      • min_crowdsec_reputation — pre-filter by threat intel

    **Threat Intel** (best-effort, concurrent):
      Argus (7 upstream sources) + CrowdSec CTI (behaviors, MITRE, CVE) +
      AbuseIPDB (abuse score, reports) + VirusTotal (engine verdicts) +
      GreyNoise Community (scanner/business classification).

    **Required Permissions**: Wazuh Indexer read access. CROWDSEC_API_KEY for
    CrowdSec enrichment. ARGUS_API_KEY for Argus enrichment.

    **Worked Example**

    1. *Indonesian attackers targeting .go.id domains*:
       ``blueteam_curated_threat_report(filters={"geo_country": "Indonesia", "domain_pattern": "*.go.id"})``

    2. *Critical-severity recon against thezoo-prod*:
       ``blueteam_curated_threat_report(filters={"rule_level_min": 10, "agent_name": "thezoo-prod", "rule_groups": ["recon"]})``

    3. *Visual Studio Code probing from Indonesia*:
       ``blueteam_curated_threat_report(filters={"geo_country": "Indonesia", "url_pattern": "/.vscode/*"})``

    4. *T1083 technique, 7-day window*:
       ``blueteam_curated_threat_report(since="7d", filters={"mitre_techniques": ["T1083"]})``

    5. *Exclude known scanner*:
       ``blueteam_curated_threat_report(filters={"exclude_srcips": ["203.0.113.42"]})``
    """
    _audit_log("blueteam_curated_threat_report", {"filters": str(params.filters)[:200]})
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return json.dumps({"error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set."}, indent=2)

    since_iso, until_iso = _parse_time_window(params.since, params.until)
    f = params.filters

    # Phase 1: Aggregation query (size: 0, no documents fetched)
    clauses = _build_curated_query(since_iso, until_iso, f)

    # Time-decay weighting via function_score gauss decay on @timestamp
    query_wrapper: dict = {"bool": {"must": clauses}}
    if params.time_decay != "none":
        half_life = max(60, _duration_minutes(since_iso, until_iso) * 15)  # seconds
        decay_config = {"@timestamp": {"origin": until_iso, "scale": f"{half_life:.0f}s",
                                        "decay": 0.5}}
        query_wrapper = {
            "function_score": {
                "query": {"bool": {"must": clauses}},
                "functions": [{"gauss": decay_config}],
                "boost_mode": "replace",
            }
        }

    # Select primary aggregation axis based on group_by
    group_config: dict[str, tuple[str, str]] = {
        "srcip": ("data.srcip.keyword", "top_entities"),
        "domain": ("data.domain.keyword", "top_entities"),
        "rule.id": ("rule.id.keyword", "top_entities"),
        "agent": ("agent.name.keyword", "top_entities"),
    }
    agg_field, agg_name = group_config.get(params.group_by, group_config["srcip"])

    body = {
        "size": 0,
        "query": query_wrapper,
        "aggs": {
            agg_name: {
                "terms": {"field": agg_field, "size": params.max_entities,
                          "order": {"_count": "desc"}},
                "aggs": {
                    "first_seen": {"min": {"field": "@timestamp"}},
                    "last_seen": {"max": {"field": "@timestamp"}},
                    "max_level": {"max": {"field": "rule.level"}},
                    "top_rules": {"terms": {"field": "rule.id.keyword", "size": 5}},
                    "top_urls": {"terms": {"field": "data.url.keyword", "size": 5}},
                    "sample_geo": {"top_hits": {"size": 1, "_source": {"includes": ["GeoLocation"]}}},
                },
            },
            "total_alerts": {"value_count": {"field": "_id"}},
            "total_with_geo": {"value_count": {"field": "GeoLocation.country_name"}},
            "top_rules": {"terms": {"field": "rule.id.keyword", "size": 10}},
            "top_agents": {"terms": {"field": "agent.name.keyword", "size": 10}},
            "top_domains": {"terms": {"field": "data.domain.keyword", "size": 10}},
            "severity_bands": {
                "range": {"field": "rule.level",
                          "ranges": [{"key": "low", "to": 5},
                                     {"key": "medium", "from": 5, "to": 10},
                                     {"key": "high", "from": 10}]},
            },
        },
    }
    raw = await _wazuh_indexer_post(body)
    if "error" in raw:
        return json.dumps(raw, indent=2)

    aggs = raw.get("aggregations", {})
    total_alerts = aggs.get("total_alerts", {}).get("value", 0)
    total_with_geo = aggs.get("total_with_geo", {}).get("value", 0)
    geo_coverage_pct = round(total_with_geo / total_alerts * 100, 1) if total_alerts > 0 else 0.0
    entity_buckets = aggs.get(agg_name, {}).get("buckets", [])
    rule_buckets = aggs.get("top_rules", {}).get("buckets", [])
    rule_buckets = aggs.get("top_rules", {}).get("buckets", [])
    agent_buckets = aggs.get("top_agents", {}).get("buckets", [])
    domain_buckets = aggs.get("top_domains", {}).get("buckets", [])
    severity = {b["key"]: b["doc_count"] for b in aggs.get("severity_bands", {}).get("buckets", [])}

    # Deduplication: remove child alert wrapper counts
    dedup_note = ""
    if params.deduplicate:
        dedup_body = {
            "size": 0,
            "query": {"bool": {"must": clauses + [
                {"terms": {"rule.id": ["606029", "651"]}},
            ]}},
            "aggs": {"total_children": {"value_count": {"field": "_id"}}},
        }
        try:
            dedup_raw = await _wazuh_indexer_post(dedup_body)
            child_count = (dedup_raw.get("aggregations", {})
                          .get("total_children", {}).get("value", 0))
            total_alerts = max(0, total_alerts - child_count)
            dedup_note = f" ({child_count} Active Response wrappers deduplicated)"
        except Exception:
            dedup_note = ""

    # Compare mode: run second query for previous period
    compare_data: dict[str, Any] = {}
    if params.compare_since:
        try:
            curr_duration = _duration_minutes(since_iso, until_iso)
            window_mins = max(60, curr_duration)
            comp_since_dt = datetime.fromisoformat(since_iso.replace("Z", "+00:00").rstrip("Z"))
            comp_since_iso = (comp_since_dt - timedelta(minutes=window_mins)).strftime("%Y-%m-%dT%H:%M:%SZ")
            comp_until_iso = since_iso

            comp_clauses = _build_curated_query(comp_since_iso, comp_until_iso, f)
            comp_body = {
                "size": 0,
                "query": {"bool": {"must": comp_clauses}},
                "aggs": {
                    agg_name: {"terms": {"field": agg_field, "size": params.max_entities}},
                    "total_alerts": {"value_count": {"field": "_id"}},
                    "severity_bands": {"range": {"field": "rule.level",
                        "ranges": [{"key": "low", "to": 5},
                                   {"key": "medium", "from": 5, "to": 10},
                                   {"key": "high", "from": 10}]}},
                },
            }
            comp_raw = await _wazuh_indexer_post(comp_body)
            if "error" not in comp_raw:
                c_aggs = comp_raw.get("aggregations", {})
                compare_data = {
                    "total_alerts": c_aggs.get("total_alerts", {}).get("value", 0),
                    "entities": len(c_aggs.get(agg_name, {}).get("buckets", [])),
                    "severity": {b["key"]: b["doc_count"]
                        for b in c_aggs.get("severity_bands", {}).get("buckets", [])},
                    "window": {"since": comp_since_iso, "until": comp_until_iso},
                }
        except Exception:
            compare_data = {"error": "comparison_query_failed"}

    # min_crowdsec_reputation pre-filter (Phase 0.5)
    crowdsec_filter_note = ""
    if params.filters.min_crowdsec_reputation and entity_buckets and params.group_by == "srcip" and os.environ.get(CROWDSEC_API_KEY_ENV):
        threshold_rep = params.filters.min_crowdsec_reputation.strip()
        all_ips = [b["key"] for b in entity_buckets]
        cs_verdicts: dict[str, str] = {}
        for ip in all_ips[:50]:
            try:
                cs = await _crowdsec_request(f"/v2/smoke/{ip}")
                cs_verdicts[ip] = cs.get("reputation", "unknown")
            except Exception:
                cs_verdicts[ip] = "lookup_failed"
        before = len(entity_buckets)
        entity_buckets = [b for b in entity_buckets if cs_verdicts.get(b["key"]) == threshold_rep]
        removed = before - len(entity_buckets)
        crowdsec_filter_note = f" (CrowdSec pre-filter '{threshold_rep}': {removed} IPs removed, {len(entity_buckets)} retained)"

    # Diversity re-ranking (when scoring_mode="diversity")
    if params.scoring_mode == "diversity" and entity_buckets:
        # Score each entity by rule group diversity (Shannon entropy * alert_count)
        for b in entity_buckets:
            rule_buckets_inner = b.get("top_rules", {}).get("buckets", [])
            distinct_rules = len(rule_buckets_inner)
            alert_count = b["doc_count"]
            # Diversity score: distinct rules * log(1 + alert_count)
            # rewards multi-phase attackers with moderate volume over noisy single-rule scanners
            import math
            b["_diversity_score"] = distinct_rules * math.log(1 + alert_count)
        entity_buckets.sort(key=lambda b: b.get("_diversity_score", 0), reverse=True)

    # Phase 2: Concurrent threat intel enrichment
    threat_data: dict[str, dict] = {}
    if params.include_threat_intel and entity_buckets and params.group_by == "srcip":
        top_ips = [b["key"] for b in entity_buckets[:min(params.max_entities, 15)]]

        async def _enrich_ip(ip: str) -> tuple[str, dict]:
            result: dict = {}
            # CrowdSec (cached)
            if os.environ.get(CROWDSEC_API_KEY_ENV):
                try:
                    cs = await _crowdsec_request(f"/v2/smoke/{ip}")
                    result["crowdsec"] = {
                        "reputation": cs.get("reputation", "unknown"),
                        "behaviors": [b.get("name", "") for b in cs.get("behaviors", [])],
                        "cves": cs.get("cves", []),
                    }
                except Exception:
                    result["crowdsec"] = {"error": "lookup_failed"}
            # Argus
            if os.environ.get(ARGUS_API_KEY_ENV):
                try:
                    argus_data = await _argus_request("/api/v1/lookup", {"ip_address": ip})
                    result["argus"] = {
                        "overall_score": argus_data.get("overall_score"),
                        "sources": list(argus_data.get("sources", {}).keys()) if isinstance(argus_data.get("sources"), dict) else [],
                    }
                except Exception:
                    result["argus"] = {"error": "lookup_failed"}
            # AbuseIPDB
            if ABUSEIPDB_API_KEY:
                try:
                    client = await _get_client("http")
                    resp = await client.get(
                        "https://api.abuseipdb.com/api/v2/check",
                        headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                        params={"ipAddress": ip, "maxAgeInDays": "90"},
                    )
                    resp.raise_for_status()
                    data = resp.json().get("data", {})
                    result["abuseipdb"] = {
                        "abuse_score": data.get("abuseConfidenceScore"),
                        "total_reports": data.get("totalReports"),
                        "country": data.get("countryCode"),
                    }
                except Exception:
                    result["abuseipdb"] = {"error": "lookup_failed"}
            # VirusTotal
            if VIRUSTOTAL_API_KEY:
                try:
                    client = await _get_client("http")
                    resp = await client.get(
                        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                        headers={"x-apikey": VIRUSTOTAL_API_KEY, "Accept": "application/json"},
                    )
                    resp.raise_for_status()
                    vt_data = resp.json().get("data", {}).get("attributes", {})
                    stats = vt_data.get("last_analysis_stats", {})
                    result["virustotal"] = {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "total_engines": sum(stats.values()) if stats else 0,
                    }
                except Exception:
                    result["virustotal"] = {"error": "lookup_failed"}
            return (ip, result)

        enrich_results = await asyncio.gather(*[_enrich_ip(ip) for ip in top_ips])
        threat_data = dict(enrich_results)

    # Phase 3: Format report
    if params.response_format == "json":
        result = {
            "window": {"since": since_iso, "until": until_iso},
            "filters_applied": f.model_dump(exclude_none=True),
            "total_alerts": total_alerts,
            "severity": severity,
            "top_rules": [{"id": b["key"], "count": b["doc_count"]} for b in rule_buckets],
            "top_agents": [{"name": b["key"], "count": b["doc_count"]} for b in agent_buckets],
            "top_domains": [{"domain": b["key"], "count": b["doc_count"]} for b in domain_buckets],
            "dedup_note": dedup_note if dedup_note else None,
            "compare": compare_data if compare_data else None,
            "attackers": [
                {
                    "ip": b["key"],
                    "alerts": b["doc_count"],
                    "max_level": int(b.get("max_level", {}).get("value", 0)),
                    "first_seen": b.get("first_seen", {}).get("value_as_string", ""),
                    "last_seen": b.get("last_seen", {}).get("value_as_string", ""),
                    "top_rules": [r["key"] for r in b.get("top_rules", {}).get("buckets", [])],
                    "top_urls": list(set(u["key"] for u in b.get("top_urls", {}).get("buckets", [])))[:5],
                    "threat_intel": threat_data.get(b["key"], {}),
                }
                for b in entity_buckets[:params.max_entities]
            ],
        }
        return _truncate_if_needed(json.dumps(result, indent=2, ensure_ascii=False))

    # Markdown report
    filter_desc_parts: list[str] = []
    for field_name in ["geo_country", "domain_pattern", "domain_contains", "rule_ids",
                        "rule_level_min", "rule_level_max", "rule_groups",
                        "rule_desc_contains", "mitre_tactics", "mitre_techniques",
                        "agent_name", "agent_ip", "agent_id", "decoder",
                        "url_pattern", "referrer_pattern",
                        "response_size_min", "response_size_max",
                        "rule_firedtimes_min", "log_source_pattern",
                        "response_codes", "http_methods", "user_agent_contains",
                        "geo_bbox", "exclude_srcips"]:
        val = getattr(f, field_name, None)
        if val:
            filter_desc_parts.append(f"`{field_name}={val}`")
    filter_desc = ", ".join(filter_desc_parts) if filter_desc_parts else "(none — all alerts)"

    lines = [
        f"# 🛡️ Curated Threat Report",
        "",
        f"**Window**: `{since_iso}` → `{until_iso}`",
        f"**Filters**: {filter_desc}",
        "",
        "---",
        "",
        "## 📊 Executive Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Total alerts matching filters | **{total_alerts:,}** |",
        f"| Unique entities | **{len(entity_buckets)}** |",
        f"| High-severity (L10+) | {severity.get('high', 0):,} |",
        f"| Medium-severity (L5-9) | {severity.get('medium', 0):,} |",
        f"| Low-severity (L1-4) | {severity.get('low', 0):,} |",
        f"| Unique rules triggered | {len(rule_buckets)} |",
        f"| Agents targeted | {len(agent_buckets)} |",
        f"| GeoIP coverage | {total_with_geo:,} of {total_alerts:,} ({geo_coverage_pct}%) |",
        f"| Dedup note | {dedup_note or 'none'} |",
        f"| CrowdSec filter | {crowdsec_filter_note or 'none'} |",
        "",
    ]
    # Comparison delta table
    if compare_data and "error" not in compare_data:
        prev_total = compare_data.get("total_alerts", 0)
        delta = total_alerts - prev_total
        delta_pct = (delta / prev_total * 100) if prev_total > 0 else float("inf")
        arrow = "↑" if delta > 0 else "↓" if delta < 0 else "—"
        lines.append("")
        lines.append("## 📈 Comparison vs Previous Period")
        lines.append("")
        lines.append("| Metric | Current | Previous | Δ |")
        lines.append("|--------|---------|----------|---|")
        lines.append(f"| Total alerts | {total_alerts:,} | {prev_total:,} | {delta:+,} ({delta_pct:+.0f}%) {arrow} |")
        prev_entities = compare_data.get("entities", 0)
        e_delta = len(entity_buckets) - prev_entities
        lines.append(f"| Unique entities | {len(entity_buckets)} | {prev_entities} | {e_delta:+} |")
        prev_sev = compare_data.get("severity", {})
        for sev_key in ["high", "medium", "low"]:
            cur_s = severity.get(sev_key, 0)
            prev_s = prev_sev.get(sev_key, 0)
            s_delta = cur_s - prev_s
            lines.append(f"| {sev_key.title()} severity | {cur_s:,} | {prev_s:,} | {s_delta:+,} |")
        lines.append("")

    # Top entities table - heading changes based on group_by
    entity_labels: dict[str, str] = {
        "srcip": ("🔴 Top Attackers", "IP", "Alerts"),
        "domain": ("🌐 Top Targeted Domains", "Domain", "Alerts"),
        "rule.id": ("🔥 Top Rules Triggered", "Rule ID", "Alerts"),
        "agent": ("🖥️ Most Targeted Agents", "Agent", "Alerts"),
    }
    section_title, col_name, col_alerts = entity_labels.get(params.group_by, entity_labels["srcip"])

    if entity_buckets:
        lines.append(f"## {section_title}")
        lines.append("")
        if params.group_by == "srcip":
            lines.append(f"| {col_name} | {col_alerts} | Max Lvl | Threat Intel | Top Rules | First → Last |")
            lines.append("|----|--------|---------|-------------|-----------|-------------|")
            for b in entity_buckets[:30]:
                key = b["key"]
                alerts = b["doc_count"]
                lvl = int(b.get("max_level", {}).get("value", 0))
                rules = ", ".join(f"`{r['key']}`" for r in b.get("top_rules", {}).get("buckets", [])[:2])
                fst = (b.get("first_seen", {}).get("value_as_string", "") or "")[:19]
                lst = (b.get("last_seen", {}).get("value_as_string", "") or "")[:19]
                ti = threat_data.get(key, {})
                ti_parts = []
                cs = ti.get("crowdsec", {})
                if cs and "error" not in cs:
                    ti_parts.append(f"CS:`{cs.get('reputation','?')}`")
                arg = ti.get("argus", {})
                if arg and "error" not in arg and arg.get("overall_score"):
                    ti_parts.append(f"Arg:{arg['overall_score']}")
                ab = ti.get("abuseipdb", {})
                if ab and "error" not in ab and ab.get("abuse_score") is not None:
                    ti_parts.append(f"AB:{ab['abuse_score']}%")
                vt = ti.get("virustotal", {})
                if vt and "error" not in vt:
                    ti_parts.append(f"VT:{vt.get('malicious',0)}/{vt.get('total_engines',0)}")
                ti_str = " ".join(ti_parts) if ti_parts else "-"
                lines.append(f"| `{key}` | {alerts:,} | {lvl} | {ti_str} | {rules} | {fst} → {lst} |")
        else:
            lines.append(f"| {col_name} | {col_alerts} | Top Rules | First → Last |")
            lines.append("|----|--------|-----------|-------------|")
            for b in entity_buckets[:30]:
                key = b["key"]
                alerts = b["doc_count"]
                rules = ", ".join(f"`{r['key']}`" for r in b.get("top_rules", {}).get("buckets", [])[:3])
                fst = (b.get("first_seen", {}).get("value_as_string", "") or "")[:19]
                lst = (b.get("last_seen", {}).get("value_as_string", "") or "")[:19]
                lines.append(f"| `{key}` | {alerts:,} | {rules} | {fst} → {lst} |")

    if rule_buckets:
        lines.append("")
        lines.append("## 🔥 Top Rules")
        for b in rule_buckets:
            lines.append(f"- `{b['key']}` — {b['doc_count']:,} alerts")

    if domain_buckets:
        lines.append("")
        lines.append("## 🌐 Top Targeted Domains")
        for b in domain_buckets[:10]:
            lines.append(f"- `{b['key']}` — {b['doc_count']:,} alerts")

    if agent_buckets:
        lines.append("")
        lines.append("## 🖥️ Most Targeted Agents")
        for b in agent_buckets[:10]:
            lines.append(f"- `{b['key']}` — {b['doc_count']:,} alerts")

    lines.append("")
    lines.append("## 🛠️ Recommended Actions")

    high_entities = [b for b in entity_buckets if int(b.get("max_level", {}).get("value", 0)) >= 10]
    if high_entities:
        lines.append(f"1. 🚨 {len(high_entities)} entities triggered critical-severity rules — initiate incident response")
    for b in entity_buckets[:5]:
        ip = b["key"]
        ti = threat_data.get(ip, {})
        cs = ti.get("crowdsec", {})
        if cs and cs.get("reputation") == "malicious":
            lines.append(f"2. Block `{ip}` — confirmed malicious by CrowdSec")
            break
    else:
        lines.append("2. Review top-10 IPs in external threat intel platforms for confirmation")
    lines.append(f"3. Total {len(entity_buckets)} unique entities — add high-severity offenders to watchlist")

    # Deep investigation: auto-chain attack chain analysis
    if params.investigation_depth == "deep" and entity_buckets and params.group_by == "srcip":
        deep_ips = []
        for b in entity_buckets[:10]:
            key = b["key"]
            lvl = int(b.get("max_level", {}).get("value", 0))
            ti = threat_data.get(key, {})
            cs = ti.get("crowdsec", {})
            if lvl >= 10 or (cs.get("reputation") == "malicious" and "error" not in cs):
                deep_ips.append(key)

        if deep_ips:
            lines.append("")
            lines.append("## 🔬 Deep Investigation (Auto-Chained)")
            lines.append("")
            lines.append(f"*{len(deep_ips)} qualifying IPs (max_level≥10 or CrowdSec=malicious)*")
            lines.append("")

            async def _chain_for_ip(ip):
                cbody = {"size": 500, "sort": [{"@timestamp": {"order": "asc"}}],
                    "query": {"bool": {"must": [
                        {"range": {"@timestamp": {"gte": since_iso, "lt": until_iso,
                                                 "format": "strict_date_optional_time"}}},
                        {"bool": {"should": [{"match": {"data.srcip": ip}},
                                            {"match_phrase": {"full_log": ip}}],
                                  "minimum_should_match": 1}},
                    ]}},
                    "_source": ["@timestamp", "rule.id", "rule.description"]}
                cr = await _wazuh_indexer_post(cbody)
                if "error" in cr:
                    return (ip, None)
                hits = cr.get("hits", {}).get("hits", [])
                rule_seq = [str(h.get("_source", {}).get("rule", {}).get("id", "?")) for h in hits]
                # compress consecutive duplicates
                comp = []
                for r in rule_seq:
                    if not comp or r != comp[-1]:
                        comp.append(r)
                rc = Counter(rule_seq)
                return (ip, {"total": len(hits), "chain": comp[:15], "top": rc.most_common(4)})

            chain_results = await asyncio.gather(*[_chain_for_ip(ip) for ip in deep_ips])
            for ip, ci in chain_results:
                if ci is None:
                    continue
                lines.append(f"### `{ip}`")
                lines.append(f"- Alerts: {ci['total']} | Chain: `{' → '.join(ci['chain'][:10])}`")
                top_str = ", ".join(f"`{r}`({c})" for r, c in ci["top"][:4])
                lines.append(f"- Top rules: {top_str}")
                lines.append("")

    lines.append("")
    lines.append("---")
    lines.append(f"*Report generated by blue_team_mcp (Wazuh Ft. AI by TangerangKota-CSIRT) at {datetime.utcnow().isoformat()[:19]}Z*")

    return _truncate_if_needed("\n".join(lines))





# Threat intel tools
import os, json, re
from mcp_server.core.http_client import _api_call, _get_client, _handle_api_error, ValidPublicIp
from mcp_server.core.audit import _audit_log
from mcp_server.core.constants import _BLOCKMODE_SEVERITY, _KNOWN_ATTACK_CHAINS, NETRA_BASE_URL


# AbuseIPDB
@mcp.tool(
    name="blueteam_lookup_ip_abuseipdb",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_lookup_ip_abuseipdb(ip: ValidPublicIp, max_age_days: int = 90, response_format: str = "markdown") -> str:
    """Check IP reputation via AbuseIPDB."""
    _audit_log("blueteam_lookup_ip_abuseipdb", {"ip": ip})
    from mcp_server import ABUSEIPDB_API_KEY
    if not ABUSEIPDB_API_KEY:
        return json.dumps({"error": "ABUSEIPDB_API_KEY not set."})
    try:
        client = await _get_client("http")
        resp = await client.get("https://api.abuseipdb.com/api/v2/check",
                                 headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                                 params={"ipAddress": ip, "maxAgeInDays": str(max_age_days)})
        resp.raise_for_status()
        data = resp.json().get("data", {})
        if response_format == "json":
            return _truncate_if_needed(json.dumps({"ip": ip, "abuse_score": data.get("abuseConfidenceScore"), "total_reports": data.get("totalReports"), "country": data.get("countryCode")}, indent=2))
        return _truncate_if_needed(f"# AbuseIPDB — {ip}\n\n- **Abuse Score**: {data.get('abuseConfidenceScore','?')}%\n- **Reports**: {data.get('totalReports','?')}\n- **Country**: {data.get('countryCode','?')}")
    except Exception as e:
        return _handle_api_error(e, context="abuseipdb")


# VirusTotal Hash
@mcp.tool(
    name="blueteam_lookup_hash_virustotal",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_lookup_hash_virustotal(hash: str, response_format: str = "markdown") -> str:
    """Check file hash reputation via VirusTotal."""
    _audit_log("blueteam_lookup_hash_virustotal", {"hash": hash})
    from mcp_server import VIRUSTOTAL_API_KEY
    if not VIRUSTOTAL_API_KEY:
        return json.dumps({"error": "VIRUSTOTAL_API_KEY not set."})
    try:
        client = await _get_client("http")
        resp = await client.get(f"https://www.virustotal.com/api/v3/files/{hash}",
                                 headers={"x-apikey": VIRUSTOTAL_API_KEY, "Accept": "application/json"})
        resp.raise_for_status()
        data = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        if response_format == "json":
            return _truncate_if_needed(json.dumps({"hash": hash, "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0), "harmless": stats.get("harmless", 0)}, indent=2))
        return _truncate_if_needed(f"# VirusTotal Hash — {hash}\n\n- **Malicious**: {stats.get('malicious',0)}\n- **Suspicious**: {stats.get('suspicious',0)}\n- **Harmless**: {stats.get('harmless',0)}")
    except Exception as e:
        return _handle_api_error(e, context="virustotal")


# VirusTotal Domain
@mcp.tool(
    name="blueteam_lookup_domain_virustotal",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_lookup_domain_virustotal(domain: str, response_format: str = "markdown") -> str:
    """Check domain reputation via VirusTotal."""
    _audit_log("blueteam_lookup_domain_virustotal", {"domain": domain})
    from mcp_server import VIRUSTOTAL_API_KEY
    if not VIRUSTOTAL_API_KEY:
        return json.dumps({"error": "VIRUSTOTAL_API_KEY not set."})
    try:
        client = await _get_client("http")
        resp = await client.get(f"https://www.virustotal.com/api/v3/domains/{domain}",
                                 headers={"x-apikey": VIRUSTOTAL_API_KEY, "Accept": "application/json"})
        resp.raise_for_status()
        data = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        if response_format == "json":
            return _truncate_if_needed(json.dumps({"domain": domain, "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0), "harmless": stats.get("harmless", 0)}, indent=2))
        return _truncate_if_needed(f"# VirusTotal Domain — {domain}\n\n- **Malicious**: {stats.get('malicious',0)}\n- **Suspicious**: {stats.get('suspicious',0)}\n- **Harmless**: {stats.get('harmless',0)}")
    except Exception as e:
        return _handle_api_error(e, context="virustotal")


# Argus
@mcp.tool(
    name="argus_ip_lookup",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def argus_ip_lookup(ip: ValidPublicIp, response_format: str = "markdown") -> str:
    """Query Argus Threat Intelligence (TangerangKota-CSIRT) aggregating 7 sources."""
    _audit_log("argus_ip_lookup", {"ip": ip})
    from mcp_server import ARGUS_API_KEY_ENV, ARGUS_VERIFY_SSL
    api_key = os.environ.get(ARGUS_API_KEY_ENV, "")
    base_url = os.environ.get("ARGUS_BASE_URL", "")
    if not api_key or not base_url:
        return json.dumps({"error": "ARGUS_API_KEY and ARGUS_BASE_URL must be set."})
    try:
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json", "accept": "application/json"}
        resp = await _api_call("post", f"{base_url}/api/v1/lookup", client_name="argus", verify=ARGUS_VERIFY_SSL,
                                headers=headers, json={"ip_address": ip})
        raw = resp.json()
        if response_format == "json":
            return _truncate_if_needed(json.dumps(raw, indent=2))
        results = raw.get("results", {})
        return _truncate_if_needed(f"# Argus — {ip}\n\n- **Overall Score**: {raw.get('overall_score','?')}\n- **Sources**: {', '.join(results.keys())}")
    except Exception as e:
        return _handle_api_error(e, context="argus")


# Netra
@mcp.tool(
    name="netra_ip_analysis",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def netra_ip_analysis(ip: ValidPublicIp, response_format: str = "markdown", bypass_redaction: bool = False) -> str:
    """Query Netra Threat Intelligence for IP analysis."""
    _audit_log("netra_ip_analysis", {"ip": ip})
    from mcp_server import NETRA_API_KEY_ENV, NETRA_VERIFY_SSL
    api_key = os.environ.get(NETRA_API_KEY_ENV, "")
    if not api_key:
        return json.dumps({"error": "NETRA_API_KEY not set."})
    try:
        headers = {"X-API-Key": api_key, "accept": "application/json"}
        resp = await _api_call("get", f"{NETRA_BASE_URL}/ip/{ip}", headers=headers)
        raw = resp.json()
        if response_format == "json":
            return _truncate_if_needed(json.dumps(raw, indent=2))
        return _truncate_if_needed(f"# Netra — {ip}\n\n- **Reputation**: {raw.get('reputation','unknown')}")
    except Exception as e:
        return _handle_api_error(e, context="netra")


# Sangfor Blocklist
class SangforBlocklistCheckInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    ip: ValidPublicIp = Field(..., min_length=3, max_length=45)
    response_format: str = Field(default="markdown")

class SangforBlocklistListInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    limit: int = Field(default=100, ge=1, le=1000)
    response_format: str = Field(default="markdown")

@mcp.tool(
    name="sangfor_blocklist_check",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def sangfor_blocklist_check(params: SangforBlocklistCheckInput) -> str:
    """Check if an IP is currently blocked by Sangfor firewall."""
    _audit_log("sangfor_blocklist_check", {"ip": params.ip})
    from mcp_server import SANGFOR_BLOCKLIST_URL, SANGFOR_BLOCKLIST_TOKEN, SANGFOR_BLOCKLIST_VERIFY_SSL
    if not SANGFOR_BLOCKLIST_TOKEN or not SANGFOR_BLOCKLIST_URL:
        return json.dumps({"error": "SANGFOR_BLOCKLIST_TOKEN and SANGFOR_BLOCKLIST_URL must be set."})
    try:
        headers = {"Authorization": f"Bearer {SANGFOR_BLOCKLIST_TOKEN}", "accept": "application/json"}
        resp = await _api_call("get", f"{SANGFOR_BLOCKLIST_URL}/check/{params.ip}", headers=headers)
        raw = resp.json()
        if params.response_format == "json":
            return _truncate_if_needed(json.dumps(raw, indent=2))
        blocked = raw.get("blocked", False)
        return _truncate_if_needed(f"# Sangfor Blocklist — {params.ip}\n\n- **Blocked**: {blocked}")
    except Exception as e:
        return _handle_api_error(e, context="sangfor")

@mcp.tool(
    name="sangfor_blocklist_list",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def sangfor_blocklist_list(params: SangforBlocklistListInput) -> str:
    """List all IPs currently blocked by Sangfor firewall."""
    _audit_log("sangfor_blocklist_list", {"limit": params.limit})
    from mcp_server import SANGFOR_BLOCKLIST_URL, SANGFOR_BLOCKLIST_TOKEN, SANGFOR_BLOCKLIST_VERIFY_SSL
    if not SANGFOR_BLOCKLIST_TOKEN or not SANGFOR_BLOCKLIST_URL:
        return json.dumps({"error": "SANGFOR_BLOCKLIST_TOKEN and SANGFOR_BLOCKLIST_URL must be set."})
    try:
        headers = {"Authorization": f"Bearer {SANGFOR_BLOCKLIST_TOKEN}", "accept": "application/json"}
        resp = await _api_call("get", f"{SANGFOR_BLOCKLIST_URL}/list?limit={params.limit}", headers=headers)
        raw = resp.json()
        if params.response_format == "json":
            return _truncate_if_needed(json.dumps(raw, indent=2))
        items = raw if isinstance(raw, list) else raw.get("data", [])
        return _truncate_if_needed(f"# Sangfor Blocklist ({len(items)} IPs)\n\n" + "\n".join(f"- `{i.get('ip_address','?')}`" for i in items[:50]))
    except Exception as e:
        return _handle_api_error(e, context="sangfor_list")


# Unified Threat Confidence Scoring
class UnifiedThreatScoreInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    ip: str = Field(..., min_length=7, max_length=45, description="Public IP to score.")
    response_format: str = Field(default="markdown", description="'markdown' or 'json'.")

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        v = v.strip()
        try:
            __import__("ipaddress").ip_address(v)
        except ValueError as exc:
            raise ValueError(f"Invalid IP: '{v}'") from exc
        if __import__("ipaddress").ip_address(v).is_private:
            raise ValueError(f"'{v}' is a private IP — this tool accepts public IPs only.")
        return v


@mcp.tool(
    name="blueteam_unified_threat_score",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
)
async def blueteam_unified_threat_score(params: UnifiedThreatScoreInput) -> str:
    """Query multiple threat intel sources and return a unified confidence score.

    Aggregates CrowdSec + ThreatFox + AbuseIPDB into a single weighted verdict
    (0.0–1.0) eliminating the need for 3+ sequential LLM tool calls per IP.
    """
    _audit_log("blueteam_unified_threat_score", {"ip": params.ip})

    async def _crowdsec(ip):
        try:
            from mcp_server.threat_intel.crowdsec import _crowdsec_request
            r = await _crowdsec_request(f"/v2/smoke/{ip}"); rep = r.get("reputation","unknown")
            m = {"malicious":1.0,"suspicious":0.5,"known":0.2,"unknown":0.1,"safe":0.0}
            return m.get(rep,0.1), {"reputation":rep,"behaviors":[b.get("name","?") for b in r.get("behaviors",[])[:3]]}
        except Exception: return 0.0, {}

    async def _threatfox(ip):
        try:
            from mcp_server.threat_intel.threatfox import _threatfox_request
            r = await _threatfox_request(ip,False); items = r.get("data",[])
            if not items: return 0.0, {}
            c = max(e.get("confidence_level",0) for e in items)/100.0
            return c, {"malware":items[0].get("malware_printable","?"),"threat_type":items[0].get("threat_type_desc","?"),"confidence":items[0].get("confidence_level",0)}
        except Exception: return 0.0, {}

    async def _abuseipdb(ip):
        try:
            from mcp_server import ABUSEIPDB_API_KEY
            if not ABUSEIPDB_API_KEY: return 0.0, {}
            h = {"Key":ABUSEIPDB_API_KEY,"Accept":"application/json"}
            r = await _api_call("get",f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",headers=h)
            d = r.json().get("data",{})
            s = d.get("abuseConfidenceScore",0)/100.0
            return s, {"confidence":d.get("abuseConfidenceScore",0),"total_reports":d.get("totalReports",0)}
        except Exception: return 0.0, {}

    cs_s, cs_d = await _crowdsec(params.ip)
    tf_s, tf_d = await _threatfox(params.ip)
    ab_s, ab_d = await _abuseipdb(params.ip)

    w = {"crowdsec":0.35,"threatfox":0.35,"abuseipdb":0.30}
    parts = []
    if cs_d: parts.append((cs_s*w["crowdsec"], w["crowdsec"]))
    if tf_d: parts.append((tf_s*w["threatfox"], w["threatfox"]))
    if ab_d: parts.append((ab_s*w["abuseipdb"], w["abuseipdb"]))
    uw = sum(p[1] for p in parts)
    unified = sum(p[0] for p in parts)/uw if uw>0 else 0.0

    if unified>=0.8: v="CRITICAL — Active threat, escalate immediately"
    elif unified>=0.5: v="HIGH — Likely malicious, investigate"
    elif unified>=0.2: v="MEDIUM — Suspicious, monitor"
    elif parts: v="LOW — Probably benign"
    else: v="UNKNOWN — No threat intel sources available"

    if params.response_format=="json":
        return _truncate_if_needed(json.dumps({"ip":params.ip,"unified_score":round(unified,2),"verdict":v,
            "sources":{"crowdsec":{"score":round(cs_s,2),**cs_d} if cs_d else None,
                       "threatfox":{"score":round(tf_s,2),**tf_d} if tf_d else None,
                       "abuseipdb":{"score":round(ab_s,2),**ab_d} if ab_d else None},
            "scoring_model":{"weights":w,"used_weight":round(uw,2)}},indent=2))

    lines=[f"# Unified Threat Score — `{params.ip}`","",f"**Score**: {unified:.2f}  |  **Verdict**: {v}","","| Source | Score | Details |","|--------|-------|---------|"]
    if cs_d: lines.append(f"| CrowdSec | {cs_s:.2f} | `{cs_d.get('reputation','?')}` — {', '.join(cs_d.get('behaviors',[])[:2])} |")
    else: lines.append("| CrowdSec | — | ⚠️ Not configured |")
    if tf_d: lines.append(f"| ThreatFox | {tf_s:.2f} | `{tf_d.get('malware','?')}` ({tf_d.get('threat_type','?')}, conf={tf_d.get('confidence','?')}) |")
    else: lines.append("| ThreatFox | — | ⚠️ Not configured |")
    if ab_d: lines.append(f"| AbuseIPDB | {ab_s:.2f} | {ab_d.get('confidence',0)}% confidence, {ab_d.get('total_reports',0)} reports |")
    else: lines.append("| AbuseIPDB | — | ⚠️ Not configured |")
    return _truncate_if_needed("\n".join(lines))
