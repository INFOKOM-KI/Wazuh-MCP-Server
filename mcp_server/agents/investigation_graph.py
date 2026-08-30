#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
LangGraph SOC investigation workflow - orchestrates the platform's in-process
tool functions as a stateful, conditionally-routed graph.
Graph: START -> extract -> enrich -> vuln -> correlate -> analytics -> baseline -> report -> verdict -> END
Conditional routing:
- enrich/vuln/correlate skipped when there are no IOCs, no srcip, and no manifest
- killchain runs only when a srcip is provided
- baseline runs only when 3-Sum flagged anomalies
- report/verdict run only when requested (generate_report / record_verdict)
Every node degrades gracefully: steps without required credentials (indexer,
API keys) are recorded in `errors` and the workflow continues.
"""
from __future__ import annotations
import asyncio, json, logging, os, uuid
from typing import Annotated, Optional, TypedDict
from operator import add
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import InMemorySaver

logger = logging.getLogger("blue_team_mcp.investigation_graph")

# Per-node timeout (seconds) - prevents a stuck Indexer call from blocking
# the entire workflow indefinitely.
_NODE_TIMEOUT = float(os.environ.get("BLUETEAM_LANGGRAPH_NODE_TIMEOUT", "120"))

# State persistence: InMemorySaver is the reliable default.
# NOTE: AsyncSqliteSaver is intentionally NOT used here - aiosqlite connections
# created via asyncio.run() die when the temporary loop closes, causing
# "'Connection' object has no attribute 'is_alive'" at ainvoke() runtime.
# Re-enable SqliteSaver only when the FastMCP server exposes its own event loop
# for lazy checkpointer init (future langgraph upgrade).
_checkpointer = InMemorySaver()


class InvestigationState(TypedDict, total=False):
    # inputs
    alert_text: str
    srcip: Optional[str]
    window: str
    dependency_manifest: Optional[str]
    use_attack_graph: bool
    generate_report: bool
    record_verdict: bool
    verdict_label: str
    report_dir: str
    # step outputs
    extract_iocs: Optional[dict]
    enrichment: Optional[dict]
    vulnerabilities: Optional[list]
    correlation: Optional[dict]
    attack_graph: Optional[dict]
    killchain: Optional[dict]
    baseline: Optional[dict]
    report_path: Optional[str]
    verdict: Optional[dict]
    # execution log
    steps: Annotated[list[str], add]
    errors: Annotated[list[str], add]


# Per-node timeout wrapper - catches TimeoutError and degrades gracefully.
async def _with_timeout(coro, label: str) -> dict:
    try:
        return await asyncio.wait_for(coro, timeout=_NODE_TIMEOUT)
    except asyncio.TimeoutError:
        return {"errors": [f"{label}: timed out after {_NODE_TIMEOUT:.0f}s"],
                "steps": [f"{label}: timed out"]}


# Node adapters - call existing tool handlers in-process
async def extract_step(state: InvestigationState) -> dict:
    text = state.get("alert_text")
    if not text:
        return {"steps": ["extract: skipped (no alert_text)"]}
    from mcp_server.tools.ioc_tools import _extract_iocs
    from mcp_server.core.ioc_store import record_iocs
    iocs = _extract_iocs(text)
    all_iocs = (iocs["ips"] + iocs["domains"] + iocs["urls"] + iocs["emails"]
                + iocs["hashes"]["md5"] + iocs["hashes"]["sha1"] + iocs["hashes"]["sha256"])
    record_iocs(all_iocs, source="investigation_graph")
    cve_count = len(iocs.get("cves", []))
    return {"extract_iocs": iocs,
            "steps": [f"extract: {len(all_iocs)} IOCs + {cve_count} CVEs extracted"]}


async def enrich_step(state: InvestigationState) -> dict:
    """IP threat-intel enrichment only. CVE handling lives in vuln_step."""
    iocs = state.get("extract_iocs") or {}
    ips = list(iocs.get("ips", []))
    if state.get("srcip") and state["srcip"] not in ips:
        ips.insert(0, state["srcip"])
    ips = ips[:10]

    if not ips:
        return {"steps": ["enrich: skipped (no IPs)"]}

    from mcp_server.tools.correlation import _enrich_ips
    try:
        enr = await _with_timeout(_enrich_ips(ips), "enrich")
        return {"enrichment": enr, "steps": [f"enrich: {len(enr)} IPs enriched"]}
    except Exception as e:
        return {"errors": [f"enrich: degraded ({e})"],
                "steps": ["enrich: degraded"]}


async def vuln_step(state: InvestigationState) -> dict:
    """CVE pipeline: optional dependency-manifest scan, then composite risk
    score + SSVC action band + MITRE attack mapping for every discovered CVE.
    Populates `vulnerabilities`, which `correlate_step` consumes as the 3-Sum
    `vuln_context` (risk_score + techniques). SSVC stays out of the scoring
    math; it rides along as advisory triage metadata in the final state."""
    iocs = state.get("extract_iocs") or {}
    cves: list[str] = list(iocs.get("cves", []))[:5]

    manifest = state.get("dependency_manifest")
    if manifest:
        from mcp_server.tools.dependency_scan import (
            blueteam_dependency_scan, DependencyScanInput)
        try:
            raw = await _with_timeout(
                blueteam_dependency_scan(DependencyScanInput(
                    raw_text=manifest, response_format="json")), "vuln_depscan")
            dep = json.loads(raw)
            for r in dep.get("results", []):
                for v in r.get("vulns", []):
                    for cid in v.get("cve_ids", []):
                        if cid and cid not in cves:
                            cves.append(cid)
        except Exception:
            pass  # depscan is best-effort; alert-text CVEs still process
        cves = cves[:10]

    if not cves:
        return {"steps": ["vuln: skipped (no CVEs)"]}

    from mcp_server.tools.cve_enrichment import _gather_cve_data
    from mcp_server.threat_intel.cve_enrichment import (
        _extract_cvss_score, _lookup_kev, score_cve)
    from mcp_server.threat_intel.ssvc import ssvc_decision
    from mcp_server.tools.stix_correlation import get_attack_mapping

    vulns: list[dict] = []
    for cid in cves:
        entry: dict = {"cve_id": cid}
        # One fetch per CVE (NVD + EPSS + KEV + PoC, all cached), then derive both
        # the numeric score and the SSVC band from the same data - avoids
        # doubling NVD requests (the 5 req/30s unauth limit is the constraint).
        try:
            nvd, epss_entries, kev_catalog, poc = await _with_timeout(
                _gather_cve_data(cid), "vuln_score")
            cvss = _extract_cvss_score(nvd)
            epss_entry = next((e for e in epss_entries if e.get("cve") == cid), None)
            epss_probability = float(epss_entry["epss"]) if epss_entry else 0.0
            kev_entry = _lookup_kev(kev_catalog, cid)
            epss_data = {"probability": epss_probability} if epss_entry else None
            entry["score"] = score_cve(cid, nvd, epss_data, kev_entry, poc)
            entry["ssvc"] = ssvc_decision(
                in_kev=bool(kev_entry),
                epss_probability=epss_probability,
                poc_confidence=(poc or {}).get("confidence", "NONE"),
                cvss_score=cvss,
                exposure="open",
            )
        except Exception:
            entry["score"] = None
            entry["ssvc"] = None
        try:
            entry["attack_mapping"] = await asyncio.to_thread(get_attack_mapping, cid)
        except Exception:
            entry["attack_mapping"] = None
        vulns.append(entry)

    return {"vulnerabilities": vulns,
            "steps": [f"vuln: {len(vulns)} CVEs enriched (score+SSVC+MITRE)"]}


async def correlate_step(state: InvestigationState) -> dict:
    from mcp_server.tools.correlation import three_sum_correlation, ThreeSumCorrelationInput
    vuln_context: list[dict] = []
    for v in state.get("vulnerabilities") or []:
        mapping = v.get("attack_mapping") or {}
        if mapping.get("techniques"):
            score = v.get("score") or {}
            vuln_context.append({
                "cve_id": v.get("cve_id"),
                "risk_score": score.get("risk_score"),
                "techniques": mapping.get("techniques", []),
            })
    try:
        out = await _with_timeout(
            three_sum_correlation(ThreeSumCorrelationInput(
                response_format="json",
                follow_up="threat_intel" if state.get("srcip") else "none",
                use_attack_graph=state.get("use_attack_graph", True),
                vuln_srcip=state.get("srcip"),
                vuln_context=vuln_context or None,
            )), "correlate")
        result = json.loads(out)
        if isinstance(result, dict) and result.get("error"):
            return {"correlation": result,
                    "errors": [f"correlate: {result['error']}"],
                    "steps": ["correlate: degraded (no indexer data)"]}
        return {"correlation": result, "steps": ["correlate: 3-Sum complete"]}
    except Exception as e:
        return {"errors": [f"correlate: {e}"], "steps": ["correlate: degraded"]}


async def analytics_step(state: InvestigationState) -> dict:
    """Run attack graph analysis + STIX killchain in parallel.
    graph_step and killchain_step are independent - the attack graph
    operates on the IOC store while the killchain queries the Indexer
    per-srcip. Running them concurrently cuts ~30% from the serial path.
    """
    srcip = state.get("srcip")

    async def _run_graph():
        from mcp_server.tools.attack_graph import blueteam_attack_graph, AttackGraphInput
        out = await blueteam_attack_graph(AttackGraphInput(response_format="json"))
        return ("graph", json.loads(out), None)

    async def _run_killchain():
        if not srcip:
            return ("killchain", None, "skipped (no srcip)")
        from mcp_server.tools.stix_correlation import blueteam_stix_killchain, StixKillchainInput
        out = await blueteam_stix_killchain(StixKillchainInput(
            srcip=srcip, since=state.get("window", "24h"), response_format="json"))
        return ("killchain", json.loads(out), None)

    tasks = [
        _with_timeout(_run_graph(), "graph"),
        _with_timeout(_run_killchain(), "killchain"),
    ]
    results = await asyncio.gather(*tasks)

    update: dict = {"steps": [], "errors": []}
    for key, data, skip_reason in results:
        if skip_reason:
            update["steps"].append(f"{key}: {skip_reason}")
        elif isinstance(data, dict) and "error" not in data:
            update[key] = data
            if key == "graph":
                update["steps"].append("graph: attack graph analyzed")
            else:
                update["steps"].append("killchain: STIX chain built")
        else:
            err = data.get("error", "unknown") if isinstance(data, dict) else str(data)
            update["errors"].append(f"{key}: {err}")
            update["steps"].append(f"{key}: degraded")
    return update


async def baseline_step(state: InvestigationState) -> dict:
    from mcp_server.tools.baseline import blueteam_baseline_drift, BaselineDriftInput
    try:
        out = await _with_timeout(
            blueteam_baseline_drift(BaselineDriftInput(
                window=state.get("window", "24h"), response_format="json")),
            "baseline")
        return {"baseline": json.loads(out), "steps": ["baseline: drift evaluated"]}
    except Exception as e:
        return {"errors": [f"baseline: {e}"], "steps": ["baseline: degraded"]}


async def report_step(state: InvestigationState) -> dict:
    if not state.get("generate_report"):
        return {"steps": ["report: skipped"]}
    from mcp_server.tools.report_export import blueteam_export_report, ReportExportInput
    try:
        steps = list(state.get("steps") or [])
        corr = state.get("correlation") or {}
        summary = f"{len(steps)} investigation steps executed"
        out = await blueteam_export_report(ReportExportInput(
            format="docx",
            path=f"{state.get('report_dir', '/tmp')}/investigation_{uuid.uuid4().hex[:8]}.docx",
            title="SOC Investigation — Blue Team MCP",
            docx_sections=[{
                "heading": "Investigation Summary",
                "paragraphs": [summary, json.dumps(corr.get("unified_scoring", {}), indent=2)],
                "bullets": steps[-10:],
            }],
        ))
        d = json.loads(out)
        return {"report_path": d.get("path"), "steps": [f"report: {d.get('path')}"]}
    except Exception as e:
        return {"errors": [f"report: {e}"], "steps": ["report: degraded"]}


async def verdict_step(state: InvestigationState) -> dict:
    srcip = state.get("srcip")
    if not state.get("record_verdict") or not srcip:
        return {"steps": ["verdict: skipped"]}
    from mcp_server.tools.investigation_history import blueteam_mark_investigated, MarkInvestigatedInput
    try:
        out = await blueteam_mark_investigated(MarkInvestigatedInput(
            srcip=srcip, verdict=state.get("verdict_label", "suspicious"),
            notes="auto investigation workflow"))
        return {"verdict": json.loads(out), "steps": ["verdict: recorded"]}
    except Exception as e:
        return {"errors": [f"verdict: {e}"], "steps": ["verdict: degraded"]}


# Conditional routing
def _has_targets(state: InvestigationState) -> str:
    if (state.get("extract_iocs") or state.get("srcip")
            or state.get("dependency_manifest")):
        return "enrich"
    return "analytics"


def _correlate_flagged(state: InvestigationState) -> bool:
    us = (state.get("correlation") or {}).get("unified_scoring", {})
    return bool(us.get("engine_a_triggers") or us.get("engine_b_anomalies"))


def _after_analytics(state: InvestigationState) -> str:
    if _correlate_flagged(state):
        return "baseline"
    if state.get("generate_report"):
        return "report"
    return "verdict" if state.get("record_verdict") else END


def _after_baseline(state: InvestigationState) -> str:
    if state.get("generate_report"):
        return "report"
    return "verdict" if state.get("record_verdict") else END


def _after_report(state: InvestigationState) -> str:
    return "verdict" if state.get("record_verdict") else END


def build_investigation_graph():
    """Build and compile the StateGraph. Uses module-level checkpointer.
    Graph: START -> extract -> enrich -> vuln -> correlate -> analytics -> baseline -> report -> verdict -> END
    analytics runs graph (networkx) and killchain (STIX) concurrently.
    """
    g = StateGraph(InvestigationState)
    g.add_node("extract", extract_step)
    g.add_node("enrich", enrich_step)
    g.add_node("vuln", vuln_step)
    g.add_node("correlate", correlate_step)
    g.add_node("analytics", analytics_step)
    g.add_node("baseline", baseline_step)
    g.add_node("report", report_step)
    g.add_node("verdict", verdict_step)
    g.add_edge(START, "extract")
    g.add_conditional_edges("extract", _has_targets, {"enrich": "enrich", "graph": "analytics"})
    g.add_edge("enrich", "vuln")
    g.add_edge("vuln", "correlate")
    g.add_edge("correlate", "analytics")
    g.add_conditional_edges("analytics", _after_analytics, {
        "baseline": "baseline", "report": "report", "verdict": "verdict", END: END})
    g.add_conditional_edges("baseline", _after_baseline, {
        "report": "report", "verdict": "verdict", END: END})
    g.add_conditional_edges("report", _after_report, {"verdict": "verdict", END: END})
    g.add_edge("verdict", END)
    return g.compile(checkpointer=_checkpointer)


# Pre-compiled graph singleton - reused across all ainvoke calls.
_investigation_graph = build_investigation_graph()


async def run_investigation(alert_text: str | None = None, srcip: str | None = None,
                            window: str = "24h", use_attack_graph: bool = True,
                            generate_report: bool = False,
                            record_verdict: bool = False, verdict_label: str = "suspicious",
                            report_dir: str = "/tmp",
                            dependency_manifest: str | None = None) -> dict:
    """Run the investigation workflow end-to-end and return the final state summary."""
    graph = _investigation_graph  # reuse pre-compiled singleton
    initial: InvestigationState = {
        "alert_text": alert_text or "",
        "srcip": srcip,
        "window": window,
        "dependency_manifest": dependency_manifest,
        "use_attack_graph": use_attack_graph,
        "generate_report": generate_report,
        "record_verdict": record_verdict,
        "verdict_label": verdict_label,
        "report_dir": report_dir,
        "steps": [],
        "errors": [],
    }
    config = {"configurable": {"thread_id": uuid.uuid4().hex}}
    final = await graph.ainvoke(initial, config=config)
    return {
        "status": "complete",
        "srcip": srcip,
        "steps": final.get("steps", []),
        "errors": final.get("errors", []),
        "extract_iocs": (final.get("extract_iocs") or {}).get("ips", [])[:10],
        "enrichment": final.get("enrichment"),
        "vulnerabilities": final.get("vulnerabilities"),
        "correlation": (final.get("correlation") or {}).get("unified_scoring"),
        "attack_graph": final.get("attack_graph"),
        "killchain": (final.get("killchain") or {}).get("tactics_seen"),
        "baseline": (final.get("baseline") or {}).get("stats"),
        "report_path": final.get("report_path"),
        "verdict": final.get("verdict"),
    }
