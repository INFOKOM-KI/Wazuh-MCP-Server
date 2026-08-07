#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
G5: Alert-driven playbook runner (langgraph supervisor).
Given an alert (rule_id / MITRE technique / rule_groups / alert_text / srcip),
selects the matching threat-hunt template, runs the hunt, picks the top source
IP, and dispatches the G2 investigation workflow. The supervisor node retries
the hunt once with the generic (c2_beacon) template when the targeted hunt
finds no source IPs, and records every degraded step.
"""
from __future__ import annotations
import json, uuid
from typing import Annotated, Optional, TypedDict
from operator import add

from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import InMemorySaver

from mcp_server.tools.threat_hunt import _THREAT_HUNT_TEMPLATES
from mcp_server.agents.investigation_graph import run_investigation

_FALLBACK_TEMPLATE = "c2_beacon"

# Playbook metadata: rule-group keywords + investigation focus per template.
# `focus` labels which investigation steps matter most for the report narrative.
_PLAYBOOK_META: dict[str, dict] = {
    "c2_beacon":              {"rule_groups": ["c2", "beacon", "netflow", "outbound"],
                               "focus": ["extract", "enrich", "correlate", "graph", "killchain", "baseline"]},
    "credential_dumping":     {"rule_groups": ["credential", "mimikatz", "lsass"],
                               "focus": ["extract", "enrich", "killchain"]},
    "dns_tunneling":          {"rule_groups": ["dns", "tunnel"],
                               "focus": ["extract", "enrich", "correlate", "graph"]},
    "encoded_powershell":     {"rule_groups": ["powershell", "sysmon", "ps"],
                               "focus": ["extract", "enrich", "killchain"]},
    "kerberoasting":          {"rule_groups": ["kerberos", "krbtgt"],
                               "focus": ["extract", "correlate", "killchain"]},
    "lateral_movement":       {"rule_groups": ["lateral", "psexec", "wmi", "smb"],
                               "focus": ["extract", "enrich", "correlate", "graph"]},
    "lsass_access":           {"rule_groups": ["sysmon", "lsass"],
                               "focus": ["extract", "enrich", "killchain"]},
    "suspicious_parent":      {"rule_groups": ["process", "parent"],
                               "focus": ["extract", "killchain"]},
    "suspicious_scheduled_tasks": {"rule_groups": ["schtasks", "task", "cron"],
                                   "focus": ["extract", "killchain"]},
    "web_shells":             {"rule_groups": ["web", "webshell", "apache", "nginx"],
                               "focus": ["extract", "enrich", "correlate", "graph", "killchain"]},
    "wmi_persistence":        {"rule_groups": ["wmi", "persistence"],
                               "focus": ["extract", "killchain"]},
}

_RULE_GROUP_INDEX: dict[str, str] = {
    kw: tpl for tpl, meta in _PLAYBOOK_META.items() for kw in meta["rule_groups"]
}

class PlaybookState(TypedDict, total=False):
    # inputs
    alert_text: str
    rule_id: Optional[str]
    technique: Optional[str]
    rule_groups: Optional[str]
    srcip: Optional[str]
    window: str
    use_attack_graph: bool
    generate_report: bool
    record_verdict: bool
    verdict_label: str
    report_dir: str
    # runtime
    template_name: Optional[str]
    generic_retried: bool
    hunt: Optional[dict]
    srcips: list[str]
    selected_srcip: Optional[str]
    investigation: Optional[dict]
    steps: Annotated[list[str], add]
    errors: Annotated[list[str], add]
    _route: str


# Nodes
def select_playbook(state: PlaybookState) -> dict:
    """Resolve the threat-hunt template from the alert context."""
    tpl = (state.get("template_name") or "").strip().lower()
    if tpl in _THREAT_HUNT_TEMPLATES:
        return {"template_name": tpl,
                "steps": [f"playbook: selected '{tpl}' (explicit)"]}
    technique = (state.get("technique") or "").strip().upper()
    if technique:
        for name, tmpl in _THREAT_HUNT_TEMPLATES.items():
            if technique in tmpl.get("mitre", "").upper():
                return {"template_name": name,
                        "steps": [f"playbook: selected '{name}' (MITRE {technique})"]}
    groups = (state.get("rule_groups") or "").lower()
    for kw, name in _RULE_GROUP_INDEX.items():
        if kw in groups:
            return {"template_name": name,
                    "steps": [f"playbook: selected '{name}' (rule group '{kw}')"]}
    return {"template_name": _FALLBACK_TEMPLATE,
            "steps": [f"playbook: selected '{_FALLBACK_TEMPLATE}' (fallback)"]}


async def run_hunt(state: PlaybookState) -> dict:
    from mcp_server.tools.threat_hunt import blueteam_threat_hunt, ThreatHuntInput
    tpl = state.get("template_name") or _FALLBACK_TEMPLATE
    try:
        out = await blueteam_threat_hunt(ThreatHuntInput(
            template=tpl, since=state.get("window", "24h"), response_format="json"))
        hunt = json.loads(out)
        if isinstance(hunt, dict) and hunt.get("error"):
            return {"hunt": hunt, "srcips": [],
                    "errors": [f"hunt: {hunt['error']}"],
                    "steps": [f"hunt: '{tpl}' degraded"]}
        srcips = []
        agg = (hunt.get("aggregations") or {}).get("by_srcip") or {}
        for b in (agg.get("buckets") or []):
            ip = b.get("key")
            if ip:
                srcips.append({"ip": ip, "count": b.get("doc_count", 0)})
        srcips.sort(key=lambda x: x["count"], reverse=True)
        return {"hunt": hunt, "srcips": srcips,
                "steps": [f"hunt: '{tpl}' -> {len(srcips)} srcip(s), {hunt.get('total_matching_alerts', 0)} alerts"]}
    except Exception as e:
        return {"hunt": None, "srcips": [],
                "errors": [f"hunt: {e}"], "steps": [f"hunt: '{tpl}' degraded"]}


def supervise(state: PlaybookState) -> dict:
    """Node: pick the top srcip and decide retry/investigate/end.

    Mutates state (selected_srcip, retry flags, _route); the router function
    reads _route so langgraph sees a dict update, not a bare string.
    """
    updates: dict = {}
    if state.get("srcips") and not state.get("selected_srcip"):
        updates["selected_srcip"] = state["srcips"][0]["ip"]
        updates["steps"] = [f"supervise: top srcip = {updates['selected_srcip']}"]
    retry = (not state.get("srcips")
             and state.get("template_name") != _FALLBACK_TEMPLATE
             and not state.get("generic_retried"))
    if retry:
        updates["template_name"] = _FALLBACK_TEMPLATE
        updates["generic_retried"] = True
        updates["steps"] = ["supervise: hunt empty -> retrying with c2_beacon"]
    if retry:
        updates["_route"] = "retry"
    elif state.get("selected_srcip") or state.get("srcip") or state.get("alert_text"):
        updates["_route"] = "investigate"
    else:
        updates["_route"] = END
    return updates


def route_after_supervise(state: PlaybookState) -> str:
    return state.get("_route", END)


async def investigate(state: PlaybookState) -> dict:
    srcip = state.get("selected_srcip") or state.get("srcip")
    try:
        res = await run_investigation(
            alert_text=state.get("alert_text"),
            srcip=srcip,
            window=state.get("window", "24h"),
            use_attack_graph=state.get("use_attack_graph", True),
            generate_report=state.get("generate_report", False),
            report_dir=state.get("report_dir", "/tmp"),
            record_verdict=state.get("record_verdict", False),
            verdict_label=state.get("verdict_label", "suspicious"),
        )
        steps = [f"investigate: {s}" for s in res.get("steps", [])]
        errs = [f"investigate: {e}" for e in res.get("errors", [])]
        return {"investigation": res, "steps": steps, "errors": errs}
    except Exception as e:
        return {"errors": [f"investigate: {e}"], "steps": ["investigate: degraded"]}


def build_playbook_graph():
    g = StateGraph(PlaybookState)
    g.add_node("select", select_playbook)
    g.add_node("hunt", run_hunt)
    g.add_node("supervise", supervise)
    g.add_node("investigate", investigate)

    g.add_edge(START, "select")
    g.add_edge("select", "hunt")
    g.add_edge("hunt", "supervise")
    g.add_conditional_edges("supervise", route_after_supervise, {
        "retry": "hunt", "investigate": "investigate", END: END})
    g.add_edge("investigate", END)
    return g.compile(checkpointer=InMemorySaver())


async def run_playbook(alert_text: str | None = None, rule_id: str | None = None,
                       technique: str | None = None, rule_groups: str | None = None,
                       srcip: str | None = None, template_name: str | None = None,
                       window: str = "24h", use_attack_graph: bool = True,
                       generate_report: bool = False,
                       record_verdict: bool = False, verdict_label: str = "suspicious",
                       report_dir: str = "/tmp") -> dict:
    """Run the playbook end-to-end and return the final summary."""
    graph = build_playbook_graph()
    initial: PlaybookState = {
        "alert_text": alert_text or "",
        "rule_id": rule_id,
        "technique": technique,
        "rule_groups": rule_groups,
        "srcip": srcip,
        "template_name": template_name,
        "window": window,
        "use_attack_graph": use_attack_graph,
        "generate_report": generate_report,
        "record_verdict": record_verdict,
        "verdict_label": verdict_label,
        "report_dir": report_dir,
        "srcips": [],
        "steps": [],
        "errors": [],
    }
    config = {"configurable": {"thread_id": uuid.uuid4().hex}}
    final = await graph.ainvoke(initial, config=config)
    return {
        "status": "complete",
        "template": final.get("template_name"),
        "hunt_total_alerts": (final.get("hunt") or {}).get("total_matching_alerts"),
        "hunt_srcips": [s["ip"] for s in final.get("srcips", [])][:10],
        "selected_srcip": final.get("selected_srcip") or srcip,
        "investigation": final.get("investigation"),
        "steps": final.get("steps", []),
        "errors": final.get("errors", []),
    }
