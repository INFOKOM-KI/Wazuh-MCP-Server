#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
STIX/ATT&CK correlation - maps Wazuh findings to threat actors, TTPs, and campaigns
via the MITRE ATT&CK STIX 2.1 knowledge graph (pure JSON parse, no stix2 dependency).
"""
from __future__ import annotations
import json, os
from typing import Literal, Optional
from pydantic import BaseModel, ConfigDict, Field
from mcp_server import mcp
from mcp_server.core.audit import _audit_log, _truncate_if_needed

_STIX_PATH = os.environ.get("MITRE_ATTACK_STIX", "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/enterprise-attack/enterprise-attack.json")
_STIX_CACHE = "/var/log/blue-team-mcp/mitre_enterprise_attack.json"

# ATT&CK STIX 2.1 loader (lazy mode aul, cached)
_stix_data: dict | None = None
_stix_error: str | None = None


def _fetch_stix_bundle() -> dict:
    """Fetch the ATT&CK STIX bundle from URL or local path; cache to disk."""
    if os.path.exists(_STIX_PATH) and not _STIX_PATH.startswith("http"):
        with open(_STIX_PATH) as f:
            return json.load(f)
    if os.path.exists(_STIX_CACHE):
        with open(_STIX_CACHE) as f:
            return json.load(f)
    # URL fetch via stdlib urllib (no httpx dependency in loader)
    import urllib.request
    req = urllib.request.Request(_STIX_PATH, headers={"User-Agent": "blue-team-mcp/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    try:
        os.makedirs(os.path.dirname(_STIX_CACHE), exist_ok=True)
        with open(_STIX_CACHE, "w") as f:
            json.dump(data, f)
    except Exception:
        pass
    return data


def _load_stix():
    """Load and index the ATT&CK STIX bundle once. Returns (objects_by_id, ...)."""
    global _stix_data, _stix_error
    if _stix_data is not None or _stix_error:
        return
    try:
        bundle = _fetch_stix_bundle()
        objects = bundle.get("objects", [])

        by_id: dict[str, dict] = {}
        by_type: dict[str, list[dict]] = {}
        relationships: list[dict] = []
        for o in objects:
            by_id[o.get("id", "")] = o
            by_type.setdefault(o.get("type", ""), []).append(o)
            if o.get("type") == "relationship":
                relationships.append(o)

        # index relationships: object_id -> list of related objects
        rel_index: dict[str, list[dict]] = {}
        for r in relationships:
            for key in ("source_ref", "target_ref"):
                ref = r.get(key)
                if ref:
                    rel_index.setdefault(ref, []).append(r)

        _stix_data = {"by_id": by_id, "by_type": by_type,
                      "relationships": relationships, "rel_index": rel_index}
    except Exception as e:
        _stix_error = f"Failed to load STIX: {e}"


def _mitre_id(obj: dict) -> str:
    """Extract the MITRE ATT&CK external ID (e.g. T1059.001, G0001, C0025)."""
    for ref in obj.get("external_references", []):
        eid = ref.get("external_id", "")
        if eid and (eid.startswith("T") or eid.startswith("G") or eid.startswith("C")
                    or eid.startswith("S") or eid.startswith("M")):
            return eid
    return obj.get("id", "")


class StixAnalyzeInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    technique_id: Optional[str] = Field(default=None, max_length=20,
        description="MITRE ATT&CK technique ID to look up (e.g. T1059.001, T1003).")
    actor_name: Optional[str] = Field(default=None, max_length=100,
        description="Threat-actor / intrusion-set name or fragment (e.g. 'APT41', 'Lazarus').")
    campaign_name: Optional[str] = Field(default=None, max_length=100,
        description="Campaign name or fragment to look up.")
    indicator: Optional[str] = Field(default=None, max_length=200,
        description="Free-text indicator (IP, domain, malware name) — matches actor/TTP by name overlap.")
    include_actors: bool = Field(default=True, description="Return matched intrusion-sets.")
    include_ttp: bool = Field(default=True, description="Return matched attack-patterns (techniques).")
    include_campaigns: bool = Field(default=True, description="Return matched campaigns.")
    include_mitigations: bool = Field(default=True, description="Return matched courses-of-action.")
    max_relations: int = Field(default=15, ge=1, le=50)
    response_format: Literal["markdown", "json"] = Field(default="markdown")


@mcp.tool(name="blueteam_stix_analyze",
          annotations={"readOnlyHint": True, "destructiveHint": False,
                       "idempotentHint": True, "openWorldHint": True})
async def blueteam_stix_analyze(params: StixAnalyzeInput) -> str:
    """Correlate Wazuh findings with the MITRE ATT&CK STIX 2.1 knowledge graph.

    Maps MITRE technique IDs (from rule.mitre), threat-actor names, and campaigns
    to their relationships: which actors use a technique, which campaigns a TTP
    belongs to, and what mitigations exist.

    **Data source**: MITRE ATT&CK enterprise STIX bundle (set MITRE_ATTACK_STIX).

    **Worked Examples**

    1. *Map a technique to actors + mitigations*:
       ``blueteam_stix_analyze(technique_id="T1059.001")``

    2. *Find which TTPs a threat actor uses*:
       ``blueteam_stix_analyze(actor_name="Lazarus")``

    3. *Correlate a campaign*:
       ``blueteam_stix_analyze(campaign_name="Wizard Spider")``
    """
    _audit_log("blueteam_stix_analyze", {
        "technique_id": params.technique_id, "actor": params.actor_name,
        "campaign": params.campaign_name, "indicator": params.indicator})
    _load_stix()
    if _stix_error:
        return json.dumps({"error": _stix_error,
                           "hint": "Set MITRE_ATTACK_STIX to the ATT&CK enterprise-attack.json path"},
                          indent=2)
    assert _stix_data is not None
    by_id, by_type, rel_index = _stix_data["by_id"], _stix_data["by_type"], _stix_data["rel_index"]

    # Find matching objects by query
    matched: list[dict] = []
    if params.technique_id:
        tid = params.technique_id.strip().upper()
        for o in by_type.get("attack-pattern", []):
            if _mitre_id(o) == tid:
                matched.append(o)
    if params.actor_name:
        frag = params.actor_name.strip().lower()
        for o in by_type.get("intrusion-set", []):
            if frag in o.get("name", "").lower():
                matched.append(o)
    if params.campaign_name:
        frag = params.campaign_name.strip().lower()
        for o in by_type.get("campaign", []):
            if frag in o.get("name", "").lower():
                matched.append(o)
    if params.indicator and not matched:
        frag = params.indicator.strip().lower()
        for o in by_type.get("intrusion-set", []) + by_type.get("campaign", []):
            if frag in o.get("name", "").lower():
                matched.append(o)

    if not matched:
        return _truncate_if_needed(f"# STIX/ATT&CK — no match\n\nNo object matched the query. "
                                   f"Try a technique ID (T1059), actor name, or campaign name.")

    # Traverse relationships
    seen = set(matched[0]["id"] for m in matched if m.get("id"))
    results: dict[str, list[dict]] = {"actors": [], "ttps": [], "campaigns": [], "mitigations": []}
    frontier = [m.get("id") for m in matched if m.get("id")]
    hops = 0
    while frontier and hops < 2:
        next_frontier = []
        for oid in frontier:
            for rel in rel_index.get(oid, []):
                target = rel.get("target_ref")
                if not target or target in seen:
                    continue
                seen.add(target)
                next_frontier.append(target)
                obj = by_id.get(target)
                if not obj:
                    continue
                t = obj.get("type")
                if t == "intrusion-set" and params.include_actors:
                    results["actors"].append({"name": obj.get("name"), "mitre_id": _mitre_id(obj),
                                              "desc": (obj.get("description") or "")[:150],
                                              "via": rel.get("relationship_type", "related-to")})
                elif t == "attack-pattern" and params.include_ttp:
                    results["ttps"].append({"name": obj.get("name"), "mitre_id": _mitre_id(obj),
                                            "desc": (obj.get("description") or "")[:150]})
                elif t == "campaign" and params.include_campaigns:
                    results["campaigns"].append({"name": obj.get("name"), "mitre_id": _mitre_id(obj),
                                                 "desc": (obj.get("description") or "")[:150]})
                elif t == "course-of-action" and params.include_mitigations:
                    results["mitigations"].append({"name": obj.get("name"),
                                                   "desc": (obj.get("description") or "")[:150]})
        frontier = next_frontier
        hops += 1

    # Cap relation lists
    for k in results:
        results[k] = results[k][:params.max_relations]

    if params.response_format == "json":
        return json.dumps({
            "query": params.model_dump(exclude={"response_format"}),
            "matched": [{"name": o.get("name"), "mitre_id": _mitre_id(o), "type": o.get("type")}
                        for o in matched],
            **results,
        }, indent=2, ensure_ascii=False)

    lines = [f"# 🕵️ STIX/ATT&CK Correlation", "",
             f"**Query**: {json.dumps(params.model_dump(exclude={'response_format'}))}", ""]
    if matched:
        lines.append("## Matched")
        for o in matched:
            lines.append(f"- **{o.get('name')}** (`{_mitre_id(o)}`, {o.get('type')})")
        lines.append("")
    for label, key, icon in [("Threat Actors", "actors", "🦠"), ("Techniques (TTPs)", "ttps", "⚡"),
                             ("Campaigns", "campaigns", "🎯"), ("Mitigations", "mitigations", "🛡️")]:
        items = results[key]
        if items:
            lines.append(f"## {icon} {label} ({len(items)})")
            for it in items:
                extra = f" — {it.get('desc','')}" if it.get('desc') else ""
                lines.append(f"- **{it.get('name')}** (`{it.get('mitre_id','')}`){extra}")
            lines.append("")
    if not any(results.values()):
        lines.append("*No related objects found in the first two relationship hops.*")
    return _truncate_if_needed("\n".join(lines))
