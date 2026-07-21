#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Wazuh SIEM tools — agents, alerts, manager logs, rules, decoders, groups, cluster, security events
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Optional
from typing import Optional, Literal
from pydantic import BaseModel, ConfigDict, Field
from mcp_server import WAZUH_INDEXER_PASSWORD
from mcp_server.core.constants import _WAZUH_ALERTS_MAX_LINES, MITRE_TACTIC_TO_CATEGORY
from mcp_server import WAZUH_INDEXER_URL

from mcp_server import mcp
from mcp_server.core.audit import _audit_log, _truncate_if_needed
from mcp_server.core.redact import _redact_alert_data
from mcp_server.wazuh.auth import _wazuh_api_get
from mcp_server.wazuh.indexer import _WAZUH_INDEX_PATTERNS

# blueteam_wazuh_get_rules
class WazuhRulesInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    rule_id: Optional[str] = Field(default=None, max_length=16)
    limit: int = Field(default=50, ge=1, le=500)
    response_format: Literal["markdown","json"] = Field(default="markdown")

@mcp.tool(name="blueteam_wazuh_get_rules", annotations={"readOnlyHint":True,"destructiveHint":False,"idempotentHint":True,"openWorldHint":False})
async def blueteam_wazuh_get_rules(params: WazuhRulesInput) -> str:
    _audit_log("blueteam_wazuh_get_rules", {"rule_id": params.rule_id})
    api = {"limit": str(params.limit)}
    if params.rule_id: api["rule_ids"] = params.rule_id.strip()
    data = await _wazuh_api_get("/rules", api)
    if isinstance(data.get("error"), str): return json.dumps(data, indent=2)
    items = data.get("data",{}).get("affected_items",[])
    if params.response_format == "json":
        return _truncate_if_needed(json.dumps({"count":len(items),"rules":items[:params.limit]},indent=2))
    return _truncate_if_needed("\n".join([f"# Wazuh Rules ({len(items)})",""]+[f"- `{r.get('id','?')}` (L{r.get('level','?')}): {r.get('description','?')[:80]}" for r in items[:30]]))

# blueteam_wazuh_get_decoders
class WazuhDecodersInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    decoder_name: Optional[str] = Field(default=None, max_length=64)
    limit: int = Field(default=50, ge=1, le=500)
    response_format: Literal["markdown","json"] = Field(default="markdown")

@mcp.tool(name="blueteam_wazuh_get_decoders", annotations={"readOnlyHint":True,"destructiveHint":False,"idempotentHint":True,"openWorldHint":False})
async def blueteam_wazuh_get_decoders(params: WazuhDecodersInput) -> str:
    _audit_log("blueteam_wazuh_get_decoders", {"decoder": params.decoder_name})
    api = {"limit": str(params.limit)}
    if params.decoder_name: api["decoder_names"] = params.decoder_name.strip()
    data = await _wazuh_api_get("/decoders", api)
    if isinstance(data.get("error"), str): return json.dumps(data, indent=2)
    items = data.get("data",{}).get("affected_items",[])
    if params.response_format == "json":
        return _truncate_if_needed(json.dumps({"count":len(items),"decoders":items[:params.limit]},indent=2))
    return _truncate_if_needed("\n".join([f"# Wazuh Decoders ({len(items)})",""]+[f"- `{d.get('name','?')}`: {str(d.get('details',''))[:60]}" for d in items[:30]]))

# blueteam_wazuh_get_groups
class WazuhGroupsInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    group_name: Optional[str] = Field(default=None, max_length=64)
    response_format: Literal["markdown","json"] = Field(default="markdown")

@mcp.tool(name="blueteam_wazuh_get_groups", annotations={"readOnlyHint":True,"destructiveHint":False,"idempotentHint":True,"openWorldHint":False})
async def blueteam_wazuh_get_groups(params: WazuhGroupsInput) -> str:
    _audit_log("blueteam_wazuh_get_groups", {"group": params.group_name})
    api = {}
    if params.group_name: api["group_list"] = params.group_name.strip()
    data = await _wazuh_api_get("/groups", api)
    if isinstance(data.get("error"), str): return json.dumps(data, indent=2)
    items = data.get("data",{}).get("affected_items",[])
    if params.response_format == "json":
        return _truncate_if_needed(json.dumps({"count":len(items),"groups":items},indent=2))
    return _truncate_if_needed("\n".join([f"# Agent Groups ({len(items)})",""]+[f"- `{g.get('name','?')}` ({g.get('count',0)} agents)" for g in items[:30]]))

# blueteam_wazuh_get_security_events
class WazuhSecurityEventsInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    limit: int = Field(default=50, ge=1, le=500)
    response_format: Literal["markdown","json"] = Field(default="markdown")

@mcp.tool(name="blueteam_wazuh_get_security_events", annotations={"readOnlyHint":True,"destructiveHint":False,"idempotentHint":True,"openWorldHint":False})
async def blueteam_wazuh_get_security_events(params: WazuhSecurityEventsInput) -> str:
    _audit_log("blueteam_wazuh_get_security_events", {"limit": params.limit})
    api = {"limit": str(min(params.limit,500)), "sort": "-timestamp"}
    data = await _wazuh_api_get("/security/events", api)
    if isinstance(data.get("error"), str): return json.dumps(data, indent=2)
    items = data.get("data",{}).get("affected_items",[])
    if params.response_format == "json":
        return _truncate_if_needed(json.dumps({"count":len(items),"events":items[:params.limit]},indent=2))
    return _truncate_if_needed("\n".join([f"# Security Events ({len(items)})",""]+[f"- `[{str(e.get('timestamp','?'))[:19]}]` {e.get('user','?')}: {str(e.get('action','?'))[:80]}" for e in items[:20]]))

# blueteam_wazuh_get_cluster_nodes
class WazuhClusterNodesInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    response_format: Literal["markdown","json"] = Field(default="markdown")

@mcp.tool(name="blueteam_wazuh_get_cluster_nodes", annotations={"readOnlyHint":True,"destructiveHint":False,"idempotentHint":True,"openWorldHint":False})
async def blueteam_wazuh_get_cluster_nodes(params: WazuhClusterNodesInput) -> str:
    _audit_log("blueteam_wazuh_get_cluster_nodes", {})
    data = await _wazuh_api_get("/cluster/nodes")
    if isinstance(data.get("error"), str): return json.dumps(data, indent=2)
    items = data.get("data",{}).get("affected_items",[])
    if params.response_format == "json":
        return _truncate_if_needed(json.dumps({"count":len(items),"nodes":items},indent=2))
    return _truncate_if_needed("\n".join([f"# Cluster Nodes ({len(items)})",""]+[f"- `{n.get('name','?')}` ({n.get('type','?')}) v{n.get('version','?')} @ {n.get('ip','?')}" for n in items]))


@mcp.resource("wazuh://rules/taxonomy")
async def wazuh_rule_taxonomy() -> str:
    """Expose the current Wazuh rule taxonomy as an MCP resource.

    The LLM reads this resource before querying alerts to understand which
    rule IDs and severity levels exist without making a Manager API call.
    Returns a compact JSON summary of rule counts by level and top rule
    descriptions.
    """
    if not WAZUH_API_URL or not WAZUH_API_PASSWORD:
        return json.dumps({"error": "WAZUH_API_URL and WAZUH_API_PASSWORD must be set."})
    data = await _wazuh_api_get("/rules", {"limit": "500", "sort": "-level"})
    if isinstance(data.get("error"), str):
        return json.dumps(data)
    items = data.get("data", {}).get("affected_items", [])
    by_level: dict[int, int] = {}
    top_rules: list[dict] = []
    for r in items[:200]:
        lvl = r.get("level", 0)
        by_level[lvl] = by_level.get(lvl, 0) + 1
        top_rules.append({"id": r.get("id"), "level": lvl, "description": str(r.get("description", ""))[:80]})
    return json.dumps({
        "total_rules": len(items),
        "by_level": {str(k): v for k, v in sorted(by_level.items(), reverse=True)},
        "top_rules": top_rules[:50],
    }, indent=2)


# MITRE ATT&CK Resource
# Embedded MITRE technique catalog - common techniques the LLM encounters in alerts.
# Full framework: https://attack.mitre.org - this subset covers the most frequent Wazuh detections.
_MITRE_TECHNIQUES: dict[str, dict] = {
    # Reconnaissance
    "T1595": {"name": "Active Scanning", "tactic": "Reconnaissance",
              "desc": "Adversary scans victim infrastructure via port scans, vulnerability scans, or wordlist scanning."},
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery",
              "desc": "Adversary scans for open services/ports — typical Nmap/SYN scan behavior."},
    # Initial Access
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access",
              "desc": "Adversary exploits internet-facing app vulnerability (CVE) for initial foothold."},
    "T1078": {"name": "Valid Accounts", "tactic": "Initial Access",
              "desc": "Adversary uses stolen/compromised credentials for initial access."},
    "T1566": {"name": "Phishing", "tactic": "Initial Access",
              "desc": "Adversary sends spearphishing emails with malicious attachments or links."},
    # Execution
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution",
              "desc": "Adversary executes commands/scripts — PowerShell, bash, Python, wscript, etc."},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution",
                    "desc": "PowerShell execution — often encoded (-enc) or obfuscated."},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Execution",
              "desc": "Adversary creates scheduled tasks (schtasks, at, cron) for persistence/recurring execution."},
    # Persistence
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "Persistence",
              "desc": "Adversary adds entries to Run keys, Startup folder, or logon scripts."},
    "T1546": {"name": "Event Triggered Execution", "tactic": "Persistence",
              "desc": "Adversary sets up triggers — WMI event subscriptions, .bashrc/.profile hooks."},
    "T1505": {"name": "Server Software Component", "tactic": "Persistence",
              "desc": "Adversary installs web shells, SQL triggers, or other server-side persistence."},
    # Privilege Escalation
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation",
              "desc": "Adversary exploits kernel or service vulnerability to elevate from user to root/SYSTEM."},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation",
              "desc": "Adversary abuses sudo, UAC bypass, or Setuid binaries to elevate."},
    # Defense Evasion
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion",
              "desc": "Adversary encodes/encrypts payloads — base64, XOR, AES — to evade signature detection."},
    "T1070": {"name": "Indicator Removal", "tactic": "Defense Evasion",
              "desc": "Adversary clears logs, deletes files, or wipes bash history to cover tracks."},
    "T1562": {"name": "Impair Defenses", "tactic": "Defense Evasion",
              "desc": "Adversary disables firewall, stops security services, or uninstalls AV/EDR."},
    # Credential Access
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access",
              "desc": "Adversary dumps credentials — mimikatz, LSASS memory, /etc/shadow, SAM hive."},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access",
              "desc": "Adversary brute-forces SSH, RDP, FTP, or web login forms."},
    "T1555": {"name": "Credentials from Password Stores", "tactic": "Credential Access",
              "desc": "Adversary extracts saved credentials from browsers, keychains, or password managers."},
    # Discovery
    "T1082": {"name": "System Information Discovery", "tactic": "Discovery",
              "desc": "Adversary gathers OS version, hostname, patches — uname, systeminfo, ver."},
    "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery",
              "desc": "Adversary enumerates files — ls, dir, find, tree — looking for sensitive data."},
    "T1018": {"name": "Remote System Discovery", "tactic": "Discovery",
              "desc": "Adversary scans network for other hosts — ping sweep, net view, arp -a."},
    "T1049": {"name": "System Network Connections Discovery", "tactic": "Discovery",
              "desc": "Adversary inspects active connections — netstat, ss, lsof -i."},
    # Lateral Movement
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement",
              "desc": "Adversary moves laterally via RDP, SSH, SMB, WinRM, or VNC to other hosts."},
    "T1570": {"name": "Lateral Tool Transfer", "tactic": "Lateral Movement",
              "desc": "Adversary copies tools/payloads between hosts — scp, smbclient, certutil."},
    # Collection
    "T1560": {"name": "Archive Collected Data", "tactic": "Collection",
              "desc": "Adversary compresses/encrypts stolen data — tar, zip, rar, gpg — before exfiltration."},
    # Command and Control
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control",
              "desc": "Adversary uses HTTP/HTTPS, DNS, or WebSocket for C2 — blends with normal traffic."},
    "T1095": {"name": "Non-Application Layer Protocol", "tactic": "Command and Control",
              "desc": "Adversary uses raw TCP/UDP/ICMP for C2 — netcat, socat, custom protocols."},
    "T1572": {"name": "Protocol Tunneling", "tactic": "Command and Control",
              "desc": "Adversary tunnels C2 over DNS, ICMP, or SSH — DNS exfiltration, ICMP tunnels."},
    # Exfiltration
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration",
              "desc": "Adversary exfiltrates data over the same channel used for C2."},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration",
              "desc": "Adversary exfiltrates via DNS, ICMP, or other non-C2 channels to evade detection."},
    # Impact
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact",
              "desc": "Adversary encrypts data (ransomware) for extortion — files renamed/locked."},
    "T1485": {"name": "Data Destruction", "tactic": "Impact",
              "desc": "Adversary wipes data — rm -rf, shred, format — to disrupt operations."},
}


@mcp.resource("wazuh://mitre/attack")
async def wazuh_mitre_attack() -> str:
    """Expose MITRE ATT&CK framework mapping as an MCP resource.

    The LLM reads this resource to understand which MITRE techniques map to
    which kill-chain phases and 3-Sum correlation categories. Includes a catalog
    of 30+ common techniques with names, descriptions, and tactic mappings.

    Returns JSON with the tactic→category mapping and the technique catalog.
    """
    return json.dumps({
        "framework_version": "ATT&CK v16 (subset)",
        "tactic_to_category": MITRE_TACTIC_TO_CATEGORY,
        "categories": {
            "A": "Reconnaissance / Discovery / Resource Development — early-stage recon",
            "B": "Access / Execution / Defense Evasion / Credential Access — active intrusion",
            "C": "Persistence / C2 / Exfiltration / Impact — post-compromise / dwell",
        },
        "techniques": _MITRE_TECHNIQUES,
        "_usage": "Use tactic_to_category to map Wazuh rule.mitre.tactic to 3-Sum category (A/B/C). "
                  "Use techniques to look up technique names/descriptions from IDs seen in alerts.",
    }, indent=2)


@mcp.tool(
    name="blueteam_mitre_lookup",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
)
async def blueteam_mitre_lookup(
    technique_id: str = "",
    tactic: str = "",
) -> str:
    """Look up MITRE ATT&CK technique details or list techniques by tactic.

    Use this when a Wazuh alert contains ``rule.mitre`` fields and you need to
    understand what a technique ID means, or when building a threat hunt for a
    specific kill-chain phase.

    **Worked Examples**

    1. *What is T1003?*:
       ``blueteam_mitre_lookup(technique_id="T1003")``

    2. *List all credential access techniques*:
       ``blueteam_mitre_lookup(tactic="Credential Access")``

    3. *Both — find a specific technique and verify its tactic*:
       ``blueteam_mitre_lookup(technique_id="T1059.001", tactic="Execution")``
    """
    results: dict = {}

    if tactic:
        matches = {tid: t for tid, t in _MITRE_TECHNIQUES.items()
                   if t["tactic"].lower() == tactic.strip().lower()}
        results["tactic"] = tactic
        results["category"] = MITRE_TACTIC_TO_CATEGORY.get(tactic.strip(), "?")
        results["techniques"] = matches

    if technique_id:
        tid = technique_id.strip().upper()
        tech = _MITRE_TECHNIQUES.get(tid)
        if tech:
            results["technique"] = {"id": tid, **tech,
                                     "category": MITRE_TACTIC_TO_CATEGORY.get(tech["tactic"], "?")}
        else:
            results["technique"] = {"id": tid,
                                     "error": f"Technique {tid} not in embedded catalog. "
                                              "Check https://attack.mitre.org/techniques/{tid.replace('.','/')}/"}

    if not results:
        # Return full mapping as fallback
        results["tactic_to_category"] = MITRE_TACTIC_TO_CATEGORY
        results["technique_count"] = len(_MITRE_TECHNIQUES)
        results["hint"] = "Pass technique_id or tactic to filter."

    return json.dumps(results, indent=2, ensure_ascii=False)


# Core Wazuh tools (hand-migrated)
import json
from pathlib import Path
from mcp_server.core.constants import _WAZUH_LOG_TAG, _WAZUH_ALERTS_PATH, _WAZUH_ALERTS_MAX_LINES
from mcp_server.core.redact import _redact_alert_data
from mcp_server.core.subprocess import _run_async
from mcp_server.wazuh.auth import _wazuh_api_get

@mcp.tool(
    name="blueteam_wazuh_agents",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_wazuh_agents(limit: int = 100, cursor: Optional[str] = None) -> str:
    """List Wazuh agents with cursor pagination — one page per call."""
    _audit_log("blueteam_wazuh_agents", {})
    offset = 0
    if cursor:
        decoded = _decode_cursor(cursor)
        if decoded:
            offset = decoded.get("offset", 0)
    params = {"offset": str(offset), "limit": str(min(limit, 500))}
    data = await _wazuh_api_get("/agents", params)
    if isinstance(data.get("error"), str):
        return json.dumps(data, indent=2)
    agents = data.get("data", {}).get("affected_items", [])
    total = data.get("data", {}).get("total_affected_items", len(agents))
    next_cursor = _encode_cursor({"offset": offset + len(agents)}) if len(agents) >= limit else None
    return json.dumps({"total": total, "offset": offset, "limit": limit, "next_cursor": next_cursor, "agents": agents}, indent=2)

@mcp.tool(
    name="blueteam_wazuh_agents_summary",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_wazuh_agents_summary() -> str:
    """Get Wazuh agent count by status."""
    _audit_log("blueteam_wazuh_agents_summary", {})
    data = await _wazuh_api_get("/agents/summary/status")
    if isinstance(data.get("error"), str):
        return json.dumps(data, indent=2)
    return json.dumps(data.get("data", data), indent=2)


@mcp.tool(
    name="blueteam_wazuh_manager_logs",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def blueteam_wazuh_manager_logs(log_type: str = "alerts", limit: int = 50, cursor: Optional[str] = None) -> str:
    """Fetch Wazuh manager logs with cursor pagination."""
    _audit_log("blueteam_wazuh_manager_logs", {})
    if log_type not in _WAZUH_LOG_TAG:
        return json.dumps({"error": f"log_type must be one of: {tuple(_WAZUH_LOG_TAG)}"})
    offset = 0
    if cursor:
        decoded = _decode_cursor(cursor)
        if decoded:
            offset = decoded.get("offset", 0)
    api_params = {"offset": str(offset), "limit": str(min(limit, 500)), "pretty": "true", "tag": _WAZUH_LOG_TAG[log_type]}
    data = await _wazuh_api_get("/manager/logs", api_params)
    if isinstance(data.get("error"), str):
        return json.dumps(data, indent=2)
    items = data.get("data", {}).get("affected_items", data.get("data", []))
    if isinstance(items, dict):
        items = [items]
    total = data.get("data", {}).get("total_affected_items", len(items))
    next_cursor = _encode_cursor({"offset": offset + len(items)}) if len(items) >= limit else None
    return json.dumps({"total": total, "offset": offset, "limit": limit, "next_cursor": next_cursor, "logs": items}, indent=2)


@mcp.tool(
    name="blueteam_wazuh_alerts",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}
)
async def blueteam_wazuh_alerts(agent_name: Optional[str] = None, srcip: Optional[str] = None,
                                 since: Optional[str] = None, until: Optional[str] = None,
                                 limit: int = 500, cursor: Optional[str] = None,
                                 bypass_redaction: bool = False) -> str:
    """Read Wazuh security alerts — local alerts.json first, auto-fallback to Indexer."""
    _audit_log("blueteam_wazuh_alerts", {})
    p = Path(_WAZUH_ALERTS_PATH)
    if not p.exists():
        from mcp_server.wazuh.indexer import _wazuh_indexer_post, _WAZUH_INDEX_PATTERNS
        if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
            return json.dumps({"error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set. "
                              "Set these to enable automatic indexer fallback, or use blueteam_wazuh_manager_logs."}, indent=2)
        search_after = None
        if cursor:
            decoded = _decode_cursor(cursor)
            if decoded:
                search_after = decoded.get("search_after")
        must = [{"range": {"@timestamp": {"gte": since or "now-24h", "lt": until or "now", "format": "strict_date_optional_time"}}}]
        if agent_name: must.append({"match": {"agent.name": agent_name}})
        if srcip:
            must.append({"bool": {"should": [{"match": {"data.srcip": srcip}}, {"match_phrase": {"full_log": srcip}}], "minimum_should_match": 1}})
        body = {"size": min(limit, 2000), "sort": [{"@timestamp": {"order": "asc"}}], "query": {"bool": {"must": must}}}
        if search_after: body["search_after"] = search_after
        raw = await _wazuh_indexer_post(body)
        if "error" in raw: return json.dumps(raw, indent=2)
        hits = raw.get("hits", {})
        docs = [h.get("_source", h) for h in hits.get("hits", [])]
        next_cursor = None
        hit_list = hits.get("hits", [])
        if hit_list and len(docs) >= limit:
            last_sort = hit_list[-1].get("sort")
            if last_sort: next_cursor = _encode_cursor({"search_after": last_sort})
        return _truncate_if_needed(json.dumps({"source": "wazuh-indexer", "alerts": _redact_alert_data(docs, bypass=bypass_redaction), "count": len(docs), "next_cursor": next_cursor}, indent=2))
    # Local alerts.json path
    skip = 0
    if cursor:
        decoded = _decode_cursor(cursor)
        if decoded: skip = decoded.get("scanned", 0)
    page = min((skip + limit) * 3, _WAZUH_ALERTS_MAX_LINES)
    r = await _run_async(["tail", "-n", str(page), _WAZUH_ALERTS_PATH])
    if r.get("returncode", 0) != 0:
        return json.dumps({"error": "Failed to read alerts", "stderr": r.get("stderr", "")})
    alerts = []
    af = (agent_name or "").strip()
    ipf = (srcip or "").strip()
    scanned = 0
    for line in (r.get("stdout") or "").strip().splitlines():
        scanned += 1
        if scanned <= skip: continue
        if len(alerts) >= limit: break
        line = line.strip()
        if not line: continue
        try:
            a = json.loads(line)
            if af:
                ag = a.get("agent") or {}
                n = ag.get("name") or ag.get("id", "") if isinstance(ag, dict) else str(ag)
                if af.lower() not in (n or "").lower(): continue
            if ipf:
                ds = str(a.get("data", {}).get("srcip", ""))
                ds2 = str(a.get("data", {}).get("srcip2", ""))
                ts = str(a.get("srcip", ""))
                fl = str(a.get("full_log", ""))
                if ipf not in (ds, ds2, ts) and ipf not in fl: continue
            alerts.append(a)
        except json.JSONDecodeError: continue
    next_cursor = _encode_cursor({"scanned": scanned}) if len(alerts) >= limit else None
    return _truncate_if_needed(json.dumps({"source": "local", "alerts": alerts, "count": len(alerts), "next_cursor": next_cursor}, indent=2))

@mcp.tool(
    name="blueteam_wazuh_indexer_search",
    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}
)
async def blueteam_wazuh_indexer_search(agent_name: Optional[str] = None, srcip: Optional[str] = None,
                                         since: Optional[str] = None, until: Optional[str] = None,
                                         limit: int = 500, keyword: Optional[str] = None,
                                         response_format: str = "json") -> str:
    """Query Wazuh Indexer (OpenSearch) for alerts/events with cursor pagination."""
    _audit_log("blueteam_wazuh_indexer_search", {})
    from mcp_server.wazuh.indexer import _wazuh_indexer_post, _WAZUH_INDEX_PATTERNS, _KEYWORD_SEARCH_FIELDS
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return json.dumps({"error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set."}, indent=2)
    must = []
    if agent_name: must.append({"match": {"agent.name": agent_name}})
    if srcip:
        must.append({"bool": {"should": [{"match": {"data.srcip": srcip}}, {"match": {"data.srcip2": srcip}}, {"match": {"srcip": srcip}}, {"match_phrase": {"full_log": srcip}}], "minimum_should_match": 1}})
    if since or until:
        tr = {}
        if since: tr["gte"] = since
        if until: tr["lt"] = until
        tr["format"] = "strict_date_optional_time"
        must.append({"range": {"@timestamp": tr}})
    if keyword:
        parts = [f'{f}: ({keyword})^{b}' if b else f'{f}: ({keyword})' for f, b in _KEYWORD_SEARCH_FIELDS]
        must.append({"query_string": {"query": " OR ".join(parts), "default_operator": "AND", "lenient": True}})
    body = {"size": min(limit, 10000), "sort": [{"@timestamp": {"order": "asc"}}], "query": {"bool": {"must": must}} if must else {"match_all": {}}}
    raw = await _wazuh_indexer_post(body)
    if "error" in raw: return json.dumps(raw, indent=2)
    hits = raw.get("hits", {})
    docs = [h.get("_source", h) for h in hits.get("hits", [])]
    total = hits.get("total", {})
    total_val = total.get("value", 0) if isinstance(total, dict) else total
    return _truncate_if_needed(json.dumps({"total": {"value": total_val}, "count": len(docs), "documents": docs}, indent=2))
