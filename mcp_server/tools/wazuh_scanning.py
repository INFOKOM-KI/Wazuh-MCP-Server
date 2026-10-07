#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Wazuh vulnerability, syscheck (FIM), compliance, and geo heatmap tools.
"""
from __future__ import annotations
import json
from typing import Optional, Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from mcp_server import mcp, WAZUH_INDEXER_URL, WAZUH_INDEXER_PASSWORD, _REDACTION_POLICY_DESC, _REVEAL_OWNED_DESC, _FORENSIC_TOKEN_DESC
from mcp_server.core.audit import _audit_log, _truncate_if_needed
from mcp_server.core.redact import _redact_alert_data, _IDENTITY_PATHS
from mcp_server.wazuh.indexer import (_wazuh_indexer_post, _wazuh_indexer_field_caps,
                                       _SYSCHECK_FIELD_PATHS, _AGG_SAFE_TYPES,
                                       _WAZUH_INDEX_PATTERNS, _srcip_should_clauses)
from mcp_server.wazuh.time_utils import _parse_time_window
from mcp_server.core.validators import ValidAgentName

# Vulnerability Search
class VulnerabilityInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    since: str | None = Field(default="30d", max_length=30)
    until: str | None = Field(default=None, max_length=30)
    agent_name: ValidAgentName = Field(default=None, max_length=64)
    cve: str | None = Field(default=None, max_length=20, description="Filter by CVE ID (e.g. CVE-2024-1234)")
    severity: str | None = Field(default=None, max_length=20, description="Filter by severity: Critical, High, Medium, Low")
    top_n: int = Field(default=20, ge=3, le=100)
    response_format: Literal["markdown", "json"] = Field(default="markdown")


@mcp.tool(name="blueteam_wazuh_vulnerabilities",
          annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def blueteam_wazuh_vulnerabilities(params: VulnerabilityInput) -> str:
    """Query Wazuh vulnerability scanning results from the indexer.

    Searches ``wazuh-states-vulnerabilities-*`` index for CVE findings.
    Returns top vulnerable agents, CVE breakdown, and severity distribution.

    **Worked Examples**

    1. *All vulnerabilities last 30 days*:
       ``blueteam_wazuh_vulnerabilities()``

    2. *Filter by CVE*:
       ``blueteam_wazuh_vulnerabilities(cve="CVE-2024-6387", since="90d")``

    3. *Critical only on a specific agent*:
       ``blueteam_wazuh_vulnerabilities(severity="Critical", agent_name="dc01-prod")``
    """
    _audit_log("blueteam_wazuh_vulnerabilities", {"cve": params.cve, "severity": params.severity})
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return json.dumps({"error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set."}, indent=2)
    since_iso, until_iso = _parse_time_window(params.since, params.until)
    filters = [{"range": {"@timestamp": {"gte": since_iso, "lt": until_iso, "format": "strict_date_optional_time"}}}]
    if params.agent_name:
        filters.append({"match": {"agent.name": params.agent_name}})
    if params.cve:
        filters.append({"match": {"vulnerability.cve": params.cve.strip().upper()}})
    if params.severity:
        filters.append({"match": {"vulnerability.severity": params.severity.strip()}})
    body = {"size": 0, "query": {"bool": {"filter": filters}},
            "aggs": {"by_cve": {"terms": {"field": "vulnerability.cve", "size": params.top_n,
                                          "order": {"_count": "desc"}}},
                     "by_agent": {"terms": {"field": "agent.name", "size": params.top_n}},
                     "by_severity": {"terms": {"field": "vulnerability.severity", "size": 10}}}}
    raw = await _wazuh_indexer_post(body, index_pattern=_WAZUH_INDEX_PATTERNS["vulnerabilities"])
    if "error" in raw:
        return json.dumps(raw, indent=2)
    aggs = _redact_alert_data(raw.get("aggregations", {}))
    total = raw.get("hits", {}).get("total", {}).get("value", 0)
    if params.response_format == "json":
        return json.dumps({"total": total, "aggregations": aggs}, indent=2, ensure_ascii=False)
    lines = [f"# 🛡️ Vulnerability Scan — `{since_iso}` → `{until_iso}`", "",
             f"**Total findings**: {total:,}", ""]
    sev = aggs.get("by_severity", {}).get("buckets", [])
    if sev:
        lines.append("## Severity")
        for s in sev:
            lines.append(f"- **{s['key']}**: {s['doc_count']:,}")
        lines.append("")
    cves = aggs.get("by_cve", {}).get("buckets", [])
    if cves:
        lines.append(f"## Top CVEs ({len(cves)})")
        lines.append("| CVE | Count |")
        lines.append("|-----|-------|")
        for c in cves[:20]:
            lines.append(f"| `{c['key']}` | {c['doc_count']:,} |")
        lines.append("")
    agents = aggs.get("by_agent", {}).get("buckets", [])
    if agents:
        lines.append("## Affected Agents")
        for a in agents[:15]:
            lines.append(f"- `{a['key']}`: {a['doc_count']:,} findings")
    return _truncate_if_needed("\n".join(lines))


# Syscheck / FIM
class SyscheckInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    since: str | None = Field(default="24h", max_length=30)
    until: str | None = Field(default=None, max_length=30)
    agent_name: ValidAgentName = Field(default=None, max_length=64)
    event_type: str | None = Field(default=None, max_length=20,
                                    description="Filter: added, modified, deleted")
    path_filter: str | None = Field(default=None, max_length=256,
                                     description="Filter by file path (wildcard, e.g. '/etc/*')")
    syscheck_field: Optional[str] = Field(default=None, max_length=64,
        description="Any template syscheck leaf to filter on (e.g. 'syscheck.md5_after'); "
                    "requires syscheck_value. '*'/'?' in the value switch to wildcard matching.")
    syscheck_value: Optional[str] = Field(default=None, max_length=256,
        description="Value for syscheck_field.")
    changed_attribute: Optional[str] = Field(default=None, max_length=64,
        description="Filter syscheck.changed_attributes containing this attribute (e.g. 'md5').")
    include_diff: bool = Field(default=False,
        description="Include sampled syscheck.diff excerpts in the response.")
    by_field: Optional[str] = Field(default=None, max_length=64,
        description="Group by a template syscheck leaf (e.g. 'syscheck.uid_after').")
    top_n: int = Field(default=20, ge=3, le=50)
    response_format: Literal["markdown", "json"] = Field(default="markdown")

    @field_validator("syscheck_field", "by_field")
    @classmethod
    def validate_syscheck_field(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip()
        if v not in _SYSCHECK_FIELD_PATHS:
            raise ValueError(
                f"'{v}' is not a template syscheck field. "
                "Use blueteam_index_schema(index='wazuh-alerts-*') to list valid fields."
            )
        return v

    @model_validator(mode="after")
    def require_value_with_field(self) -> "SyscheckInput":
        if self.syscheck_field and not (self.syscheck_value or "").strip():
            raise ValueError("syscheck_value is required when syscheck_field is set")
        if self.syscheck_value and not self.syscheck_field:
            raise ValueError("syscheck_field is required when syscheck_value is set")
        return self


@mcp.tool(name="blueteam_wazuh_syscheck",
          annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def blueteam_wazuh_syscheck(params: SyscheckInput) -> str:
    """Query Wazuh File Integrity Monitoring (syscheck) events from the indexer.

    Detects file changes - additions, modifications, deletions across agents.
    Essential for finding unauthorized file modifications, backdoor persistence,
    and configuration tampering.

    Optional FIM drill-down: filter any template syscheck field
    (``syscheck_field`` + ``syscheck_value``), match a changed attribute
    (``changed_attribute``), group by a syscheck leaf (``by_field``), and
    include sampled ``syscheck.diff`` excerpts (``include_diff``).

    **Worked Examples**

    1. *All FIM events last 24h*:
       ``blueteam_wazuh_syscheck()``

    2. *Modified files under /etc/*:
       ``blueteam_wazuh_syscheck(event_type="modified", path_filter="/etc/*", since="7d")``

    3. *Deleted files on a specific agent*:
       ``blueteam_wazuh_syscheck(event_type="deleted", agent_name="web-prod", since="24h")``
    """
    _audit_log("blueteam_wazuh_syscheck", {"event_type": params.event_type, "path_filter": params.path_filter})
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return json.dumps({"error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set."}, indent=2)
    since_iso, until_iso = _parse_time_window(params.since, params.until)
    filters = [{"range": {"@timestamp": {"gte": since_iso, "lt": until_iso, "format": "strict_date_optional_time"}}}]
    if params.agent_name:
        filters.append({"match": {"agent.name": params.agent_name}})
    if params.event_type:
        filters.append({"match": {"syscheck.event": params.event_type.strip()}})
    if params.path_filter:
        filters.append({"wildcard": {"syscheck.path": params.path_filter.strip()}})
    if params.syscheck_field:
        value = (params.syscheck_value or "").strip()
        if "*" in value or "?" in value:
            filters.append({"wildcard": {params.syscheck_field: value}})
        else:
            filters.append({"term": {params.syscheck_field: value}})
    if params.changed_attribute:
        filters.append({"wildcard": {"syscheck.changed_attributes":
                                     f"*{params.changed_attribute.strip()}*"}})

    by_field_agg: Optional[str] = None
    if params.by_field:
        caps = await _wazuh_indexer_field_caps([params.by_field, f"{params.by_field}.keyword"])
        if caps.get(params.by_field) in _AGG_SAFE_TYPES:
            by_field_agg = params.by_field
        elif caps.get(f"{params.by_field}.keyword") in _AGG_SAFE_TYPES:
            by_field_agg = f"{params.by_field}.keyword"
        else:
            return json.dumps({"error": f"'{params.by_field}' is not aggregatable in the "
                                        "current index mapping."}, indent=2)

    body = {"size": 0, "query": {"bool": {"filter": filters}},
            "aggs": {"by_agent": {"terms": {"field": "agent.name", "size": params.top_n}},
                     "by_event": {"terms": {"field": "syscheck.event", "size": 3}},
                     "by_path": {"terms": {"field": "syscheck.path", "size": params.top_n,
                                           "order": {"_count": "desc"}}}}}
    if by_field_agg:
        body["aggs"]["by_field"] = {"terms": {"field": by_field_agg, "size": params.top_n,
                                              "order": {"_count": "desc"}}}
    if params.include_diff:
        body["aggs"]["diff_samples"] = {"top_hits": {
            "size": min(params.top_n, 10),
            "_source": {"includes": ["syscheck.path", "syscheck.diff",
                                     "syscheck.event", "@timestamp"]},
            "sort": [{"@timestamp": "desc"}]}}
    raw = await _wazuh_indexer_post(body)
    if "error" in raw:
        return json.dumps(raw, indent=2)
    aggs = _redact_alert_data(raw.get("aggregations", {}))
    total = raw.get("hits", {}).get("total", {}).get("value", 0)
    if params.response_format == "json":
        return json.dumps({"total": total, "aggregations": aggs}, indent=2, ensure_ascii=False)
    lines = [f"# 📁 FIM / Syscheck — `{since_iso}` → `{until_iso}`", "",
             f"**Total events**: {total:,}", ""]
    evt = aggs.get("by_event", {}).get("buckets", [])
    if evt:
        lines.append("## Event Types")
        for e in evt:
            lines.append(f"- **{e['key']}**: {e['doc_count']:,}")
        lines.append("")
    paths = aggs.get("by_path", {}).get("buckets", [])
    if paths:
        lines.append(f"## Top Changed Paths ({len(paths)})")
        lines.append("| Path | Count |")
        lines.append("|------|-------|")
        for p in paths[:20]:
            lines.append(f"| `{p['key']}` | {p['doc_count']:,} |")
        lines.append("")
    agents = aggs.get("by_agent", {}).get("buckets", [])
    if agents:
        lines.append("## By Agent")
        for a in agents[:15]:
            lines.append(f"- `{a['key']}`: {a['doc_count']:,} events")
    by_field_buckets = aggs.get("by_field", {}).get("buckets", [])
    if by_field_buckets:
        lines.append("")
        lines.append(f"## By `{params.by_field}`")
        for b in by_field_buckets[:20]:
            key = b.get("key")
            if params.by_field in _IDENTITY_PATHS and isinstance(key, str) and key:
                key = _redact_alert_data({params.by_field: key})[params.by_field]
            lines.append(f"- `{key}`: {b['doc_count']:,} events")
    if params.include_diff:
        samples = (aggs.get("diff_samples", {}).get("hits", {}) or {}).get("hits", [])
        if samples:
            lines.append("")
            lines.append("## Sampled Diffs")
            for s in samples[:10]:
                sc = s.get("_source", {}).get("syscheck", {})
                if not isinstance(sc, dict):
                    continue
                lines.append(f"- `{sc.get('path', '?')}` ({sc.get('event', '?')})")
                if sc.get("diff"):
                    lines.append(f"```\n{sc['diff']}\n```")
    if total == 0:
        lines.append("✅ No FIM events found in this window.")
    return _truncate_if_needed("\n".join(lines))


# Compliance
COMPLIANCE_FIELDS = {"cis": "rule.cis", "pci_dss": "rule.pci_dss", "gdpr": "rule.gdpr",
                      "hipaa": "rule.hipaa", "nist": "rule.nist_800_53"}

class ComplianceInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    since: str | None = Field(default="30d", max_length=30)
    until: str | None = Field(default=None, max_length=30)
    agent_name: ValidAgentName = Field(default=None, max_length=64)
    framework: str = Field(default="all", max_length=20,
                           description="Compliance framework: all, cis, pci_dss, gdpr, hipaa, nist")
    top_n: int = Field(default=20, ge=3, le=50)
    response_format: Literal["markdown", "json"] = Field(default="markdown")


@mcp.tool(name="blueteam_wazuh_compliance",
          annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def blueteam_wazuh_compliance(params: ComplianceInput) -> str:
    """Summarize Wazuh alerts by compliance framework (CIS, PCI DSS, GDPR, HIPAA, NIST 800-53).

    Wazuh maps rules to compliance controls. This tool aggregates alerts by
    framework, showing which controls have the most findings essential for
    audit preparation and compliance gap analysis.

    **Worked Examples**

    1. *All frameworks overview*:
       ``blueteam_wazuh_compliance()``

    2. *PCI DSS only*:
       ``blueteam_wazuh_compliance(framework="pci_dss", since="90d")``

    3. *CIS on a specific agent*:
       ``blueteam_wazuh_compliance(framework="cis", agent_name="db-prod")``
    """
    _audit_log("blueteam_wazuh_compliance", {"framework": params.framework})
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return json.dumps({"error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set."}, indent=2)
    since_iso, until_iso = _parse_time_window(params.since, params.until)
    filters = [{"range": {"@timestamp": {"gte": since_iso, "lt": until_iso, "format": "strict_date_optional_time"}}}]
    if params.agent_name:
        filters.append({"match": {"agent.name": params.agent_name}})
    # Select framework fields
    if params.framework == "all":
        frameworks = list(COMPLIANCE_FIELDS.keys())
    elif params.framework in COMPLIANCE_FIELDS:
        frameworks = [params.framework]
    else:
        return json.dumps({"error": f"Unknown framework '{params.framework}'. Valid: all, {', '.join(COMPLIANCE_FIELDS)}"}, indent=2)
    aggs = {}
    if len(frameworks) > 1:
        # framework="all" -> OR the exists filters (alerts with ANY compliance mapping)
        filters.append({"bool": {"should": [{"exists": {"field": COMPLIANCE_FIELDS[fw]}}
                                             for fw in frameworks],
                                    "minimum_should_match": 1}})
    else:
        filters.append({"exists": {"field": COMPLIANCE_FIELDS[frameworks[0]]}})
    for fw in frameworks:
        aggs[f"by_{fw}"] = {"terms": {"field": COMPLIANCE_FIELDS[fw], "size": params.top_n}}
    body = {"size": 0, "query": {"bool": {"filter": filters}}, "aggs": aggs}
    raw = await _wazuh_indexer_post(body)
    if "error" in raw:
        return json.dumps(raw, indent=2)
    aggs_result = _redact_alert_data(raw.get("aggregations", {}))
    total = raw.get("hits", {}).get("total", {}).get("value", 0)
    if params.response_format == "json":
        return json.dumps({"total": total, "aggregations": aggs_result}, indent=2, ensure_ascii=False)
    lines = [f"# 📋 Compliance Summary - `{since_iso}` -> `{until_iso}`", "",
             f"**Framework**: {params.framework}", f"**Total alerts with compliance data**: {total:,}", ""]
    for fw in frameworks:
        buckets = aggs_result.get(f"by_{fw}", {}).get("buckets", [])
        if buckets:
            fw_label = fw.upper().replace("_", " ")
            lines.append(f"## {fw_label}")
            lines.append("| Control | Alerts |")
            lines.append("|---------|--------|")
            for b in buckets[:15]:
                lines.append(f"| `{b['key']}` | {b['doc_count']:,} |")
            lines.append("")
    if total == 0:
        lines.append("✅ No alerts with compliance mappings found.")
    return _truncate_if_needed("\n".join(lines))


# Geo Heatmap
class GeoHeatmapInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    since: str | None = Field(default="24h", max_length=30)
    until: str | None = Field(default=None, max_length=30)
    srcip: str | None = Field(default=None, max_length=45)
    top_n: int = Field(default=30, ge=3, le=100)
    response_format: Literal["markdown", "json"] = Field(default="markdown")
    bypass_redaction: bool = Field(default=False,
        description="Accepted for API consistency. Heatmap returns aggregates only (no raw PII).")
    redaction_policy: Optional[Literal["full", "protect_victim", "raw"]] = Field(
        default=None,
        description=_REDACTION_POLICY_DESC,
    )
    reveal_owned: bool = Field(default=False, description=_REVEAL_OWNED_DESC)
    forensic_token: Optional[str] = Field(default=None, max_length=128, description=_FORENSIC_TOKEN_DESC)


def _centroid_coord(bucket: dict, axis: str, digits: int = 4) -> Optional[float]:
    """City centroid axis from a ``geo_centroid`` bucket.
    ``None`` when the bucket holds no valid point unmeasured, not zero. The
    separate ``GeoLocation.latitude``/``longitude`` fields are mapped but
    unpopulated in this deployment, and mapping an absent coordinate to 0 pins
    every city in the Gulf of Guinea.
    """
    location = (bucket.get("centroid") or {}).get("location") or {}
    value = location.get(axis)
    return None if value is None else round(float(value), digits)


@mcp.tool(name="blueteam_wazuh_geo_heatmap",
          annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def blueteam_wazuh_geo_heatmap(params: GeoHeatmapInput) -> str:
    """Generate attack coordinate and city-level geo heatmap data.
    Aggregates alerts by GeoLocation.city_name with the bucket's geo centroid
    for external heatmap visualization (e.g. Leaflet, Kepler.gl).
    Returns top attacking cities with coordinates, alert counts, and IP counts.

    Args:
        params.bypass_redaction: When true, skip PII/credential redaction for audit investigations.
        params.redaction_policy: 'full' (shape-based, default), 'protect_victim' (mask victim-owned indicators only), 'raw' (Layer 1 credential strip only, requires BLUETEAM_ALLOW_FORENSIC_BYPASS).
        params.reveal_owned: When true (forensic), expose emails/subdomains at owned domains (BLUETEAM_OWNED_DOMAINS) unmasked; Layer 1 credentials remain masked.
        params.forensic_token: Operator forensic token (matches BLUETEAM_FORENSIC_TOKEN); required for redaction_policy='raw' / bypass_redaction when that env is set.

    **Worked Examples**

    1. *Global attack heatmap last 24h*:
       ``blueteam_wazuh_geo_heatmap()``

    2. *Heatmap for a specific attacker IP*:
       ``blueteam_wazuh_geo_heatmap(srcip="103.166.210.53", since="7d")``

    3. *JSON output for visualization tool*:
       ``blueteam_wazuh_geo_heatmap(response_format="json")``
    """
    _audit_log("blueteam_wazuh_geo_heatmap", {"srcip": params.srcip})
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return json.dumps({"error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set."}, indent=2)
    since_iso, until_iso = _parse_time_window(params.since, params.until)
    filters = [{"range": {"@timestamp": {"gte": since_iso, "lt": until_iso, "format": "strict_date_optional_time"}}},
               {"exists": {"field": "GeoLocation.location"}}]
    if params.srcip:
        filters.append(_srcip_should_clauses(params.srcip))
    body = {"size": 0, "query": {"bool": {"filter": filters}},
            "aggs": {"by_city": {"terms": {"field": "GeoLocation.city_name", "size": params.top_n,
                                           "order": {"_count": "desc"}},
                                 "aggs": {"centroid": {"geo_centroid": {"field": "GeoLocation.location"}},
                                          # Single-path cardinality: exact cross-path counting needs terms scans.
                                          "unique_ips": {"cardinality": {"field": "data.srcip",
                                                                         "precision_threshold": 40000}}}}}}
    raw = await _wazuh_indexer_post(body)
    if "error" in raw:
        return json.dumps(raw, indent=2)
    aggs = _redact_alert_data(raw.get("aggregations", {}), reveal_owned=params.reveal_owned)
    total = raw.get("hits", {}).get("total", {}).get("value", 0)
    buckets = aggs.get("by_city", {}).get("buckets", [])
    if params.response_format == "json":
        return json.dumps({"total": total, "cities": [
            {"city": b["key"], "alerts": b["doc_count"],
             "lat": _centroid_coord(b, "lat"), "lon": _centroid_coord(b, "lon"),
             "unique_ips": b.get("unique_ips", {}).get("value", 0)}
            for b in buckets
        ]}, indent=2, ensure_ascii=False)
    lines = [f"# 🗺️ Geo Heatmap - `{since_iso}` -> `{until_iso}`", "",
             f"**Total alerts with coordinates**: {total:,}", ""]
    if params.srcip:
        lines.append(f"**Source IP filter**: `{params.srcip}`")
    lines.extend(["", "| City | Alerts | Lat | Lon | Unique IPs |",
                   "|------|--------|-----|-----|------------|"])
    for b in buckets[:25]:
        lat = _centroid_coord(b, "lat", 2)
        lon = _centroid_coord(b, "lon", 2)
        ips = b.get("unique_ips", {}).get("value", 0)
        lines.append(f"| {b['key']} | {b['doc_count']:,} | {lat} | {lon} | {ips:,} |")
    if total == 0:
        lines.append("| *(no data)* | - | - | - | - |")
    return _truncate_if_needed("\n".join(lines))
