#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Dependency scan MCP tool - parse a dependency manifest and check every package
against OSV.dev for known vulnerabilities. Bridges Wazuh host inventory to CVEs:
each returned CVE ID feeds ``blueteam_cve_score`` (composite risk) and
``blueteam_cve_attack_mapping`` (MITRE ATT&CK), so the result slots directly
into the LangGraph investigation and 3-Sum Engine A (MITRE driven).
"""
from __future__ import annotations
import json
from typing import Literal
import httpx
from pydantic import BaseModel, ConfigDict, Field
from mcp_server import mcp
from mcp_server.core.audit import _audit_log, _truncate_if_needed
from mcp_server.core.http_client import CircuitOpenError, _handle_api_error
from mcp_server.threat_intel.dependency_scan import (
    MAX_PACKAGES,
    parse_dependency_list,
    scan_dependencies_bulk,
)


class DependencyScanInput(BaseModel):
    """Input model for blueteam_dependency_scan."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    raw_text: str = Field(
        ..., min_length=1,
        description=(
            "Dependency manifest contents: requirements.txt, package.json, "
            "pom.xml, or 'name:ecosystem:version' lines (one per line)."
        ),
    )
    response_format: Literal["markdown", "json"] = Field(default="markdown")


@mcp.tool(
    name="blueteam_dependency_scan",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": True},
)
async def blueteam_dependency_scan(params: DependencyScanInput) -> str:
    """Scan a dependency manifest against OSV.dev and return vulnerable packages.

    Auto-detects requirements.txt, package.json, pom.xml, or generic
    ``name:ecosystem:version`` lines, then batch-queries the OSV database for
    known vulnerabilities. Returns only packages with hits, each with its top-5
    CVEs. The CVE IDs are the hand-off: feed them to ``blueteam_cve_score`` for
    a composite risk score and to ``blueteam_cve_attack_mapping`` for MITRE
    technique/tactic mapping, so dependency findings flow into the 3-Sum
    correlation Engine A.

    **Required Permissions**: none. OSV.dev is free and unauthenticated.

    **Rate Limit**: OSV.dev is free and unauthenticated; this tool queries one
    request per package (capped at 500 packages) and caches results for 30
    minutes.

    **Worked Examples**

    1. *Scan a requirements.txt for a Python service*:
       ``blueteam_dependency_scan(raw_text="requests==2.28.0\\nflask>=2.0")``

    2. *Scan package.json dependencies*:
       ``blueteam_dependency_scan(raw_text='{"dependencies":{"lodash":"4.17.15"}}')``

    3. *JSON output for a report pipeline*:
       ``blueteam_dependency_scan(raw_text="log4j-core:2.14.1", response_format="json")``
    """
    _audit_log("blueteam_dependency_scan", {"input_chars": len(params.raw_text)})

    packages = parse_dependency_list(params.raw_text)
    if not packages:
        return ("_No parseable packages found. Expected requirements.txt, "
                "package.json, pom.xml, or 'name:ecosystem:version' lines._")

    truncated = len(packages) > MAX_PACKAGES
    packages = packages[:MAX_PACKAGES]

    try:
        results = await scan_dependencies_bulk(packages)
    except (httpx.HTTPStatusError, httpx.TimeoutException, ValueError,
            CircuitOpenError) as e:
        return _handle_api_error(e, context="blueteam_dependency_scan")

    if params.response_format == "json":
        payload = {
            "packages_scanned": len(packages),
            "vulnerable_packages": len(results),
            "truncated": truncated,
            "results": results,
        }
        return _truncate_if_needed(json.dumps(payload, indent=2, default=str))

    if not results:
        return (f"# Dependency Vulnerability Scan\n\n"
                f"_No known vulnerabilities for the {len(packages)} scanned "
                f"package(s)._{' (input truncated to %d)' % MAX_PACKAGES if truncated else ''}")

    lines = ["# Dependency Vulnerability Scan", ""]
    lines.append(f"**Packages scanned**: {len(packages)} | "
                 f"**Vulnerable**: {len(results)}")
    if truncated:
        lines.append(f"_Input truncated to {MAX_PACKAGES} packages._")
    lines.append("")

    for r in results:
        ver = f"@{r['version']}" if r["version"] else ""
        lines.append(f"## `{r['package']}{ver}` ({r['ecosystem']}) — "
                     f"{r['vuln_count']} vuln(s)")
        lines.append("")
        lines.append("| CVE | Severity | Summary |")
        lines.append("|-----|----------|---------|")
        for v in r["vulns"]:
            cves = ", ".join(f"`{c}`" for c in v["cve_ids"]) or f"`{v['id']}`"
            summary = v["summary"].replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {cves} | {v['severity']} | {summary} |")
        lines.append("")

    lines.append("_Feed the CVE IDs to `blueteam_cve_score` (risk) and "
                 "`blueteam_cve_attack_mapping` (MITRE) for correlation._")
    return _truncate_if_needed("\n".join(lines))
