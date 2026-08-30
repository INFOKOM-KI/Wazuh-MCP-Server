#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Vendor advisory MCP tool - pull Microsoft (MSRC), Red Hat, and Ubuntu security
advisories for a CVE. This is the remediation half of CVE triage: after
``blueteam_cve_score`` (risk) and ``blueteam_cve_ssvc`` (action band), this tool
returns the vendor patch guidance (advisory IDs, affected products, USN notices).
"""
from __future__ import annotations
import json
from typing import Literal
import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator
from mcp_server import mcp
from mcp_server.core.audit import _audit_log, _truncate_if_needed
from mcp_server.core.http_client import CircuitOpenError, _handle_api_error
from mcp_server.threat_intel.cve_enrichment import normalize_cve
from mcp_server.threat_intel.vendor_advisory import get_vendor_advisory


class CveAdvisoryInput(BaseModel):
    """Input model for blueteam_cve_advisory."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    cve_id: str = Field(..., min_length=10, max_length=20,
                        description="CVE ID to look up vendor advisories for, e.g. 'CVE-2021-44228'.")
    response_format: Literal["markdown", "json"] = Field(default="markdown")

    @field_validator("cve_id")
    @classmethod
    def validate_cve(cls, v: str) -> str:
        norm = normalize_cve(v)
        if norm is None:
            raise ValueError("cve_id must match CVE-YYYY-NNNN, e.g. CVE-2021-44228")
        return norm


@mcp.tool(
    name="blueteam_cve_advisory",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": True},
)
async def blueteam_cve_advisory(params: CveAdvisoryInput) -> str:
    """Fetch Microsoft (MSRC), Red Hat, and Ubuntu security advisories for a CVE.

    Returns the remediation guidance the numeric scores can't give: vendor
    severity, affected products, advisory IDs (RHSA / USN), and patch state.
    Pair with ``blueteam_cve_score`` (risk) and ``blueteam_cve_ssvc`` (action
    band) for a full triage-to-remediation loop.

    **Required Permissions**: none. All three vendor APIs are public.

    **Rate Limit**: Red Hat and MSRC are lightly rate-limited; results are
    cached for 4 hours.

    **Worked Examples**

    1. *Get remediation guidance for log4shell*:
       ``blueteam_cve_advisory(cve_id="CVE-2021-44228")``

    2. *JSON output for a report pipeline*:
       ``blueteam_cve_advisory(cve_id="CVE-2024-6387", response_format="json")``

    3. *CVE with no vendor tracking*:
       ``blueteam_cve_advisory(cve_id="CVE-2024-1234")``
    """
    _audit_log("blueteam_cve_advisory", {"cve_id": params.cve_id})

    try:
        result = await get_vendor_advisory(params.cve_id)
    except (httpx.HTTPStatusError, httpx.TimeoutException, ValueError,
            CircuitOpenError) as e:
        return _handle_api_error(e, context="blueteam_cve_advisory")

    if params.response_format == "json":
        return _truncate_if_needed(json.dumps(result, indent=2, default=str))

    cve = result["cve_id"]
    lines = [f"# Vendor Advisories - `{cve}`", ""]
    found_any = False

    ms = result.get("microsoft") or {}
    lines.append("## Microsoft (MSRC)")
    if ms.get("_error"):
        lines.append(f"_Lookup failed ({ms['_error']}), retry._")
    elif ms:
        found_any = True
        lines.append(f"**{ms.get('title')}** - {ms.get('product') or 'n/a'}")
        lines.append(f"Exploited: {ms.get('exploited') or 'n/a'} | "
                     f"Publicly disclosed: {ms.get('publicly_disclosed') or 'n/a'}")
        if ms.get("release_date"):
            lines.append(f"Released: {ms.get('release_date')}")
        if ms.get("description"):
            lines.append("")
            lines.append(ms["description"])
    else:
        lines.append("_No advisory._")
    lines.append("")

    rh = result.get("redhat") or {}
    lines.append("## Red Hat")
    if rh.get("_error"):
        lines.append(f"_Lookup failed ({rh['_error']}), retry._")
    elif rh:
        found_any = True
        head = f"**Severity**: {rh.get('severity') or 'n/a'}"
        if rh.get("cvss3_score"):
            head += f" (CVSS {rh['cvss3_score']})"
        lines.append(head)
        if rh.get("cwe"):
            lines.append(f"CWE: {rh['cwe']}")
        for a in rh.get("advisories", []):
            lines.append(f"- {a['advisory']} — {a['package']} ({a['product_name']})")
        affected = [s for s in rh.get("package_states", [])
                    if s.get("state") and s["state"].lower() not in
                    ("not affected", "will not fix")]
        if affected:
            lines.append(f"**Affected packages**: "
                         f"{', '.join(s['package'] for s in affected[:10])}")
    else:
        lines.append("_No advisory._")
    lines.append("")

    ub = result.get("ubuntu") or {}
    lines.append("## Ubuntu")
    if ub.get("_error"):
        lines.append(f"_Lookup failed ({ub['_error']}), retry._")
    elif ub:
        found_any = True
        head = f"**Priority**: {ub.get('priority') or 'n/a'}"
        if ub.get("cvss3"):
            head += f" (CVSS {ub['cvss3']})"
        lines.append(head)
        if ub.get("description"):
            lines.append("")
            lines.append(ub["description"])
        for n in ub.get("notices", []):
            lines.append(f"- {n['id']} — {n['title']}")
    else:
        lines.append("_No advisory._")
    lines.append("")

    if not found_any:
        lines.append("_No vendor advisory found for this CVE._")
    return _truncate_if_needed("\n".join(lines))
