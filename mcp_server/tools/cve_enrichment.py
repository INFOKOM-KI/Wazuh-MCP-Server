#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
CVE enrichment MCP tools - NVD lookup, EPSS, CISA KEV, public-PoC, composite risk.
Tier-1 port from the cve-mcp-server. These tools enrich a CVE ID surfaced by
Wazuh vulnerability alerts (``blueteam_wazuh_vulnerabilities``) with external
exploitation data the Indexer does not carry: EPSS probability, CISA KEV
membership, public-PoC availability, and a composite 0-100 risk score.
"""
from __future__ import annotations
import json
from typing import Literal
import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator
from mcp_server import mcp
from mcp_server.core.audit import _audit_log, _truncate_if_needed
from mcp_server.core.http_client import _handle_api_error
from mcp_server.threat_intel.cve_enrichment import (
    normalize_cve,
    _fetch_nvd,
    _fetch_epss,
    _fetch_kev_catalog,
    _lookup_kev,
    search_poc,
    score_cve,
    _extract_cvss_score,
)


class CveLookupInput(BaseModel):
    """Input model for blueteam_cve_lookup."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    cve_id: str = Field(
        ..., min_length=10, max_length=20,
        description="CVE ID to look up, e.g. 'CVE-2024-6387' (case-insensitive).",
    )
    response_format: Literal["markdown", "json"] = Field(default="markdown")

    @field_validator("cve_id")
    @classmethod
    def validate_cve(cls, v: str) -> str:
        norm = normalize_cve(v)
        if norm is None:
            raise ValueError("cve_id must match CVE-YYYY-NNNN, e.g. CVE-2024-6387")
        return norm


def _severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _en_description(nvd: dict) -> str:
    for d in nvd.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return (nvd.get("descriptions") or [{}])[0].get("value", "")


@mcp.tool(
    name="blueteam_cve_lookup",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": True},
)
async def blueteam_cve_lookup(params: CveLookupInput) -> str:
    """Fetch a CVE record from NVD: description, CVSS, severity, references.

    Complements ``blueteam_wazuh_vulnerabilities``, which finds CVEs in Wazuh
    alerts but carries no external description, CVSS vector, or vendor links.

    **Required Permissions**: none. Works unauthenticated (rate-limited).
    Set ``NVD_API_KEY`` to raise the limit from 5 to 50 requests / 30s.

    **Rate Limit**: NVD allows 5 req/30s without a key, 50/30s with one. This
    tool applies a 24-hour in-memory cache.

    **Worked Examples**

    1. *Enrich a CVE found in a Wazuh vulnerability alert*:
       ``blueteam_cve_lookup(cve_id="CVE-2024-6387")``

    2. *JSON output for a report*:
       ``blueteam_cve_lookup(cve_id="cve-2021-44228", response_format="json")``

    3. *Case-insensitive input*:
       ``blueteam_cve_lookup(cve_id="cve-2019-0708")``
    """
    _audit_log("blueteam_cve_lookup", {"cve_id": params.cve_id})

    try:
        nvd = await _fetch_nvd(params.cve_id)
    except (httpx.HTTPStatusError, httpx.TimeoutException, ValueError) as e:
        return _handle_api_error(e, context="blueteam_cve_lookup")

    if nvd is None:
        return json.dumps({"cve_id": params.cve_id, "found": False,
                           "detail": "No NVD record for this CVE."}, indent=2)

    cvss = _extract_cvss_score(nvd)
    refs = [r.get("url") for r in nvd.get("references", []) if r.get("url")]
    cwes = []
    for w in nvd.get("weaknesses", []):
        for d in w.get("description", []):
            cwes.append(d.get("value"))
    # CPE count (configurations -> nodes -> cpeMatch)
    cpe_count = 0
    for node in nvd.get("configurations", []):
        for m in node.get("nodes", []):
            cpe_count += len(m.get("cpeMatch", []))

    if params.response_format == "json":
        return _truncate_if_needed(json.dumps({
            "cve_id": nvd.get("id"),
            "description": _en_description(nvd),
            "cvss_score": cvss,
            "severity": _severity_from_cvss(cvss),
            "published": nvd.get("published"),
            "modified": nvd.get("lastModified"),
            "references": refs[:10],
            "weaknesses": cwes[:5],
            "cpe_count": cpe_count,
            "source": nvd.get("sourceIdentifier"),
        }, indent=2, default=str))

    lines = [f"# NVD - `{nvd.get('id')}`", ""]
    lines.append(f"**Severity**: {_severity_from_cvss(cvss)} (CVSS {cvss})")
    lines.append(f"**Published**: {nvd.get('published')} | **Modified**: {nvd.get('lastModified')}")
    lines.append("")
    lines.append(_en_description(nvd))
    if cwes:
        lines.append("")
        lines.append(f"**Weaknesses**: {', '.join(f'`{c}`' for c in cwes[:5])}")
    lines.append(f"**CPE matches**: {cpe_count}")
    if refs:
        lines.append("")
        lines.append("**References**:")
        for u in refs[:10]:
            lines.append(f"- {u}")
    return _truncate_if_needed("\n".join(lines))


class CveEpssInput(BaseModel):
    """Input model for blueteam_cve_epss."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    cve_ids: list[str] = Field(
        ..., min_length=1, max_length=50,
        description="CVE IDs to score with EPSS (max 50), e.g. ['CVE-2024-6387'].",
    )
    response_format: Literal["markdown", "json"] = Field(default="markdown")

    @field_validator("cve_ids")
    @classmethod
    def validate_cves(cls, v: list[str]) -> list[str]:
        out = []
        for c in v:
            norm = normalize_cve(c)
            if norm is None:
                raise ValueError(f"Invalid CVE ID: '{c[:30]}' (want CVE-YYYY-NNNN)")
            out.append(norm)
        return out


@mcp.tool(
    name="blueteam_cve_epss",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": True},
)
async def blueteam_cve_epss(params: CveEpssInput) -> str:
    """Return EPSS scores for one or more CVE IDs (exploitation probability).

    EPSS (Exploit Prediction Scoring System, FIRST.org) estimates the probability
    a CVE is exploited in the wild in the next 30 days, independent of CVSS
    severity. Free, no API key. Complements ``blueteam_cve_lookup``.

    **Required Permissions**: none.

    **Rate Limit**: EPSS is unauthenticated; this tool caches for 24 hours.

    **Worked Examples**

    1. *Score a single CVE from a 3-Sum trigger*:
       ``blueteam_cve_epss(cve_ids=["CVE-2024-6387"])``

    2. *Score multiple CVEs from a curated report*:
       ``blueteam_cve_epss(cve_ids=["CVE-2024-6387", "CVE-2021-44228"])``

    3. *JSON output*:
       ``blueteam_cve_epss(cve_ids=["CVE-2024-6387"], response_format="json")``
    """
    _audit_log("blueteam_cve_epss", {"count": len(params.cve_ids)})

    try:
        entries = await _fetch_epss(params.cve_ids)
    except (httpx.HTTPStatusError, httpx.TimeoutException, ValueError) as e:
        return _handle_api_error(e, context="blueteam_cve_epss")

    if params.response_format == "json":
        return _truncate_if_needed(json.dumps({
            "count": len(entries), "results": entries,
        }, indent=2, default=str))

    if not entries:
        return "_No EPSS data returned for these CVE IDs._"
    lines = ["# EPSS Scores", ""]
    lines.append("| CVE | EPSS | Percentile |")
    lines.append("|-----|------|------------|")
    for e in entries:
        epss = e.get("epss", "?")
        pct = e.get("percentile", "?")
        lines.append(f"| `{e.get('cve','?')}` | {epss} | {pct} |")
    return _truncate_if_needed("\n".join(lines))


class CveKevInput(BaseModel):
    """Input model for blueteam_cve_kev."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    cve_id: str = Field(..., min_length=10, max_length=20,
                        description="CVE ID to check against the CISA KEV catalog.")
    response_format: Literal["markdown", "json"] = Field(default="markdown")

    @field_validator("cve_id")
    @classmethod
    def validate_cve(cls, v: str) -> str:
        norm = normalize_cve(v)
        if norm is None:
            raise ValueError("cve_id must match CVE-YYYY-NNNN, e.g. CVE-2024-6387")
        return norm


@mcp.tool(
    name="blueteam_cve_kev",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": True},
)
async def blueteam_cve_kev(params: CveKevInput) -> str:
    """Check if a CVE is in the CISA Known Exploited Vulnerabilities (KEV) catalog.

    KEV membership means the CVE is *known to be actively exploited in the
    wild* - the single strongest exploitation signal. A KEV hit should be
    treated as critical regardless of CVSS. Catalog is fetched fresh daily.

    **Required Permissions**: none. Public CISA feed.

    **Worked Examples**

    1. *Gate a patch decision*:
       ``blueteam_cve_kev(cve_id="CVE-2024-6387")``

    2. *JSON output*:
       ``blueteam_cve_kev(cve_id="CVE-2021-44228", response_format="json")``

    3. *Check a log4j CVE*:
       ``blueteam_cve_kev(cve_id="cve-2021-44228")``
    """
    _audit_log("blueteam_cve_kev", {"cve_id": params.cve_id})

    try:
        catalog = await _fetch_kev_catalog()
    except (httpx.HTTPStatusError, httpx.TimeoutException, ValueError) as e:
        return _handle_api_error(e, context="blueteam_cve_kev")

    entry = _lookup_kev(catalog, params.cve_id)

    if params.response_format == "json":
        return _truncate_if_needed(json.dumps({
            "cve_id": params.cve_id, "in_kev": entry is not None, "entry": entry,
        }, indent=2, default=str))

    if entry is None:
        return f"# CISA KEV - `{params.cve_id}`\n\n_Not in the Known Exploited Vulnerabilities catalog._"
    lines = [f"# CISA KEV - `{params.cve_id}`", ""]
    lines.append("**⚠️ ACTIVELY EXPLOITED IN THE WILD**")
    lines.append("")
    lines.append(f"- **Vendor/Product**: {entry.get('vendorProject','?')} {entry.get('product','?')}")
    lines.append(f"- **Vulnerability**: {entry.get('vulnerabilityName','?')}")
    lines.append(f"- **Added**: {entry.get('dateAdded','?')}")
    lines.append(f"- **Due date**: {entry.get('dueDate','?')}")
    lines.append(f"- **Required action**: {entry.get('requiredAction','?')}")
    lines.append(f"- **Ransomware campaign use**: {entry.get('knownRansomwareCampaignUse','Unknown')}")
    notes = entry.get("notes")
    if notes:
        lines.append(f"- **Notes**: {notes}")
    return _truncate_if_needed("\n".join(lines))


class CvePocInput(BaseModel):
    """Input model for blueteam_cve_poc."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    cve_id: str = Field(..., min_length=10, max_length=20,
                        description="CVE ID to search for public proof-of-concept exploits.")
    response_format: Literal["markdown", "json"] = Field(default="markdown")

    @field_validator("cve_id")
    @classmethod
    def validate_cve(cls, v: str) -> str:
        norm = normalize_cve(v)
        if norm is None:
            raise ValueError("cve_id must match CVE-YYYY-NNNN, e.g. CVE-2024-6387")
        return norm


@mcp.tool(
    name="blueteam_cve_poc",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": True},
)
async def blueteam_cve_poc(params: CvePocInput) -> str:
    """Search for public proof-of-concept exploits for a CVE (GitHub + Nuclei).

    Reports whether exploit/PoC code is publicly available and its quality,
    which is a strong signal the CVE is being actively weaponized. Results are
    advisory: presence of a PoC does not prove compromise of your assets.

    **Required Permissions**: none for GitHub repo search. Set ``GITHUB_TOKEN``
    to raise the rate limit and enable the Nuclei code-search check.

    **Rate Limit**: GitHub search is unauthenticated rate-limited (10 req/min).
    Results cached for 1 hour.

    **Worked Examples**

    1. *Check if a CVE has public exploit code*:
       ``blueteam_cve_poc(cve_id="CVE-2024-6387")``

    2. *JSON output*:
       ``blueteam_cve_poc(cve_id="CVE-2021-44228", response_format="json")``

    3. *Confirm no public PoC (defensive posture)*:
       ``blueteam_cve_poc(cve_id="CVE-2024-1234")``
    """
    _audit_log("blueteam_cve_poc", {"cve_id": params.cve_id})

    try:
        poc = await search_poc(params.cve_id)
    except (httpx.HTTPStatusError, httpx.TimeoutException) as e:
        return _handle_api_error(e, context="blueteam_cve_poc")

    if params.response_format == "json":
        return _truncate_if_needed(json.dumps(poc, indent=2, default=str))

    lines = [f"# Public PoC - `{poc['cve_id']}`", ""]
    lines.append(f"**Confidence**: `{poc['confidence']}` | **Sources found**: {poc['total_sources_found']}")
    gh = poc.get("github_results", [])
    if gh:
        lines.append("")
        lines.append("## GitHub repositories")
        for r in gh[:10]:
            lines.append(f"- **{r['full_name']}** ({r['stars']}⭐, score {r['score']}) - {r['html_url']}")
    nuclei = poc.get("nuclei_templates", [])
    if nuclei:
        lines.append("")
        lines.append("## Nuclei templates")
        for t in nuclei[:10]:
            lines.append(f"- `{t['path']}` - {t['html_url']}")
    if not gh and not nuclei:
        lines.append("")
        lines.append("_No public PoC or Nuclei template found._")
    return _truncate_if_needed("\n".join(lines))


class CveScoreInput(BaseModel):
    """Input model for blueteam_cve_score."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    cve_id: str = Field(..., min_length=10, max_length=20,
                        description="CVE ID to score with the composite risk model.")
    response_format: Literal["markdown", "json"] = Field(default="markdown")

    @field_validator("cve_id")
    @classmethod
    def validate_cve(cls, v: str) -> str:
        norm = normalize_cve(v)
        if norm is None:
            raise ValueError("cve_id must match CVE-YYYY-NNNN, e.g. CVE-2024-6387")
        return norm


@mcp.tool(
    name="blueteam_cve_score",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": True},
)
async def blueteam_cve_score(params: CveScoreInput) -> str:
    """Compute a composite 0-100 risk score for a CVE (CVSS + EPSS + KEV + PoC).

    Fetches NVD, EPSS, CISA KEV, and public-PoC availability concurrently, then
    combines them into one score with a severity label and patch urgency. KEV
    membership is a hard floor: a KEV-listed CVE is always CRITICAL.

    **Required Permissions**: none (optional ``NVD_API_KEY`` / ``GITHUB_TOKEN``
    raise rate limits).

    **Rate Limit**: NVD 5 req/30s unauth; results cached (NVD/EPSS/KEV 24h, PoC 1h).

    **Worked Examples**

    1. *Triage a CVE from a Wazuh vulnerability alert*:
       ``blueteam_cve_score(cve_id="CVE-2024-6387")``

    2. *JSON output*:
       ``blueteam_cve_score(cve_id="CVE-2021-44228", response_format="json")``

    3. *Patch-prioritization across a batch (loop per CVE)*:
       ``blueteam_cve_score(cve_id="CVE-2024-6387")``
    """
    _audit_log("blueteam_cve_score", {"cve_id": params.cve_id})

    try:
        nvd, epss_entries, kev_catalog, poc = await _gather_cve_data(params.cve_id)
    except (httpx.HTTPStatusError, httpx.TimeoutException, ValueError) as e:
        return _handle_api_error(e, context="blueteam_cve_score")

    epss_entry = next((e for e in epss_entries if e.get("cve") == params.cve_id), None)
    epss_data = {"probability": float(epss_entry["epss"])} if epss_entry else None
    kev_entry = _lookup_kev(kev_catalog, params.cve_id)
    result = score_cve(params.cve_id, nvd, epss_data, kev_entry, poc)

    if params.response_format == "json":
        return _truncate_if_needed(json.dumps(result, indent=2, default=str))

    c = result["components"]
    lines = [f"# CVE Risk Score - `{params.cve_id}`", ""]
    lines.append(f"## {result['risk_label']} — {result['risk_score']}/100")
    lines.append(f"**Urgency**: {result['urgency']}")
    lines.append("")
    lines.append("| Signal | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| CVSS | {c['cvss_score']} |")
    lines.append(f"| EPSS | {c['epss_probability']:.1%} |")
    lines.append(f"| In CISA KEV | {'**YES**' if c['in_kev'] else 'No'} |")
    lines.append(f"| Public PoC | `{c['poc_confidence']}` |")
    if result.get("boosters_applied"):
        lines.append(f"| Boosters | {', '.join(result['boosters_applied'])} |")
    if result.get("days_since_published") is not None:
        lines.append(f"| Days since published | {result['days_since_published']} |")
    return _truncate_if_needed("\n".join(lines))


async def _gather_cve_data(cve_id: str):
    """Fetch NVD + EPSS + KEV + PoC concurrently. Returns a 4-tuple."""
    import asyncio
    nvd, epss, kev, poc = await asyncio.gather(
        _fetch_nvd(cve_id),
        _fetch_epss([cve_id]),
        _fetch_kev_catalog(),
        search_poc(cve_id),
    )
    return nvd, epss, kev, poc
