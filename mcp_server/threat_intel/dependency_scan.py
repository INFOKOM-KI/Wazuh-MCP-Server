#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Dependency manifest scanning - parse requirements.txt / package.json / pom.xml /
generic name:ecosystem:version lines, then query OSV.dev for known
vulnerabilities. Bridges "this host runs package X@Y" to "these CVEs affect it",
which feeds ``blueteam_cve_score`` / ``blueteam_cve_attack_mapping`` and the
3-Sum correlation Engine A (MITRE-driven).
Reuses this repo's ``_api_call`` (retry + circuit breaker) and shared TTL cache
instead of the cve-mcp-server's TokenBucketRateLimiter + SQLite VulnCache.
Endpoints are FIXED (no user-controlled host), so there is no SSRF surface.
"""
from __future__ import annotations
import asyncio
import json
import logging
import re
import defusedxml.ElementTree as ET
import httpx
from mcp_server.core.http_client import _api_call
from mcp_server.threat_intel._cache import cache_get, cache_set, get_limiter

logger = logging.getLogger("blue_team_mcp.depscan")

OSV_BASE = "https://api.osv.dev/v1"  # fixed endpoint - no SSRF surface - Aul Tunnings;P

TTL_DEP_SCAN = 1800      # OSV results cached 30 minutes
MAX_PACKAGES = 500       # bound input so a giant manifest can't fan out unbounded
MAX_INPUT_SIZE = 1_000_000  # 1 MB of raw manifest text

# Highest-severity-first ordering. MODERATE (GitHub) maps to MEDIUM.
_SEVERITY_ORDER = {
    "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "MODERATE": 2, "LOW": 3, "UNKNOWN": 4,
}

# OSV /query is one request per package. 20 req/s is polite for a free API;
# worst case (500 packages) is ~25s.
_limiter = get_limiter("osv", max_concurrent=8, min_interval=0.05)


# Format parsers
def _parse_requirements_txt(text: str) -> list[dict]:
    results: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*([><=!~]+)\s*([A-Za-z0-9_.\-\*]+)", line)
        if m:
            results.append({"name": m.group(1).strip(), "ecosystem": "PyPI",
                            "version": m.group(3).strip()})
        else:
            bare = re.match(r"^([A-Za-z0-9_.\-]+)\s*$", line)
            if bare:
                results.append({"name": bare.group(1).strip(), "ecosystem": "PyPI",
                                "version": ""})
    return results


def _parse_package_json(text: str) -> list[dict]:
    try:
        pkg = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    results: list[dict] = []
    for key in ("dependencies", "devDependencies", "peerDependencies"):
        deps = pkg.get(key, {})
        if not isinstance(deps, dict):
            continue
        for name, ver_spec in deps.items():
            version = re.sub(r"^[\^~>=<\s]+", "", str(ver_spec)).strip()
            if version in ("*", "latest", ""):
                version = ""
            results.append({"name": name, "ecosystem": "npm", "version": version})
    return results


def _parse_pom_xml(text: str) -> list[dict]:
    try:
        root = ET.fromstring(text)  # defusedxml - safe against XXE / entity bombs exploit
    except ET.ParseError:
        return []
    ns_match = re.match(r"\{(.+?)\}", root.tag)
    prefix = f"{{{ns_match.group(1)}}}" if ns_match else ""
    results: list[dict] = []
    for dep in root.iter(f"{prefix}dependency"):
        group_id = (dep.findtext(f"{prefix}groupId") or "").strip()
        artifact_id = (dep.findtext(f"{prefix}artifactId") or "").strip()
        version = (dep.findtext(f"{prefix}version") or "").strip()
        if group_id and artifact_id:
            if version.startswith("${"):
                version = ""  # property ref, unresolvable from the pom alone.
            results.append({"name": f"{group_id}:{artifact_id}",
                            "ecosystem": "Maven", "version": version})
    return results


def _parse_generic_lines(text: str) -> list[dict]:
    results: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 3:
            results.append({"name": parts[0].strip(), "ecosystem": parts[1].strip(),
                            "version": parts[2].strip()})
    return results


def parse_dependency_list(raw_text: str) -> list[dict]:
    """Auto-detect manifest format -> [{name, ecosystem, version}].
    Supported: requirements.txt (pip), package.json (npm), pom.xml (Maven),
    and generic ``name:ecosystem:version`` lines.
    """
    if len(raw_text) > MAX_INPUT_SIZE:
        return []
    text = raw_text.strip()
    if not text:
        return []

    if text.startswith("{"):
        parsed = _parse_package_json(text)
        if parsed:
            return parsed

    if text.lstrip().startswith("<?xml") or "<project" in text[:500]:
        parsed = _parse_pom_xml(text)
        if parsed:
            return parsed

    if re.search(r"^[A-Za-z0-9_.\-]+\s*[><=!~]=", text, re.MULTILINE):
        return _parse_requirements_txt(text)

    generic = _parse_generic_lines(text)
    if generic:
        return generic

    return _parse_requirements_txt(text)


# OSV batch scan
def _cache_key(pkg: dict) -> str:
    return f"bulk:{pkg.get('ecosystem', '')}:{pkg.get('name', '')}:{pkg.get('version', '')}"


def _query_for(pkg: dict) -> dict:
    q: dict = {"package": {"name": pkg.get("name", ""),
                           "ecosystem": pkg.get("ecosystem", "")}}
    ver = pkg.get("version", "")
    if ver:
        q["version"] = ver
    return q


def _band_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _band_from_vector(vector: str) -> str:
    # coarse C/I/A weighting for ranking only. A full CVSS v3 base-score
    # parser is the upgrade path if per-CVE severity precision is ever needed here
    # (downstream blueteam_cve_score already computes the real number).
    c = re.search(r"/C:([HLN])", vector)
    i = re.search(r"/I:([HLN])", vector)
    a = re.search(r"/A:([HLN])", vector)
    if not (c and i and a):
        return "UNKNOWN"
    weights = {"N": 0, "L": 1, "H": 2}
    total = weights[c.group(1)] + weights[i.group(1)] + weights[a.group(1)]
    if total >= 5:
        return "CRITICAL"
    if total >= 4:
        return "HIGH"
    if total >= 2:
        return "MEDIUM"
    return "LOW"


def _extract_severity(vuln: dict) -> str:
    """Best-effort severity label from an OSV record (label > numeric > vector)."""
    labels: list[str] = []

    db = vuln.get("database_specific") or {}
    if isinstance(db, dict) and isinstance(db.get("severity"), str) and db["severity"]:
        labels.append(db["severity"])

    for sev in vuln.get("severity") or []:
        if not isinstance(sev, dict):
            continue
        score = sev.get("score")
        if isinstance(score, (int, float)):
            labels.append(_band_from_cvss(float(score)))
        elif isinstance(score, str) and score:
            try:
                labels.append(_band_from_cvss(float(score)))
            except ValueError:
                labels.append(_band_from_vector(score))

    for aff in vuln.get("affected") or []:
        if not isinstance(aff, dict):
            continue
        eco = aff.get("ecosystem_specific") or {}
        if isinstance(eco, dict):
            if isinstance(eco.get("severity"), str) and eco["severity"]:
                labels.append(eco["severity"])
            cvss = eco.get("cvss") or {}
            if isinstance(cvss, dict) and isinstance(cvss.get("score"), (int, float)):
                labels.append(_band_from_cvss(float(cvss["score"])))

    if not labels:
        return "UNKNOWN"
    return min(labels, key=lambda s: _SEVERITY_ORDER.get(str(s).upper(), 4))


def _summarize_vuln(vuln: dict) -> dict:
    aliases = vuln.get("aliases") or []
    ids = [vuln.get("id", "")] + [a for a in aliases if isinstance(a, str)]
    cve_ids = [x for x in ids if x.startswith("CVE-")]
    return {
        "id": vuln.get("id", ""),
        "cve_ids": cve_ids,
        "severity": _extract_severity(vuln),
        "summary": (vuln.get("summary") or vuln.get("details") or "")[:300],
        "references": [r.get("url", "") for r in (vuln.get("references") or [])
                       if r.get("url")][:3],
    }


async def _query_package(pkg: dict) -> list[dict]:
    """POST /v1/query for one package. Returns full vuln records ([] on error).
    OSV's /querybatch returns only id+modified stubs, so we use the single
    /query endpoint which returns full records (aliases, severity, summary).
    """
    key = _cache_key(pkg)
    try:
        async with _limiter:
            resp = await _api_call("post", f"{OSV_BASE}/query", json=_query_for(pkg))
        vulns = resp.json().get("vulns", [])
    except (httpx.HTTPStatusError, httpx.TimeoutException, ValueError) as exc:
        logger.warning("OSV query failed for %s@%s: %s",
                       pkg.get("name"), pkg.get("version"), exc)
        return []
    cache_set("osv", key, vulns, TTL_DEP_SCAN)
    return vulns


async def scan_dependencies_bulk(packages: list[dict]) -> list[dict]:
    """Query OSV /v1/query for a list of packages (concurrent fan-out).
    Returns only packages with known vulnerabilities, each with its top-5 vulns
    sorted highest-severity first. Per-package HTTP failures degrade to empty;
    a circuit-breaker open propagates so the tool layer can surface it.
    """
    if not packages:
        return []

    results_map: dict[int, list[dict]] = {}
    uncached: list[tuple[int, dict]] = []
    for i, pkg in enumerate(packages):
        key = _cache_key(pkg)
        cached = cache_get("osv", key)
        if cached is not None:
            results_map[i] = cached
        else:
            uncached.append((i, pkg))

    if uncached:
        gathered = await asyncio.gather(
            *(_query_package(pkg) for _, pkg in uncached),
            return_exceptions=True,
        )
        first_exc: BaseException | None = None
        for (orig_idx, _pkg), res in zip(uncached, gathered):
            if isinstance(res, BaseException):
                first_exc = first_exc or res
                results_map[orig_idx] = []
            else:
                results_map[orig_idx] = res
        if first_exc is not None:
            raise first_exc

    output: list[dict] = []
    for i, pkg in enumerate(packages):
        vulns = results_map.get(i, [])
        if not vulns:
            continue
        top = sorted(vulns, key=lambda v: _SEVERITY_ORDER.get(
            _extract_severity(v).upper(), 4))
        output.append({
            "package": pkg.get("name", ""),
            "ecosystem": pkg.get("ecosystem", ""),
            "version": pkg.get("version", ""),
            "vuln_count": len(vulns),
            "vulns": [_summarize_vuln(v) for v in top[:5]],
        })
    return output
