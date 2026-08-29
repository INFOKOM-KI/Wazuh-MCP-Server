#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
CVE enrichment - NVD / EPSS / CISA KEV / public-PoC lookups for Wazuh alerts.

Ported from the cve-mcp-server (TangerangKota-CSIRT) Tier-1 toolset. Reuses this
repo's ``_api_call`` (retry + circuit breaker) and shared TTL cache instead of the
CVE server's TokenBucketRateLimiter + SQLite VulnCache.

Endpoints are FIXED (no user-controlled host), so there is no SSRF surface: the
only user input is a CVE ID, validated by ``CVE_RE`` before any request is made.
"""
from __future__ import annotations
import asyncio
import logging
import os
import re
from datetime import datetime, timezone

import httpx

from mcp_server.core.http_client import _api_call
from mcp_server.threat_intel._cache import cache_get, cache_set, get_limiter

logger = logging.getLogger("blue_team_mcp.cve")

# Fixed public endpoints (no user-controlled host - no SSRF surface).
NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_BASE = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_FALLBACK = "https://raw.githubusercontent.com/cisagov/kev-data/main/data/known_exploited_vulnerabilities.json"
GITHUB_REPO_SEARCH_URL = "https://api.github.com/search/repositories"
NUCLEI_SEARCH_URL = "https://api.github.com/search/code"

# Optional API keys (tools degrade gracefully without them).
NVD_API_KEY_ENV = "NVD_API_KEY"
GITHUB_TOKEN_ENV = "GITHUB_TOKEN"

# Cache TTLs (seconds).
TTL_CVE = 86400      # NVD CVE records change rarely
TTL_EPSS = 86400     # EPSS updates daily
TTL_KEV = 86400      # CISA KEV catalog updates daily
TTL_POC = 3600       # GitHub/Nuclei PoC searches are churny

MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MB safety cap

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

if not os.environ.get(NVD_API_KEY_ENV):
    logger.warning(
        "%s not set - NVD lookups use the unauthenticated rate limit (5 req/30s). "
        "Get a free key at https://nvd.nist.gov/developers/request-an-api-key",
        NVD_API_KEY_ENV,
    )

# NVD unauth limit is ~5 req/30s (0.167 r/s); a key raises it to ~50/30s.
_limiter = get_limiter("cve", max_concurrent=2, min_interval=0.35)


def normalize_cve(cve_id: str) -> str | None:
    """Return the upper-cased CVE ID if it matches CVE-YYYY-NNNN, else None."""
    s = cve_id.strip().upper()
    return s if CVE_RE.match(s) else None


def _headers() -> dict:
    h = {"Accept": "application/json"}
    key = os.environ.get(NVD_API_KEY_ENV, "")
    if key:
        h["apiKey"] = key
    return h


def _guard_size(resp: httpx.Response) -> None:
    if len(resp.content) > MAX_RESPONSE_BYTES:
        raise ValueError("response too large (>10 MB)")


# ── NVD ──────────────────────────────────────────────────────────────────────
async def _fetch_nvd(cve_id: str) -> dict | None:
    """Fetch a CVE record from NVD. Returns None when the CVE is unknown."""
    key = f"cve:{cve_id}"
    cached = cache_get("cve", key)
    if cached is not None:
        return cached

    async with _limiter:
        resp = await _api_call("get", NVD_BASE, params={"cveId": cve_id}, headers=_headers())
        _guard_size(resp)
        data = resp.json()

    if data.get("totalResults", 0) == 0:
        return None
    record = data["vulnerabilities"][0]["cve"]
    cache_set("cve", key, record, TTL_CVE)
    return record


# ── EPSS ─────────────────────────────────────────────────────────────────────
async def _fetch_epss(cve_ids: list[str]) -> list[dict]:
    """Fetch EPSS scores for one or more CVE IDs (chunked, cached per CVE)."""
    results: list[dict] = []
    uncached: list[str] = []
    for cid in cve_ids:
        cached = cache_get("epss", cid)
        if cached is not None:
            results.append(cached)
        else:
            uncached.append(cid)

    if not uncached:
        return results

    for i in range(0, len(uncached), 30):
        chunk = uncached[i : i + 30]
        async with _limiter:
            resp = await _api_call(
                "get", EPSS_BASE,
                params={"cve": ",".join(chunk), "limit": len(chunk)},
            )
            _guard_size(resp)
            data = resp.json()
        for entry in data.get("data", []):
            cid = entry.get("cve", "")
            if cid:
                cache_set("epss", cid, entry, TTL_EPSS)
            results.append(entry)
    return results


# ── CISA KEV ─────────────────────────────────────────────────────────────────
async def _fetch_kev_catalog() -> list[dict]:
    cached = cache_get("kev", "catalog")
    if cached is not None:
        return cached

    for url in (KEV_URL, KEV_FALLBACK):
        try:
            async with _limiter:
                resp = await _api_call("get", url, max_retries=0)
                _guard_size(resp)
                data = resp.json()
            catalog = data.get("vulnerabilities", [])
            cache_set("kev", "catalog", catalog, TTL_KEV)
            logger.info("KEV catalog loaded (%d entries)", len(catalog))
            return catalog
        except (httpx.HTTPStatusError, httpx.TimeoutException, ValueError) as exc:
            logger.warning("KEV fetch failed from %s: %s", url, exc)
    return []


def _lookup_kev(catalog: list[dict], cve_id: str) -> dict | None:
    for e in catalog:
        if e.get("cveID") == cve_id:
            return e
    return None


# ── Public PoC search (GitHub + Nuclei) ──────────────────────────────────────
def _score_github_repo(repo: dict) -> int:
    score = 0
    stars = repo.get("stargazers_count", 0)
    if stars > 100:
        score += 3
    elif stars > 10:
        score += 2
    if not repo.get("fork", True):
        score += 2
    lang = repo.get("language") or ""
    if lang in ("Python", "C", "C++", "Ruby", "Go", "JavaScript", "TypeScript",
                "Rust", "Java", "PHP"):
        score += 1
    desc = (repo.get("description") or "").lower()
    if "exploit" in desc:
        score += 1
    if "poc" in desc:
        score += 1
    return score


async def _search_github_pocs(cve_id: str) -> list[dict]:
    headers = {"Accept": "application/vnd.github.v3+json"}
    token = os.environ.get(GITHUB_TOKEN_ENV, "")
    if token:
        headers["Authorization"] = f"token {token}"

    seen: set[int] = set()
    repos: list[dict] = []
    for q in (cve_id, f"{cve_id} exploit"):
        try:
            async with _limiter:
                resp = await _api_call(
                    "get", GITHUB_REPO_SEARCH_URL,
                    params={"q": q, "sort": "stars", "order": "desc", "per_page": 10},
                    headers=headers, max_retries=0,
                )
            data = resp.json()
            for repo in data.get("items", []):
                rid = repo.get("id")
                if rid and rid not in seen:
                    seen.add(rid)
                    repos.append(repo)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (403, 422):
                continue  # rate-limited / bad query - degrade silently
            logger.warning("GitHub PoC search failed (%d) for %s",
                           exc.response.status_code, cve_id)
        except httpx.TimeoutException:
            logger.warning("GitHub PoC search timed out for %s", cve_id)

    out = []
    for repo in repos:
        score = _score_github_repo(repo)
        if score >= 2:
            out.append({
                "name": repo.get("name", ""),
                "full_name": repo.get("full_name", ""),
                "html_url": repo.get("html_url", ""),
                "stars": repo.get("stargazers_count", 0),
                "description": (repo.get("description") or "")[:500],
                "language": repo.get("language", ""),
                "fork": repo.get("fork", False),
                "score": score,
            })
    return out


async def _search_nuclei(cve_id: str) -> list[dict]:
    headers = {"Accept": "application/vnd.github.v3+json"}
    token = os.environ.get(GITHUB_TOKEN_ENV, "")
    if token:
        headers["Authorization"] = f"token {token}"
    try:
        async with _limiter:
            resp = await _api_call(
                "get", NUCLEI_SEARCH_URL,
                params={"q": f"{cve_id} repo:projectdiscovery/nuclei-templates"},
                headers=headers, max_retries=0,
            )
        data = resp.json()
        return [
            {"name": i.get("name", ""), "html_url": i.get("html_url", ""), "path": i.get("path", "")}
            for i in data.get("items", [])
        ]
    except (httpx.HTTPStatusError, httpx.TimeoutException):
        # GitHub code-search requires a token; degrade to empty without one.
        return []


async def search_poc(cve_id: str) -> dict:
    """Aggregate public-PoC availability across GitHub + Nuclei templates."""
    github, nuclei = await asyncio.gather(
        _search_github_pocs(cve_id), _search_nuclei(cve_id)
    )

    if github and any(r.get("score", 0) >= 5 for r in github):
        confidence = "PUBLIC_EXPLOIT"
    elif nuclei or (github and any(r.get("score", 0) >= 3 for r in github)):
        confidence = "PUBLIC_POC_HIGH_QUALITY"
    elif github:
        confidence = "PUBLIC_POC_LOW_QUALITY"
    else:
        confidence = "NONE"

    return {
        "cve_id": cve_id,
        "confidence": confidence,
        "github_results": github,
        "nuclei_templates": nuclei,
        "total_sources_found": len(github) + len(nuclei),
        "search_timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── Composite risk scoring (pure) ────────────────────────────────────────────
def _extract_cvss_score(nvd_data: dict | None) -> float:
    """Extract the best CVSS base score from an NVD record (v3.1 > v3.0 > v2)."""
    if not nvd_data:
        return 0.0
    for key in ("cvss_v31_score", "cvss_v30_score", "cvss_v2_score"):
        val = nvd_data.get(key)
        if val is not None:
            return float(val)
    metrics = nvd_data.get("metrics", {})
    if isinstance(metrics, dict):
        for mk in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(mk, [])
            if entries and isinstance(entries, list) and len(entries) > 0:
                base = entries[0].get("cvssData", {}).get("baseScore")
                if base is not None:
                    return float(base)
    return 0.0


def _extract_published_date(nvd_data: dict | None) -> datetime | None:
    if not nvd_data:
        return None
    raw = nvd_data.get("published")
    if not raw:
        return None
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def score_cve(
    cve_id: str,
    nvd_data: dict | None,
    epss_data: dict | None,
    kev_entry: dict | None,
    poc_result: dict | None,
) -> dict:
    """Compute a composite 0-100 risk score (CVSS + EPSS + KEV + PoC).

    KEV membership is the strongest exploitation signal and acts as a hard
    floor: a KEV-listed CVE can never score below CRITICAL.
    """
    cvss_score = _extract_cvss_score(nvd_data)
    epss_probability = (epss_data or {}).get("probability", 0.0)
    in_kev = bool(kev_entry)
    poc_confidence = (poc_result or {}).get("confidence", "NONE")

    poc_score_map = {
        "PUBLIC_EXPLOIT": 10,
        "PUBLIC_POC_HIGH_QUALITY": 7,
        "PUBLIC_POC_LOW_QUALITY": 3,
        "NONE": 0,
    }

    cvss_contribution = (cvss_score / 10.0) * 20.0
    epss_contribution = epss_probability * 100 * 0.35
    kev_contribution = 30.0 if in_kev else 0.0
    poc_contribution = poc_score_map.get(poc_confidence, 0)

    base = cvss_contribution + epss_contribution + kev_contribution + poc_contribution

    multiplier = 1.0
    boosters: list[str] = []
    if in_kev and poc_confidence != "NONE":
        multiplier *= 1.15
        boosters.append("KEV+PoC")
    if cvss_score >= 9.0 and epss_probability > 0.7:
        multiplier *= 1.10
        boosters.append("CVSS>=9+EPSS>0.7")
    published_dt = _extract_published_date(nvd_data)
    days_since = None
    if published_dt is not None:
        days_since = (datetime.now(timezone.utc) - published_dt).days
        if days_since <= 7:
            multiplier *= 1.05
            boosters.append("Published<7days")

    risk_score = min(100.0, round(base * multiplier, 2))
    if risk_score <= 25:
        label = "LOW"
    elif risk_score <= 50:
        label = "MEDIUM"
    elif risk_score <= 75:
        label = "HIGH"
    else:
        label = "CRITICAL"

    if in_kev:
        label = "CRITICAL"
        risk_score = max(risk_score, 76.0)

    if in_kev and epss_probability > 0.5:
        urgency = "PATCH IMMEDIATELY"
    elif in_kev:
        urgency = "PATCH WITHIN 24 HOURS"
    elif epss_probability > 0.5:
        urgency = "PATCH WITHIN 72 HOURS"
    elif cvss_score >= 9.0:
        urgency = "PATCH THIS WEEK"
    elif cvss_score >= 7.0:
        urgency = "PATCH THIS MONTH"
    else:
        urgency = "SCHEDULE FOR NEXT CYCLE"

    return {
        "cve_id": cve_id,
        "scoring_version": "1.0",
        "risk_score": risk_score,
        "risk_label": label,
        "urgency": urgency,
        "components": {
            "cvss_score": cvss_score,
            "epss_probability": epss_probability,
            "in_kev": in_kev,
            "poc_confidence": poc_confidence,
            "cvss_contribution": round(cvss_contribution, 2),
            "epss_contribution": round(epss_contribution, 2),
            "kev_contribution": kev_contribution,
            "poc_contribution": poc_contribution,
        },
        "boosters_applied": boosters,
        "days_since_published": days_since,
    }
