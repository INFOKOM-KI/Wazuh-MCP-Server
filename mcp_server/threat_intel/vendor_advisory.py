#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Vendor security advisories - Microsoft MSRC, Red Hat, and Ubuntu remediation
guidance for a CVE. Ported from the cve-mcp-server but rewritten against the
current upstream response shapes (MSRC SUG v2.0 and Ubuntu Security API both
changed field names since the original port).
Reuses this repo's ``_api_call`` (retry + circuit breaker) and shared TTL cache.
Endpoints are FIXED (no user-controlled host), so there is no SSRF surface:
the only user input is a CVE ID, validated by ``normalize_cve`` before any call.
"""
from __future__ import annotations
import asyncio
import logging
import re
import httpx
from mcp_server.core.http_client import _api_call
from mcp_server.threat_intel._cache import cache_get, cache_set, get_limiter

logger = logging.getLogger("blue_team_mcp.advisory")

MSRC_SUG_URL = "https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability"
REDHAT_SECURITY_BASE = "https://access.redhat.com/hydra/rest/securitydata"
UBUNTU_SECURITY_BASE = "https://ubuntu.com/security/cves"

TTL_ADVISORY = 14400  # 4 hours - vendor advisories change slowly

_limiter = get_limiter("advisory", max_concurrent=3, min_interval=0.2)

_REDHAT_HEADERS = {"Accept": "application/json", "User-Agent": "blue-team-mcp"}


def _strip_html(text: str) -> str:
    text = (text or "").replace("&nbsp;", " ")
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text).strip()


# Parsers
def _parse_msrc(entries: list) -> dict:
    """MSRC SUG v2.0 'value' list -> single advisory dict ({} when none)."""
    if not entries:
        return {}
    e = entries[0]
    return {
        "title": e.get("cveTitle", ""),
        "product": e.get("tag", ""),
        "exploited": e.get("exploited", ""),
        "publicly_disclosed": e.get("publiclyDisclosed", ""),
        "release_date": e.get("releaseDate", ""),
        "latest_revision": e.get("latestRevisionDate", ""),
        "description": _strip_html(e.get("description", "")),
        "mitre_url": e.get("mitreUrl", ""),
    }


def _parse_redhat(data: dict) -> dict:
    """Red Hat securitydata CVE JSON -> advisory dict ({} when untracked)."""
    cvss3 = data.get("cvss3") or {}
    bugzilla = data.get("bugzilla") or {}
    advisories = [
        {
            "advisory": r.get("advisory", ""),
            "package": r.get("package", ""),
            "product_name": r.get("product_name", ""),
            "release_date": r.get("release_date", ""),
            "cpe": r.get("cpe", ""),
        }
        for r in (data.get("affected_release") or [])[:20]
    ]
    package_states = [
        {
            "package": s.get("package_name", ""),
            "product_name": s.get("product_name", ""),
            "state": s.get("fix_state", ""),
            "cpe": s.get("cpe", ""),
        }
        for s in (data.get("package_state") or [])[:20]
    ]
    if not advisories and not package_states and not data.get("threat_severity"):
        return {}
    return {
        "severity": data.get("threat_severity", ""),
        "cvss3_score": cvss3.get("cvss3_base_score", ""),
        "cvss3_vector": cvss3.get("cvss3_scoring_vector", ""),
        "cwe": data.get("cwe", ""),
        "statement": data.get("statement", ""),
        "bugzilla_url": bugzilla.get("url", ""),
        "bugzilla_description": bugzilla.get("description", ""),
        "advisories": advisories,
        "package_states": package_states,
    }


def _parse_ubuntu(data: dict) -> dict:
    """Ubuntu Security API CVE JSON -> advisory dict ({} when untracked)."""
    if not data.get("description") and not data.get("priority"):
        return {}
    notices = [
        {
            "id": n.get("id", ""),
            "title": n.get("title", ""),
            "summary": n.get("summary", ""),
            "published": n.get("published", ""),
        }
        for n in (data.get("notices") or [])[:10]
    ]
    packages = []
    for p in (data.get("packages") or [])[:20]:
        statuses = [
            {
                "release": s.get("release_codename", ""),
                "status": s.get("status", ""),
                "description": s.get("description", ""),
            }
            for s in (p.get("statuses") or [])[:10]
        ]
        packages.append({"name": p.get("name", ""), "statuses": statuses})
    return {
        "priority": data.get("priority", ""),
        "status": data.get("status", ""),
        "cvss3": data.get("cvss3", ""),
        "description": (data.get("ubuntu_description")
                        or data.get("description") or "").strip(),
        "notices": notices,
        "packages": packages,
        "references": (data.get("references") or [])[:10],
    }


# Network fetchers (each caches its own result, {} = confirmed untracked)
async def _fetch_msrc(cve_id: str) -> dict:
    key = f"msrc:{cve_id}"
    cached = cache_get("advisory", key)
    if cached is not None:
        return cached
    result: dict = {}
    try:
        async with _limiter:
            resp = await _api_call(
                "get", MSRC_SUG_URL,
                params={"$filter": f"cveNumber eq '{cve_id}'"},
                headers={"Accept": "application/json"},
            )
        result = _parse_msrc(resp.json().get("value", []))
        cache_set("advisory", key, result, TTL_ADVISORY)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            cache_set("advisory", key, result, TTL_ADVISORY)
        else:
            logger.warning("MSRC query failed (%d) for %s",
                           exc.response.status_code, cve_id)
            result = {"_error": f"HTTP {exc.response.status_code}"}
    except (httpx.TimeoutException, ValueError) as exc:
        logger.warning("MSRC error for %s: %s", cve_id, exc)
        result = {"_error": str(exc)[:80]}
    return result


async def _fetch_redhat(cve_id: str) -> dict:
    key = f"redhat:{cve_id}"
    cached = cache_get("advisory", key)
    if cached is not None:
        return cached
    result: dict = {}
    try:
        async with _limiter:
            resp = await _api_call(
                "get", f"{REDHAT_SECURITY_BASE}/cve/{cve_id}.json",
                headers=_REDHAT_HEADERS,
            )
        result = _parse_redhat(resp.json())
        cache_set("advisory", key, result, TTL_ADVISORY)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            cache_set("advisory", key, result, TTL_ADVISORY)
        else:
            logger.warning("Red Hat query failed (%d) for %s",
                           exc.response.status_code, cve_id)
            result = {"_error": f"HTTP {exc.response.status_code}"}
    except (httpx.TimeoutException, ValueError) as exc:
        logger.warning("Red Hat error for %s: %s", cve_id, exc)
        result = {"_error": str(exc)[:80]}
    return result


async def _fetch_ubuntu(cve_id: str) -> dict:
    key = f"ubuntu:{cve_id}"
    cached = cache_get("advisory", key)
    if cached is not None:
        return cached
    result: dict = {}
    try:
        async with _limiter:
            resp = await _api_call(
                "get", f"{UBUNTU_SECURITY_BASE}/{cve_id}.json",
                headers={"Accept": "application/json"},
            )
        result = _parse_ubuntu(resp.json())
        cache_set("advisory", key, result, TTL_ADVISORY)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            cache_set("advisory", key, result, TTL_ADVISORY)
        else:
            logger.warning("Ubuntu query failed (%d) for %s",
                           exc.response.status_code, cve_id)
            result = {"_error": f"HTTP {exc.response.status_code}"}
    except (httpx.TimeoutException, ValueError) as exc:
        logger.warning("Ubuntu error for %s: %s", cve_id, exc)
        result = {"_error": str(exc)[:80]}
    return result


async def get_vendor_advisory(cve_id: str) -> dict:
    """Fetch MSRC + Red Hat + Ubuntu advisories concurrently. Each vendor is a
    dict (empty dict when that vendor does not track the CVE)."""
    msrc, redhat, ubuntu = await asyncio.gather(
        _fetch_msrc(cve_id), _fetch_redhat(cve_id), _fetch_ubuntu(cve_id),
    )
    return {
        "cve_id": cve_id,
        "microsoft": msrc,
        "redhat": redhat,
        "ubuntu": ubuntu,
    }
