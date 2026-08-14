#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
AlienVault OTX threat intelligence integration.

OTX (Open Threat Exchange) is the largest open threat intel community.
Unlike CrowdSec/ThreatFox (reputation-only), OTX provides *pulses* — curated
IOC collections with malware families, adversaries, industries, and MITRE
techniques. This gives attribution + campaign context.

Endpoints:
/api/v1/indicators/{type}/{indicator}/general     - reputation summary
/api/v1/indicators/{type}/{indicator}/{section}   - pulses, geo, malware, etc.

Sections: general, reputation, geo, malware, url_list, passive_dns
"""
from __future__ import annotations
import json, logging, time, os, re, asyncio
from typing import Any
import httpx

from mcp_server import OTX_API_KEY_ENV, OTX_BASE_URL, OTX_CACHE_TTL
from mcp_server.core.http_client import _api_call, _handle_api_error
from mcp_server.core.audit import _audit_log, _truncate_if_needed

logger = logging.getLogger("blue_team_mcp.otx")

_otx_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_OTX_CACHE_MAXSIZE = 1000
_otx_semaphore = asyncio.Semaphore(5)
_otx_last_request = 0.0
_OTX_MIN_INTERVAL = 0.2  # 200ms = 5 req/sec (conservative for free tier)

# Indicator type resolution
_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$")
_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")

# Valid OTX indicator types
_VALID_TYPES = ("IPv4", "IPv6", "domain", "hostname", "url", "file")


def _classify_indicator(value: str) -> str:
    """Classify an IOC string into an OTX indicator type."""
    v = (value or "").strip()
    if _IP_RE.match(v):
        return "IPv4"
    if _MD5_RE.match(v):
        return "file"
    if _SHA1_RE.match(v) or _SHA256_RE.match(v):
        return "file"
    if v.startswith(("http://", "https://")):
        return "url"
    if _DOMAIN_RE.match(v):
        return "domain"
    if _HOSTNAME_RE.match(v):
        return "hostname"
    return ""


def _get_otx_api_key() -> str:
    key = os.environ.get(OTX_API_KEY_ENV, "")
    if not key:
        raise RuntimeError(
            f"{OTX_API_KEY_ENV} not set. "
            "Get a free key at https://otx.alienvault.com/api"
        )
    return key


async def _otx_request(indicator: str, section: str = "general") -> dict[str, Any]:
    """Query the OTX API with TTL caching + rate limiting."""
    ind_type = _classify_indicator(indicator)
    if not ind_type:
        return {"error": f"Unrecognized indicator type for '{indicator}'. "
                         "Supported: IP, domain, hostname, URL, MD5/SHA1/SHA256 hash."}

    cache_key = f"{ind_type}:{indicator}:{section}"
    now = time.monotonic()
    global _otx_last_request
    if cache_key in _otx_cache:
        expiry, data = _otx_cache[cache_key]
        if now < expiry:
            return data
        del _otx_cache[cache_key]

    async with _otx_semaphore:
        elapsed = time.monotonic() - _otx_last_request
        if elapsed < _OTX_MIN_INTERVAL:
            await asyncio.sleep(_OTX_MIN_INTERVAL - elapsed)

        headers = {
            "X-OTX-API-KEY": _get_otx_api_key(),
            "accept": "application/json",
            "User-Agent": "blue-team-mcp/1.0.0 (TangerangKota-CSIRT)",
        }
        url = f"{OTX_BASE_URL}/api/v1/indicators/{ind_type}/{indicator}/{section}"
        resp = await _api_call("get", url, headers=headers)
        data = resp.json()
        _otx_last_request = time.monotonic()

    if len(_otx_cache) >= _OTX_CACHE_MAXSIZE:
        _otx_cache.pop(next(iter(_otx_cache)))  # LRU eviction
    _otx_cache[cache_key] = (now + OTX_CACHE_TTL, data)
    return data


def _extract_pulse_summary(pulses: list[dict]) -> list[dict]:
    """Condense OTX pulses to the fields the LLM needs for attribution."""
    out = []
    for p in pulses:
        out.append({
            "name": p.get("name", "?"),
            "author": (p.get("author") or {}).get("username", "?"),
            "created": p.get("created", "?"),
            "modified": p.get("modified", "?"),
            "tags": p.get("tags", [])[:10],
            "malware_families": p.get("malware_families", [])[:5],
            "adversary": p.get("adversary", ""),
            "industries": p.get("industries", [])[:5],
            "attack_ids": p.get("attack_ids", [])[:10],
            "targeted_countries": p.get("targeted_countries", [])[:5],
            "indicator_count": p.get("indicator_count", 0),
        })
    return out


def _format_otx_markdown(indicator: str, ind_type: str, general: dict, pulses: list[dict]) -> str:
    """Format OTX result as a markdown threat card."""
    lines = [f"# OTX AlienVault — `{indicator}`", ""]

    pulse_info = general.get("pulse_info", {})
    pulse_count = pulse_info.get("count", 0)
    lines.append(f"**Indicator Type**: `{ind_type}` | **Pulses**: {pulse_count}")

    if pulse_count == 0:
        lines.append("")
        lines.append("_No pulses found - this indicator is not in any public OTX pulse._")
        return "\n".join(lines)

    # Pulse details
    lines.append("")
    for i, p in enumerate(pulses[:10], 1):
        name = p.get("name", "?")
        author = (p.get("author") or {}).get("username", "?")
        adversary = p.get("adversary", "")
        lines.append(f"## Pulse {i}: {name}")
        lines.append("")
        lines.append(f"| Field | Value |")
        lines.append(f"|-------|-------|")
        lines.append(f"| Author | {author} |")
        if adversary:
            lines.append(f"| Adversary | **{adversary}** |")
        mf = p.get("malware_families", [])
        if mf:
            lines.append(f"| Malware Families | {', '.join(f'`{m}`' for m in mf[:5])} |")
        tags = p.get("tags", [])
        if tags:
            lines.append(f"| Tags | {', '.join(f'`{t}`' for t in tags[:10])} |")
        attack_ids = p.get("attack_ids", [])
        if attack_ids:
            lines.append(f"| MITRE ATT&CK | {', '.join(f'`{a}`' for a in attack_ids[:10])} |")
        industries = p.get("industries", [])
        if industries:
            lines.append(f"| Industries | {', '.join(industries[:5])} |")
        countries = p.get("targeted_countries", [])
        if countries:
            lines.append(f"| Targeted Countries | {', '.join(countries[:5])} |")
        lines.append("")

    return "\n".join(lines)


def _format_geo_markdown(indicator: str, geo: dict) -> str:
    """Format OTX geo section."""
    lines = [f"# OTX Geo — `{indicator}`", ""]
    lines.append(f"| Field | Value |")
    lines.append(f"|-------|-------|")
    lines.append(f"| Country | {geo.get('country_name', '?')} ({geo.get('country_code', '?')}) |")
    lines.append(f"| City | {geo.get('city', '?')} |")
    lines.append(f"| ASN | {geo.get('asn', '?')} |")
    lines.append(f"| Org | {geo.get('org', '?')} |")
    lines.append(f"| Coordinates | {geo.get('latitude', '?')}, {geo.get('longitude', '?')} |")
    return "\n".join(lines)
