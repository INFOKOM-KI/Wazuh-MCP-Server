#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
GreyNoise Community API - free, no key required.
"""
from __future__ import annotations
import json
from pydantic import BaseModel, ConfigDict, Field
from typing import Literal
import httpx
from mcp_server import mcp, GREYNOISE_COMMUNITY_BASE_URL
from mcp_server.core.http_client import _api_call, ValidPublicIp
from mcp_server.core.audit import _audit_log, _truncate_if_needed
from mcp_server.threat_intel._cache import cache_get, cache_set, get_limiter

# Community data moves slowly, and the cache is what keeps a report that repeats
# an IP inside the provider's daily quota.
_CACHE_TTL = 900
_greynoise_limiter = get_limiter("greynoise", max_concurrent=2, min_interval=1.0)

_NO_DATA = {"noise": False, "riot": False, "classification": "unknown",
            "message": "No data in GreyNoise Community dataset"}


async def _greynoise_lookup(ip: str) -> dict:
    """Shared GreyNoise Community lookup for the standalone tool and the aggregator.

    Returns the provider body. A 404 becomes the explicit no-data record; every
    other HTTP error propagates, so a throttled provider is never read as clean.
    Errors are not cached. ``_api_call`` does not retry a 429 without a usable
    ``Retry-After``, so this layer adds no blind retries.
    """
    cached = cache_get("greynoise", ip)
    if cached is not None:
        return cached
    async with _greynoise_limiter:
        headers = {"accept": "application/json", "User-Agent": "blue-team-mcp/1.0.0"}
        try:
            resp = await _api_call("get", f"{GREYNOISE_COMMUNITY_BASE_URL}/{ip}", headers=headers)
            raw = resp.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code != 404:
                raise
            raw = {"ip": ip, **_NO_DATA}
    cache_set("greynoise", ip, raw, _CACHE_TTL)
    return raw


class GreyNoiseContextInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    ip: ValidPublicIp = Field(..., description="Public IP to check against GreyNoise Community")
    response_format: Literal["markdown", "json"] = Field(default="markdown", description="'markdown' or 'json'")


@mcp.tool(name="greynoise_ip_context", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
async def greynoise_ip_context(params: GreyNoiseContextInput) -> str:
    """Check if an IP is a known internet scanner or business service (free, no auth).

    Args:
        params.ip: Public IP to check
        params.response_format: 'markdown' or 'json'
    """
    _audit_log("greynoise_ip_context", {"ip": params.ip})
    raw = await _greynoise_lookup(params.ip)
    if params.response_format == "json":
        return _truncate_if_needed(json.dumps(raw, indent=2))
    lines = [f"# GreyNoise Community - {params.ip}", "",
             f"- **Noise**: {'Yes' if raw.get('noise') else 'No'}",
             f"- **RIOT**: {'Yes' if raw.get('riot') else 'No'}",
             f"- **Classification**: `{raw.get('classification','unknown')}`"]
    return _truncate_if_needed("\n".join(lines))
