#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
GreyNoise Community API - free, no key required.
"""
from __future__ import annotations
import json
from pydantic import BaseModel, ConfigDict, Field
from typing import Literal

from mcp_server import mcp
from mcp_server.core.http_client import _api_call, ValidPublicIp
from mcp_server.core.audit import _audit_log, _truncate_if_needed

GREYNOISE_COMMUNITY_BASE_URL = "https://api.greynoise.io/v3/community"


@mcp.tool(name="greynoise_ip_context", annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True})
async def greynoise_ip_context(ip: ValidPublicIp, response_format: Literal["markdown","json"] = "markdown") -> str:
    """Check if an IP is a known internet scanner or business service (free, no auth)."""
    _audit_log("greynoise_ip_context", {"ip": ip})
    headers = {"accept": "application/json", "User-Agent": "blue-team-mcp/1.0.0"}
    resp = await _api_call("get", f"{GREYNOISE_COMMUNITY_BASE_URL}/{ip}", headers=headers)
    raw = resp.json()
    if response_format == "json":
        return _truncate_if_needed(json.dumps(raw, indent=2))
    lines = [f"# GreyNoise Community — {ip}", "",
             f"- **Noise**: {'Yes' if raw.get('noise') else 'No'}",
             f"- **RIOT**: {'Yes' if raw.get('riot') else 'No'}",
             f"- **Classification**: `{raw.get('classification','unknown')}`"]
    return _truncate_if_needed("\n".join(lines))
