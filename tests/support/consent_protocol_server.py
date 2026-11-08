"""MCP server used by protocol-level consent tests.

This server is intentionally separate from main.py: it exposes only the
consent gate and does not import Wazuh or VirusTotal transport.
"""
from __future__ import annotations

import os
import sys

from mcp.server.fastmcp import Context, FastMCP

from mcp_server.threat_intel.virustotal_consent import (
    consent_message,
    consume_consent,
    issue_consent,
    request_ioc_sharing,
)

_PORT = int(os.environ.get("CONSENT_TEST_PORT", "0"))
mcp = FastMCP("consent-protocol-test", host="127.0.0.1", port=_PORT)


@mcp.tool()
async def consent_probe(ip: str, ctx: Context) -> dict[str, bool]:
    approved = await request_ioc_sharing(ctx, consent_message("ip_addresses", ip))
    if not approved:
        return {"approved": False, "token_valid": False}
    token = issue_consent("ip_addresses", ip)
    try:
        consume_consent(token, "ip_addresses", ip)
    except Exception:
        return {"approved": True, "token_valid": False}
    return {"approved": True, "token_valid": True}


if __name__ == "__main__":
    if "--http" in sys.argv:
        mcp.run(transport="streamable-http")
    else:
        mcp.run(transport="stdio")
