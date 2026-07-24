#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Blue Team Wazuh MCP Server
"""
from __future__ import annotations
from pydantic import field_validator
import argparse
import os


def main() -> None:
    # Parse args first — set env vars BEFORE importing mcp_server
    # so FastMCP picks up correct host/port at construction time.
    parser = argparse.ArgumentParser(description="blue_team_mcp (85 tools)")
    parser.add_argument("--transport", choices=["stdio","streamable_http","http"],
                        default=os.environ.get("MCP_TRANSPORT","stdio"))
    parser.add_argument("--host", default=os.environ.get("MCP_HOST","127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("MCP_PORT","8000")))
    args = parser.parse_args()

    os.environ["MCP_HOST"] = args.host
    os.environ["MCP_PORT"] = str(args.port)

    from mcp_server import mcp, logger
    from mcp_server.tools import register_all_tools

    register_all_tools()

    logger.info("85 tools + 2 resources. Starting %s on %s:%s",
                args.transport, args.host, args.port)
    if args.transport in ("streamable_http", "http"):
        mcp.run(transport="streamable-http")
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
