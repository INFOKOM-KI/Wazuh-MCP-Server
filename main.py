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
    from mcp_server import mcp, logger
    from mcp_server.tools import register_all_tools

    register_all_tools()

    parser = argparse.ArgumentParser(description="blue_team_mcp (68 tools)")
    parser.add_argument("--transport", choices=["stdio","streamable_http","http"],
                        default=os.environ.get("MCP_TRANSPORT","stdio"))
    parser.add_argument("--host", default=os.environ.get("MCP_HOST","127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("MCP_PORT","8000")))
    args = parser.parse_args()

    logger.info("68 tools registered. Starting %s on %s:%s",
                args.transport, args.host, args.port)
    if args.transport == "streamable_http":
        mcp.run(transport=args.transport, host=args.host, port=args.port)
    else:
        mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
