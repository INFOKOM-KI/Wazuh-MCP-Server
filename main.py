#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Blue Team Wazuh MCP Server - entry point.

Startup order (must NOT be reordered):
  1. Parse CLI args, set MCP_HOST / MCP_PORT env vars.
  2. Import mcp_server — creates the FastMCP instance.
  3. init_config()       — validate typed configuration, raise on fatal errors.
  4. init_auth_manager() — initialize JWT token manager singleton.
  5. register_all_tools()— import tool modules; gating is enforced here.
  6. mcp.run()           — start the selected transport.
"""

import argparse
import os
import sys


def main() -> None:
    # 1: CLI args (before FastMCP construction)
    parser = argparse.ArgumentParser(
        description="blue_team_mcp — SOC automation MCP server for Wazuh"
    )
    parser.add_argument(
        "--transport", choices=["stdio", "streamable_http", "http"],
        default=os.environ.get("MCP_TRANSPORT", "stdio"),
    )
    parser.add_argument("--host", default=os.environ.get("MCP_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("MCP_PORT", "8000")))
    args = parser.parse_args()

    os.environ["MCP_HOST"] = args.host
    os.environ["MCP_PORT"] = str(args.port)

    # 2: Import mcp_server (creates FastMCP, reads env vars)
    from mcp_server import mcp, logger

    # 3: Validate typed configuration
    from mcp_server.core.config import init_config
    try:
        init_config()
    except Exception as exc:
        logger.critical("Configuration validation failed: %s", exc)
        sys.exit(1)

    # 4: Initialize Wazuh auth manager singleton
    from mcp_server.core.config import config
    from mcp_server.wazuh.auth import init_auth_manager
    if config is not None:
        init_auth_manager(
            url=config.wazuh_manager.url,
            username=config.wazuh_manager.username,
            password=config.wazuh_manager.password,
            verify_ssl=config.wazuh_manager.verify_ssl,
        )

    # 5: Register tools (respects tool-gating config)
    from mcp_server.tools import register_all_tools
    register_all_tools()

    # 6: Start transport
    tool_count = len(getattr(mcp._tool_manager, "_tools", {}))
    logger.info("%d tools registered. Starting %s transport on %s:%s",
                tool_count, args.transport, args.host, args.port)

    if args.transport in ("streamable_http", "http"):
        mcp.run(transport="streamable-http")
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
