#!/usr/bin/env python3
"""
Tests for the blue-team tool decorator's error contract.
A tool returning error text is reported to the MCP client as isError=false, which
lets an LLM read a hard upstream failure as a finding. The decorator must let the
exception escape so FastMCP turns it into an isError=true result.
"""
from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "pw")

import pytest
from mcp_server.core.exceptions import ThreatIntelError
from mcp_server.core.tool_decorator import blueteam_tool


@blueteam_tool(name="blueteam_test_error_contract",
               audit=False, truncate=False, redact=False)
async def _failing_tool(params=None) -> str:
    raise ThreatIntelError("[ctx] Error: Access forbidden (403)")


@blueteam_tool(name="blueteam_test_success_contract",
               audit=False, truncate=False, redact=False)
async def _ok_tool(params=None) -> str:
    return "fine"


@pytest.mark.asyncio
async def test_blue_team_error_propagates():
    """Raised BlueTeamMCPError escapes the decorator instead of becoming text."""
    with pytest.raises(ThreatIntelError) as ei:
        await _failing_tool()
    assert "403" in str(ei.value)


@pytest.mark.asyncio
async def test_success_path_unchanged():
    assert await _ok_tool() == "fine"
