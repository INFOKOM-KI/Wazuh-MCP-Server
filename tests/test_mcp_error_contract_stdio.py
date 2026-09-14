#!/usr/bin/env python3
"""
End-to-end MCP contract test over real stdio.
Regression for the reported symptom: a failing tool was returned as
``isError: false`` with the error as ordinary text, so an LLM could read a hard
upstream failure ("You are not subscribed to this API.") as a finding.
This boots the real server as a subprocess and speaks JSON-RPC to it, which also
proves stdout stays clean (FastMCP would fail to parse otherwise).
"""
from __future__ import annotations
import os
import sys
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _server_params() -> StdioServerParameters:
    env = dict(os.environ)
    env.update({
        "WAZUH_INDEXER_URL": "https://indexer:9200",
        "WAZUH_INDEXER_PASSWORD": "test-indexer-pass",
        "PYTHONPATH": ROOT,
        "PYTHONUNBUFFERED": "1",
    })
    # Forces the missing-credential failure path: no network needed.
    env.pop("RAPIDAPI_KEY", None)
    return StdioServerParameters(command=sys.executable, args=["main.py"], cwd=ROOT, env=env)


@pytest.mark.asyncio
async def test_tool_failure_sets_iserror_true():
    async with stdio_client(_server_params()) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            res = await session.call_tool(
                "blueteam_ip_blacklist", {"params": {"ip": "185.220.101.49"}}
            )

    assert res.isError is True, "a hard tool failure must not be reported as success"
    text = "".join(c.text for c in res.content if getattr(c, "type", "") == "text")
    assert "RAPIDAPI_KEY" in text, text
    assert "blueteam_ip_blacklist" in text, text


@pytest.mark.asyncio
async def test_successful_tool_is_not_an_error():
    """Control: a tool that cannot fail on network still returns isError=false."""
    async with stdio_client(_server_params()) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            res = await session.call_tool("blueteam_metrics", {"params": {}})

    assert res.isError is False
