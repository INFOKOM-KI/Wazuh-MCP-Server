#!/usr/bin/env python3
"""
Regression checks for the 2026-09-28 pipeline review:
  - transport truncation must never reach an in-process json.loads
  - a tool reporting {"error": ...} must not render as a successful step
  - an automated attacker-registry hit must not be presented as an analyst verdict
"""
from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import asyncio
import json
import pytest
from mcp_server.core import audit
from mcp_server.core import tool_decorator
from mcp_server.core.attacker_registry import (
    clear_attacker_registry,
    attacker_ioc_source,
    is_attacker_ioc,
    register_attacker_ioc,
)
from mcp_server.core.tool_decorator import blueteam_tool, full_payload
from mcp_server.agents import fp_validator_graph as fpv
from mcp_server.agents import investigation_graph as ig


@blueteam_tool(name="blueteam_test_full_payload_contract", audit=False, redact=False)
async def _blob_tool(params=None) -> str:
    return {"blob": "x" * (audit.CHARACTER_LIMIT + 10)}


def test_oversized_json_is_capped_to_valid_json():
    payload = json.dumps({"items": [{"i": index} for index in range(20000)]})
    assert len(payload) > audit.CHARACTER_LIMIT
    parsed = json.loads(audit._truncate_if_needed(payload))
    assert parsed["truncated"] is True
    assert parsed["response_chars"] == len(payload)


def test_oversized_markdown_returns_a_complete_notice():
    assert audit._truncate_if_needed('{"a": 1}') == '{"a": 1}'
    long_markdown = "x" * (audit.CHARACTER_LIMIT + 1)
    notice = audit._truncate_if_needed(long_markdown)
    assert "exceeds the character limit" in notice
    assert "Narrow the query" in notice
    assert "x" * 100 not in notice


def test_in_process_calls_skip_truncation_but_transport_still_caps():
    with full_payload():
        full = asyncio.run(_blob_tool())
    assert len(full) > audit.CHARACTER_LIMIT

    capped = json.loads(asyncio.run(_blob_tool()))
    assert capped["truncated"] is True


def test_langgraph_nodes_inherit_the_full_payload_flag():
    """langgraph runs nodes in tasks of its own; if the flag does not follow them,
    the in-process tool calls truncate again and the fix is cosmetic."""
    from typing import TypedDict
    from langgraph.graph import StateGraph, START, END

    class _ProbeState(TypedDict):
        pass

    seen: list[bool] = []

    async def _probe(state):
        seen.append(tool_decorator._FULL_PAYLOAD.get())
        return {}

    graph = StateGraph(_ProbeState)
    graph.add_node("probe", _probe)
    graph.add_edge(START, "probe")
    graph.add_edge("probe", END)
    app = graph.compile()

    with full_payload():
        asyncio.run(app.ainvoke({}))
    assert seen == [True]
    assert tool_decorator._FULL_PAYLOAD.get() is False


@pytest.mark.asyncio
async def test_report_export_error_is_degraded_not_success(monkeypatch):
    async def _refuse(params):
        return json.dumps({"error": "Path not allowed: /tmp/report.docx",
                           "allowed": ["/var/log/blue-team-mcp/exports"]})

    monkeypatch.setattr("mcp_server.tools.report_export.blueteam_export_report", _refuse)
    out = await ig.report_step({"generate_report": True})
    assert out["steps"] == ["report: degraded"]
    assert "Path not allowed" in out["errors"][0]


@pytest.mark.asyncio
async def test_verdict_error_is_degraded_not_recorded(monkeypatch):
    async def _refuse(params):
        return json.dumps({"error": "BLUETEAM_INVESTIGATION_HISTORY env var not set."})

    monkeypatch.setattr("mcp_server.tools.investigation_history.blueteam_mark_investigated", _refuse)
    out = await ig.verdict_step({"record_verdict": True, "srcip": "203.0.113.9"})
    assert out["steps"] == ["verdict: degraded"]
    assert "not set" in out["errors"][0]


def test_registry_source_survives_domain_suffix_match():
    clear_attacker_registry()
    register_attacker_ioc("evil.example", source="enrichment")
    assert attacker_ioc_source("www.evil.example") == "enrichment"
    assert is_attacker_ioc("www.evil.example") is True
    assert is_attacker_ioc("deep.sub.evil.example") is False


def test_automated_registry_hit_is_not_reported_as_analyst_confirmation():
    clear_attacker_registry()
    register_attacker_ioc("198.51.100.77", source="engine_a")
    result = asyncio.run(fpv.run_fp_validation("198.51.100.77", "web shell probe"))
    assert result["verdict"] == "likely_true_positive"
    assert result["evidence"]["attacker_registry_source"] == "engine_a"
    assert "engine_a" in result["rationale"]
    assert "analyst confirmation" not in result["rationale"]


def test_analyst_verdict_still_outranks_the_corpus():
    clear_attacker_registry()
    register_attacker_ioc("198.51.100.78", source="verdict")
    result = asyncio.run(fpv.run_fp_validation("198.51.100.78", "beaconing"))
    assert result["evidence"]["attacker_registry_source"] == "verdict"
    assert "analyst confirmation" in result["rationale"]
