#!/usr/bin/env python3
"""Tests for the label step in agents/investigation_graph.py.
The step must gate on config, cap the state text at MAX_STATE_CHARS instead of
letting the Pydantic max_length reject it, and treat an unavailable backend as an
error rather than a label.
"""
from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import json
import pytest
from mcp_server.agents import investigation_graph as ig
from mcp_server.core.config import config
from mcp_server.label.labeler import MAX_STATE_CHARS


@pytest.mark.asyncio
async def test_label_step_skips_when_disabled(monkeypatch):
    monkeypatch.setattr(config.label, "enabled", False)
    out = await ig.label_step({"alert_text": "beaconing"})
    assert out["steps"] == ["label: disabled"]
    assert "incident_label" not in out


@pytest.mark.asyncio
async def test_label_step_skips_without_text(monkeypatch):
    monkeypatch.setattr(config.label, "enabled", True)
    out = await ig.label_step({"alert_text": "   "})
    assert out["steps"] == ["label: skipped (no alert_text)"]


@pytest.mark.asyncio
async def test_label_step_caps_text_and_records_the_label(monkeypatch):
    monkeypatch.setattr(config.label, "enabled", True)
    captured: dict = {}

    async def fake_label(params):
        captured["chars"] = len(params.text)
        return json.dumps({"status": "ok", "label": "Command and Control",
                           "category": "c2_exfil", "confidence": 0.81})

    monkeypatch.setattr("mcp_server.tools.label.blueteam_incident_label", fake_label)
    out = await ig.label_step({"alert_text": "a" * (MAX_STATE_CHARS + 500)})
    assert captured["chars"] == MAX_STATE_CHARS
    assert out["incident_label"]["label"] == "Command and Control"
    assert out["steps"] == ["label: Command and Control (confidence=0.81, status=ok)"]


@pytest.mark.asyncio
async def test_label_step_records_unavailable_as_an_error(monkeypatch):
    monkeypatch.setattr(config.label, "enabled", True)

    async def fake_label(params):
        return json.dumps({"status": "unavailable", "label": None, "confidence": None,
                           "reason": "model load failed"})

    monkeypatch.setattr("mcp_server.tools.label.blueteam_incident_label", fake_label)
    out = await ig.label_step({"alert_text": "beaconing"})
    assert out["steps"] == ["label: degraded (backend unavailable)"]
    assert out["errors"] == ["label: unavailable (model load failed)"]


def test_graph_wires_label_between_cluster_and_analytics():
    graph = ig.build_investigation_graph()
    edges = {(edge.source, edge.target) for edge in graph.get_graph().edges}
    assert ("cluster", "label") in edges
    assert ("label", "analytics") in edges
