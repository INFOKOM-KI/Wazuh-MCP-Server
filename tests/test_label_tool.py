#!/usr/bin/env python3
"""Tests for tools/label.py.
The backend is monkeypatched, so this covers the tool contract: the disabled gate,
both input modes, the floor rendering, and the two security properties that matter
most - the alert body never reaches the output, and never reaches the audit log.
Tool bodies run through ``__wrapped__``; the decorator pipeline has its own test.
"""
from __future__ import annotations

import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import asyncio
import json
import pytest
from mcp_server.core.config import config
from mcp_server.core.exceptions import BlueTeamMCPError
from mcp_server.label.backends import LabelVerdict
from mcp_server.label.labeler import build_state_text
from mcp_server.tools import label as label_tool

_run = asyncio.run
_classify = label_tool.blueteam_incident_label.__wrapped__

SECRET = "ZZTOP-MARKER-42"


def _verdict(**overrides) -> LabelVerdict:
    base = dict(backend="onnx_prototype", status="ok", criteria_version="v1:deadbeef",
                label="Command and Control", category="C", confidence=0.71,
                probabilities={"Command and Control": 0.71, "Impact": 0.12,
                               "Collection": 0.17},
                scored=True, uncertain=False, reason=None)
    base.update(overrides)
    return LabelVerdict(**base)


@pytest.fixture(autouse=True)
def _setup(monkeypatch):
    config.label.enabled = True
    config.label.confidence_floor = 0.6
    _verdicts = [_verdict()]
    label_tool._TEST_VERDICTS = _verdicts

    async def _fake_classify(state_text):
        label_tool._TEST_STATE = state_text
        return _verdicts[0]

    label_tool._TEST_STATE = None
    monkeypatch.setattr(label_tool, "classify_state", _fake_classify)
    yield
    config.label.enabled = False


def test_disabled_tool_raises_an_enable_hint():
    config.label.enabled = False
    with pytest.raises(BlueTeamMCPError, match="disabled"):
        _run(_classify(label_tool.LabelClassifyInput(text="anything")))


def test_json_output_carries_label_category_and_floor():
    out = _run(_classify(label_tool.LabelClassifyInput(
        mode="text", text="beacon to c2", response_format="json")))
    payload = json.loads(out)
    assert payload["status"] == "ok"
    assert payload["label"] == "Command and Control"
    assert payload["category"] == "C"
    assert payload["floor"] == 0.6
    assert payload["backend"] == "onnx_prototype"
    assert payload["criteria_version"] == "v1:deadbeef"
    assert payload["probabilities"]["Impact"] == 0.12
    assert payload["alternatives"][0]["tactic"] == "Command and Control"


def test_include_probabilities_false_drops_the_vector_but_keeps_alternatives():
    out = _run(_classify(label_tool.LabelClassifyInput(
        mode="text", text="beacon to c2", include_probabilities=False,
        top_k=2, response_format="json")))
    payload = json.loads(out)
    assert payload["probabilities"] is None
    assert len(payload["alternatives"]) == 2


def test_text_mode_requires_text():
    with pytest.raises(BlueTeamMCPError, match="requires text"):
        _run(_classify(label_tool.LabelClassifyInput(mode="text")))


def test_alert_mode_requires_an_object():
    with pytest.raises(BlueTeamMCPError, match="requires alert"):
        _run(_classify(label_tool.LabelClassifyInput(mode="alert")))


def test_alert_mode_refuses_an_alert_with_no_allowlisted_fields():
    with pytest.raises(BlueTeamMCPError, match="rule.description"):
        _run(_classify(label_tool.LabelClassifyInput(
            mode="alert", alert={"full_log": "raw body", "data": {"password": "x"}})))


def test_alert_body_never_reaches_the_output():
    out = _run(_classify(label_tool.LabelClassifyInput(
        mode="alert", alert={"rule": {"description": SECRET, "level": 10}},
        response_format="json")))
    payload = json.loads(out)
    assert SECRET not in out
    assert payload["state"]["chars"] > 0
    assert payload["state"]["fields"] == ["rule.level", "rule.description"]


def test_audit_row_carries_counts_not_content(monkeypatch):
    captured: list = []
    monkeypatch.setattr(label_tool, "_audit_log",
                        lambda name, params: captured.append((name, params)))
    _run(_classify(label_tool.LabelClassifyInput(
        mode="alert", alert={"rule": {"description": SECRET, "level": 10}})))
    assert len(captured) == 1
    name, params = captured[0]
    assert name == "blueteam_incident_label"
    assert params["label"] == "Command and Control"
    assert params["confidence_bucket"] == "0.6-0.8"
    assert params["state_chars"] > 0
    assert SECRET not in json.dumps(params)


def test_uncertain_verdict_is_rendered_without_a_label():
    label_tool._TEST_VERDICTS[0] = _verdict(status="uncertain", label=None, category=None,
                                            confidence=0.31, scored=True,
                                            reason="top score 0.310 is below the floor 0.6")
    out = _run(_classify(label_tool.LabelClassifyInput(mode="text", text="mixed activity")))
    assert "uncertain" in out
    assert "below the floor" in out
    assert "Label**: `Command" not in out


def test_unscored_verdict_reports_no_fabricated_confidence():
    label_tool._TEST_VERDICTS[0] = _verdict(status="uncertain", label="Impact",
                                            confidence=None, probabilities=None,
                                            scored=False, uncertain=True,
                                            reason="backend exposes no scores")
    out = _run(_classify(label_tool.LabelClassifyInput(
        mode="text", text="ransomware note", response_format="json")))
    payload = json.loads(out)
    assert payload["scored"] is False
    assert payload["confidence"] is None
    assert payload["label"] == "Impact"


def test_unavailable_verdict_renders_the_reason():
    label_tool._TEST_VERDICTS[0] = _verdict(status="unavailable", label=None,
                                            category=None, confidence=None,
                                            probabilities=None, scored=False,
                                            reason="model load failed: no module named laya")
    out = _run(_classify(label_tool.LabelClassifyInput(mode="text", text="anything")))
    assert "model load failed" in out
    assert "did not run" in out


def test_state_text_is_dropped_when_every_field_is_refused():
    text, used = build_state_text({"data": {"srcip": {"nested": "object"}}})
    assert text == ""
    assert used == []


def test_state_text_reads_nested_and_flat_keys():
    text, used = build_state_text({"rule": {"level": 10}, "data.srcip": "45.194.92.25"})
    assert "rule.level=10" in text
    assert "data.srcip=45.194.92.25" in text
    assert used == ["rule.level", "data.srcip"]


def test_state_text_caps_a_long_field():
    text, _used = build_state_text({"rule": {"description": "A" * 5000}})
    assert len(text) <= 4000
    assert "A" * 401 not in text
