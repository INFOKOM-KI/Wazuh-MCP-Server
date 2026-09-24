#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Incident labeling: map an alert or a piece of text to one of the 16 MITRE ATT&CK
tactics the 3-Sum engine already scores, and derive its A/B/C category from it.

Pipeline position
    blueteam_alert_cluster        -> which activity shapes exist in a window
    blueteam_incident_label       -> which phase this alert resembles (this tool)
    blueteam_rag_query            -> have we handled something like this before

The label is a resemblance verdict, not an attribution. Nothing here writes,
mitigates or escalates; the analyst decides.

NOTE: No ``from __future__ import annotations`` - deferred annotation evaluation
      (PEP 563) breaks @blueteam_tool type resolution.
"""
import json
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from mcp_server.core.audit import _audit_log
from mcp_server.core.config import config
from mcp_server.core.exceptions import BlueTeamMCPError
from mcp_server.core.tool_decorator import blueteam_tool
from mcp_server.label.labeler import (
    MAX_STATE_CHARS,
    STATE_FIELDS,
    build_state_text,
    classify_state,
    require_enabled,
)

_BUCKETS = ((0.8, ">=0.8"), (0.6, "0.6-0.8"), (0.4, "0.4-0.6"))


def _bucket(confidence: Optional[float]) -> str:
    if confidence is None:
        return "none"
    for edge, name in _BUCKETS:
        if confidence >= edge:
            return name
    return "<0.4"


def _render_markdown(payload: dict) -> str:
    lines = ["# Incident label", ""]
    label = payload["label"]
    lines.append(f"**Label**: `{label}`"
                 + (f" (category {payload['category']})" if label else "")
                 + f" | **Backend**: `{payload['backend']}`")
    lines.append(f"**Status**: `{payload['status']}` | **Scored**: {payload['scored']} "
                 f"| **Confidence**: {payload['confidence']} | **Floor**: {payload['floor']}")
    lines.append(f"**Criteria**: `{payload['criteria_version']}`")
    if payload["reason"]:
        lines += ["", f"**Why**: {payload['reason']}"]
    if payload["alternatives"]:
        lines += ["", "| Tactic | Score |", "|--------|-------|"]
        lines += [f"| {row['tactic']} | {row['score']:.4f} |" for row in payload["alternatives"]]
    state = payload["state"]
    lines += ["", f"**State used**: {state['chars']} chars from {state['fields']} "
                  f"allowlisted alert fields. The text itself is not returned."]
    lines += ["", payload["caveat"]]
    return "\n".join(lines)


class LabelClassifyInput(BaseModel):
    """Input model for blueteam_incident_label."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    mode: Literal["text", "alert"] = Field(
        default="text",
        description="'text' labels the supplied text; 'alert' builds the state text "
                    "from the allowlisted fields of the supplied alert object.")
    text: Optional[str] = Field(default=None, max_length=MAX_STATE_CHARS,
        description="Required when mode='text'. Never returned and never audited.")
    alert: Optional[dict] = Field(default=None,
        description="Required when mode='alert'. Only rule.*, agent.name and "
                    "data.srcip/dstip/url/proto are read; full_log and nested "
                    "objects are ignored.")
    include_probabilities: bool = Field(default=True,
        description="Return the full 16-tactic score vector instead of just the "
                    "ranked alternatives.")
    top_k: int = Field(default=3, ge=1, le=16,
        description="Alternatives reported when the score vector exists.")
    response_format: Literal["markdown", "json"] = Field(default="markdown")


@blueteam_tool(
    name="blueteam_incident_label",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
    audit=False, truncate=True, redact=True,
)
async def blueteam_incident_label(params: LabelClassifyInput) -> str:
    """Label an alert or a text excerpt with one MITRE ATT&CK tactic phase.
    A label is only returned above the configured confidence floor; below it the
    answer is ``uncertain`` with the score vector attached, which is a result and
    not a failure. The A/B/C category is derived from the tactic through the same
    mapping the 3-Sum engine uses, so the label always lands in a known category.
    Two backends, selected by ``BLUETEAM_LAYA_BACKEND``:
    ``onnx`` (default) reuses the RAG embedder and costs no extra memory;
    ``laya`` runs the real classifier and requires CPU torch plus vendored weights.
    A backend that exposes no scores reports ``scored=false`` and never invents a
    confidence value.

    Args:
        params.mode: 'text' (default) or 'alert'.
        params.text: Free text to label; required for mode='text'.
        params.alert: Alert object to label; required for mode='alert'.
        params.include_probabilities: Include the full score vector.
        params.top_k: Alternatives to report (1-16).
        params.response_format: 'markdown' (default) or 'json'.

    Returns:
        markdown or json with the label, its category, the confidence, the floor
        applied, the score vector or ranked alternatives, the backend, the criteria
        version and the status. ``status='unavailable'`` carries the reason the
        backend could not run (no model, pin mismatch, runtime missing).

    Worked Examples:
        1. Label a suspicious URL alert -> ``blueteam_incident_label(mode="alert",
           alert={"rule": {"id": "100234", "level": 10,
                           "description": "Beaconing to a known C2 domain",
                           "mitre": {"tactic": "Command and Control"}},
                  "data": {"srcip": "45.194.92.25"}})``
        2. Label a raw excerpt -> ``blueteam_incident_label(mode="text",
           text="Mass file encryption observed on workstation WS-014")``
        3. Audit the score spread -> ``blueteam_incident_label(mode="text",
           text="...", include_probabilities=True, response_format="json")``

    Permissions: none beyond the tool call. Reads no store, calls no upstream API.
    Requires BLUETEAM_LAYA_ENABLED=true; the default backend also needs the RAG
    embedder cached on disk (setup.sh with BLUETEAM_RAG_ENABLED=true).
    Rate limits: one inference per call, serialized by
    BLUETEAM_LAYA_MAX_CONCURRENCY (default 1). The ONNX backend embeds the 32
    taxonomy prototypes once per process, then one embedding per call.
    """
    require_enabled()
    fields_used: list[str] = []
    state_text = ""
    if params.mode == "text":
        if not params.text:
            raise BlueTeamMCPError("mode='text' requires text to be set.")
        state_text = params.text
    else:
        if not isinstance(params.alert, dict) or not params.alert:
            raise BlueTeamMCPError("mode='alert' requires alert to be a non-empty object.")
        state_text, fields_used = build_state_text(params.alert)
        if not state_text:
            raise BlueTeamMCPError(
                "alert carries none of the fields this tool reads: "
                + ", ".join(STATE_FIELDS)
            )
    verdict = await classify_state(state_text)
    ranked: list[dict[str, Any]] = []
    if verdict.probabilities:
        ordered = sorted(verdict.probabilities.items(), key=lambda item: item[1], reverse=True)
        ranked = [{"tactic": tactic, "score": score}
                  for tactic, score in ordered[:params.top_k]]
    caveat = ("A label is the phase this activity resembles, not proof of compromise. "
              "Feed it to the 3-Sum category and to blueteam_rag_query, never to a "
              "mitigation decision on its own.")
    if verdict.status == "unavailable":
        caveat = "The backend did not run. Fix the reason above before trusting any label."
    elif verdict.uncertain and verdict.scored:
        caveat = ("No tactic reached the floor, which is the honest answer for "
                  "unscorable or mixed text. Do not lower the floor to force a label.")
    payload = {
        "status": verdict.status,
        "label": verdict.label,
        "category": verdict.category,
        "confidence": verdict.confidence,
        "floor": config.label.confidence_floor,
        "scored": verdict.scored,
        "uncertain": verdict.uncertain,
        "reason": verdict.reason,
        "backend": verdict.backend,
        "criteria_version": verdict.criteria_version,
        "alternatives": ranked,
        "probabilities": verdict.probabilities if params.include_probabilities else None,
        "state": {"chars": len(state_text), "fields": fields_used},
        "caveat": caveat,
    }
    # audit=False on the decorator: its pre-call audit serializes every param, which
    # would put the alert body or the raw text into BLUETEAM_AUDIT_LOG. This row
    # carries the verdict and the counts instead.
    _audit_log("blueteam_incident_label", {
        "mode": params.mode,
        "backend": verdict.backend,
        "status": verdict.status,
        "label": verdict.label,
        "confidence_bucket": _bucket(verdict.confidence),
        "criteria_version": verdict.criteria_version,
        "state_chars": len(state_text),
        "state_fields": len(fields_used),
    })
    if params.response_format == "json":
        return json.dumps(payload, indent=2, ensure_ascii=False)
    return _render_markdown(payload)
