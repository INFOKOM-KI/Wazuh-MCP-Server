#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Subject-scoped memory recall: prior analyst decisions recorded for one IP.

Structured history only: no free-text query, no SQL, no embedding.

NOTE: No ``from __future__ import annotations`` deferred annotation evaluation
      (PEP 563) breaks @blueteam_tool type resolution. Same constraint as
      tools/rag_kb.py, tools/yara_rules.py and tools/sigma_rules.py.
"""
import json
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field
from mcp_server.core import memory_store
from mcp_server.core.audit import _audit_log
from mcp_server.core.tool_decorator import blueteam_tool


class MemoryRecallInput(BaseModel):
    """Input model for blueteam_memory_recall."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    srcip: str = Field(..., min_length=7, max_length=45,
        description="Source IP whose prior decisions to read.")
    limit: int = Field(default=5, ge=1, le=20,
        description="Decisions and reasons returned per list (max 20).")
    response_format: Literal["markdown", "json"] = Field(default="markdown",
        description="'markdown' or 'json'.")


def _age(decision: dict) -> str:
    days = decision.get("age_days")
    return f"{days:g}d ago" if isinstance(days, (int, float)) else "age unknown"


def _render(envelope: dict) -> str:
    decisions = envelope.get("decisions") or []
    reasons = envelope.get("recent_reasons") or []
    lines = [f"**Subject**: `{envelope.get('subject')}`",
             f"**Status**: {envelope.get('status')}",
             f"**Boundary**: {envelope.get('boundary')}"]
    if not decisions and not reasons:
        lines.append("")
        lines.append("No prior decisions for this subject.")
        return "\n".join(lines)
    if decisions:
        lines.append("")
        lines.append(f"**Prior decisions** ({len(decisions)})")
        for unit in decisions:
            origin = unit.get("recorded_by") or "unknown"
            if unit.get("advisory"):
                origin += ", machine-recorded"
            lines.append(
                f"- `{unit.get('verdict') or 'unknown'}` via {origin}, last confirmed "
                f"{_age(unit)}, support {unit.get('support_count')}, "
                f"decay {unit.get('decay_weight')}")
    if reasons:
        lines.append("")
        lines.append(f"**Recent reasons** ({len(reasons)}, tainted free text)")
        for unit in reasons:
            lines.append(f"- {str(unit.get('text') or '')[:300]}")
    return "\n".join(lines)


@blueteam_tool(
    name="blueteam_memory_recall",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
    audit=True, truncate=True, redact=True,
)
async def blueteam_memory_recall(params: MemoryRecallInput) -> str:
    """Read prior analyst decisions recorded for one subject.

    Structured history: each decision carries its verdict, who recorded it, when it
    was last confirmed and how many times. Free-text reasons come back in a separate
    list marked tainted, because a reason can quote attacker content. It is not
    document search (that is `blueteam_rag_query`) and it cannot change a score, a
    verdict or a suppression.

    **Required**: BLUETEAM_MEM_ENABLED=true and BLUETEAM_MEM_DB. A disabled store
    or an unknown subject returns an empty envelope instead of an error.

    **Worked Examples**

    1. *Before re-investigating an IP*:
       ``blueteam_memory_recall(srcip="103.107.116.202")``
    2. *Machine-readable, wider*:
       ``blueteam_memory_recall(srcip="8.8.8.8", limit=10, response_format="json")``
    3. *Subject with no history*: returns ``status="empty"`` and only the boundary
       line, so an absent history is never read as an absent indicator.
    """
    _audit_log("blueteam_memory_recall", {"srcip": params.srcip, "limit": params.limit})
    envelope = memory_store.recall_subject(memory_store.subject_for_srcip(params.srcip),
                                           limit=params.limit)
    if params.response_format == "json":
        return json.dumps(envelope, indent=2, ensure_ascii=False)
    return _render(envelope)
