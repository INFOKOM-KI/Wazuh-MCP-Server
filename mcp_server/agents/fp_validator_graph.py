#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
LangGraph false-positive validation workflow.

Graph shape (4 nodes, 2 conditional edges):
    START -> assemble_evidence
                 |-- degraded (store down / node timeout) --> decide_degraded
                 |-- authority signal fired ---------------> decide_authority
                 +-- otherwise -----------------------------> decide_corpus
                                                                    |
                                                                   END
Every terminal node sets ``verdict`` and ``rationale``. Why conditional routing
instead of the earlier straight line:
1. **Exact suppression is authoritative and free.** A registered false-positive
   indicator is already excluded from 3-Sum scoring, so retrieval would add cost
   without changing the answer, and a similarity score must never be allowed to
   argue against an analyst's recorded decision.
2. **A conflicting signal must not be resolved by similarity.** When both the
   suppression set and the attacker registry match, no corpus score gets a vote.
3. **A degraded run must not read as a negative finding.** If the store is
   unreachable or a node times out, ``insufficient_evidence`` would claim the
   corpus was searched and came back empty. ``decide_degraded`` says what
   actually happened.
Node outputs are advisory. Nothing here writes to the suppression set or the
attacker registry; recording an analyst decision stays with
``blueteam_mark_investigated``.

No confidence percentage is produced at any node. Nothing in this pipeline
yields a calibrated probability, and an invented number would drive exactly the
wrong call on a live alert.
"""
from __future__ import annotations
import asyncio
import logging
import os
import uuid
from typing import Annotated, Optional, TypedDict
from operator import add
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import InMemorySaver
from mcp_server.core.attacker_registry import is_attacker_ioc
from mcp_server.core.config import config
from mcp_server.core.false_positive_kb import is_false_positive
from mcp_server.core.rerank import rerank_hits
from mcp_server.core import rag_store
# Shared with the investigation graph rather than duplicated: the aiosqlite
# backport and the per-node timeout wrapper are the same mechanism for both.
# See investigation_graph.py for why _ensure_aiosqlite_is_alive() exists.
from mcp_server.agents.investigation_graph import (
    _DB_PATH,
    _NODE_TIMEOUT,
    _ensure_aiosqlite_is_alive,
    _with_timeout,
)

logger = logging.getLogger("blue_team_mcp.fp_validator_graph")

# Corpus statuses that mean "we never actually looked", as opposed to
# "no_corpus" which means we did look and it was empty. The distinction is what
# separates insufficient_evidence from validation_incomplete.
_NOT_SEARCHED = ("disabled",)


class FPValidatorState(TypedDict, total=False):
    # inputs
    indicator: str
    description: str
    min_matches: int
    min_rerank_score: Optional[float]
    top_k: int
    rerank: bool
    # node outputs
    authority_signal: Optional[str]
    corpus_status: Optional[str]
    corpus_searched: bool
    hits: list
    evidence: dict
    verdict: str
    rationale: str
    degraded: bool
    reranked: bool
    # execution log
    steps: Annotated[list[str], add]
    errors: Annotated[list[str], add]


def _empty_evidence(min_matches: int, floor: Optional[float]) -> dict:
    return {
        "exact_suppression_match": False,
        "attacker_registry_match": False,
        "kb_matches": 0,
        "min_matches_required": min_matches,
        "top_vector_score": None,
        "top_rerank_score": None,
        "rerank_score_floor": floor,
        "score_floor_met": True,
        "corpus_status": None,
        "corpus_searched": False,
        "rerank_status": None,
        "confidence": "not_computed",
    }


async def _timed(coro, label: str) -> tuple[bool, object]:
    """Run ``coro`` under the shared per-node timeout.

    ``_with_timeout`` returns a ``{errors, steps}`` dict on timeout, which is
    indistinguishable to a caller from a real result by type alone (both wrapped
    coroutines here return tuples). Returns ``(ok, value_or_degradation_update)``
    so callers branch on ``ok`` instead of guessing.
    """
    result = await _with_timeout(coro, label)
    if isinstance(result, dict):
        return False, result
    return True, result


async def assemble_evidence(state: FPValidatorState) -> dict:
    """Deterministic checks first, retrieval second, and only if needed.
    The two registry lookups are O(1) and need no model. They run before any
    embedding, so the cheapest and most authoritative signals decide the graph's
    route on their own.
    """
    indicator = state.get("indicator", "")
    min_matches = state.get("min_matches", 3)
    evidence = _empty_evidence(min_matches, state.get("min_rerank_score"))
    exact = is_false_positive(indicator)
    attacker = is_attacker_ioc(indicator)
    evidence["exact_suppression_match"] = exact
    evidence["attacker_registry_match"] = attacker

    if exact and attacker:
        return {"evidence": evidence, "authority_signal": "conflicting_state",
                "steps": ["evidence: suppression set AND attacker registry both match"]}
    if exact:
        return {"evidence": evidence, "authority_signal": "suppressed_exact",
                "steps": ["evidence: exact suppression hit, retrieval skipped"]}
    if attacker:
        return {"evidence": evidence, "authority_signal": "likely_true_positive",
                "steps": ["evidence: attacker registry hit, corpus cannot outrank it"]}

    if not config.rag.enabled or not config.rag.db_path:
        evidence["corpus_status"] = "disabled"
        return {"evidence": evidence, "corpus_status": "disabled", "hits": [],
                "degraded": True,
                "errors": ["evidence: RAG store not configured"],
                "steps": ["evidence: corpus skipped, store disabled"]}

    text = state.get("description") or indicator
    top_k = state.get("top_k", 10)
    ok, result = await _timed(rag_store.query(text, top_k=top_k), "fp_retrieve")
    if not ok:
        evidence["corpus_status"] = "timeout"
        return {"evidence": evidence, "corpus_status": "timeout", "hits": [],
                "degraded": True,
                "errors": result.get("errors", []),
                "steps": list(result.get("steps", [])) + ["evidence: retrieval timed out"]}

    hits, status = result
    evidence["corpus_status"] = status
    evidence["corpus_searched"] = not (
        status is not None and (status in _NOT_SEARCHED or status.startswith("unavailable"))
    )
    if not hits:
        return {"evidence": evidence, "corpus_status": status, "hits": [],
                "degraded": not evidence["corpus_searched"],
                "errors": [] if evidence["corpus_searched"] else [f"evidence: corpus {status}"],
                "steps": [f"evidence: no candidates (status={status})"]}

    reranked = False
    rerank_status = None
    if state.get("rerank"):
        ok, result = await _timed(rerank_hits(text, hits, top_k), "fp_rerank")
        if not ok:
            evidence["rerank_status"] = "timeout"
            return {"evidence": evidence, "hits": hits, "corpus_status": status,
                    "errors": result.get("errors", []),
                    "steps": list(result.get("steps", [])) + ["evidence: rerank timed out"]}
        hits, reranked, rerank_status = result

    evidence["kb_matches"] = len(hits)
    evidence["rerank_status"] = rerank_status
    top_vector = hits[0].get("vector_score")
    top_rerank = hits[0].get("rerank_score")
    evidence["top_vector_score"] = round(top_vector, 6) if top_vector is not None else None
    evidence["top_rerank_score"] = round(top_rerank, 6) if top_rerank is not None else None
    if state.get("min_rerank_score") is not None:
        evidence["score_floor_met"] = (
            top_rerank is not None and top_rerank >= state["min_rerank_score"]
        )
    return {"evidence": evidence, "hits": hits, "corpus_status": status,
            "reranked": reranked,
            "steps": [f"evidence: {len(hits)} candidates"
                      + ("" if not reranked else ", reranked")]}


def decide_authority(state: FPValidatorState) -> dict:
    """Terminal node for the two registry signals and their conflict."""
    signal = state.get("authority_signal")
    if signal == "conflicting_state":
        rationale = (
            "The indicator is in the false-positive suppression set AND the attacker "
            "registry. Both were written from analyst verdicts and neither store clears "
            "the other, so precedence is unresolved here. Resolve it before trusting "
            "either verdict, and note that 3-Sum currently excludes the indicator as a "
            "suppression hit."
        )
    elif signal == "suppressed_exact":
        rationale = (
            "In the exact false-positive suppression set. The 3-Sum engine already "
            "excludes it, so this alert is suppressed by an existing analyst decision. "
            "Fix the upstream detection if it keeps firing."
        )
    else:
        rationale = (
            "Registered in the attacker registry from a prior analyst confirmation. "
            "That decision outranks corpus similarity. Escalate."
        )
    return {"verdict": signal or "insufficient_evidence", "rationale": rationale,
            "steps": [f"authority: {signal}"]}


def decide_corpus(state: FPValidatorState) -> dict:
    """Terminal node when no registry signal fired and the corpus was searched."""
    evidence = dict(state.get("evidence") or {})
    matches = evidence.get("kb_matches", 0)
    required = evidence.get("min_matches_required", 3)
    if matches >= required and evidence.get("score_floor_met", True):
        verdict = "likely_false_positive"
        rationale = (
            f"{matches} corpus match(es) at or above min_matches={required}. Advisory: "
            "confirm the matched cases describe the same activity before closing this out."
        )
    else:
        verdict = "insufficient_evidence"
        detail = (f"{matches} corpus match(es), below min_matches={required}"
                  if matches < required else
                  f"rerank score below the configured floor {evidence.get('rerank_score_floor')}")
        rationale = (f"{detail}. This is not evidence of a true positive either. "
                     "Investigate; do not auto-close.")
    return {"verdict": verdict, "rationale": rationale,
            "steps": [f"corpus: {verdict}"]}


def decide_degraded(state: FPValidatorState) -> dict:
    """Terminal node when the corpus could not be consulted at all.
    Returning ``insufficient_evidence`` here would read as "we checked and found
    nothing", which is a different and much more confident claim.
    """
    errors = state.get("errors") or []
    return {
        "verdict": "validation_incomplete",
        "rationale": (
            "Corpus validation did not run, so no false-positive assessment is possible. "
            "The registry checks above still hold. Reason: "
            + ("; ".join(errors) if errors else "store unavailable")
        ),
        "steps": ["degraded: verdict withheld"],
    }


def _route_after_evidence(state: FPValidatorState) -> str:
    if state.get("degraded"):
        return "decide_degraded"
    if state.get("authority_signal"):
        return "decide_authority"
    return "decide_corpus"


def build_fp_validator_graph(checkpointer=None):
    """Build and compile the StateGraph. InMemorySaver by default; pass an
    AsyncSqliteSaver for durable state across restarts."""
    g = StateGraph(FPValidatorState)
    g.add_node("assemble_evidence", assemble_evidence)
    g.add_node("decide_authority", decide_authority)
    g.add_node("decide_corpus", decide_corpus)
    g.add_node("decide_degraded", decide_degraded)
    g.add_edge(START, "assemble_evidence")
    g.add_conditional_edges("assemble_evidence", _route_after_evidence, {
        "decide_authority": "decide_authority",
        "decide_corpus": "decide_corpus",
        "decide_degraded": "decide_degraded",
    })
    g.add_edge("decide_authority", END)
    g.add_edge("decide_corpus", END)
    g.add_edge("decide_degraded", END)
    return g.compile(checkpointer=checkpointer or InMemorySaver())


_fp_validator_graph = build_fp_validator_graph()


async def run_fp_validation(indicator: str, description: str = "",
                            min_matches: int = 3,
                            min_rerank_score: Optional[float] = None,
                            top_k: int = 10, rerank: bool = False) -> dict:
    """Run the validation workflow and return the terminal state as a plain dict.
    Never raises for an operational failure: a broken store comes back as
    ``verdict="validation_incomplete"`` with the reason in ``errors``.
    """
    initial: FPValidatorState = {
        "indicator": indicator,
        "description": description or "",
        "min_matches": min_matches,
        "min_rerank_score": min_rerank_score,
        "top_k": top_k,
        "rerank": rerank,
        "hits": [],
        "steps": [],
        "errors": [],
    }
    run_config = {"configurable": {"thread_id": uuid.uuid4().hex}}
    if _DB_PATH:
        _ensure_aiosqlite_is_alive()
        from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
        parent = os.path.dirname(_DB_PATH)
        if parent:
            os.makedirs(parent, exist_ok=True)
        async with AsyncSqliteSaver.from_conn_string(_DB_PATH) as cp:
            final = await build_fp_validator_graph(cp).ainvoke(initial, config=run_config)
    else:
        final = await _fp_validator_graph.ainvoke(initial, config=run_config)

    return {
        "indicator": indicator,
        "verdict": final.get("verdict", "validation_incomplete"),
        "rationale": final.get("rationale", ""),
        "evidence": final.get("evidence") or _empty_evidence(min_matches, min_rerank_score),
        "matches": final.get("hits") or [],
        "steps": final.get("steps", []),
        "errors": final.get("errors", []),
        "reranked": bool(final.get("reranked")),
    }
