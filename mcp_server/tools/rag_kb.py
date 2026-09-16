#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
RAG knowledge-base tools: rebuild the analyst corpus, retrieve candidates, and
assemble false-positive evidence.

Pipeline position
-----------------
    blueteam_rag_ingest       -> derived index (case_store + false_positive_kb + pasted text)
    blueteam_rag_query        -> stage 1 vector recall + stage 2 cross-encoder rerank
    blueteam_rag_fp_validate  -> deterministic evidence assembly on top of rag_query

The vector table lives in ``mcp_server.core.rag_store``. Content lives in
``core/case_store.py`` and ``core/false_positive_kb.py``; the RAG index is
derived from those, which is why ingest deletes a label before rebuilding it.
No tool in this module performs a mitigation action: ``blueteam_rag_fp_validate``
recommends and stops. Recording an analyst's decision stays with
``blueteam_mark_investigated``.

Why `blueteam_rag_fp_validate` returns no confidence number The earlier design sketch fed a literal ``0.92`` into a ``> 0.80`` test, which
makes every alert a false positive. Nothing in the store produces a calibrated
probability, so this tool reports the *evidence* (match counts, exact-suppression
hit, attacker registry hit, raw scores) and a verdict derived only from those
counts. ``min_rerank_score`` is ``None`` by default because cross-encoder logits
are uncalibrated across corpora; set it only after measuring on labelled cases.

NOTE: No ``from __future__ import annotations`` deferred annotation evaluation
      (PEP 563) breaks @blueteam_tool type resolution. Same constraint as
      tools/yara_rules.py and tools/sigma_rules.py.
"""
import json
from typing import Literal, Optional
from pydantic import BaseModel, ConfigDict, Field
from mcp_server.core import rag_store
from mcp_server.core.audit import _audit_log
from mcp_server.core.attacker_registry import is_attacker_ioc
from mcp_server.core.case_store import list_cases
from mcp_server.core.config import config
from mcp_server.core.exceptions import BlueTeamMCPError
from mcp_server.core.false_positive_kb import false_positive_entries, is_false_positive
from mcp_server.core.rerank import rerank as _cross_rerank
from mcp_server.core.tool_decorator import blueteam_tool

_NOT_CONFIGURED = (
    "RAG store is not configured. Set BLUETEAM_RAG_ENABLED=true and "
    "BLUETEAM_RAG_DB=/abs/path/rag.db, then restart the server. Run "
    "blueteam_rag_ingest afterwards to populate the corpus."
)


def _require_store() -> None:
    """Fail loudly instead of returning an empty result set that reads like
    'no similar cases exist' when the truth is 'no store is configured'."""
    if not config.rag.enabled or not config.rag.db_path:
        raise BlueTeamMCPError(_NOT_CONFIGURED)


# Chunking + corpus rendering
def _chunk_text(text: str, size: int, overlap: int) -> list[str]:
    """Sliding-window split with overlap.
    Overlap keeps a sentence straddling a boundary retrievable from either side.
    Fixed character window, it can cut mid-sentence. Swap for a
    paragraph/sentence-aware splitter if retrieval precision on long playbooks turns out too noisy.
    """
    body = (text or "").strip()
    if not body:
        return []
    if len(body) <= size:
        return [body]
    chunks: list[str] = []
    step = max(1, size - overlap)
    start = 0
    while start < len(body):
        chunk = body[start:start + size].strip()
        if chunk:
            chunks.append(chunk)
        if start + size >= len(body):
            break
        start += step
    return chunks


def _case_text(case: dict) -> str:
    """Render one case_store record as a retrievable document."""
    lines = [f"Case {case.get('case_id', '')}: {case.get('title', '')}"]
    if case.get("srcips"):
        lines.append("Source IPs: " + ", ".join(case["srcips"][:20]))
    if case.get("iocs"):
        lines.append("IOCs: " + ", ".join(case["iocs"][:30]))
    for verdict in case.get("verdicts", [])[:20]:
        lines.append(
            f"Verdict {verdict.get('verdict', '')} for {verdict.get('srcip', '')}: "
            f"{verdict.get('notes', '')}"
        )
    if case.get("notes"):
        lines.append("Notes: " + case["notes"])
    return "\n".join(line for line in lines if line)


def _docs_from_cases(size: int, overlap: int) -> list[dict]:
    docs: list[dict] = []
    seq = 0
    for case in list_cases():
        meta = {"case_id": case.get("case_id"), "created_at": case.get("created_at")}
        for chunk in _chunk_text(_case_text(case), size, overlap):
            docs.append({"source": "cases", "seq": seq, "text": chunk, "meta": meta})
            seq += 1
    return docs


def _docs_from_false_positives(size: int, overlap: int) -> list[dict]:
    docs: list[dict] = []
    seq = 0
    for entry in false_positive_entries():
        body = (f"Confirmed false positive {entry['ioc']} "
                f"(marked by {entry['source']}): {entry['reason']}")
        meta = {"ioc": entry["ioc"], "ts": entry["ts"]}
        for chunk in _chunk_text(body, size, overlap):
            docs.append({"source": "false_positives", "seq": seq, "text": chunk,
                         "meta": meta})
            seq += 1
    return docs


async def _rerank_hits(query: str, hits: list[dict], top_k: int) -> tuple[list[dict], bool, Optional[str]]:
    """Second stage: re-score ``hits`` with the local cross-encoder.
    Returns ``(hits, reranked, status)``. Rank-based truncation only, no score
    threshold: raw logits are not comparable across query distributions, and a
    fixed floor silently deletes good matches. ``status`` non-None means the
    caller keeps the vector ordering unchanged. Candidates are clamped by
    ``config.rerank.max_candidates`` so the rerank fan-out is bounded the same
    way for every caller, not just blueteam_semantic_search.
    """
    candidates = hits[:config.rerank.max_candidates]
    scores, status = await _cross_rerank(query, [hit["text"] for hit in candidates])
    if status is not None:
        return hits[:top_k], False, status
    order = sorted(range(len(candidates)),
                   key=lambda i: (-scores[i], -candidates[i]["vector_score"]))
    ranked = [{**candidates[i], "rerank_score": round(float(scores[i]), 6)}
              for i in order[:top_k]]
    return ranked, True, None


# Ingest
class RagIngestInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    source: Literal["cases", "false_positives", "text"] = Field(
        default="cases",
        description="cases = case_store records. false_positives = the suppression KB with "
                    "its analyst reasons. text = the `texts` argument, stored under `label`.",
    )
    texts: list[str] = Field(default_factory=list, max_length=200,
        description="Documents for source='text'. Ignored otherwise.")
    label: str = Field(default="manual", max_length=64,
        description="Source label for source='text' chunks. Use a distinct label per corpus "
                    "so queries can filter with `sources`.")
    response_format: Literal["markdown", "json"] = Field(default="markdown")


@blueteam_tool(
    name="blueteam_rag_ingest",
    annotations={"readOnlyHint": False, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
    audit=False, truncate=True, redact=True,
)
async def blueteam_rag_ingest(params: RagIngestInput) -> str:
    """Rebuild a RAG corpus label from its source of truth and embed it locally.
    Requires ``BLUETEAM_RAG_ENABLED=true`` and an absolute ``BLUETEAM_RAG_DB``.
    Requires the ``wazuh:write`` scope on the streamable_http transport (derived
    automatically from ``readOnlyHint=False``).
    ``source="cases"`` reads ``case_store``, ``source="false_positives"`` reads the
    suppression KB with its analyst notes. Both DELETE their label first and
    rebuild, because the index is derived: an edited case would otherwise leave
    its stale chunk matching forever. ``source="text"`` only upserts.
    Embeddings are computed in-process by fastembed's ONNX runtime. With
    ``BLUETEAM_RAG_ALLOW_DOWNLOAD=false`` (default) no text can leave the host.
    The audit entry records counts only, never chunk content.

    Args:
        params.source: 'cases', 'false_positives', or 'text'.
        params.texts: documents for source='text'.
        params.label: corpus label for source='text' (default 'manual').

    Returns:
        markdown or json with inserted, deleted, status, documents, and store stats.

    Examples:
        1. Rebuild from cases -> ``blueteam_rag_ingest(source="cases")``
        2. Rebuild suppression-KB chunks -> ``blueteam_rag_ingest(source="false_positives")``
        3. Add an IR excerpt -> ``blueteam_rag_ingest(source="text", label="ir_playbooks",
           texts=["Step 1: contain the host..."])``
        4. Store not configured -> an error, not an empty corpus.

    Permissions: write on BLUETEAM_RAG_DB. Rate limits: none, but ingest is
    CPU-bound (one ONNX batch per call) and blocked by BLUETEAM_RAG_MAX_CHUNKS.
    """
    if params.source == "text":
        if not params.texts:
            raise BlueTeamMCPError("source='text' requires at least one entry in `texts`.")
        corpus_label = params.label or "manual"
    else:
        corpus_label = params.source

    _require_store()
    size = config.rag.chunk_chars
    overlap = config.rag.chunk_overlap

    if params.source == "cases":
        docs = _docs_from_cases(size, overlap)
    elif params.source == "false_positives":
        docs = _docs_from_false_positives(size, overlap)
    else:
        # seq is unique across the whole label, not per document: the chunk id is
        # (source, seq, text), so two identical documents sharing seq=0 would
        # collapse into a single chunk on upsert.
        docs = []
        seq = 0
        for doc_index, raw in enumerate(params.texts):
            for chunk in _chunk_text(raw, size, overlap):
                docs.append({"source": corpus_label, "seq": seq, "text": chunk,
                             "meta": {"doc_index": doc_index}})
                seq += 1

    # Derived labels rebuild; a content-hash index cannot notice edits on its own.
    deleted = 0
    if params.source != "text":
        deleted = await rag_store.delete_source(corpus_label)

    inserted, status = await rag_store.add_documents(docs)
    _audit_log("blueteam_rag_ingest", {"source": corpus_label, "documents": len(docs),
                                       "chunks_inserted": inserted, "chunks_deleted": deleted})
    store = rag_store.stats()

    if params.response_format == "json":
        return json.dumps({"source": corpus_label, "documents": len(docs),
                           "chunks_inserted": inserted, "chunks_deleted": deleted,
                           "status": status, "store": store}, indent=2, ensure_ascii=False)

    lines = [f"# 📚 RAG Ingest - `{corpus_label}`", "",
             f"**Documents**: {len(docs)} | **Chunks stored**: {inserted} | "
             f"**Replaced**: {deleted}",
             f"**Model**: `{store['model']}` | **Corpus size**: "
             f"{sum(store['chunks_by_model'].values())} chunks", ""]
    if status:
        lines.append(f"**Status**: {status}")
        lines.append("")
    if not inserted:
        lines.append("Nothing was stored. If the store is otherwise healthy, the source "
                     "store is empty.")
        lines.append("")
    lines.append("**Operational note**: rerun this after editing cases or marking new "
                 "false positives, otherwise the index is stale.")
    return "\n".join(lines)


# Query
class RagQueryInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    query: str = Field(..., min_length=2, max_length=1000,
        description="Natural language query, English or Indonesian (alert text, rule "
                    "description, or a question about prior cases).")
    top_k: int = Field(default=10, ge=1, le=50,
        description="Results returned after rerank. Default comes from BLUETEAM_RAG_TOP_K.")
    recall_k: int = Field(default=100, ge=1, le=500,
        description="Stage-1 vector candidates. High recall on purpose; clamped by "
                    "BLUETEAM_RAG_MAX_CANDIDATES.")
    sources: Optional[list[str]] = Field(default=None, max_length=10,
        description="Optional corpus label filter, e.g. ['cases']. None searches everything.")
    rerank: bool = Field(default=False,
        description="Re-score the vector candidates with the local cross-encoder "
                    "(BAAI/bge-reranker-base). Needs BLUETEAM_RERANK_ENABLED=true; "
                    "falls back to vector order otherwise.")
    response_format: Literal["markdown", "json"] = Field(default="markdown")


@blueteam_tool(
    name="blueteam_rag_query",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
    audit=True, truncate=True, redact=True,
)
async def blueteam_rag_query(params: RagQueryInput) -> str:
    """Retrieve analyst knowledge: prior cases, confirmed false positives, IR playbooks.
    Two stages. Vector recall pulls ``recall_k`` candidates (default 100) from the
    local SQLite store; the optional cross-encoder rerank re-scores them and keeps
    ``top_k``. Rerank is rank-based and applies NO score threshold, so a hit always
    carries its raw scores rather than a pass/fail verdict.
    Use this when the question is "have we seen this before / is this noise",
    not for searching live alerts (use ``blueteam_semantic_search`` for that) or
    live rule text (``blueteam_wazuh_get_rules``).

    Args:
        params.query: Natural-language query over the indexed corpus.
        params.top_k: Results after rerank.
        params.recall_k: Stage-1 candidate count.
        params.sources: Optional corpus label filter.
        params.rerank: Enable the cross-encoder second stage.
        params.response_format: 'markdown' (default) or 'json'.

    Returns:
        markdown or json with matches (text, source, scores, metadata) and the
        store's corpus stats so a stale index is visible.

    Examples:
        1. Prior cases on a host -> ``blueteam_rag_query(query="ssh brute force mail server")``
        2. Did we already call this noise? -> ``blueteam_rag_query(query="8.8.8.8 scanner noise",
           sources=["false_positives"])``
        3. Wider recall with rerank -> ``blueteam_rag_query(query="webshell upload nginx",
           rerank=True, recall_k=100)``
        4. IR guidance -> ``blueteam_rag_query(query="containment steps for ransomware",
           sources=["ir_playbooks"])``

    Permissions: read on BLUETEAM_RAG_DB. Rate limits: none; the first call loads
    the embedder (one-off ONNX session build, a few seconds).
    """
    _require_store()
    recall = min(params.recall_k, config.rag.max_candidates)

    hits, status = await rag_store.query(params.query, top_k=recall, sources=params.sources)
    if status is not None and not hits:
        if params.response_format == "json":
            return json.dumps({"query": params.query, "matches": [], "status": status},
                              indent=2, ensure_ascii=False)
        return (f"# 🔎 RAG Query - `{params.query}`\n\n"
                f"No matches (status: `{status}`).\n\n"
                "- `disabled` / `unavailable: ...` -> the store or embedder is not ready.\n"
                "- `no_corpus` -> the store is empty or this query found nothing. Run "
                "`blueteam_rag_ingest`.")

    reranked = False
    rerank_status: Optional[str] = None
    if params.rerank and hits:
        hits, reranked, rerank_status = await _rerank_hits(params.query, hits, params.top_k)
    else:
        hits = hits[:params.top_k]

    store = rag_store.stats()
    if params.response_format == "json":
        return json.dumps({
            "query": params.query, "matches": hits, "reranked": reranked,
            "rerank_status": rerank_status, "recall_k": recall, "returned": len(hits),
            "store": store,
        }, indent=2, ensure_ascii=False)

    score_col = "Rerank" if reranked else "Vector"
    lines = [f"# 🔎 RAG Query - `{params.query}`", "",
             f"**Candidates**: {recall} | **Returned**: {len(hits)} | "
             f"**Corpus**: {sum(store['chunks_by_model'].values())} chunks "
             f"(`{store['model']}`)", "",
             f"| # | {score_col} | Source | Meta | Text |",
             "|---|--------|--------|------|------|"]
    for rank, hit in enumerate(hits, 1):
        score = hit.get("rerank_score", hit.get("vector_score", 0.0))
        meta = json.dumps(hit.get("meta") or {}, ensure_ascii=False)[:40]
        text = " ".join(str(hit.get("text", "")).split())[:120]
        lines.append(f"| {rank} | {score:.3f} | `{hit.get('source', '?')}` | {meta} | {text} |")
    lines.append("")
    if params.rerank and rerank_status:
        lines.append(f"*Rerank fallback: {rerank_status} - results are vector-order only.*")
        lines.append("")
    lines.append("*Evidence only. Verify against live alerts before acting.*")
    return "\n".join(lines)


# False-positive evidence
class RagFpValidateInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    srcip: str = Field(..., min_length=2, max_length=128,
        description="The indicator under review (IP, domain, or hash). Checked against the "
                    "exact-suppression set and the attacker registry before any embedding.")
    description: str = Field(default="", max_length=2000,
        description="Alert text or rule description to match against the corpus. Empty falls "
                    "back to querying with the indicator itself.")
    min_matches: int = Field(default=3, ge=1, le=20,
        description="Corpus matches required before recommending FALSE POSITIVE.")
    min_rerank_score: Optional[float] = Field(default=None,
        description="Optional cross-encoder logit floor. None (default) uses match count "
                    "only, because raw logits are not calibrated across corpora. Set this "
                    "only from measured results on labelled cases.")
    top_k: int = Field(default=10, ge=1, le=50)
    rerank: bool = Field(default=True)
    response_format: Literal["markdown", "json"] = Field(default="markdown")


@blueteam_tool(
    name="blueteam_rag_fp_validate",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
    audit=True, truncate=True, redact=True,
)
async def blueteam_rag_fp_validate(params: RagFpValidateInput) -> str:
    """Assemble false-positive evidence for one indicator. Recommends; never writes.
    Deterministic, in this order:
    1. The indicator is in the exact-suppression set AND the attacker registry ->
       ``conflicting_state``. Neither store clears the other, so this tool refuses
       to pick a winner.
    2. The indicator is in the exact-suppression set -> ``suppressed_exact``. No
       embedding, no model, already excluded from 3-Sum scoring.
    3. The indicator is in the attacker registry -> ``likely_true_positive``. An
       analyst confirmed it; that outranks any corpus similarity.
    4. Corpus matches >= ``min_matches`` (and >= ``min_rerank_score`` when set) ->
       ``likely_false_positive``. Advisory.
    5. Otherwise -> ``insufficient_evidence``.

    This returns no confidence percentage. Nothing here produces a calibrated
    probability, and a fabricated number would drive exactly the wrong decision.
    Recording the outcome is a separate step: ``blueteam_mark_investigated``.

    Args:
        params.srcip: Indicator under review.
        params.description: Alert text to match against the corpus.
        params.min_matches: Match count needed for a false-positive recommendation.
        params.min_rerank_score: Optional calibrated logit floor.
        params.top_k: Corpus matches to return as evidence.
        params.rerank: Use the cross-encoder for the evidence ranking.
        params.response_format: 'markdown' (default) or 'json'.

    Returns:
        markdown or json with verdict, evidence block, and the matched corpus entries.

    Examples:
        1. Already suppressed IP -> ``blueteam_rag_fp_validate(srcip="8.8.8.8",
           description="ssh auth failure")`` returns ``suppressed_exact``.
        2. Confirmed attacker -> ``blueteam_rag_fp_validate(srcip="103.107.116.202", ...)``
           returns ``likely_true_positive`` even when the corpus looks similar.
        3. Marked false positive then later true positive -> ``conflicting_state``; the
           suppression entry is not cleared automatically.
        3. Unknown indicator with no corpus -> ``insufficient_evidence``; escalate.
        4. Strict gate after calibration -> ``blueteam_rag_fp_validate(..., rerank=True,
           min_rerank_score=1.5)``.

    Permissions: read on BLUETEAM_RAG_DB and BLUETEAM_FALSE_POSITIVE_KB. Rate limits:
    none. Findings are advisory; the analyst verdict is authoritative.
    """
    _require_store()
    exact_suppressed = is_false_positive(params.srcip)
    known_attacker = is_attacker_ioc(params.srcip)

    evidence_text = params.description or params.srcip
    hits, status = await rag_store.query(evidence_text, top_k=params.top_k)
    reranked = False
    rerank_status: Optional[str] = None
    if params.rerank and hits:
        hits, reranked, rerank_status = await _rerank_hits(evidence_text, hits, params.top_k)

    top_vector = hits[0]["vector_score"] if hits else None
    top_rerank = hits[0].get("rerank_score") if hits else None

    score_floor_ok = True
    if params.min_rerank_score is not None:
        score_floor_ok = top_rerank is not None and top_rerank >= params.min_rerank_score
    enough_matches = len(hits) >= params.min_matches

    if exact_suppressed and known_attacker:
        verdict = "conflicting_state"
        rationale = ("This indicator is in the false-positive suppression set AND the attacker "
                     "registry. Both were written from analyst verdicts, and neither store "
                     "clears the other, so precedence is unresolved here. Resolve it before "
                     "trusting either: re-mark the indicator with blueteam_mark_investigated, "
                     "and note that 3-Sum currently excludes it as a suppression hit.")
    elif exact_suppressed:
        verdict = "suppressed_exact"
        rationale = ("In the exact false-positive suppression set; the 3-Sum engine already "
                     "excludes it. Fix the upstream detection if it keeps alerting.")
    elif known_attacker:
        verdict = "likely_true_positive"
        rationale = ("Registered in the attacker registry from a prior analyst confirmation. "
                     "That outranks corpus similarity. Escalate.")
    elif enough_matches and score_floor_ok:
        verdict = "likely_false_positive"
        rationale = (f"{len(hits)} corpus match(es) at or above min_matches="
                     f"{params.min_matches}. Advisory: confirm the matched cases are the same "
                     "activity before closing.")
    else:
        verdict = "insufficient_evidence"
        rationale = (f"{len(hits)} corpus match(es), below min_matches={params.min_matches}. "
                     "Not evidence of a true positive either - investigate, do not auto-close.")

    evidence = {
        "exact_suppression_match": exact_suppressed,
        "attacker_registry_match": known_attacker,
        "kb_matches": len(hits),
        "min_matches_required": params.min_matches,
        "top_vector_score": round(top_vector, 6) if top_vector is not None else None,
        "top_rerank_score": round(top_rerank, 6) if top_rerank is not None else None,
        "rerank_score_floor": params.min_rerank_score,
        "score_floor_met": score_floor_ok,
        "corpus_status": status,
        "rerank_status": rerank_status,
        "confidence": "not_computed",
    }

    if params.response_format == "json":
        return json.dumps({
            "indicator": params.srcip, "verdict": verdict, "rationale": rationale,
            "evidence": evidence, "matches": hits, "reranked": reranked,
        }, indent=2, ensure_ascii=False)

    lines = [f"# ⚖️ FP Validation - `{params.srcip}`", "",
             f"**Verdict**: `{verdict}`", "",
             rationale, "",
             "## Evidence", "",
             f"- Exact suppression match: `{exact_suppressed}`",
             f"- Attacker registry match: `{known_attacker}`",
             f"- Corpus matches: `{len(hits)}` (min required: `{params.min_matches}`)",
             f"- Top vector score: `{evidence['top_vector_score']}`",
             f"- Top rerank score: `{evidence['top_rerank_score']}` "
             f"(floor: `{params.min_rerank_score}`)",
             f"- Confidence: `not_computed` (no calibrated probability is produced)", ""]
    if hits:
        lines.append("## Matched Corpus Entries")
        lines.append("")
        lines.append("| # | Source | Meta | Text |")
        lines.append("|---|--------|------|------|")
        for rank, hit in enumerate(hits, 1):
            meta = json.dumps(hit.get("meta") or {}, ensure_ascii=False)[:40]
            text = " ".join(str(hit.get("text", "")).split())[:110]
            lines.append(f"| {rank} | `{hit.get('source', '?')}` | {meta} | {text} |")
        lines.append("")
    lines.append("## Next Step")
    lines.append("")
    lines.append("Record the analyst decision with `blueteam_mark_investigated(srcip, verdict, "
                 "notes)`. A `false_positive` verdict also adds the indicator to the suppression "
                 "set and excludes it from 3-Sum scoring.")
    return "\n".join(lines)
