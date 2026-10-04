#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Optional two stage retrieval reranker: BM25 recall + cross-encoder rerank.
Local-only ONNX cross-encoder (BAAI/bge-reranker-base)
via fastembed's TextCrossEncoder. On by default (BLUETEAM_RERANK_ENABLED=true);
unsupported model names fail closed at startup (see config._fastembed_rerank_models).
Never a hosted API, query and document text never leave the process.
Lazy load on first use, thread-offloaded load + inference, graceful fallback to
BM25-only when fastembed is missing or the model cannot be loaded.
"""
from __future__ import annotations
import asyncio
import hashlib
import logging
import os
import threading
from typing import Optional
from mcp_server.core import term_sim
from mcp_server.core.config import config

logger = logging.getLogger("blue_team_mcp.rerank")

logger = logging.getLogger("blue_team_mcp.rerank")

CUSTOM_RERANK_MODELS: dict[str, dict] = {
    "madebyaris/rerank-indonesia": {
        "hf": "madebyaris/rerank-indonesia",
        "model_file": "onnx/model.onnx",
        "additional_files": [
            "config.json", "tokenizer.json", "tokenizer_config.json",
            "special_tokens_map.json", "sentencepiece.bpe.model",
        ],
        "description": "Indonesian cross-encoder distilled from BAAI/bge-reranker-v2-m3",
        "license": "apache-2.0",
        "size_in_gb": 0.12,
    },
}


def register_custom_models() -> int:
    """Make the models in ``CUSTOM_RERANK_MODELS`` loadable by fastembed.
    Idempotent and non-fatal by design: called from ``RerankConfig.validate()``, which
    runs during ``init_config()`` at import time. A registration failure must therefore
    degrade to the existing fail-closed registry error, never to a startup crash on a
    host that simply has no fastembed. Returns the number registered by this call.
    """
    try:
        from fastembed.common.model_description import ModelSource
        from fastembed.rerank.cross_encoder import TextCrossEncoder
    except ImportError:
        return 0
    try:
        already = {entry["model"] for entry in TextCrossEncoder.list_supported_models()}
        registered = 0
        for model_name, spec in CUSTOM_RERANK_MODELS.items():
            if model_name in already:
                continue
            TextCrossEncoder.add_custom_model(
                model=model_name,
                sources=ModelSource(hf=spec["hf"]),
                model_file=spec["model_file"],
                additional_files=spec["additional_files"],
                description=spec["description"],
                license=spec["license"],
                size_in_gb=spec["size_in_gb"],
            )
            registered += 1
        if registered:
            logger.info("Registered %d custom cross-encoder(s): %s",
                        registered, ", ".join(CUSTOM_RERANK_MODELS))
        return registered
    except Exception as exc:
        logger.warning("Custom reranker registration failed: %s", exc)
        return 0


# Module level (mirrors prompt_router._get_router singleton pattern).
_encoder: Optional[object] = None
_reason: str = "not loaded"
_load_lock = threading.Lock()


def _sha256_file(path: str) -> str:
    """sha256 of a file's bytes, streamed (models are hundreds of MB)."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _model_file_name(model: str) -> str:
    """Relative ONNX path fastembed loads for ``model`` (e.g. ``onnx/model.onnx``).
    Read from fastembed's public registry so the name tracks fastembed versions.
    """
    from fastembed.rerank.cross_encoder import TextCrossEncoder

    for entry in TextCrossEncoder.list_supported_models():
        if entry["model"] == model:
            return entry["model_file"]
    raise ValueError(
        f"model {model!r} is not in fastembed's TextCrossEncoder registry"
    )


def reason() -> str:
    """Human readable status of the last (attempted) model load."""
    return _reason


def status_dict(status: Optional[str], fallback_engine: str = "bm25") -> dict:
    """Uniform ``{rerank_used, rerank_engine, rerank_status}`` block for tool output.
    Retrieval tools spread this into their payload so an analyst can never
    mistake a lexical/vector result for a cross-encoder-ranked one. ``status``
    is the value returned by ``rerank()``/``rerank_hits()``: ``None`` means the
    cross-encoder produced the ranking, anything else is why it did not.
    ``fallback_engine`` names the ranking that was used instead (``bm25`` for
    lexical recall, ``vector`` for the RAG embedding store).
    """
    used = status is None
    return {
        "rerank_used": used,
        "rerank_engine": f"cross-encoder:{config.rerank.model}" if used else fallback_engine,
        "rerank_status": "ok" if used else (status or "not_requested"),
    }


def prewarm() -> None:
    """Load the cross encoder in a daemon thread so the first tool call is warm.
    Called once at startup from ``main.py``. Deliberately non-blocking: a cold
    cache load can take tens of seconds, and stdio clients time out if the MCP
    handshake waits on it. A no-op when the reranker is disabled.
    """
    if not config.rerank.enabled:
        return
    threading.Thread(target=_ensure_loaded, name="rerank-prewarm", daemon=True).start()


def _ensure_loaded() -> bool:
    """Load the cross-encoder on first use. Never called at import time.
    Runs under a lock; safe to call from a worker thread. Any failure
    (fastembed missing, model not downloaded, ONNX session error) leaves the
    reranker unavailable, callers fall back to BM25-only.
    With BLUETEAM_RERANK_MODEL_SHA256 set (supply-chain pin), the model is
    resolved from cache without any network download and the exact ONNX file
    fastembed will load is hashed and compared to the pin BEFORE the ONNX
    session is built (lazy_load). Any mismatch refuses the load - fail closed.
    """
    global _encoder, _reason
    if _encoder is not None:
        return True
    with _load_lock:
        if _encoder is not None:
            return True
        try:
            from fastembed.rerank.cross_encoder import TextCrossEncoder
            pin = config.rerank.sha256
            if pin:
                # Pinned path: never download at runtime. local_files_only makes
                # fastembed raise if the model is not already cached, lazy_load
                # defers the ONNX session until after verification below.
                encoder = TextCrossEncoder(
                    model_name=config.rerank.model,
                    cache_dir=config.rerank.cache_path or None,
                    specific_model_path=config.rerank.model_path or None,
                    lazy_load=True,
                    local_files_only=True,
                )
                # _model_dir is fastembed internal and lives on the INNER
                # encoder (encoder.model), not the outer TextCrossEncoder
                # verified on 0.5.0 and 0.8.0; the outer raises AttributeError.
                loaded = os.path.join(str(encoder.model._model_dir), _model_file_name(config.rerank.model))
                if not os.path.isfile(loaded):
                    _reason = (
                        f"sha256 pin mismatch: model file not found: {loaded}; "
                        "re-run setup.sh to bootstrap the model into the cache"
                    )
                    return False
                actual = _sha256_file(loaded)
                if actual != pin:
                    _reason = (
                        f"sha256 pin mismatch: {loaded} hashes to {actual}, "
                        f"expected {pin}; refusing to load (regenerate the pin with "
                        "sha256sum if the model was legitimately updated)"
                    )
                    return False
                _encoder = encoder
            else:
                _encoder = TextCrossEncoder(
                    model_name=config.rerank.model,
                    cache_dir=config.rerank.cache_path or None,
                    specific_model_path=config.rerank.model_path or None,
                    local_files_only=not config.rerank.allow_download,
                )
            _reason = "ready"
            logger.info("Reranker loaded model=%s", config.rerank.model)
            return True
        except Exception as exc:  # ImportError / OSError / download / ONNX errors
            _reason = f"model load failed: {exc}"
            logger.warning("Reranker unavailable: %s", _reason)
            return False


async def rerank(query: str, docs: list[str]) -> tuple[list[float], Optional[str]]:
    """Re-score candidate docs against the query via the cross-encoder.
    Returns ``(scores, status)``:
    - ``scores``: raw logits in the SAME order as ``docs`` (empty on fallback).
    - ``status``: ``None`` on success; otherwise a short reason (``"disabled"``,
      ``"unavailable: …"``, ``"empty"``) so callers can surface the fallback.
    Callers fall back to lexical-only when ``status`` is not ``None``. Both the
    model load and the inference run via ``asyncio.to_thread`` so the event loop
    is never blocked by ONNX CPU work. Use ``rerank_hits`` instead when the input
    is a list of retrieval hit dicts rather than raw strings.
    """
    if not docs:
        return [], "empty"
    if not config.rerank.enabled:
        return [], "disabled"
    if not await asyncio.to_thread(_ensure_loaded):
        return [], f"unavailable: {_reason}"
    scores = await asyncio.to_thread(_encoder.rerank, query, docs)
    return list(scores), None


def normalize_rerank_scores(scores: list[float]) -> list[float]:
    """Rescale cross-encoder output onto [0,1]. Ported from RAGFlow's
    ``NormalizeRerankScores``.
    - Empty: unchanged.
    - Already inside [0,1]: unchanged, so a calibrated provider's magnitudes survive.
    - Spread under 1e-3 (all-identical, or one candidate): clamp per element, never
      min-max, so a lone high score is not zeroed.
    - Otherwise min-max onto [0,1], which stops a negative logit dragging a hit below a
      keyword match.
    Returns a new list; the input is never mutated.
    """
    if not scores:
        return list(scores)
    low = min(scores)
    high = max(scores)
    if low >= 0.0 and high <= 1.0:
        return list(scores)
    if high - low < 1e-3:
        return [0.0 if s < 0.0 else (1.0 if s > 1.0 else s) for s in scores]
    span = 1.0 / (high - low)
    return [(s - low) * span for s in scores]


async def rerank_hits(query: str, hits: list[dict], top_k: int,
                      score_field: str = "vector_score", *,
                      term_scores: Optional[list[float]] = None,
                      vector_weight: Optional[float] = None
                      ) -> tuple[list[dict], bool, Optional[str]]:
    """Re-score retrieval ``hits`` (dicts carrying a ``text`` key) against ``query``.
    This is the second stage for every retrieval caller, so the ordering rule
    lives in exactly one place. Candidates are clamped by
    ``config.rerank.max_candidates`` so the rerank fan out is bounded identically
    for every caller. Returns ``(hits, reranked, status)``. When ``status`` is not
    ``None`` the original ordering is returned truncated and the caller should
    surface why.
    Each text is bounded to ``config.rag.chunk_chars``, since a parent hit carries the
    whole document while a child chunk is already within that bound.

    ``config.rerank.normalize`` rescales the cross-encoder output onto [0,1] with
    :func:`normalize_rerank_scores`, but only on the fusion path, which needs
    ``term_scores`` and a ``vector_weight`` below 1.0. Every other caller receives the
    raw logit in ``rerank_score``, so a logit threshold keeps its units.

    Fusion is ``sim = vector_weight*rerank + (1-vector_weight)*term``; ``term_scores``
    aligns to ``hits`` and the caller computes it over the corpus term tables.
    ``vector_weight=1.0`` omits the term leg, so it neither fuses nor normalizes. On the
    fused path ``rerank_score`` is the normalized value, ``rerank_raw`` keeps the logit,
    and ``term_score``/``hybrid_score`` carry the blend.
    """
    candidates = hits[:config.rerank.max_candidates]
    # A parent holds the whole document and can run several chunks long. Bound each
    # text to one retrieval unit; a child chunk is already at or below it.
    bound = config.rag.chunk_chars
    scores, status = await rerank(query, [hit["text"][:bound] for hit in candidates])
    if status is not None:
        return hits[:top_k], False, status

    # Fusion is the only consumer that needs a common scale; other callers keep the logit.
    normalizing = (config.rerank.normalize and term_scores is not None
                   and vector_weight is not None and vector_weight < 1.0)

    raw_scores: Optional[list[float]] = None
    fused: Optional[list[float]] = None
    if normalizing:
        raw_scores = list(scores)
        scores = normalize_rerank_scores(scores)
        if len(term_scores) < len(candidates):
            raise ValueError(
                f"term_scores has {len(term_scores)} entries for {len(candidates)} "
                "rerank candidates; they must align by chunk index"
            )
        fused = term_sim.hybrid(scores, term_scores[:len(candidates)], vector_weight)
        order = sorted(range(len(candidates)), key=lambda i: (-fused[i], -scores[i]))
    else:
        order = sorted(range(len(candidates)),
                       key=lambda i: (-scores[i], -candidates[i].get(score_field, 0.0)))

    ranked: list[dict] = []
    for i in order[:top_k]:
        hit = {**candidates[i], "rerank_score": round(float(scores[i]), 6)}
        if raw_scores is not None:
            hit["rerank_raw"] = round(float(raw_scores[i]), 6)
        if fused is not None:
            hit["term_score"] = round(float(term_scores[i]), 6)
            hit["hybrid_score"] = round(float(fused[i]), 6)
        ranked.append(hit)
    return ranked, True, None
