#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Optional two stage retrieval reranker: BM25 recall + cross-encoder rerank.
Local-only INT8-quantized ONNX cross-encoder (BAAI/bge-reranker-v2-m3)
via fastembed's TextCrossEncoder. Off by default (BLUETEAM_RERANK_ENABLED=false).
Never a hosted API, query and document text never leave the process.
Lazy load on first use, thread-offloaded load + inference, graceful fallback to
BM25-only when fastembed is missing or the model cannot be loaded.
"""
from __future__ import annotations
import asyncio
import logging
import threading
from typing import Optional
from mcp_server.core.config import config

logger = logging.getLogger("blue_team_mcp.rerank")

# Module level (mirrors prompt_router._get_router singleton pattern).
_encoder: Optional[object] = None
_reason: str = "not loaded"
_load_lock = threading.Lock()


def reason() -> str:
    """Human readable status of the last (attempted) model load."""
    return _reason


def _ensure_loaded() -> bool:
    """Load the cross-encoder on first use. Never called at import time.
    Runs under a lock; safe to call from a worker thread. Any failure
    (fastembed missing, model not downloaded, ONNX session error) leaves the
    reranker unavailable, callers fall back to BM25-only.
    """
    global _encoder, _reason
    if _encoder is not None:
        return True
    with _load_lock:
        if _encoder is not None:
            return True
        try:
            from fastembed.rerank.cross_encoder import TextCrossEncoder
            _encoder = TextCrossEncoder(
                model_name=config.rerank.model,
                cache_dir=config.rerank.cache_path or None,
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
    Callers fall back to BM25-only when ``status`` is not ``None``. Both the
    model load and the inference run via ``asyncio.to_thread`` so the event
    loop is never blocked by ONNX CPU work.
    """
    if not docs:
        return [], "empty"
    if not config.rerank.enabled:
        return [], "disabled"
    if not await asyncio.to_thread(_ensure_loaded):
        return [], f"unavailable: {_reason}"
    scores = await asyncio.to_thread(_encoder.rerank, query, docs)
    return list(scores), None
