#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Optional two stage retrieval reranker: BM25 recall + cross-encoder rerank.
Local-only ONNX cross-encoder (BAAI/bge-reranker-base)
via fastembed's TextCrossEncoder. Off by default (BLUETEAM_RERANK_ENABLED=false).
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
from mcp_server.core.config import config

logger = logging.getLogger("blue_team_mcp.rerank")

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
                    lazy_load=True,
                    local_files_only=True,
                )
                # _model_dir is fastembed-internal (verified 0.5.0 and 0.8.0);
                # it is the dir fastembed's own load path resolves the ONNX from.
                loaded = os.path.join(str(encoder._model_dir), _model_file_name(config.rerank.model))
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
