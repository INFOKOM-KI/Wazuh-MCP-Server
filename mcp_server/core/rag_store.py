#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Local case knowledge retrieval store: ONNX embeddings (fastembed) + SQLite.
Stage 1 of the retrieval pipeline. Holds analyst-authored cases, confirmed
false positives and converted IR playbooks as embedded chunks, and returns the
high-recall candidate set that ``core/rerank.py`` then re-scores.
Design constraints (each one is a deliberate choice, not a default):
- **No torch.** Embeddings come from fastembed's ONNX runtime, the same library
  ``rerank.py`` uses. ``sentence-transformers`` was rejected because it pulls
  torch, and torch is quarantined behind ``BLUETEAM_INSTALL_MARKER`` for the
  numpy<2 / torchvision==0.29.0 reason documented in requirements.txt.
- **No server process.** SQLite, not ChromaDB. At the corpus sizes this store
  is capped to (``BLUETEAM_RAG_MAX_CHUNKS``, default 50k) a single table plus a
  numpy dot product is smaller than the dependency tree ChromaDB brings.
- **No egress.** ``local_files_only=True`` unless ``allow_download`` is set.
  Chunks are stored UNREDACTED on purpose: they are embedded in-process and
  never leave it. Redaction belongs on the output path, and masking attacker
  domains before embedding would make the corpus unmatchable (the same failure
  PRD FR-40 documents for YARA rules).
- **Numpy.** numpy is only a transitive dependency via fastembed, so it is
  imported inside functions. A module-level ``import numpy`` would break
  ``register_all_tools()`` for every tool at once if fastembed is absent, the
  exact failure mode requirements.txt warns about for pyyaml.
Nothing here is loaded at import time; the embedder is built on first use.
Every failure path returns ``(None, status)`` so callers degrade to lexical-only
retrieval instead of raising.
"""
from __future__ import annotations
import asyncio
import contextlib
import hashlib
import json
import logging
import os
import sqlite3
import threading
import time
from typing import Optional
from mcp_server.core.config import config
from mcp_server.core.rerank import _sha256_file

logger = logging.getLogger("blue_team_mcp.rag_store")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS chunks (
    id         TEXT PRIMARY KEY,
    source     TEXT NOT NULL,
    seq        INTEGER NOT NULL,
    text       TEXT NOT NULL,
    meta       TEXT NOT NULL DEFAULT '{}',
    model      TEXT NOT NULL,
    dim        INTEGER NOT NULL,
    vec        BLOB NOT NULL,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chunks_model  ON chunks(model);
CREATE INDEX IF NOT EXISTS idx_chunks_source ON chunks(source);
"""

# Module level singleton, mirrors rerank.py's encoder pattern.
_embedder: Optional[object] = None
_reason: str = "not loaded"
_load_lock = threading.Lock()

# Matrix cache: streaming the whole table per query is O(n) disk reads, and a
# query is the hot path. Keyed on (path, mtime, count, model, sources) so an
# ingest in this process OR another one invalidates it. Whole corpus
# in-memory cache, swap to an ANN index only past ~500k chunks.
_cache_lock = threading.Lock()
_cache_key: Optional[tuple] = None
_cache_rows: Optional[list[dict]] = None
_cache_matrix: Optional[object] = None


def _db_path() -> str:
    return (config.rag.db_path or "").strip()


def reason() -> str:
    """Human readable status of the last (attempted) embedder load."""
    return _reason


def _embedding_model_file(model: str) -> str:
    """Relative ONNX path fastembed loads for ``model`` (e.g. ``onnx/model.onnx``).
    Read from fastembed's public registry so the name tracks fastembed versions;
    same approach as ``rerank._model_file_name`` (different registry: the
    embedding class, not the cross-encoder class).
    """
    from fastembed import TextEmbedding

    for entry in TextEmbedding.list_supported_models():
        if entry["model"] == model:
            return entry["model_file"]
    raise ValueError(f"model {model!r} is not in fastembed's TextEmbedding registry")


def _ensure_loaded() -> bool:
    """Build the ONNX embedder on first use. Never called at import time.
    Runs under a lock; safe from a worker thread. Any failure (fastembed
    missing, model not cached, ONNX session error) leaves the store unavailable
    and callers degrade to lexical-only.
    With ``sha256`` set, the model is resolved from cache without any network
    access and the exact ONNX file fastembed will load is hashed before the
    session is built (``lazy_load``). A mismatch refuses the load: fail closed.
    """
    global _embedder, _reason
    if _embedder is not None:
        return True
    with _load_lock:
        if _embedder is not None:
            return True
        try:
            from fastembed import TextEmbedding
            cfg = config.rag
            cache_dir = cfg.cache_path or None
            if cfg.sha256:
                embedder = TextEmbedding(
                    model_name=cfg.model, cache_dir=cache_dir,
                    lazy_load=True, local_files_only=True,
                )
                # _model_dir lives on the INNER onnx encoder (embedder.model),
                # not the outer TextEmbedding. Verified for TextCrossEncoder on
                # fastembed 0.5.0/0.8.0; see rerank.py. If a future fastembed
                # moves it, this raises AttributeError and is caught below.
                loaded = os.path.join(
                    str(embedder.model._model_dir), _embedding_model_file(cfg.model))
                if not os.path.isfile(loaded):
                    _reason = (
                        f"sha256 pin mismatch: model file not found: {loaded}; "
                        "re-run setup.sh to bootstrap the model into the cache"
                    )
                    return False
                actual = _sha256_file(loaded)
                if actual != cfg.sha256:
                    _reason = (
                        f"sha256 pin mismatch: {loaded} hashes to {actual}, "
                        f"expected {cfg.sha256}; refusing to load (regenerate the pin "
                        "with sha256sum if the model was legitimately updated)"
                    )
                    return False
                _embedder = embedder
            else:
                _embedder = TextEmbedding(
                    model_name=cfg.model, cache_dir=cache_dir,
                    local_files_only=not cfg.allow_download,
                )
            _reason = "ready"
            logger.info("RAG embedder loaded model=%s", cfg.model)
            return True
        except Exception as exc:
            _reason = f"model load failed: {exc}"
            logger.warning("RAG embedder unavailable: %s", _reason)
            return False


async def embed_texts(texts: list[str]) -> tuple[Optional[object], Optional[str]]:
    """Embed ``texts`` to L2-normalized float32 rows.
    Returns ``(matrix, status)``: ``matrix`` is shape ``(len(texts), dim)`` and
    ``status`` is ``None`` on success, else ``"empty"`` / ``"disabled"`` /
    ``"unavailable: ..."``. Normalizing at write time means cosine similarity
    downstream is a plain dot product.
    """
    if not texts:
        return None, "empty"
    if not config.rag.enabled or not _db_path():
        return None, "disabled"
    if not await asyncio.to_thread(_ensure_loaded):
        return None, f"unavailable: {_reason}"
    import numpy as np

    raw = await asyncio.to_thread(lambda: list(_embedder.embed(texts)))
    matrix = np.vstack([np.asarray(v, dtype=np.float32) for v in raw])
    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    matrix = matrix / np.maximum(norms, 1e-12)
    return matrix, None


def _connect() -> sqlite3.Connection:
    """Fresh connection per call. A shared connection would need
    ``check_same_thread=False`` plus its own lock, because every call runs
    inside ``asyncio.to_thread`` on an arbitrary worker thread.
    """
    conn = sqlite3.connect(_db_path(), timeout=30.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(_SCHEMA)


def _chunk_id(source: str, seq: int, text: str) -> str:
    """Content-addressed id: re-ingesting the same chunk is a no-op upsert."""
    return hashlib.sha256(f"{source}\x00{seq}\x00{text}".encode("utf-8")).hexdigest()[:32]


def _write_rows(rows: list[tuple]) -> tuple[int, int]:
    """Persist embedded rows. Returns ``(inserted, rejected)``.
    ``rejected`` counts rows dropped by the corpus cap surfaced rather than
    swallowed, because a silently truncated corpus looks like a retrieval bug.
    """
    cap = config.rag.max_chunks
    path = _db_path()
    with contextlib.closing(_connect()) as conn:
        _ensure_schema(conn)
        used = conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
        room = max(0, cap - used)
        kept = rows[:room]
        if kept:
            conn.executemany(
                "INSERT OR REPLACE INTO chunks "
                "(id, source, seq, text, meta, model, dim, vec, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                kept,
            )
            conn.commit()
    # Owner only: the corpus holds attacker IOC and internal hostnames.
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)
    return len(kept), max(0, len(rows) - room)


def _load_matrix(model: str, sources: Optional[list[str]]):
    """Return ``(matrix, rows)`` for ``model``, cached across queries."""
    global _cache_key, _cache_rows, _cache_matrix
    import numpy as np

    path = _db_path()
    if not os.path.exists(path):
        return None, []
    key = (path, os.stat(path).st_mtime_ns, model, tuple(sources or ()))
    with _cache_lock:
        if _cache_key == key and _cache_matrix is not None:
            return _cache_matrix, _cache_rows

        sql = "SELECT id, source, seq, text, meta, dim, vec FROM chunks WHERE model = ?"
        args: list = [model]
        if sources:
            sql += f" AND source IN ({','.join('?' * len(sources))})"
            args.extend(sources)
        with contextlib.closing(_connect()) as conn:
            fetched = conn.execute(sql, args).fetchall()
        if not fetched:
            return None, []

        dims = {row[5] for row in fetched}
        if len(dims) != 1:
            # Mixed dims mean a partial re-embed or a hand-edited db; refuse
            # rather than build a ragged matrix.
            logger.warning("RAG store has mixed vector dims %s - refusing to search", dims)
            return None, []
        matrix = np.vstack([np.frombuffer(row[6], dtype=np.float32) for row in fetched])
        rows = [{
            "id": row[0], "source": row[1], "seq": row[2], "text": row[3],
            "meta": json.loads(row[4] or "{}"), "dim": row[5],
        } for row in fetched]
        _cache_key, _cache_rows, _cache_matrix = key, rows, matrix
        return matrix, rows


def _search_sync(query_vec_bytes: bytes, model: str, k: int,
                 sources: Optional[list[str]]) -> list[dict]:
    """Dot-product top-k over the (already normalized) corpus matrix."""
    import numpy as np

    matrix, rows = _load_matrix(model, sources)
    if matrix is None or not rows:
        return []
    query_vec = np.frombuffer(query_vec_bytes, dtype=np.float32)
    if query_vec.shape[0] != matrix.shape[1]:
        logger.warning("RAG query dim %d != corpus dim %d",
                       query_vec.shape[0], matrix.shape[1])
        return []
    scores = matrix @ query_vec
    k = max(1, min(k, len(rows)))
    # argpartition then sort the shortlist: O(n) instead of a full O(n log n) sort.
    top = np.argpartition(-scores, k - 1)[:k]
    top = top[np.argsort(-scores[top])]
    out = []
    for idx in top:
        hit = dict(rows[int(idx)])
        hit["vector_score"] = round(float(scores[int(idx)]), 6)
        out.append(hit)
    return out


async def add_documents(docs: list[dict]) -> tuple[int, Optional[str]]:
    """Embed and persist ``docs``. Each doc: ``{source, text, seq?, meta?}``.
    Returns ``(inserted, status)``. Idempotent: the chunk id is a content hash,
    so ingesting the same corpus twice does not duplicate rows.
    """
    if not docs:
        return 0, "empty"
    if not config.rag.enabled or not _db_path():
        return 0, "disabled"
    matrix, status = await embed_texts([d["text"] for d in docs])
    if matrix is None:
        return 0, status
    now = time.time()
    rows = []
    for i, doc in enumerate(docs):
        source = str(doc.get("source", ""))
        seq = int(doc.get("seq", i))
        text = doc["text"]
        rows.append((
            _chunk_id(source, seq, text), source, seq, text,
            json.dumps(doc.get("meta") or {}, ensure_ascii=False),
            config.rag.model, int(matrix.shape[1]), matrix[i].tobytes(), now,
        ))
    inserted, dropped = await asyncio.to_thread(_write_rows, rows)
    if dropped:
        logger.warning("RAG corpus cap %d reached - %d chunk(s) rejected",
                       config.rag.max_chunks, dropped)
        return inserted, (f"capped: {dropped} chunk(s) rejected at "
                          "BLUETEAM_RAG_MAX_CHUNKS; raise it or prune the corpus")
    return inserted, None


async def query(text: str, top_k: Optional[int] = None,
                sources: Optional[list[str]] = None) -> tuple[list[dict], Optional[str]]:
    """Stage 1 retrieval: high-recall candidate set for the reranker.
    Returns ``(hits, status)`` sorted by descending vector score. ``status`` is
    ``None`` on success, else ``"empty"`` / ``"disabled"`` / ``"unavailable: ..."``
    / ``"no_corpus"``. Callers pass hits to ``core/rerank.py`` and truncate;
    this function applies NO score threshold, because raw cosine values are not
    calibrated across corpora.
    """
    if not (text or "").strip():
        return [], "empty"
    k = top_k if top_k is not None else config.rag.max_candidates
    matrix, status = await embed_texts([text])
    if matrix is None:
        return [], status
    hits = await asyncio.to_thread(
        _search_sync, matrix[0].tobytes(), config.rag.model, k, sources)
    return (hits, None) if hits else ([], "no_corpus")


async def delete_source(source: str) -> int:
    """Drop every chunk carrying this source label. Returns rows removed.
    The RAG index is DERIVED from case_store / false_positive_kb. Chunk ids are
    content hashes, so an edited case would otherwise leave its old chunk behind
    alongside the new one and keep matching queries forever. Ingest deletes the
    label first because of this.
    """
    if not source or not _db_path():
        return 0
    return await asyncio.to_thread(_delete_source_sync, source)


def _delete_source_sync(source: str) -> int:
    if not os.path.exists(_db_path()):
        return 0
    with contextlib.closing(_connect()) as conn:
        _ensure_schema(conn)
        removed = conn.execute("DELETE FROM chunks WHERE source = ?", (source,)).rowcount
        conn.commit()
    return removed


def stats() -> dict:
    """Operator-facing store status. No model load, safe to call anywhere."""
    path = _db_path()
    counts: dict = {}
    sources: list = []
    if path and os.path.exists(path):
        with contextlib.closing(_connect()) as conn:
            _ensure_schema(conn)
            counts = {row[0]: row[1] for row in
                      conn.execute("SELECT model, COUNT(*) FROM chunks GROUP BY model")}
            sources = [row[0] for row in
                       conn.execute("SELECT DISTINCT source FROM chunks ORDER BY source")]
    return {
        "enabled": config.rag.enabled,
        "db_path": path or None,
        "exists": bool(path) and os.path.exists(path),
        "model": config.rag.model,
        "embedder": _reason,
        "download_allowed": config.rag.allow_download,
        "chunks_by_model": counts,
        "sources": sources,
        "max_chunks": config.rag.max_chunks,
        "max_candidates": config.rag.max_candidates,
        "top_k": config.rag.top_k,
    }
