#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Local case knowledge retrieval store: ONNX embeddings (fastembed) + SQLite.
Stage 1 of the retrieval pipeline. Holds analyst-authored cases, confirmed
false positives and converted IR playbooks, and returns the high-recall
candidate set that ``core/rerank.py`` then re-scores.
A row is one of two kinds. A chunk is matchable. A parent, written only when
``config.rag.parent_child`` is set and a document spans more than one chunk,
holds the whole document text, is excluded from the matchable matrix, and is
returned in place of the children that matched it.
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
from mcp_server.core import term_sim
from mcp_server.core.config import config
from mcp_server.core.exceptions import MigrationError
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
    created_at REAL NOT NULL,
    parent_id  TEXT NOT NULL DEFAULT '',
    is_parent  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_chunks_model  ON chunks(model);
CREATE INDEX IF NOT EXISTS idx_chunks_source ON chunks(source);
"""

# Created after the column migrations: on a store that predates parent_id, an index on
# that column fails until the ALTER has run.
_PARENT_INDEX = "CREATE INDEX IF NOT EXISTS idx_chunks_parent ON chunks(parent_id)"


# Columns added after the first release. CREATE TABLE IF NOT EXISTS says nothing about
# a store that already has the table, so each one is applied by _ensure_schema.
_COLUMN_MIGRATIONS = (
    ("parent_id", "TEXT NOT NULL DEFAULT ''"),
    ("is_parent", "INTEGER NOT NULL DEFAULT 0"),
)

# Module level singleton, mirrors rerank.py's encoder pattern.
_embedder: Optional[object] = None
_reason: str = "not loaded"
_load_lock = threading.Lock()

# Matrix cache: a query would otherwise stream the whole table. Keyed on
# (path, mtime, model, sources), so any ingest invalidates it. ANN index past ~500k rows.
_cache_lock = threading.Lock()
_cache_key: Optional[tuple] = None
_cache_rows: Optional[list[dict]] = None
_cache_matrix: Optional[object] = None
_cache_stats: Optional[tuple[dict[str, int], dict[str, int]]] = None


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


async def embed_texts(texts: list[str], *,
                      require_store: bool = True) -> tuple[Optional[object], Optional[str]]:
    """Embed ``texts`` to L2-normalized float32 rows.
    Returns ``(matrix, status)``: ``matrix`` is shape ``(len(texts), dim)`` and
    ``status`` is ``None`` on success, else ``"empty"`` / ``"disabled"`` /
    ``"unavailable: ..."``. Normalizing at write time means cosine similarity
    downstream is a plain dot product.
    ``require_store=False`` skips the RAG enabled/db_path gate so a caller that
    needs vectors but no corpus (the ONNX labeler) shares this embedder instead
    of loading a second ONNX session of the same model.
    """
    if not texts:
        return None, "empty"
    if require_store and (not config.rag.enabled or not _db_path()):
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
    """Create the table when absent, then add any column the store predates.
    Idempotent: the PRAGMA read decides. A failure raises rather than continuing.
    """
    conn.executescript(_SCHEMA)
    present = {row[1] for row in conn.execute("PRAGMA table_info(chunks)")}
    for column, decl in _COLUMN_MIGRATIONS:
        if column in present:
            continue
        try:
            conn.execute(f"ALTER TABLE chunks ADD COLUMN {column} {decl}")
        except sqlite3.Error as exc:
            raise MigrationError(
                f"cannot add column {column!r} to {_db_path()}: {exc}. The store is "
                "older than this build and the migration failed, so every query "
                "would fail on the missing column. Restore write access to the "
                "file, or point BLUETEAM_RAG_DB at a fresh path and re-ingest."
            ) from exc
    try:
        conn.execute(_PARENT_INDEX)
    except sqlite3.Error as exc:
        raise MigrationError(
            f"cannot create the parent index on {_db_path()}: {exc}. Restore write "
            "access to the file, or point BLUETEAM_RAG_DB at a fresh path and "
            "re-ingest."
        ) from exc
    conn.commit()


def _chunk_id(source: str, seq: int, text: str) -> str:
    """Content-addressed id: re-ingesting the same chunk is a no-op upsert."""
    return hashlib.sha256(f"{source}\x00{seq}\x00{text}".encode("utf-8")).hexdigest()[:32]


def _parent_id(source: str, doc_key: str) -> str:
    """Parent row id derived from the document key, never from seq.
    seq shifts when a document is added or removed, and the literal "parent" cannot
    collide with the integer a chunk id puts in the same slot.
    """
    return hashlib.sha256(
        f"{source}\x00parent\x00{doc_key}".encode("utf-8")).hexdigest()[:32]


def _write_rows(rows: list[tuple]) -> tuple[int, int]:
    """Persist embedded rows. Returns ``(inserted, rejected)``.
    The cap truncates whole document groups, so no parent is persisted without its
    children and no child without its parent. ``rejected`` counts what it dropped.
    """
    cap = config.rag.max_chunks
    path = _db_path()
    groups: list[list[tuple]] = []
    for row in rows:
        # A group starts at every row with no parent_id.
        if not groups or row[9] == "":
            groups.append([row])
        else:
            groups[-1].append(row)
    with contextlib.closing(_connect()) as conn:
        _ensure_schema(conn)
        used = conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
        room = max(0, cap - used)
        kept: list[tuple] = []
        for group in groups:
            if len(kept) + len(group) > room:
                break
            kept.extend(group)
        if kept:
            conn.executemany(
                "INSERT OR REPLACE INTO chunks "
                "(id, source, seq, text, meta, model, dim, vec, created_at, parent_id, is_parent) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                kept,
            )
            conn.commit()
    # Owner only: the corpus holds attacker IOC and internal hostnames.
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)
    return len(kept), max(0, len(rows) - len(kept))


def _build_stats(rows: list[dict]) -> tuple[dict[str, int], dict[str, int]]:
    """Corpus term-frequency and document-frequency tables for the lexical leg.
    Tokenizing every chunk is the expensive part of the first hybrid query, so this
    runs inside the same worker thread and cache generation as the matrix build.
    """
    tf: dict[str, int] = {}
    df: dict[str, int] = {}
    for row in rows:
        seen: set[str] = set()
        for token in term_sim.tokenize(row["text"]):
            tf[token] = tf.get(token, 0) + 1
            if token not in seen:
                seen.add(token)
                df[token] = df.get(token, 0) + 1
    return tf, df


def _load_matrix(model: str, sources: Optional[list[str]]):
    """Return ``(matrix, rows)`` for ``model``, cached across queries."""
    global _cache_key, _cache_rows, _cache_matrix, _cache_stats
    import numpy as np

    path = _db_path()
    if not os.path.exists(path):
        return None, []
    key = (path, os.stat(path).st_mtime_ns, model, tuple(sources or ()))
    with _cache_lock:
        if _cache_key == key and _cache_matrix is not None:
            return _cache_matrix, _cache_rows

        sql = ("SELECT id, source, seq, text, meta, dim, vec, parent_id FROM chunks "
               "WHERE model = ? AND is_parent = 0")
        args: list = [model]
        if sources:
            sql += f" AND source IN ({','.join('?' * len(sources))})"
            args.extend(sources)
        with contextlib.closing(_connect()) as conn:
            # A read migrates too: this SELECT depends on parent_id.
            _ensure_schema(conn)
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
            "parent_id": row[7] or "",
        } for row in fetched]
        _cache_key, _cache_rows, _cache_matrix = key, rows, matrix
        _cache_stats = _build_stats(rows)
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
    Under ``config.rag.parent_child`` a doc may also carry ``doc_key`` and
    ``is_parent``; with the flag off the parent rows are dropped before the embed
    batch, so every row is a plain matchable chunk. Returns ``(inserted, status)``.
    """
    if not docs:
        return 0, "empty"
    if not config.rag.enabled or not _db_path():
        return 0, "disabled"
    grouped = config.rag.parent_child
    if not grouped:
        docs = [d for d in docs if not d.get("is_parent")]
        if not docs:
            return 0, "empty"
    matrix, status = await embed_texts([d["text"] for d in docs])
    if matrix is None:
        return 0, status
    now = time.time()
    rows = []
    for i, doc in enumerate(docs):
        source = str(doc.get("source", ""))
        seq = int(doc.get("seq", i))
        text = doc["text"]
        # A parent with no doc_key has no stable id and would collide with any other
        # parent that is also missing one, so it is written as an ordinary chunk row instead.
        doc_key = str(doc.get("doc_key") or "") if grouped else ""
        is_parent = 1 if (grouped and doc.get("is_parent") and doc_key) else 0
        if is_parent:
            row_id, parent_id = _parent_id(source, doc_key), ""
        else:
            row_id = _chunk_id(source, seq, text)
            parent_id = _parent_id(source, doc_key) if doc_key else ""
        rows.append((
            row_id, source, seq, text,
            json.dumps(doc.get("meta") or {}, ensure_ascii=False),
            config.rag.model, int(matrix.shape[1]), matrix[i].tobytes(), now,
            parent_id, is_parent,
        ))
    inserted, dropped = await asyncio.to_thread(_write_rows, rows)
    if dropped:
        logger.warning("RAG corpus cap %d reached - %d chunk(s) rejected",
                       config.rag.max_chunks, dropped)
        return inserted, (f"capped: {dropped} chunk(s) rejected at "
                          "BLUETEAM_RAG_MAX_CHUNKS; raise it or prune the corpus")
    return inserted, None


def _group_sync(hits: list[dict]) -> list[dict]:
    """Fold matched children into their parent document.
    A group scores as its best child, so one strongly matching chunk is not diluted by
    its siblings. A hit with no parent_id is already a whole document.
    """
    groups: dict[str, list[dict]] = {}
    out: list[dict] = []
    for hit in hits:
        parent_id = hit.get("parent_id") or ""
        if parent_id:
            groups.setdefault(parent_id, []).append(hit)
        else:
            out.append(hit)
    if not groups:
        return out
    with contextlib.closing(_connect()) as conn:
        for parent_id, children in groups.items():
            row = conn.execute(
                "SELECT id, source, seq, text, meta FROM chunks "
                "WHERE id = ? AND is_parent = 1",
                (parent_id,),
            ).fetchone()
            if row is None:
                # Defensive: an incomplete group still holds the child that matched.
                out.extend(children)
                continue
            best = max(children, key=lambda c: c.get("vector_score") or 0.0)
            out.append({
                "id": row[0], "source": row[1], "seq": row[2], "text": row[3],
                "meta": json.loads(row[4] or "{}"),
                "vector_score": best.get("vector_score"),
                "child_count": len(children),
                "matched_seq": sorted(c.get("seq") for c in children),
            })
    out.sort(key=lambda h: h.get("vector_score") or 0.0, reverse=True)
    return out


async def query(text: str, top_k: Optional[int] = None,
                sources: Optional[list[str]] = None) -> tuple[list[dict], Optional[str]]:
    """Stage 1 retrieval: high-recall candidate set for the reranker.
    Returns ``(hits, status)`` sorted by descending vector score. ``status`` is
    ``None`` on success, else ``"empty"`` / ``"disabled"`` / ``"unavailable: ..."``
    / ``"no_corpus"``. Callers pass hits to ``core/rerank.py`` and truncate;
    this function applies NO score threshold, because raw cosine values are not
    calibrated across corpora.
    With ``config.rag.parent_child`` matched children fold into their parent, so a hit
    is a document rather than a chunk. Folding cannot drop a parent whose child was
    recalled, but it can return fewer than ``k`` hits, which triggers one wider pass.
    """
    if not (text or "").strip():
        return [], "empty"
    k = top_k if top_k is not None else config.rag.max_candidates
    matrix, status = await embed_texts([text])
    if matrix is None:
        return [], status
    vec = matrix[0].tobytes()
    hits = await asyncio.to_thread(_search_sync, vec, config.rag.model, k, sources)
    if hits and config.rag.parent_child:
        grouped = await asyncio.to_thread(_group_sync, hits)
        ceiling = config.rag.max_candidates
        if len(grouped) < k < ceiling:
            wider = await asyncio.to_thread(
                _search_sync, vec, config.rag.model, ceiling, sources)
            grouped = await asyncio.to_thread(_group_sync, wider)
        return (grouped, None) if grouped else ([], "no_corpus")
    return (hits, None) if hits else ([], "no_corpus")


async def token_stats(sources: Optional[list[str]] = None) -> tuple[dict[str, int], dict[str, int]]:
    """``(tf, df)`` for the cached corpus, for the lexical leg of hybrid retrieval.
    Empty tables when the store is disabled or holds nothing: the caller's term
    similarity then scores on token shape alone instead of raising. Reads the cache
    ``query()`` populates, so the pair is built at most once per corpus generation.
    """
    if not config.rag.enabled or not _db_path():
        return {}, {}
    await asyncio.to_thread(_load_matrix, config.rag.model, sources)
    with _cache_lock:
        return _cache_stats or ({}, {})


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
    """Operator-facing store status. No model load, safe to call anywhere.
    ``chunks_by_model`` counts every stored row; ``matchable_by_model`` counts the rows a
    query can match, which excludes parent rows.
    """
    path = _db_path()
    counts: dict = {}
    matchable: dict = {}
    parents: dict = {}
    sources: list = []
    if path and os.path.exists(path):
        with contextlib.closing(_connect()) as conn:
            _ensure_schema(conn)
            counts = {row[0]: row[1] for row in
                      conn.execute("SELECT model, COUNT(*) FROM chunks GROUP BY model")}
            matchable = {row[0]: row[1] for row in
                         conn.execute("SELECT model, COUNT(*) FROM chunks "
                                      "WHERE is_parent = 0 GROUP BY model")}
            parents = {row[0]: row[1] for row in
                       conn.execute("SELECT model, COUNT(*) FROM chunks "
                                    "WHERE is_parent = 1 GROUP BY model")}
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
        "matchable_by_model": matchable,
        "parents_by_model": parents,
        "parent_child": config.rag.parent_child,
        "sources": sources,
        "max_chunks": config.rag.max_chunks,
        "max_candidates": config.rag.max_candidates,
        "top_k": config.rag.top_k,
    }
