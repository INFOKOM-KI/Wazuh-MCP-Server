#!/usr/bin/env python3
"""Tests for BLUETEAM_RAG_PARENT_CHILD: a chunked document gets a parent row, its
children are the matchable unit, and the parent is returned.
The flag is off by default, so the first group of tests pins that behaviour: every row
is an ordinary matchable chunk, and no fold ever runs.
"""

from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import asyncio
import sqlite3

import pytest

from mcp_server.core import rag_store
from mcp_server.core.config import config
from mcp_server.core.exceptions import MigrationError
from mcp_server.tools import rag_kb

# The schema as it shipped before parent-child, used to prove the migration.
_OLD_SCHEMA = """
CREATE TABLE chunks (
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
CREATE INDEX idx_chunks_model  ON chunks(model);
CREATE INDEX idx_chunks_source ON chunks(source);
"""

# 6 units is 293 runes, which splits into 2 chunks at size 200. 10 units is 3.
_TWO_CHUNKS = " ".join(f"alpha sentence number {i} with padding words here." for i in range(6))
_THREE_CHUNKS = " ".join(f"alpha sentence number {i} with padding words here." for i in range(10))
_ONE_CHUNK = "alpha short document"


class _StubEmbedder:
    """Deterministic 4-dim embedder. Character content drives the vector."""

    def embed(self, texts):
        for text in texts:
            yield [float(text.count("a")) + 1.0, float(text.count("b")) + 1.0,
                   float(len(text) % 5) + 1.0, 1.0]


def _setup(tmp_path, **over):
    config.rag.enabled = True
    config.rag.db_path = str(tmp_path / "rag.db")
    config.rag.model = "stub-model"
    config.rag.allow_download = False
    config.rag.sha256 = ""
    config.rag.max_candidates = 100
    config.rag.top_k = 10
    config.rag.max_chunks = 50000
    config.rag.chunk_chars = 200
    config.rag.chunk_overlap = 0
    config.rag.chunk_strategy = "sentences"
    config.rag.parent_child = True
    for key, value in over.items():
        setattr(config.rag, key, value)
    rag_store._embedder = _StubEmbedder()
    rag_store._reason = "ready"
    rag_store._cache_key = None
    rag_store._cache_rows = None
    rag_store._cache_matrix = None
    rag_store._cache_stats = None


@pytest.fixture(autouse=True)
def _reset():
    saved = (config.rag.enabled, config.rag.db_path, config.rag.parent_child,
             config.rag.chunk_chars, config.rag.chunk_overlap, config.rag.max_chunks)
    yield
    (config.rag.enabled, config.rag.db_path, config.rag.parent_child,
     config.rag.chunk_chars, config.rag.chunk_overlap,
     config.rag.max_chunks) = saved
    rag_store._embedder = None
    rag_store._reason = "not loaded"
    rag_store._cache_key = None
    rag_store._cache_rows = None
    rag_store._cache_matrix = None
    rag_store._cache_stats = None


def _rows(source, doc_key, text, seq=0, meta=None):
    """Build one document's rows exactly as the ingest path does."""
    added, nxt = rag_kb._document_docs(
        source, doc_key, text, config.rag.chunk_chars, config.rag.chunk_overlap,
        meta or {}, seq)
    return added, nxt


def _ingest(docs):
    return asyncio.run(rag_store.add_documents(docs))


def _stored():
    with sqlite3.connect(config.rag.db_path) as conn:
        return conn.execute(
            "SELECT id, source, seq, parent_id, is_parent FROM chunks "
            "ORDER BY source, seq").fetchall()


def _parent_ids():
    return {r[0] for r in _stored() if r[4] == 1}


def _child_parent_ids():
    return {r[3] for r in _stored() if r[4] == 0 and r[3] != ""}


def _orphans():
    """Parents with no child, and children whose parent is absent."""
    stored = _stored()
    parents = {r[0] for r in stored if r[4] == 1}
    child_parents = {r[3] for r in stored if r[4] == 0 and r[3] != ""}
    return parents - child_parents, child_parents - parents


# Flag off: the pre-parent-child shape
def test_flag_off_writes_no_parent_rows(tmp_path):
    _setup(tmp_path, parent_child=False)
    docs, _ = _rows("cases", "case-a", _THREE_CHUNKS)
    _ingest(docs)
    stored = _stored()
    assert len(stored) == 3
    assert all(row[4] == 0 and row[3] == "" for row in stored)


def test_flag_off_does_not_fold_and_scores_like_before(tmp_path):
    _setup(tmp_path, parent_child=False)
    docs, _ = _rows("cases", "case-a", _THREE_CHUNKS)
    _ingest(docs)
    hits, status = asyncio.run(rag_store.query("alpha sentence", top_k=10))
    assert status is None
    assert len(hits) == 3
    assert all("child_count" not in hit for hit in hits)
    assert all(hit["parent_id"] == "" for hit in hits)


# Flag on: parent creation
def test_chunked_document_gets_one_parent(tmp_path):
    _setup(tmp_path)
    docs, _ = _rows("cases", "case-a", _THREE_CHUNKS)
    assert [d.get("is_parent") for d in docs] == [True, None, None, None]
    _ingest(docs)
    stored = _stored()
    assert len(stored) == 4
    assert sum(row[4] for row in stored) == 1
    parent = next(row for row in stored if row[4] == 1)
    assert parent[0] == rag_store._parent_id("cases", "case-a")
    assert parent[3] == ""
    # Every child points at the parent, and the parent shares the first child's seq.
    assert {row[3] for row in stored if row[4] == 0} == {parent[0]}
    assert parent[2] == 0
    assert sorted(row[2] for row in stored if row[4] == 0) == [0, 1, 2]


def test_single_chunk_document_gets_no_parent(tmp_path):
    _setup(tmp_path)
    docs, nxt = _rows("cases", "case-a", _ONE_CHUNK)
    assert len(docs) == 1 and "is_parent" not in docs[0]
    _ingest(docs)
    stored = _stored()
    assert len(stored) == 1
    assert stored[0][3] == "" and stored[0][4] == 0


def test_parent_text_is_the_whole_document(tmp_path):
    _setup(tmp_path)
    docs, _ = _rows("cases", "case-a", _THREE_CHUNKS)
    _ingest(docs)
    parent_id = rag_store._parent_id("cases", "case-a")
    with sqlite3.connect(config.rag.db_path) as conn:
        text = conn.execute("SELECT text FROM chunks WHERE id = ?", (parent_id,)).fetchone()[0]
    assert text == _THREE_CHUNKS


# Flag on: retrieval
def test_parents_are_never_in_the_searchable_matrix(tmp_path):
    _setup(tmp_path)
    docs, _ = _rows("cases", "case-a", _THREE_CHUNKS)
    _ingest(docs)
    parents = _parent_ids()
    assert parents
    matrix, rows = rag_store._load_matrix(config.rag.model, None)
    assert matrix is not None and len(rows) == 3
    assert not (parents & {row["id"] for row in rows})
    # The fold is the only thing that surfaces a parent.
    hits, _ = asyncio.run(rag_store.query("alpha sentence", top_k=50))
    assert {hit["id"] for hit in hits} == parents


def test_child_match_returns_the_parent(tmp_path):
    _setup(tmp_path)
    docs, _ = _rows("cases", "case-a", _THREE_CHUNKS)
    _ingest(docs)
    hits, status = asyncio.run(rag_store.query("alpha sentence", top_k=50))
    assert status is None
    assert len(hits) == 1
    hit = hits[0]
    assert hit["id"] == rag_store._parent_id("cases", "case-a")
    assert hit["text"] == _THREE_CHUNKS
    assert hit["child_count"] == 3
    assert hit["matched_seq"] == [0, 1, 2]


def test_parent_scores_as_its_best_child(tmp_path):
    """The fold reports max(child scores), so one strong verdict is not diluted by
    the sibling chunks. Checked against the raw child scores rather than a literal."""
    _setup(tmp_path)
    docs, _ = _rows("cases", "case-a", _THREE_CHUNKS)
    _ingest(docs)

    config.rag.parent_child = False
    raw, _ = asyncio.run(rag_store.query("alpha sentence number", top_k=50))
    assert len(raw) == 3
    best: dict[str, float] = {}
    for hit in raw:
        assert hit["parent_id"]
        best[hit["parent_id"]] = max(best.get(hit["parent_id"], -1.0), hit["vector_score"])

    config.rag.parent_child = True
    folded, _ = asyncio.run(rag_store.query("alpha sentence number", top_k=50))
    assert len(folded) == 1
    assert folded[0]["vector_score"] == pytest.approx(
        best[folded[0]["id"]])


def test_chunked_and_standalone_documents_coexist(tmp_path):
    _setup(tmp_path)
    chunked, seq = _rows("cases", "case-a", _THREE_CHUNKS)
    short, _ = _rows("cases", "case-b", _ONE_CHUNK, seq=seq)
    _ingest(chunked + short)

    hits, status = asyncio.run(rag_store.query("alpha", top_k=50))
    assert status is None
    ids = {hit["id"] for hit in hits}
    assert rag_store._parent_id("cases", "case-a") in ids
    assert any(hit["parent_id"] == "" and "child_count" not in hit for hit in hits)


def test_folding_keeps_the_score_order(tmp_path):
    _setup(tmp_path)
    a, seq = _rows("cases", "case-a", _THREE_CHUNKS)
    b, _ = _rows("cases", "case-b", _THREE_CHUNKS, seq=seq)
    _ingest(a + b)
    hits, _ = asyncio.run(rag_store.query("alpha sentence", top_k=50))
    scores = [hit["vector_score"] for hit in hits]
    assert len(hits) == 2
    assert scores == sorted(scores, reverse=True)


# Parent id derivation
def test_parent_id_ignores_seq(tmp_path):
    """seq is a running counter over the label, so a seq-derived parent id would
    change every time a document was added or removed."""
    _setup(tmp_path)
    docs, _ = _rows("cases", "case-a", _THREE_CHUNKS, seq=0)
    _ingest(docs)
    first = _parent_ids()

    asyncio.run(rag_store.delete_source("cases"))
    docs, _ = _rows("cases", "case-a", _THREE_CHUNKS, seq=500)
    _ingest(docs)
    assert _parent_ids() == first


def test_parent_id_cannot_collide_with_a_chunk_id(tmp_path):
    _setup(tmp_path)
    docs, _ = _rows("cases", "case-a", _THREE_CHUNKS)
    parent = rag_store._parent_id("cases", "case-a")
    child_ids = {rag_store._chunk_id("cases", d["seq"], d["text"])
                 for d in docs if not d.get("is_parent")}
    assert len(child_ids) == 3
    assert parent not in child_ids


def test_identical_documents_get_distinct_parents(tmp_path):
    _setup(tmp_path)
    a, seq = _rows("cases", "case-a", _THREE_CHUNKS)
    b, _ = _rows("cases", "case-b", _THREE_CHUNKS, seq=seq)
    _ingest(a + b)
    parents = _parent_ids()
    assert len(parents) == 2
    assert _orphans() == (set(), set())


# Cap
def test_cap_truncates_whole_documents(tmp_path):
    """room is 4 and each document is 4 rows, so the first fits exactly and the second
    does not. A half-persisted document would leave a parent with no children."""
    _setup(tmp_path, max_chunks=4)
    a, seq = _rows("cases", "case-a", _THREE_CHUNKS)
    b, _ = _rows("cases", "case-b", _THREE_CHUNKS, seq=seq)
    inserted, status = _ingest(a + b)
    assert inserted == 4
    assert status is not None and status.startswith("capped:")
    assert _orphans() == (set(), set())
    assert _parent_ids() == {rag_store._parent_id("cases", "case-a")}


def test_cap_that_fits_nothing_writes_nothing(tmp_path):
    _setup(tmp_path, max_chunks=1)
    docs, _ = _rows("cases", "case-a", _THREE_CHUNKS)
    inserted, status = _ingest(docs)
    assert inserted == 0
    assert status is not None and status.startswith("capped:")
    assert _stored() == []


# Defensive fallback
def test_missing_parent_returns_the_child(tmp_path):
    _setup(tmp_path)
    docs, _ = _rows("cases", "case-a", _THREE_CHUNKS)
    _ingest(docs)
    parent_id = rag_store._parent_id("cases", "case-a")
    with sqlite3.connect(config.rag.db_path) as conn:
        conn.execute("DELETE FROM chunks WHERE id = ?", (parent_id,))
        conn.commit()
    rag_store._cache_key = None

    hits, status = asyncio.run(rag_store.query("alpha sentence", top_k=50))
    assert status is None
    assert hits
    assert all(hit["id"] != parent_id for hit in hits)
    assert all("child_count" not in hit for hit in hits)


# Widening
def test_widening_runs_at_most_once(tmp_path, monkeypatch):
    _setup(tmp_path)
    docs, _ = _rows("cases", "case-a", _THREE_CHUNKS)
    _ingest(docs)
    calls: list[int] = []
    real = rag_store._search_sync

    def counting(vec, model, k, sources):
        calls.append(k)
        return real(vec, model, k, sources)

    monkeypatch.setattr(rag_store, "_search_sync", counting)
    hits, _ = asyncio.run(rag_store.query("alpha sentence", top_k=50))
    assert len(hits) == 1
    assert len(calls) <= 2
    if len(calls) == 2:
        assert calls[1] == config.rag.max_candidates


def test_no_widening_when_the_window_is_already_the_ceiling(tmp_path, monkeypatch):
    _setup(tmp_path)
    docs, _ = _rows("cases", "case-a", _THREE_CHUNKS)
    _ingest(docs)
    calls: list[int] = []
    real = rag_store._search_sync

    def counting(vec, model, k, sources):
        calls.append(k)
        return real(vec, model, k, sources)

    monkeypatch.setattr(rag_store, "_search_sync", counting)
    asyncio.run(rag_store.query("alpha sentence", top_k=config.rag.max_candidates))
    assert calls == [config.rag.max_candidates]


# Deletion
def test_delete_source_removes_parents_and_children(tmp_path):
    _setup(tmp_path)
    docs, _ = _rows("cases", "case-a", _THREE_CHUNKS)
    _ingest(docs)
    assert len(_stored()) == 4
    removed = asyncio.run(rag_store.delete_source("cases"))
    assert removed == 4
    assert _stored() == []
    hits, status = asyncio.run(rag_store.query("alpha sentence", top_k=10))
    assert hits == [] and status == "no_corpus"


def test_delete_source_leaves_other_labels_orphan_free(tmp_path):
    _setup(tmp_path)
    a, seq = _rows("cases", "case-a", _THREE_CHUNKS)
    b, _ = _rows("playbooks", "pb-1", _THREE_CHUNKS, seq=seq)
    _ingest(a + b)
    asyncio.run(rag_store.delete_source("cases"))
    assert _orphans() == (set(), set())
    assert _parent_ids() == {rag_store._parent_id("playbooks", "pb-1")}


# Ingest through the tool
def test_tool_ingest_reports_parents_separately(tmp_path):
    from mcp_server.core import case_store

    _setup(tmp_path)
    case = case_store.create_case("SSH brute force on mail", ["203.0.113.9"],
                                  notes=_THREE_CHUNKS)
    out = asyncio.run(rag_kb.blueteam_rag_ingest.__wrapped__(
        rag_kb.RagIngestInput(source="cases", response_format="json")))
    payload = __import__("json").loads(out)
    assert payload["parents"] == 1
    assert payload["chunks"] == 3
    assert payload["chunks_inserted"] == 4
    assert case["case_id"]
    assert payload["store"]["parent_child"] is True


# Migration
def _write_old_store(path: str) -> None:
    import numpy as np

    conn = sqlite3.connect(path)
    conn.executescript(_OLD_SCHEMA)
    vec = np.asarray([1.0, 0.0, 0.0, 0.0], dtype=np.float32)
    conn.execute(
        "INSERT INTO chunks (id, source, seq, text, meta, model, dim, vec, created_at) "
        "VALUES ('old-1', 'legacy', 0, 'alpha legacy row', '{}', 'stub-model', 4, ?, 0.0)",
        (vec.tobytes(),))
    conn.commit()
    conn.close()


def test_migration_adds_columns_and_keeps_old_rows_matchable(tmp_path):
    _setup(tmp_path, parent_child=False)
    _write_old_store(config.rag.db_path)

    hits, status = asyncio.run(rag_store.query("alpha legacy", top_k=10))
    assert status is None
    assert len(hits) == 1
    assert hits[0]["id"] == "old-1"
    assert hits[0]["parent_id"] == ""

    with sqlite3.connect(config.rag.db_path) as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(chunks)")}
        row = conn.execute(
            "SELECT parent_id, is_parent FROM chunks WHERE id = 'old-1'").fetchone()
    assert {"parent_id", "is_parent"} <= columns
    assert row == ("", 0)


def test_migration_is_idempotent(tmp_path):
    _setup(tmp_path, parent_child=False)
    _write_old_store(config.rag.db_path)
    conn = rag_store._connect()
    try:
        rag_store._ensure_schema(conn)
        rag_store._ensure_schema(conn)
        columns = [row[1] for row in conn.execute("PRAGMA table_info(chunks)")]
    finally:
        conn.close()
    assert columns.count("parent_id") == 1
    assert columns.count("is_parent") == 1


def test_explicit_column_insert_still_works_after_migration(tmp_path):
    _setup(tmp_path, parent_child=False)
    _write_old_store(config.rag.db_path)
    with sqlite3.connect(config.rag.db_path) as conn:
        rag_store._ensure_schema(conn)
        conn.execute(
            "INSERT INTO chunks (id, source, seq, text, meta, model, dim, vec, created_at) "
            "VALUES ('old-2', 'legacy', 1, 'bbb', '{}', 'stub-model', 4, ?, 0.0)",
            (b"\x00" * 16,))
        conn.commit()
        assert conn.execute(
            "SELECT parent_id, is_parent FROM chunks WHERE id = 'old-2'").fetchone() == ("", 0)


def test_migration_failure_raises_instead_of_continuing(tmp_path):
    """A store that cannot be migrated must fail at the point of migration, not later
    at a query where the missing column looks like a data problem."""
    _setup(tmp_path, parent_child=False)
    _write_old_store(config.rag.db_path)
    ro = sqlite3.connect(f"file:{config.rag.db_path}?mode=ro", uri=True)
    try:
        with pytest.raises(MigrationError, match="cannot add column"):
            rag_store._ensure_schema(ro)
    finally:
        ro.close()


def test_migration_error_names_the_column_and_the_path(tmp_path):
    _setup(tmp_path, parent_child=False)
    _write_old_store(config.rag.db_path)
    ro = sqlite3.connect(f"file:{config.rag.db_path}?mode=ro", uri=True)
    try:
        with pytest.raises(MigrationError) as exc:
            rag_store._ensure_schema(ro)
    finally:
        ro.close()
    message = str(exc.value)
    assert "parent_id" in message
    assert config.rag.db_path in message


# stats
def test_stats_reports_the_parent_count(tmp_path):
    _setup(tmp_path)
    docs, _ = _rows("cases", "case-a", _THREE_CHUNKS)
    _ingest(docs)
    store = rag_store.stats()
    assert store["chunks_by_model"] == {"stub-model": 4}
    assert store["parents_by_model"] == {"stub-model": 1}
    assert store["parent_child"] is True


def test_stats_matchable_excludes_parent_rows(tmp_path):
    """Total stored rows, matchable units and parent rows are three different numbers and
    the operator-facing output has to name all three."""
    _setup(tmp_path)
    docs, _ = _rows("cases", "case-a", _THREE_CHUNKS)
    _ingest(docs)
    store = rag_store.stats()
    assert store["chunks_by_model"] == {"stub-model": 4}
    assert store["matchable_by_model"] == {"stub-model": 3}
    assert store["parents_by_model"] == {"stub-model": 1}
    total = sum(store["chunks_by_model"].values())
    assert total == (sum(store["matchable_by_model"].values())
                     + sum(store["parents_by_model"].values()))


def test_stats_for_one_non_chunked_document(tmp_path):
    _setup(tmp_path)
    docs, _ = _rows("cases", "case-a", _ONE_CHUNK)
    _ingest(docs)
    store = rag_store.stats()
    assert store["chunks_by_model"] == {"stub-model": 1}
    assert store["matchable_by_model"] == {"stub-model": 1}
    assert store["parents_by_model"] == {}


def test_stats_for_a_mixed_corpus(tmp_path):
    """One chunked document and one standalone, so the split cannot be inferred from
    either number alone."""
    _setup(tmp_path)
    chunked, seq = _rows("cases", "case-a", _THREE_CHUNKS)
    short, _ = _rows("cases", "case-b", _ONE_CHUNK, seq=seq)
    _ingest(chunked + short)
    store = rag_store.stats()
    assert store["chunks_by_model"] == {"stub-model": 5}
    assert store["matchable_by_model"] == {"stub-model": 4}
    assert store["parents_by_model"] == {"stub-model": 1}


def test_stats_matchable_equals_total_when_the_flag_is_off(tmp_path):
    _setup(tmp_path, parent_child=False)
    docs, _ = _rows("cases", "case-a", _THREE_CHUNKS)
    _ingest(docs)
    store = rag_store.stats()
    assert store["chunks_by_model"] == {"stub-model": 3}
    assert store["matchable_by_model"] == {"stub-model": 3}
    assert store["parents_by_model"] == {}


def test_markdown_corpus_line_names_matchable_and_parents(tmp_path):
    """The footer must not call a parent row a searchable chunk."""
    _setup(tmp_path)
    docs, _ = _rows("cases", "case-a", _THREE_CHUNKS)
    _ingest(docs)
    out = asyncio.run(rag_kb.blueteam_rag_query.__wrapped__(
        rag_kb.RagQueryInput(query="alpha sentence", response_format="markdown")))
    assert "3 matchable + 1 parent (4 stored)" in out


def test_markdown_corpus_line_omits_parents_when_the_flag_is_off(tmp_path):
    _setup(tmp_path, parent_child=False)
    docs, _ = _rows("cases", "case-a", _THREE_CHUNKS)
    _ingest(docs)
    out = asyncio.run(rag_kb.blueteam_rag_query.__wrapped__(
        rag_kb.RagQueryInput(query="alpha sentence", response_format="markdown")))
    assert "**Corpus**: 3 matchable" in out
    assert "parent" not in out
