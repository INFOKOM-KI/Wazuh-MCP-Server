#!/usr/bin/env python3
"""Tests for core/rag_store.py, local ONNX retrieval store.
Coverage: the fallback contract (disabled / empty / unavailable), the
write -> search round trip against a stub embedder (fastembed is absent in CI),
L2 normalization, content-hash idempotency, source filtering, the corpus cap,
the mixed-dimension guard, and the RAGConfig startup validation.
"""

from __future__ import annotations
import os

# mcp_server/__init__.py calls init_config() at import and hard-fails without
# WAZUH_INDEXER_* (ConfigurationError). Seed them at module level so this file
# passes in isolation, not only when a peer module happens to import first.
os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import asyncio
import sqlite3
import pytest
from mcp_server.core import rag_store
from mcp_server.core.config import RAGConfig, config
from mcp_server.core.exceptions import ConfigurationError


class _StubEmbedder:
    """Deterministic 4-dim embedder. Character content drives the vector, so
    docs sharing tokens score higher than unrelated ones."""

    def embed(self, texts):
        for text in texts:
            yield [float(text.count("a")) + 1.0, float(text.count("b")) + 1.0,
                   float(len(text) % 5) + 1.0, 1.0]


def _setup(tmp_path, max_chunks=50000):
    config.rag.enabled = True
    config.rag.db_path = str(tmp_path / "rag.db")
    config.rag.model = "stub-model"
    config.rag.allow_download = False
    config.rag.max_chunks = max_chunks
    config.rag.sha256 = ""
    rag_store._embedder = _StubEmbedder()
    rag_store._reason = "ready"
    rag_store._cache_key = None
    rag_store._cache_rows = None
    rag_store._cache_matrix = None


@pytest.fixture(autouse=True)
def _rag_reset():
    """Every test starts and ends with a dormant store: no leaked embedder,
    no leaked DB path, no stale matrix cache."""
    config.rag.enabled = False
    config.rag.db_path = ""
    rag_store._embedder = None
    rag_store._reason = "not loaded"
    rag_store._cache_key = None
    rag_store._cache_rows = None
    rag_store._cache_matrix = None
    yield
    config.rag.enabled = False
    config.rag.db_path = ""
    rag_store._embedder = None
    rag_store._reason = "not loaded"


# Fallback contract
def test_query_disabled_by_default():
    hits, status = asyncio.run(rag_store.query("brute force"))
    assert hits == []
    assert status == "disabled"


def test_query_empty_text():
    hits, status = asyncio.run(rag_store.query("   "))
    assert hits == []
    assert status == "empty"


def test_embed_unavailable_when_model_cannot_load(tmp_path):
    """fastembed missing OR the named model not in its registry must both end
    as 'unavailable: ...', never an exception and never a silent empty corpus."""
    _setup(tmp_path)
    rag_store._embedder = None  # force a real load attempt
    config.rag.model = "no-such-model-xyz"
    matrix, status = asyncio.run(rag_store.embed_texts(["brute force"]))
    assert matrix is None
    assert status is not None and status.startswith("unavailable:")
    assert rag_store.reason().startswith("model load failed")


def test_add_documents_empty_and_disabled(tmp_path):
    assert asyncio.run(rag_store.add_documents([])) == (0, "empty")
    _setup(tmp_path)
    config.rag.enabled = False
    assert asyncio.run(rag_store.add_documents([{"source": "a", "text": "x"}])) == (0, "disabled")


# Retrieval
def test_ingest_then_query_round_trip(tmp_path):
    _setup(tmp_path)
    inserted, status = asyncio.run(rag_store.add_documents([
        {"source": "cases", "text": "aaa brute force ssh"},
        {"source": "cases", "text": "bbbb webshell upload"},
        {"source": "cases", "text": "aa aaa ssh login failures"},
    ]))
    assert inserted == 3
    assert status is None

    hits, status = asyncio.run(rag_store.query("aaa ssh", top_k=3))
    assert status is None
    assert len(hits) == 3
    scores = [h["vector_score"] for h in hits]
    assert scores == sorted(scores, reverse=True)
    assert {"id", "source", "seq", "text", "meta", "vector_score"} <= set(hits[0])


def test_vectors_are_unit_norm(tmp_path):
    _setup(tmp_path)
    import numpy as np

    matrix, status = asyncio.run(rag_store.embed_texts(["aaa", "bbbb", "ccccc"]))
    assert status is None
    assert matrix.shape == (3, 4)
    assert np.allclose(np.linalg.norm(matrix, axis=1), 1.0, atol=1e-5)


def test_ingest_is_idempotent(tmp_path):
    _setup(tmp_path)
    docs = [{"source": "cases", "text": "duplicate me"}]
    asyncio.run(rag_store.add_documents(docs))
    asyncio.run(rag_store.add_documents(docs))
    assert rag_store.stats()["chunks_by_model"] == {"stub-model": 1}


def test_source_filter_restricts_candidates(tmp_path):
    _setup(tmp_path)
    asyncio.run(rag_store.add_documents([
        {"source": "cases", "text": "aaa one"},
        {"source": "playbooks", "text": "aaa two"},
    ]))
    hits, status = asyncio.run(rag_store.query("aaa", sources=["playbooks"]))
    assert status is None
    assert len(hits) == 1
    assert hits[0]["source"] == "playbooks"


def test_corpus_cap_reports_rejection(tmp_path):
    _setup(tmp_path, max_chunks=2)
    docs = [{"source": "cases", "text": f"doc {i}"} for i in range(4)]
    inserted, status = asyncio.run(rag_store.add_documents(docs))
    assert inserted == 2
    assert status is not None and status.startswith("capped:")
    assert rag_store.stats()["chunks_by_model"] == {"stub-model": 2}


def test_mixed_dims_refused(tmp_path):
    """A partially re-embedded corpus (two dims under one model) must refuse to
    build a ragged matrix instead of silently scoring garbage."""
    _setup(tmp_path)
    asyncio.run(rag_store.add_documents([{"source": "cases", "text": "aaa"}]))
    with sqlite3.connect(config.rag.db_path) as conn:
        conn.execute(
            "INSERT INTO chunks (id, source, seq, text, meta, model, dim, vec, created_at) "
            "VALUES ('bad', 'cases', 1, 'bbb', '{}', ?, 3, ?, 0.0)",
            ("stub-model", b"\x00" * 12),
        )
        conn.commit()

    hits, status = asyncio.run(rag_store.query("aaa", top_k=5))
    assert hits == []
    assert status == "no_corpus"


def test_db_is_owner_only(tmp_path):
    """The corpus holds attacker IOC, the file must not be world readable."""
    _setup(tmp_path)
    asyncio.run(rag_store.add_documents([{"source": "cases", "text": "secret"}]))
    assert oct(os.stat(config.rag.db_path).st_mode)[-3:] == "600"


def test_querying_missing_db_is_not_an_error(tmp_path):
    _setup(tmp_path)
    hits, status = asyncio.run(rag_store.query("brute force"))
    assert hits == []
    assert status == "no_corpus"


# Config validation (fail closed at startup)
def test_config_requires_path_when_enabled():
    with pytest.raises(ConfigurationError):
        RAGConfig(enabled=True, db_path="").validate()


def test_config_rejects_relative_path():
    with pytest.raises(ConfigurationError):
        RAGConfig(enabled=True, db_path="relative/rag.db").validate()


def test_config_rejects_recall_narrower_than_top_k():
    with pytest.raises(ConfigurationError):
        RAGConfig(max_candidates=5, top_k=10).validate()


def test_config_rejects_overlap_ge_chunk_chars():
    with pytest.raises(ConfigurationError):
        RAGConfig(chunk_chars=1000, chunk_overlap=1000).validate()


def test_config_rejects_malformed_sha256():
    with pytest.raises(ConfigurationError):
        RAGConfig(sha256="not-a-digest").validate()


def test_config_accepts_valid_defaults(tmp_path):
    RAGConfig(enabled=True, db_path=str(tmp_path / "rag.db")).validate()
