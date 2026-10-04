#!/usr/bin/env python3
"""Integration tests for BLUETEAM_RAG_QUERY_NORMALIZE around the retrieval entry points.
The regression this file exists for: one retrieval stage reading the raw query while
another reads the normalized one. The three consumers are replaced with recorders, so the
string each one receives can be compared rather than inferred from the output.
"""

from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import asyncio
import json

import pytest
from pydantic import ValidationError

from mcp_server.agents import fp_validator_graph as fpv
from mcp_server.core import rag_store
from mcp_server.core.config import config
from mcp_server.tools import rag_kb

_query = rag_kb.blueteam_rag_query.__wrapped__

FULL_WIDTH = "２０３．０．１１３．９ webshell"
NORMALIZED = "203.0.113.9 webshell"
ASCII_QUERY = "check 203.0.113.9 for brute force"


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
    config.rag.top_k = 10
    config.rag.max_candidates = 100
    config.rag.parent_child = False
    config.rag.query_normalize = False
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
    saved = (config.rag.enabled, config.rag.db_path, config.rag.query_normalize,
             config.rag.parent_child, config.rerank.normalize)
    yield
    (config.rag.enabled, config.rag.db_path, config.rag.query_normalize,
     config.rag.parent_child, config.rerank.normalize) = saved
    rag_store._embedder = None
    rag_store._cache_key = None
    rag_store._cache_rows = None
    rag_store._cache_matrix = None
    rag_store._cache_stats = None


def _run(coro):
    return asyncio.run(coro)


def _record(monkeypatch):
    """Replace the three retrieval consumers with recorders.

    vector_weight=0.3 and rerank=True are passed by the callers below so all three are
    actually reached. A hit is returned so the pipeline continues past the empty check.
    """
    seen: dict = {}

    async def fake_query(text, top_k=None, sources=None):
        seen["rag_store"] = text
        return ([{"id": "h1", "source": "cases", "seq": 0, "meta": {},
                  "text": "alpha webshell 203.0.113.9", "vector_score": 0.9,
                  "parent_id": ""}], None)

    async def fake_token_stats(sources=None):
        return {}, {}

    def fake_term_score(query, documents, tf=None, df=None):
        seen["term_sim"] = query
        return [0.5] * len(documents)

    async def fake_rerank_hits(query, hits, top_k, score_field="vector_score", **kwargs):
        seen["rerank_hits"] = query
        return hits[:top_k], True, None

    monkeypatch.setattr(rag_store, "query", fake_query)
    monkeypatch.setattr(rag_store, "token_stats", fake_token_stats)
    monkeypatch.setattr(rag_kb.term_sim, "score", fake_term_score)
    monkeypatch.setattr(rag_kb, "rerank_hits", fake_rerank_hits)
    return seen


def _ask(query: str, **over) -> dict:
    payload = _run(_query(rag_kb.RagQueryInput(
        query=query, vector_weight=over.pop("vector_weight", 0.3),
        rerank=over.pop("rerank", True), response_format="json", **over)))
    return json.loads(payload)


# The regression this phase exists to prevent
def test_all_three_consumers_receive_the_same_normalized_string(tmp_path, monkeypatch):
    """The regression this phase exists to prevent. blend_stage pins the pre-rerank blend
    call site, which is the one reachable while the rerank fusion is off."""
    _setup(tmp_path, query_normalize=True)
    seen = _record(monkeypatch)
    payload = _ask(FULL_WIDTH)

    assert payload["blend_stage"] == "pre-rerank"
    assert seen["rag_store"] == NORMALIZED
    assert seen["term_sim"] == seen["rag_store"]
    assert seen["rerank_hits"] == seen["rag_store"]


def test_all_three_consumers_receive_the_raw_string_when_the_flag_is_off(tmp_path, monkeypatch):
    _setup(tmp_path, query_normalize=False)
    seen = _record(monkeypatch)
    _ask(FULL_WIDTH)

    assert seen["rag_store"] == FULL_WIDTH
    assert seen["term_sim"] == FULL_WIDTH
    assert seen["rerank_hits"] == FULL_WIDTH


def test_post_rerank_fusion_path_uses_the_normalized_string(tmp_path, monkeypatch):
    """The second term_sim call site. It runs only when the reranker is on, the fusion is
    enabled and vector_weight is below 1.0, so it needs its own test."""
    _setup(tmp_path, query_normalize=True)
    config.rerank.normalize = True
    seen = _record(monkeypatch)
    payload = _ask(FULL_WIDTH, vector_weight=0.3, rerank=True)

    assert payload["blend_stage"] == "post-rerank"
    assert seen["rag_store"] == NORMALIZED
    assert seen["term_sim"] == seen["rag_store"]
    assert seen["rerank_hits"] == seen["rag_store"]


def test_rerank_off_uses_the_normalized_string_for_the_blend(tmp_path, monkeypatch):
    """Rerank off means the pre-rerank blend is the only ranking stage."""
    _setup(tmp_path, query_normalize=True)
    seen = _record(monkeypatch)
    payload = _ask(FULL_WIDTH, rerank=False)

    assert payload["blend_stage"] == "pre-rerank"
    assert seen["rag_store"] == NORMALIZED
    assert seen["term_sim"] == NORMALIZED
    assert "rerank_hits" not in seen


# Flag behaviour
def test_ascii_query_reaches_the_same_string_with_the_flag_on_and_off(tmp_path, monkeypatch):
    _setup(tmp_path, query_normalize=False)
    off = _record(monkeypatch)
    _ask(ASCII_QUERY)

    monkeypatch.undo()
    _setup(tmp_path, query_normalize=True)
    on = _record(monkeypatch)
    _ask(ASCII_QUERY)

    assert off == on
    assert off["rag_store"] == ASCII_QUERY


def test_query_normalized_appears_only_when_the_value_actually_changes(tmp_path, monkeypatch):
    _setup(tmp_path, query_normalize=True)
    _record(monkeypatch)

    changed = _ask(FULL_WIDTH)
    assert changed["query"] == FULL_WIDTH
    assert changed["query_normalized"] == NORMALIZED

    unchanged = _ask(ASCII_QUERY)
    assert "query_normalized" not in unchanged


def test_query_normalized_is_absent_when_the_flag_is_off(tmp_path, monkeypatch):
    _setup(tmp_path, query_normalize=False)
    _record(monkeypatch)
    payload = _ask(FULL_WIDTH)
    assert "query_normalized" not in payload
    assert payload["query"] == FULL_WIDTH


def test_markdown_reports_the_normalized_form(tmp_path, monkeypatch):
    _setup(tmp_path, query_normalize=True)
    _record(monkeypatch)
    out = _run(_query(rag_kb.RagQueryInput(query=FULL_WIDTH, vector_weight=0.3,
                                           rerank=True, response_format="markdown")))
    assert f"`{FULL_WIDTH}`" in out
    assert f"Normalized to `{NORMALIZED}`" in out


def test_markdown_omits_the_note_for_an_ascii_query(tmp_path, monkeypatch):
    _setup(tmp_path, query_normalize=True)
    _record(monkeypatch)
    out = _run(_query(rag_kb.RagQueryInput(query=ASCII_QUERY, vector_weight=0.3,
                                           rerank=True, response_format="markdown")))
    assert "Normalized to" not in out


# Empty handling
@pytest.mark.parametrize("blank", ["   ", "\t\n", "\u3000\u3000"])
def test_blank_query_is_rejected_at_the_schema(blank):
    """Pre-existing: RagQueryInput strips whitespace and then enforces min_length, so a
    blank query never reaches the tool body. Normalization does not change that."""
    with pytest.raises(ValidationError):
        rag_kb.RagQueryInput(query=blank, response_format="json")


def test_an_empty_query_still_returns_the_empty_status(tmp_path):
    """The store guard behind the schema. Empty is a status, not an exception."""
    _setup(tmp_path, query_normalize=True)
    hits, status = asyncio.run(rag_store.query(""))
    assert hits == []
    assert status == "empty"


def test_normalization_cannot_empty_a_query_that_was_not_blank():
    """NFKC has no character-deleting mappings, so the empty result is reachable only
    from input that was already whitespace. This function cannot introduce it."""
    from mcp_server.core.query_norm import normalize_query
    for text in ["\u00ad", "\u200b", "\ufeff", "\u2060", "a\u200bb", "\u00ad\u200b"]:
        assert normalize_query(text) != ""


def test_a_real_query_still_finds_the_corpus(tmp_path):
    """End to end with no mocks, so the flag cannot hide a broken pipeline."""
    _setup(tmp_path, query_normalize=True)
    _run(rag_kb.blueteam_rag_ingest.__wrapped__(
        rag_kb.RagIngestInput(source="text", label="cases",
                              texts=["alpha webshell upload"])))
    payload = _ask("alpha webshell", vector_weight=1.0, rerank=False)
    assert payload["returned"] >= 1
    assert payload["matches"]


# FP validator
def test_fp_validator_keeps_the_raw_input_when_the_flag_is_off(tmp_path, monkeypatch):
    seen: dict = {}

    async def fake_query(text, top_k=None, sources=None):
        seen["text"] = text
        return [], "no_corpus"

    _setup(tmp_path, query_normalize=False)
    monkeypatch.setattr(rag_store, "query", fake_query)
    _run(fpv.run_fp_validation("198.51.100.5", FULL_WIDTH))
    assert seen["text"] == FULL_WIDTH


def test_fp_validator_receives_the_normalized_input_when_the_flag_is_on(tmp_path, monkeypatch):
    seen: dict = {}

    async def fake_query(text, top_k=None, sources=None):
        seen["text"] = text
        return [], "no_corpus"

    _setup(tmp_path, query_normalize=True)
    monkeypatch.setattr(rag_store, "query", fake_query)
    _run(fpv.run_fp_validation("198.51.100.5", FULL_WIDTH))
    assert seen["text"] == NORMALIZED


def test_fp_validator_indicator_fallback_is_normalized_too(tmp_path, monkeypatch):
    seen: dict = {}

    async def fake_query(text, top_k=None, sources=None):
        seen["text"] = text
        return [], "no_corpus"

    _setup(tmp_path, query_normalize=True)
    monkeypatch.setattr(rag_store, "query", fake_query)
    _run(fpv.run_fp_validation("２０３．０．１１３．９", ""))
    assert seen["text"] == "203.0.113.9"


def test_fp_validator_config_requires_the_store_flag(tmp_path, monkeypatch):
    """The normalization flag is not a second on-switch for the validator."""
    _setup(tmp_path, query_normalize=True)
    config.rag.enabled = False
    result = _run(fpv.run_fp_validation("198.51.100.5", "anything"))
    assert result["evidence"]["corpus_searched"] is False
