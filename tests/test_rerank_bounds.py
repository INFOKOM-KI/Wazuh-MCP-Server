#!/usr/bin/env python3
"""Tests for the reranker input bound in core/rerank.py.
A parent hit carries the whole document, which can run several chunks long. The text
handed to the cross-encoder is bounded to ``config.rag.chunk_chars``, the retrieval unit
the chunker already enforces, so a child chunk passes through untouched.
"""

from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import asyncio

import pytest

from mcp_server.core import chunker, rerank as rerank_mod
from mcp_server.core.config import config

CHUNK_CHARS = 1200


@pytest.fixture(autouse=True)
def _cfg():
    saved = (config.rag.chunk_chars, config.rag.parent_child, config.rerank.normalize,
             config.rerank.max_candidates, config.rerank.enabled)
    config.rag.chunk_chars = CHUNK_CHARS
    config.rag.parent_child = False
    config.rerank.normalize = False
    config.rerank.max_candidates = 100
    config.rerank.enabled = True
    yield
    (config.rag.chunk_chars, config.rag.parent_child, config.rerank.normalize,
     config.rerank.max_candidates, config.rerank.enabled) = saved


def _run(coro):
    return asyncio.run(coro)


def _capture(monkeypatch, scores):
    """Record the document list handed to the cross-encoder."""
    seen: dict = {}

    async def fake(query, docs):
        seen["docs"] = list(docs)
        seen["query"] = query
        return list(scores), None

    monkeypatch.setattr(rerank_mod, "rerank", fake)
    return seen


def _hits(*texts):
    return [{"id": f"h{i}", "text": t, "vector_score": 0.9 - 0.1 * i}
            for i, t in enumerate(texts)]


# The bound
def test_a_short_parent_reaches_the_cross_encoder_unchanged(monkeypatch):
    seen = _capture(monkeypatch, [3.0])
    text = "alpha parent document"
    _run(rerank_mod.rerank_hits("q", _hits(text), 5))
    assert seen["docs"] == [text]


def test_a_text_exactly_at_the_bound_is_not_truncated(monkeypatch):
    seen = _capture(monkeypatch, [3.0])
    text = "a" * CHUNK_CHARS
    _run(rerank_mod.rerank_hits("q", _hits(text), 5))
    assert seen["docs"] == [text]


def test_a_long_parent_is_bounded_before_reranking(monkeypatch):
    seen = _capture(monkeypatch, [3.0])
    parent = "a" * CHUNK_CHARS + "b" * CHUNK_CHARS + "tail"
    _run(rerank_mod.rerank_hits("q", _hits(parent), 5))
    assert seen["docs"][0] == parent[:CHUNK_CHARS]


def test_every_candidate_is_bounded_not_only_the_first(monkeypatch):
    seen = _capture(monkeypatch, [3.0, 2.0, 1.0])
    long_text = "x" * (CHUNK_CHARS * 3)
    _run(rerank_mod.rerank_hits("q", _hits(long_text, long_text, "short"), 5))
    assert [len(d) for d in seen["docs"]] == [CHUNK_CHARS, CHUNK_CHARS, len("short")]


def test_the_bound_follows_the_configured_chunk_size(monkeypatch):
    """No new knob: the bound is the existing retrieval-unit size."""
    config.rag.chunk_chars = 200
    seen = _capture(monkeypatch, [3.0])
    _run(rerank_mod.rerank_hits("q", _hits("a" * 900), 5))
    assert len(seen["docs"][0]) == 200


# Flag-off path
def test_a_real_child_chunk_is_never_truncated(monkeypatch):
    """The chunker sizes by runes, so a child is at or below the bound already. This is
    what makes the bound a no-op while parent-child retrieval is off."""
    text = " ".join(f"alpha sentence number {i} padding words." for i in range(120))
    children = chunker.split(text, size=CHUNK_CHARS, overlap=0, strategy="sentences")
    assert max(len(c) for c in children) <= CHUNK_CHARS
    near_bound = [c for c in children if len(c) > 900]
    assert near_bound, "the fixture needs a child near the bound to be meaningful"

    seen = _capture(monkeypatch, [3.0])
    hit = {"id": "c", "text": near_bound[0], "vector_score": 0.9}
    _run(rerank_mod.rerank_hits("q", [hit], 5))
    assert seen["docs"] == [near_bound[0]]


# Score semantics
def test_raw_rerank_score_is_still_the_logit(monkeypatch):
    _capture(monkeypatch, [4.0, -2.0])
    ranked, reranked, status = _run(
        rerank_mod.rerank_hits("q", _hits("one", "two"), 5))
    assert (reranked, status) == (True, None)
    assert [h["rerank_score"] for h in ranked] == [4.0, -2.0]
    assert all("rerank_raw" not in h for h in ranked)


def test_bounding_does_not_change_the_score(monkeypatch):
    """The model sees less text, and the score it returns is passed through untouched."""
    long_text = "a" * (CHUNK_CHARS * 4)
    seen = _capture(monkeypatch, [2.5])
    ranked, _, _ = _run(rerank_mod.rerank_hits("q", _hits(long_text), 5))
    assert len(seen["docs"][0]) == CHUNK_CHARS
    assert ranked[0]["rerank_score"] == 2.5


def test_post_rerank_fusion_still_uses_the_normalized_score(monkeypatch):
    config.rerank.normalize = True

    async def fake(query, docs):
        return [4.0], None

    monkeypatch.setattr(rerank_mod, "rerank", fake)
    ranked, _, _ = _run(rerank_mod.rerank_hits(
        "q", _hits("a" * (CHUNK_CHARS * 3)), 5,
        term_scores=[0.5], vector_weight=0.3))
    hit = ranked[0]
    assert hit["rerank_score"] == pytest.approx(1.0)
    assert hit["rerank_raw"] == pytest.approx(4.0)
    assert hit["term_score"] == pytest.approx(0.5)
    assert hit["hybrid_score"] == pytest.approx(0.3 * 1.0 + 0.7 * 0.5)


# The returned text
def test_the_returned_text_stays_complete_though_the_scored_text_is_bounded(monkeypatch):
    seen = _capture(monkeypatch, [3.0])
    parent = "a" * (CHUNK_CHARS * 3)
    ranked, _, _ = _run(rerank_mod.rerank_hits("q", _hits(parent), 5))
    assert len(seen["docs"][0]) == CHUNK_CHARS
    assert ranked[0]["text"] == parent
    assert len(ranked[0]["text"]) == CHUNK_CHARS * 3


def test_the_bound_survives_the_fallback_path(monkeypatch):
    """A dead reranker returns the input order, so no bound is exercised and nothing
    breaks. The hits still carry their complete text."""
    async def fake(query, docs):
        return [], "unavailable: model load failed"

    monkeypatch.setattr(rerank_mod, "rerank", fake)
    parent = "a" * (CHUNK_CHARS * 3)
    ranked, reranked, status = _run(rerank_mod.rerank_hits("q", _hits(parent), 5))
    assert reranked is False
    assert status == "unavailable: model load failed"
    assert ranked[0]["text"] == parent
