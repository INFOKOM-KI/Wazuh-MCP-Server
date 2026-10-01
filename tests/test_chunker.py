#!/usr/bin/env python3
"""Tests for core/chunker.py, sentence-aware chunking for the RAG ingest path.
Coverage: terminator handling and the IOC-safety rule that keeps `8.8.8.8` whole,
the `size` bound on every strategy, oversized-unit windowing (the max-sequence-length
guard), soft line-break merging on hard-wrapped PDF text, empty/hostile input, and
the guarantee that a near-`size` overlap still terminates.
"""

from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import pytest
from mcp_server.core import chunker
from mcp_server.core.config import RAGConfig
from mcp_server.core.exceptions import ConfigurationError


def test_sentence_terminator_stays_with_its_sentence():
    out = chunker.split("Hello world. Next one.", size=200)
    assert out == ["Hello world. Next one."]

    out = chunker.split("one. two. three.", size=200)
    assert out == ["one. two. three."]


def test_iocs_survive_sentence_splitting():
    """A bare `.` split would turn 8.8.8.8 into '8. 8. 8. 8' and make the corpus
    unmatchable for the exact values analysts search on."""
    text = "8.8.8.8 was scanned. v1.2.3 is old. 10.20.30.40 too."
    assert chunker.split(text, size=200) == [text]

# LMAO... This Debug process write in Chinesse version.
def test_cjk_terminators_split_without_trailing_space():
    out = chunker.split("第一句。第二句。", size=200)
    assert out == ["第一句。 第二句。"]


def test_newlines_are_boundaries():
    out = chunker.split("line one\nline two", size=200)
    assert out == ["line one line two"]


def test_oversized_unit_is_windowed_not_emitted_whole():
    """Unbounded chunks silently truncate at the embedder's max sequence length:
    the tail is stored but unmatchable, and nothing in the response says so."""
    out = chunker.split("a" * 300 + ". short.", size=50)
    assert all(len(c) <= 50 for c in out), out
    assert out[-1] == "short."


def test_long_text_without_terminators_is_bounded():
    out = chunker.split("noperiods " * 400, size=100, overlap=20)
    assert len(out) > 1
    assert all(len(c) <= 100 for c in out)


def test_overlap_near_size_terminates():
    """Overlap at `size` collapses the step to 1 and shreds every unit."""
    for overlap in (0, 1, 5, 99, 10_000):
        out = chunker.split("one. two. three.", size=5, overlap=overlap)
        assert out, overlap
        assert all(len(c) <= 5 for c in out), (overlap, out)


def test_length_strategy_matches_the_previous_sliding_window():
    body = "x" * 100
    out = chunker.split(body, size=30, overlap=0, strategy="length")
    assert [len(c) for c in out] == [30, 30, 30, 10]


def test_paragraph_strategy_keeps_paragraphs_whole():
    text = "P one\nP two\nP three"
    assert chunker.split(text, size=1000, strategy="paragraphs") == ["P one P two P three"]
    assert chunker.split(text, size=10, strategy="paragraphs") == ["P one", "P two", "P three"]


def test_unknown_strategy_falls_back_to_sentences():
    assert chunker.split("A. B.", size=200, strategy="typo") == ["A. B."]


def test_empty_and_whitespace_input():
    assert chunker.split("", size=100) == []
    assert chunker.split("   \n\t ", size=100) == []
    assert chunker.normalize("") == ""


def test_normalize_merges_soft_line_breaks():
    """PDF extractors hard-wrap mid-sentence, so neither line carries the phrase."""
    out = chunker.normalize("the attacker moved\nlaterally\nthen exfiltrated.\nSecond para.")
    assert out == "the attacker moved laterally then exfiltrated.\nSecond para."


def test_normalize_handles_crlf_and_blank_lines():
    out = chunker.normalize("line one\r\nline two\r\n\r\n\r\nline three")
    assert out == "line one line two line three"


def test_no_sentence_content_is_lost():
    body = " ".join(f"Sentence number {i} here." for i in range(200))
    chunks = chunker.split(body, size=300, overlap=60)
    joined = " ".join(chunks)
    assert "Sentence number 0 here." in joined
    assert "Sentence number 199 here." in joined
    assert all(len(c) <= 300 for c in chunks)


def test_config_rejects_unknown_chunk_strategy(tmp_path):
    with pytest.raises(ConfigurationError):
        RAGConfig(enabled=True, db_path=str(tmp_path / "rag.db"),
                  chunk_strategy="paragrpahs").validate()


def test_config_accepts_the_three_chunk_strategies(tmp_path):
    for strategy in chunker.STRATEGIES:
        RAGConfig(enabled=True, db_path=str(tmp_path / f"{strategy}.db"),
                  chunk_strategy=strategy).validate()
