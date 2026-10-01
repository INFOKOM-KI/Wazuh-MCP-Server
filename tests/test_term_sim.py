#!/usr/bin/env python3
"""Tests for core/term_sim.py, term-weighted lexical scoring.
Coverage: the tokenizer contract and its drift guard against the BM25 leg, IOC-shaped
tokens staying whole and getting max weight, RAGFlow's weight-check ordering (an IPv4
literal is numeric before it is a named entity), L1 normalisation, bigram dominance,
the coverage-score epsilon paths, and the hybrid blend including its degenerate and
mismatched-length contracts.
"""

from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import pytest
from mcp_server.core import term_sim


TF = {"ssh": 500, "brute": 200, "8.8.8.8": 3}
DF = {"ssh": 400, "brute": 150, "8.8.8.8": 2}


def test_tokenize_keeps_iocs_whole():
    out = term_sim.tokenize("Failed login from 8.8.8.8 to mail.example.com!")
    assert "8.8.8.8" in out
    assert "mail.example.com" in out
    assert "failed" in out


def test_tokenize_drops_single_characters():
    assert term_sim.tokenize("a b c the report") == ["the", "report"]


def test_tokenizer_agrees_with_the_bm25_leg():
    """Two tokenizers scoring the same corpus would make the hybrid blend compare
    unlike quantities, so this pins them together rather than trusting a copy."""
    from mcp_server.tools.semantic_search import _tokenize
    for sample in ("Failed login from 8.8.8.8", "serangan webshell di nginx",
                   "CVE-2024-1234 t1059.001", "a b", ""):
        assert term_sim.tokenize(sample) == _tokenize(sample), sample


def test_ipv4_is_numeric_before_it_is_an_indicator():
    """RAGFlow checks the numeric shape first. An IP is 2.0, not 3.0."""
    assert term_sim.ner_weight("8.8.8.8") == term_sim.NUMERIC_WEIGHT


def test_indicator_shapes_get_max_weight():
    for token in ("evil.example.com", "a" * 32, "cve-2024-1234", "t1059.001"):
        assert term_sim.ner_weight(token) == term_sim.IOC_WEIGHT, token


def test_short_and_plain_tokens():
    assert term_sim.ner_weight("the") == term_sim.DEFAULT_WEIGHT
    assert term_sim.ner_weight("ab") == term_sim.SHORT_LETTER_WEIGHT


def test_weights_are_l1_normalised():
    out = term_sim.weights(term_sim.tokenize("ssh brute force 8.8.8.8"), tf=TF, df=DF)
    assert sum(out) == pytest.approx(1.0)


def test_rare_indicator_outweighs_a_common_word():
    tokens = term_sim.tokenize("ssh 8.8.8.8")
    out = term_sim.weights(tokens, tf=TF, df=DF)
    assert out[tokens.index("8.8.8.8")] > out[tokens.index("ssh")]


def test_weights_survive_an_empty_frequency_table():
    out = term_sim.weights(term_sim.tokenize("ssh brute force"))
    assert len(out) == 3
    assert sum(out) == pytest.approx(1.0)


def test_longer_unknown_tokens_score_as_rarer():
    assert term_sim._alphabetic_oov("abc") > term_sim._alphabetic_oov("abcdefghij")
    assert term_sim._alphabetic_oov("8.8") is None


def test_bigrams_outweigh_their_unigrams():
    out = term_sim.to_dict(term_sim.tokenize("credential dumping"))
    assert out["credentialdumping"] > out["credential"]
    assert out["credentialdumping"] > out["dumping"]


def test_coverage_score_spans_zero_to_one():
    query = term_sim.to_dict(term_sim.tokenize("credential dumping"))
    assert term_sim.token_dict_similarity(
        query, term_sim.to_dict(term_sim.tokenize("lateral movement and credential dumping"))
    ) == pytest.approx(1.0)
    assert term_sim.token_dict_similarity(
        query, term_sim.to_dict(term_sim.tokenize("unrelated prose about patch windows"))
    ) == pytest.approx(0.0, abs=1e-6)


def test_coverage_score_handles_empty_dicts():
    query = term_sim.to_dict(term_sim.tokenize("ssh"))
    assert term_sim.token_dict_similarity({}, query) == 0.0
    assert term_sim.token_dict_similarity(query, {}) == 0.0


def test_hybrid_blends_by_vector_weight():
    assert term_sim.hybrid([0.9, 0.1], [0.1, 0.9], 0.3) == pytest.approx([0.34, 0.66])


def test_hybrid_clamps_out_of_range_weight():
    assert term_sim.hybrid([1.0], [0.0], 5.0) == [1.0]
    assert term_sim.hybrid([1.0], [0.0], -3.0) == [0.0]


def test_hybrid_falls_back_to_term_scores_on_a_dead_vector_leg():
    assert term_sim.hybrid([0.0, 0.0], [0.1, 0.9]) == [0.1, 0.9]


def test_hybrid_handles_empty_input():
    assert term_sim.hybrid([], []) == []


def test_hybrid_rejects_misaligned_legs():
    """A silent zip would drop chunks from the result with nothing saying so."""
    with pytest.raises(ValueError):
        term_sim.hybrid([1.0], [1.0, 2.0])


def test_score_ranks_the_matching_document_first():
    scores = term_sim.score("ssh brute force", [
        "unrelated prose about patch windows",
        "sshd brute force detected",
        "ssh attempt",
    ])
    assert scores[1] > scores[2] > scores[0]
    assert scores[0] == pytest.approx(0.0, abs=1e-6)


def test_score_on_no_documents():
    assert term_sim.score("ssh", []) == []
