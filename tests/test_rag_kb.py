#!/usr/bin/env python3
"""Tests for tools/rag_kb.py ingest / query / false-positive validation.
Runs against a stub embedder (fastembed is absent in CI) and a temp SQLite
store. Covers: the not-configured contract, corpus rendering from case_store and
false_positive_kb, rebuild-not-append semantics for derived labels, source
filtering, and every branch of the FP verdict ladder including conflicting state.
Tool bodies are exercised through ``__wrapped__`` so the assertions are about
tool logic, not the @blueteam_tool redaction/truncation pipeline (that has its
own test in tests/test_tool_decorator.py). One test calls the wrapper directly to
prove the tool is callable end to end.
"""

from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import asyncio
import json
import pytest
from mcp_server.core import attacker_registry, case_store, false_positive_kb, rag_store
from mcp_server.core.config import config
from mcp_server.core.exceptions import BlueTeamMCPError
from mcp_server.tools import rag_kb


class _StubEmbedder:
    """Deterministic 4-dim embedder. Character content drives the vector."""
    def embed(self, texts):
        for text in texts:
            yield [float(text.count("a")) + 1.0, float(text.count("b")) + 1.0,
                   float(len(text) % 5) + 1.0, 1.0]


def _run(coro):
    return asyncio.run(coro)


# Underlying tool bodies, bypassing the decorator pipeline.
_ingest = rag_kb.blueteam_rag_ingest.__wrapped__
_query = rag_kb.blueteam_rag_query.__wrapped__
_validate = rag_kb.blueteam_rag_fp_validate.__wrapped__


def _setup(tmp_path):
    config.rag.enabled = True
    config.rag.db_path = str(tmp_path / "rag.db")
    config.rag.model = "stub-model"
    config.rag.allow_download = False
    config.rag.sha256 = ""
    config.rag.top_k = 10
    config.rag.max_candidates = 100
    rag_store._embedder = _StubEmbedder()
    rag_store._reason = "ready"
    rag_store._cache_key = None
    rag_store._cache_rows = None
    rag_store._cache_matrix = None


def _store_chunks() -> int:
    return sum(rag_store.stats()["chunks_by_model"].values())


@pytest.fixture(autouse=True)
def _reset(tmp_path):
    """Dormant store + empty source-of-truth stores around every test."""
    config.rag.enabled = False
    config.rag.db_path = ""
    rag_store._embedder = None
    rag_store._reason = "not loaded"
    rag_store._cache_key = None
    rag_store._cache_rows = None
    rag_store._cache_matrix = None
    false_positive_kb._ENTRIES.clear()
    attacker_registry._ENTRIES.clear()
    case_store._cases.clear()
    yield
    config.rag.enabled = False
    config.rag.db_path = ""
    rag_store._embedder = None
    false_positive_kb._ENTRIES.clear()
    attacker_registry._ENTRIES.clear()
    case_store._cases.clear()


# Not configured
def test_all_tools_fail_loudly_without_a_store(tmp_path):
    """An unconfigured store must raise, not return 'no similar cases found'."""
    with pytest.raises(BlueTeamMCPError):
        _run(_ingest(rag_kb.RagIngestInput(source="cases")))
    with pytest.raises(BlueTeamMCPError):
        _run(_query(rag_kb.RagQueryInput(query="brute force")))
    with pytest.raises(BlueTeamMCPError):
        _run(_validate(rag_kb.RagFpValidateInput(srcip="8.8.8.8")))


def test_ingest_text_requires_texts(tmp_path):
    _setup(tmp_path)
    with pytest.raises(BlueTeamMCPError):
        _run(_ingest(rag_kb.RagIngestInput(source="text")))


# Ingest
def test_ingest_from_false_positives_writes_chunks(tmp_path):
    _setup(tmp_path)
    false_positive_kb.register_false_positive("8.8.8.8", source="verdict",
                                              reason="Google DNS scanner noise")
    out = _run(_ingest(rag_kb.RagIngestInput(source="false_positives", response_format="json")))
    payload = json.loads(out)
    assert payload["source"] == "false_positives"
    assert payload["chunks_inserted"] >= 1
    assert payload["store"]["chunks_by_model"] == {"stub-model": payload["chunks_inserted"]}


def test_ingest_from_cases_renders_case_fields(tmp_path):
    _setup(tmp_path)
    case_store.create_case("SSH brute force on mail", ["203.0.113.9"],
                          notes="maintenance window, expected")
    out = _run(_ingest(rag_kb.RagIngestInput(source="cases", response_format="json")))
    assert json.loads(out)["chunks_inserted"] == 1


def test_derived_labels_rebuild_instead_of_append(tmp_path):
    """Chunk ids are content hashes, so an edited case would leave its old chunk
    behind forever unless the label is cleared first."""
    _setup(tmp_path)
    case_store.create_case("Case A", ["203.0.113.9"], notes="first")
    _run(_ingest(rag_kb.RagIngestInput(source="cases")))
    first = _store_chunks()
    assert first == 1

    out = _run(_ingest(rag_kb.RagIngestInput(source="cases", response_format="json")))
    second = json.loads(out)
    assert second["chunks_deleted"] == 1
    assert _store_chunks() == first  # rebuilt, not doubled


def test_text_ingest_upserts_under_a_distinct_label(tmp_path):
    _setup(tmp_path)
    _run(_ingest(rag_kb.RagIngestInput(source="text", label="ir_playbooks",
                                       texts=["Contain host", "Eradicate malware"])))
    assert _store_chunks() == 2
    # Re-ingesting identical text is a no-op, not a duplicate.
    _run(_ingest(rag_kb.RagIngestInput(source="text", label="ir_playbooks",
                                       texts=["Contain host", "Eradicate malware"])))
    assert _store_chunks() == 2


# Query
def test_query_returns_scores_and_matches(tmp_path):
    _setup(tmp_path)
    false_positive_kb.register_false_positive("8.8.8.8", source="verdict",
                                              reason="aaa aaa scanner noise")
    _run(_ingest(rag_kb.RagIngestInput(source="false_positives")))
    payload = json.loads(_run(_query(rag_kb.RagQueryInput(query="aaa scanner",
                                                          response_format="json"))))
    assert payload["returned"] == 1
    assert payload["matches"][0]["vector_score"] > 0
    assert payload["matches"][0]["source"] == "false_positives"


def test_query_source_filter(tmp_path):
    _setup(tmp_path)
    false_positive_kb.register_false_positive("8.8.8.8", source="verdict", reason="aaa noise")
    _run(_ingest(rag_kb.RagIngestInput(source="false_positives")))
    _run(_ingest(rag_kb.RagIngestInput(source="text", label="cases", texts=["aaa case note"])))

    payload = json.loads(_run(_query(rag_kb.RagQueryInput(
        query="aaa", sources=["cases"], response_format="json"))))
    assert payload["returned"] == 1
    assert payload["matches"][0]["source"] == "cases"


def test_query_empty_corpus_reports_no_corpus(tmp_path):
    _setup(tmp_path)
    out = _run(_query(rag_kb.RagQueryInput(query="aaa brute force")))
    assert "no_corpus" in out


# FP verdict ladder
def test_fp_validate_suppressed_exact_short_circuits(tmp_path):
    _setup(tmp_path)
    false_positive_kb.register_false_positive("8.8.8.8", source="verdict", reason="noise")
    payload = json.loads(_run(_validate(rag_kb.RagFpValidateInput(
        srcip="8.8.8.8", description="ssh auth failure", response_format="json"))))
    assert payload["verdict"] == "suppressed_exact"
    assert payload["evidence"]["exact_suppression_match"] is True


def test_fp_validate_attacker_registry_outranks_corpus_similarity(tmp_path):
    _setup(tmp_path)
    attacker_registry.register_attacker_ioc("103.107.116.202", source="verdict")
    _run(_ingest(rag_kb.RagIngestInput(source="text", label="cases", texts=[
        "Confirmed false positive nginx scanner aaa aaa",
        "Confirmed false positive nginx scanner aaa aaa",
        "Confirmed false positive nginx scanner aaa aaa",
    ])))
    payload = json.loads(_run(_validate(rag_kb.RagFpValidateInput(
        srcip="103.107.116.202", description="aaa nginx scanner",
        min_matches=1, response_format="json"))))
    assert payload["verdict"] == "likely_true_positive"
    assert payload["evidence"]["attacker_registry_match"] is True


def test_fp_validate_conflicting_state_is_surfaced(tmp_path):
    """FP set and attacker registry both match. Neither store clears the other,
    so the tool must refuse to pick a winner rather than guess."""
    _setup(tmp_path)
    false_positive_kb.register_false_positive("203.0.113.50", source="verdict", reason="noise")
    attacker_registry.register_attacker_ioc("203.0.113.50", source="verdict")
    payload = json.loads(_run(_validate(rag_kb.RagFpValidateInput(
        srcip="203.0.113.50", response_format="json"))))
    assert payload["verdict"] == "conflicting_state"


def test_fp_validate_likely_false_positive_needs_min_matches(tmp_path):
    _setup(tmp_path)
    _run(_ingest(rag_kb.RagIngestInput(source="text", label="cases", texts=[
        "Confirmed false positive aaa aaa", "Confirmed false positive aaa aaa",
        "Confirmed false positive aaa aaa",
    ])))
    payload = json.loads(_run(_validate(rag_kb.RagFpValidateInput(
        srcip="198.51.100.7", description="aaa false positive",
        min_matches=3, response_format="json"))))
    assert payload["verdict"] == "likely_false_positive"
    assert payload["evidence"]["kb_matches"] >= 3


def test_fp_validate_insufficient_evidence_below_min_matches(tmp_path):
    _setup(tmp_path)
    _run(_ingest(rag_kb.RagIngestInput(source="text", label="cases",
                                       texts=["Confirmed false positive aaa"])))
    payload = json.loads(_run(_validate(rag_kb.RagFpValidateInput(
        srcip="198.51.100.8", description="aaa false positive",
        min_matches=3, response_format="json"))))
    assert payload["verdict"] == "insufficient_evidence"


def test_fp_validate_uncalibrated_floor_blocks_the_recommendation(tmp_path):
    """Without the reranker there is no rerank score, so a caller-supplied floor
    must fail closed rather than be treated as satisfied."""
    _setup(tmp_path)
    _run(_ingest(rag_kb.RagIngestInput(source="text", label="cases", texts=[
        "Confirmed false positive aaa", "Confirmed false positive aaa",
        "Confirmed false positive aaa",
    ])))
    payload = json.loads(_run(_validate(rag_kb.RagFpValidateInput(
        srcip="198.51.100.9", description="aaa false positive",
        min_matches=1, min_rerank_score=1.5, rerank=False, response_format="json"))))
    assert payload["evidence"]["score_floor_met"] is False
    assert payload["verdict"] == "insufficient_evidence"


def test_fp_validate_never_fabricates_a_confidence(tmp_path):
    _setup(tmp_path)
    payload = json.loads(_run(_validate(rag_kb.RagFpValidateInput(
        srcip="198.51.100.10", response_format="json"))))
    assert payload["evidence"]["confidence"] == "not_computed"
    assert not any(k.endswith("_confidence") for k in payload["evidence"])


# Decorator path
def test_tool_is_callable_through_the_decorator(tmp_path):
    """Direct call goes through @blueteam_tool: audit, redact, truncate. Must
    still return a string rather than raising."""
    _setup(tmp_path)
    out = _run(rag_kb.blueteam_rag_query(rag_kb.RagQueryInput(query="aaa brute force")))
    assert isinstance(out, str) and out
