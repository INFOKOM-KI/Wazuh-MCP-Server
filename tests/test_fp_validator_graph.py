#!/usr/bin/env python3
"""Tests for agents/fp_validator_graph.py - the LangGraph false-positive workflow.
The load-bearing claim is routing: a degraded run must NOT come back as
``insufficient_evidence``, because that reads as "the corpus was searched and
came back empty". These tests cover each route, the authority short-circuit
(which must work with no corpus at all), the node-timeout seam, and the durable
checkpointer path.
"""
from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import asyncio
import pytest
from mcp_server.agents import fp_validator_graph as fpv
from mcp_server.core import attacker_registry, false_positive_kb, rag_store
from mcp_server.core.config import config


class _StubEmbedder:
    """Deterministic 4dim embedder. Character content drives the vector."""

    def embed(self, texts):
        for text in texts:
            yield [float(text.count("a")) + 1.0, float(text.count("b")) + 1.0,
                   float(len(text) % 5) + 1.0, 1.0]


def _setup_store(tmp_path):
    config.rag.enabled = True
    config.rag.db_path = str(tmp_path / "rag.db")
    config.rag.model = "stub-model"
    config.rag.allow_download = False
    config.rag.sha256 = ""
    rag_store._embedder = _StubEmbedder()
    rag_store._reason = "ready"
    rag_store._cache_key = None
    rag_store._cache_rows = None
    rag_store._cache_matrix = None


def _ingest(label: str, texts: list) -> None:
    from mcp_server.tools import rag_kb
    asyncio.run(rag_kb.blueteam_rag_ingest.__wrapped__(
        rag_kb.RagIngestInput(source="text", label=label, texts=texts)))


@pytest.fixture(autouse=True)
def _reset():
    config.rag.enabled = False
    config.rag.db_path = ""
    rag_store._embedder = None
    rag_store._cache_key = None
    rag_store._cache_rows = None
    rag_store._cache_matrix = None
    _clear_registries()
    yield
    config.rag.enabled = False
    config.rag.db_path = ""
    rag_store._embedder = None
    _clear_registries()


def _clear_registries():
    """Use the modules' own resets. attacker_registry derives _ATTACKER_EXACT and
    _ATTACKER_DOMAINS from _ENTRIES, so clearing _ENTRIES alone leaves
    is_attacker_ioc() returning True for a previous test's indicator."""
    attacker_registry.clear_attacker_registry()
    false_positive_kb.clear_false_positive_kb()


# Topology
def test_graph_wires_four_nodes_with_one_conditional_fanout():
    graph = fpv.build_fp_validator_graph().get_graph()
    assert {"assemble_evidence", "decide_authority", "decide_corpus",
            "decide_degraded"} <= set(graph.nodes)
    targets = {edge.target for edge in graph.edges if edge.source == "assemble_evidence"}
    assert targets == {"decide_authority", "decide_corpus", "decide_degraded"}


# Routing: degradation is never reported as a negative finding
def test_unconfigured_store_returns_validation_incomplete_not_insufficient():
    result = asyncio.run(fpv.run_fp_validation("198.51.100.1", "aaa brute force"))
    assert result["verdict"] == "validation_incomplete"
    assert result["evidence"]["corpus_searched"] is False
    assert result["errors"]


def test_node_timeout_routes_to_degraded(tmp_path, monkeypatch):
    _setup_store(tmp_path)

    async def _timeout(coro, label):
        coro.close()  # the real wrapper would have awaited it; avoid a warning
        return {"errors": [f"{label}: timed out"], "steps": [f"{label}: timed out"]}

    monkeypatch.setattr(fpv, "_with_timeout", _timeout)
    result = asyncio.run(fpv.run_fp_validation("198.51.100.2", "aaa"))
    assert result["verdict"] == "validation_incomplete"
    assert result["evidence"]["corpus_status"] == "timeout"


# Routing: authority signals skip retrieval entirely
def test_exact_suppression_short_circuits_without_a_store():
    """No store configured at all, and the verdict is still authoritative."""
    false_positive_kb.register_false_positive("8.8.8.8", source="verdict", reason="dns noise")
    result = asyncio.run(fpv.run_fp_validation("8.8.8.8", "ssh auth failure"))
    assert result["verdict"] == "suppressed_exact"
    assert result["matches"] == []
    assert result["evidence"]["exact_suppression_match"] is True


def test_attacker_registry_outranks_corpus(tmp_path):
    _setup_store(tmp_path)
    attacker_registry.register_attacker_ioc("103.107.116.202", source="verdict")
    _ingest("cases", ["Confirmed false positive aaa aaa"] * 3)
    result = asyncio.run(fpv.run_fp_validation(
        "103.107.116.202", "aaa", min_matches=1))
    assert result["verdict"] == "likely_true_positive"


def test_conflicting_signals_are_not_resolved_by_similarity(tmp_path):
    _setup_store(tmp_path)
    false_positive_kb.register_false_positive("203.0.113.50", source="verdict", reason="noise")
    attacker_registry.register_attacker_ioc("203.0.113.50", source="verdict")
    _ingest("cases", ["Confirmed false positive aaa aaa"] * 3)
    result = asyncio.run(fpv.run_fp_validation(
        "203.0.113.50", "aaa", min_matches=1))
    assert result["verdict"] == "conflicting_state"
    assert result["evidence"]["kb_matches"] == 0  # retrieval never ran


# Routing: the corpus path
def test_corpus_hits_produce_a_likely_false_positive(tmp_path):
    _setup_store(tmp_path)
    _ingest("cases", ["Confirmed false positive aaa aaa"] * 3)
    result = asyncio.run(fpv.run_fp_validation(
        "198.51.100.3", "aaa false positive", min_matches=3))
    assert result["verdict"] == "likely_false_positive"
    assert result["evidence"]["corpus_searched"] is True
    assert result["evidence"]["kb_matches"] >= 3


def test_empty_corpus_is_insufficient_not_degraded(tmp_path):
    """An empty store IS a search that returned nothing, so this route differs
    from the degraded route on purpose."""
    _setup_store(tmp_path)
    result = asyncio.run(fpv.run_fp_validation("198.51.100.4", "aaa"))
    assert result["verdict"] == "insufficient_evidence"
    assert result["evidence"]["corpus_searched"] is True


def test_uncalibrated_floor_blocks_the_recommendation(tmp_path):
    """Rerank off means there is no rerank score, so a caller supplied floor must
    fail closed instead of being treated as satisfied."""
    _setup_store(tmp_path)
    _ingest("cases", ["Confirmed false positive aaa aaa"] * 3)
    result = asyncio.run(fpv.run_fp_validation(
        "198.51.100.5", "aaa false positive", min_matches=1, min_rerank_score=1.5))
    assert result["evidence"]["score_floor_met"] is False
    assert result["verdict"] == "insufficient_evidence"


def test_no_calibrated_probability_is_ever_emitted(tmp_path):
    _setup_store(tmp_path)
    result = asyncio.run(fpv.run_fp_validation("198.51.100.6", "aaa"))
    assert result["evidence"]["confidence"] == "not_computed"
    assert not any(k.endswith("_confidence") for k in result["evidence"])


# Durable checkpointer
def test_sqlite_checkpointer_path(tmp_path, monkeypatch):
    pytest.importorskip("aiosqlite")
    _setup_store(tmp_path)
    monkeypatch.setattr(fpv, "_DB_PATH", str(tmp_path / "langgraph.db"))
    result = asyncio.run(fpv.run_fp_validation("198.51.100.7", "aaa"))
    assert result["verdict"] in {
        "validation_incomplete", "insufficient_evidence", "likely_false_positive"}
    assert os.path.exists(str(tmp_path / "langgraph.db"))


# Wiring into the investigation graph
def test_investigation_graph_routes_extract_into_fp_check():
    from mcp_server.agents import investigation_graph as inv
    graph = inv.build_investigation_graph().get_graph()
    assert "fp_check" in set(graph.nodes)
    targets = {e.target for e in graph.edges if e.source == "extract"}
    assert targets == {"fp_check"}
    fp_targets = {e.target for e in graph.edges if e.source == "fp_check"}
    assert fp_targets == {"verdict", "enrich", "analytics"}


def test_suppressed_indicator_short_circuits_the_investigation():
    """An already-resolved indicator must skip enrichment/correlation entirely.
    No RAG store is configured here, which also proves the authority path needs
    no corpus."""
    from mcp_server.agents.investigation_graph import run_investigation
    false_positive_kb.register_false_positive("8.8.8.8", source="verdict", reason="dns noise")
    result = asyncio.run(run_investigation(srcip="8.8.8.8", check_false_positive=True))
    assert result["fp_validation"]["verdict"] == "suppressed_exact"
    assert not any(s.startswith("enrich:") for s in result["steps"])
    assert any("fp_check: suppressed_exact" in s for s in result["steps"])


def test_fp_gate_is_opt_out_by_default():
    from mcp_server.agents.investigation_graph import run_investigation
    result = asyncio.run(run_investigation(srcip="8.8.8.8"))
    assert result["fp_validation"] is None
    assert any("fp_check: skipped" in s for s in result["steps"])
