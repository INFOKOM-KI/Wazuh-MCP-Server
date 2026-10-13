#!/usr/bin/env python3
"""The BM25 calls in semantic_search must not run on the event loop thread.

Coverage: the rule path's score call, and the alert path's index build plus score
call, each asserted to run on a worker thread while the tool is awaited. The rule
path is also checked against a direct ``_bm25_index.score`` call, so the offload
cannot quietly change which rules come back.

The thread name is the assertion because it is the only observable difference: a
call left on the loop produces "MainThread", and one under ``asyncio.to_thread``
produces a worker name.
"""
from __future__ import annotations

import json
import os
import threading

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import asyncio

from mcp_server.tools import semantic_search as ss


def _run(coro):
    return asyncio.run(coro)


def _tool():
    return getattr(ss.blueteam_semantic_search, "__wrapped__",
                   ss.blueteam_semantic_search)


def _hit(i):
    return {
        "_source": {
            "@timestamp": f"2026-10-13T00:0{i}:00Z",
            "rule": {"id": "5710", "description": "sshd brute force",
                     "level": 10, "groups": ["authentication_failed"]},
            "full_log": "Failed password for root from 10.0.0.1",
        },
        "sort": [1700000000 + i, str(i)],
    }


def test_rules_path_scores_off_the_event_loop(monkeypatch):
    # Pin the live-rules load off: its failure path rebinds _bm25_index, so the patch
    # below would be applied to an instance the tool no longer uses.
    monkeypatch.setattr(ss, "_bm25_live_loaded", True)
    index = ss._bm25_index
    real_score = index.score
    threads = []

    def recording_score(query):
        threads.append(threading.current_thread().name)
        return real_score(query)

    monkeypatch.setattr(index, "score", recording_score)
    out = json.loads(_run(_tool()(ss.SemanticSearchInput(
        query="brute force ssh", source="rules", rerank=False,
        top_k=3, response_format="json"))))

    assert threads, "the rule-path score was never called"
    assert all(name != "MainThread" for name in threads), (
        f"BM25 ran on the event loop thread: {threads}")
    assert out["matches"], "the offloaded path returned no matches"


def test_rules_path_matches_a_direct_score(monkeypatch):
    monkeypatch.setattr(ss, "_bm25_live_loaded", True)
    query = "brute force ssh"
    direct = [ss._bm25_corpus[i]["id"] for i, _ in ss._bm25_index.score(query)[:3]]
    out = json.loads(_run(_tool()(ss.SemanticSearchInput(
        query=query, source="rules", rerank=False, top_k=3, response_format="json"))))

    assert [m["rule_id"] for m in out["matches"]] == direct


def test_alerts_path_builds_and_scores_off_the_event_loop(monkeypatch):
    real_bm25 = ss._BM25
    threads = []

    class RecordingBM25(real_bm25):
        def __init__(self, corpus):
            threads.append(("build", threading.current_thread().name))
            super().__init__(corpus)

        def score(self, query):
            threads.append(("score", threading.current_thread().name))
            return super().score(query)

    # Two hits reported for the count, then the page that carries them.
    pages = [
        {"hits": {"total": {"value": 2}, "hits": []}},
        {"hits": {"total": {"value": 2}, "hits": [_hit(0), _hit(1)]}},
    ]
    calls = {"n": 0}

    async def fake_post(body, index_pattern=None):
        page = pages[min(calls["n"], len(pages) - 1)]
        calls["n"] += 1
        return page

    monkeypatch.setattr(ss, "_BM25", RecordingBM25)
    monkeypatch.setattr(ss, "_wazuh_indexer_post", fake_post)

    _run(_tool()(ss.SemanticSearchInput(
        query="brute force ssh", source="alerts", rerank=False,
        top_k=3, response_format="json")))

    assert {kind for kind, _ in threads} == {"build", "score"}, (
        f"expected both the build and the score to run, got {threads}")
    assert all(name != "MainThread" for _, name in threads), (
        f"BM25 ran on the event loop thread: {threads}")
