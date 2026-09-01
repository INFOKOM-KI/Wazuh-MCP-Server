#!/usr/bin/env python3
"""Tests for core/rerank.py; optional BM25 -> cross-encoder reranker.
Coverage: the fallback contract (disabled / empty / unavailable / success) and
the reason() status string. The model itself is never loaded - fastembed is
absent in CI, so the unavailable path is exercised against that absence.
"""

from __future__ import annotations


def _reset():
    from mcp_server.core import rerank
    from mcp_server.core.config import config
    config.rerank.enabled = False
    rerank._encoder = None
    rerank._reason = "not loaded"


def test_rerank_disabled_by_default():
    import asyncio
    from mcp_server.core import rerank
    _reset()
    scores, status = asyncio.run(rerank.rerank("query", ["doc a", "doc b"]))
    assert scores == []
    assert status == "disabled"


def test_rerank_empty_docs():
    import asyncio
    from mcp_server.core import rerank
    _reset()
    scores, status = asyncio.run(rerank.rerank("query", []))
    assert scores == []
    assert status == "empty"


def test_rerank_unavailable_when_fastembed_missing():
    import asyncio
    from mcp_server.core import rerank
    from mcp_server.core.config import config
    _reset()
    config.rerank.enabled = True
    scores, status = asyncio.run(rerank.rerank("query", ["doc a"]))
    assert scores == []
    assert status is not None and status.startswith("unavailable:")
    assert rerank.reason().startswith("model load failed")
    _reset()


def test_rerank_success_returns_scores_in_doc_order():
    import asyncio
    from mcp_server.core import rerank
    from mcp_server.core.config import config
    _reset()
    config.rerank.enabled = True

    class FakeEncoder:
        def rerank(self, query, docs):
            return [0.1, 0.9, 0.5]

    rerank._encoder = FakeEncoder()
    scores, status = asyncio.run(rerank.rerank("q", ["a", "b", "c"]))
    assert status is None
    assert scores == [0.1, 0.9, 0.5]
    _reset()


def test_ensure_loaded_sets_reason_on_failure():
    from mcp_server.core import rerank
    _reset()
    ok = rerank._ensure_loaded()
    assert ok is False
    assert rerank.reason().startswith("model load failed")
    _reset()


if __name__ == "__main__":
    import sys
    import traceback
    tests = [f for f in dir() if f.startswith("test_")]
    passed = 0
    for t in tests:
        try:
            globals()[t]()
            print(f"PASS {t}")
            passed += 1
        except Exception:
            print(f"FAIL {t}")
            traceback.print_exc()
    print(f"\n{passed}/{len(tests)} passed")
    sys.exit(0 if passed == len(tests) else 1)
