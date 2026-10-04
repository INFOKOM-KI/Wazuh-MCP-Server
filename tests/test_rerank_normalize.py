#!/usr/bin/env python3
"""Tests for BLUETEAM_RERANK_NORMALIZE: rerank -> normalize -> fuse.
With it off the ranking is byte-identical to what shipped before; with it on, the
normalized score feeds the fusion, so vector_weight reorders the result.

The cross-encoder is never loaded. ``rerank_hits`` resolves the module-global
``rerank``, so patching that swaps the model without fastembed on the host.
"""

from __future__ import annotations
import math
import os

# mcp_server/__init__.py calls init_config() at import and hard-fails without
# WAZUH_INDEXER_* (ConfigurationError). Seed them at module level so this file
# passes in isolation (same reason as tests/test_rerank.py).
os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import pytest


@pytest.fixture(autouse=True)
def _rerank_config():
    """Pin the rerank config per test and restore it, so a normalize=True test
    cannot leak into a peer module."""
    from mcp_server.core.config import config
    saved = (config.rerank.enabled, config.rerank.normalize, config.rerank.max_candidates)
    config.rerank.enabled = True
    config.rerank.normalize = False
    config.rerank.max_candidates = 100
    yield
    (config.rerank.enabled, config.rerank.normalize,
     config.rerank.max_candidates) = saved


def _patch_rerank(monkeypatch, scores, status=None):
    """Swap the cross-encoder for a fixed score list (one score per doc)."""
    from mcp_server.core import rerank as rerank_mod

    async def fake(query, docs):
        if status is None:
            assert len(scores) == len(docs), "one score per doc or the hits misalign"
        return list(scores), status

    monkeypatch.setattr(rerank_mod, "rerank", fake)


def _hits(texts):
    return [{"text": t, "vector_score": 0.9 - i * 0.1, "id": t.lower()}
            for i, t in enumerate(texts)]


# normalize_rerank_scores: the four-case contract
def test_normalize_empty_input_is_unchanged():
    from mcp_server.core.rerank import normalize_rerank_scores
    assert normalize_rerank_scores([]) == []


def test_normalize_single_candidate_clamps_instead_of_zeroing():
    """One candidate has zero spread. Min-max would divide by ~0 or map the lone
    score to 0, discarding the only signal in the batch."""
    from mcp_server.core.rerank import normalize_rerank_scores
    assert normalize_rerank_scores([2.5]) == [1.0]
    assert normalize_rerank_scores([-2.5]) == [0.0]
    assert normalize_rerank_scores([0.42]) == [0.42]


def test_normalize_keeps_scores_already_in_unit_range():
    """A calibrated provider's magnitudes are meaningful: rescaling them would
    break any threshold expressed in the provider's own units."""
    from mcp_server.core.rerank import normalize_rerank_scores
    assert normalize_rerank_scores([0.0, 0.5, 1.0]) == [0.0, 0.5, 1.0]
    assert normalize_rerank_scores([0.2, 0.2]) == [0.2, 0.2]


def test_normalize_rescales_negative_logits():
    from mcp_server.core.rerank import normalize_rerank_scores
    # -10.2 is the batch minimum and -3.0 the maximum, so the span is 7.2.
    out = normalize_rerank_scores([-10.2, -3.0, -9.0])
    assert out == pytest.approx([0.0, 1.0, 1.2 / 7.2])


def test_normalize_identical_logits_do_not_produce_nan():
    from mcp_server.core.rerank import normalize_rerank_scores
    assert normalize_rerank_scores([3.0, 3.0, 3.0]) == [1.0, 1.0, 1.0]
    assert normalize_rerank_scores([-5.0, -5.0]) == [0.0, 0.0]
    assert all(math.isfinite(s) for s in normalize_rerank_scores([7.7, 7.7]))


def test_normalize_near_identical_logits_clamp_not_min_max():
    """A 4e-4 spread is noise. Min-max would amplify it to a full [0,1] range and
    let it dominate the blend."""
    from mcp_server.core.rerank import normalize_rerank_scores
    assert normalize_rerank_scores([2.0000, 2.0004]) == [1.0, 1.0]


def test_normalize_min_max_on_a_real_spread():
    from mcp_server.core.rerank import normalize_rerank_scores
    out = normalize_rerank_scores([0.0, 2.0, 4.0])
    assert out == pytest.approx([0.0, 0.5, 1.0])
    assert all(0.0 <= s <= 1.0 for s in out)


def test_normalize_does_not_mutate_its_input():
    from mcp_server.core.rerank import normalize_rerank_scores
    scores = [4.0, 2.0, 0.0]
    normalize_rerank_scores(scores)
    assert scores == [4.0, 2.0, 0.0]


# rerank_hits: normalization
def test_fused_path_writes_the_normalized_score_and_keeps_the_logit(monkeypatch):
    from mcp_server.core import rerank as rerank_mod
    from mcp_server.core.config import config
    config.rerank.normalize = True
    _patch_rerank(monkeypatch, [4.0, 2.0, 0.0])
    ranked, reranked, status = _run(rerank_mod.rerank_hits(
        "q", _hits(["a", "b", "c"]), 3,
        term_scores=[1.0, 0.5, 0.0], vector_weight=0.3))
    assert (reranked, status) == (True, None)
    assert [h["id"] for h in ranked] == ["a", "b", "c"]
    assert [h["rerank_score"] for h in ranked] == pytest.approx([1.0, 0.5, 0.0])
    assert [h["rerank_raw"] for h in ranked] == pytest.approx([4.0, 2.0, 0.0])


def test_rerank_hits_empty_candidates(monkeypatch):
    from mcp_server.core import rerank as rerank_mod
    from mcp_server.core.config import config
    config.rerank.normalize = True
    _patch_rerank(monkeypatch, [])
    ranked, reranked, status = _run(rerank_mod.rerank_hits("q", [], 10))
    assert ranked == []
    assert (reranked, status) == (True, None)


def test_rerank_hits_falls_back_without_normalizing(monkeypatch):
    """A dead reranker has no score to normalize. The status must survive and the
    caller must still get its original order truncated."""
    from mcp_server.core import rerank as rerank_mod
    from mcp_server.core.config import config
    config.rerank.normalize = True
    _patch_rerank(monkeypatch, [], status="unavailable: model load failed")
    hits = _hits(["a", "b", "c"])
    ranked, reranked, status = _run(rerank_mod.rerank_hits("q", hits, 2))
    assert ranked == hits[:2]
    assert reranked is False
    assert status == "unavailable: model load failed"


# rerank_hits: the disabled path must be unchanged
def test_rerank_hits_disabled_path_ignores_the_term_leg(monkeypatch):
    """With normalize off, term_scores are not a ranking input and no hybrid_score
    is written: the pre-flag behaviour exactly."""
    from mcp_server.core import rerank as rerank_mod
    _patch_rerank(monkeypatch, [4.0, 2.0, 0.0])
    ranked, reranked, _ = _run(rerank_mod.rerank_hits(
        "q", _hits(["a", "b", "c"]), 3,
        term_scores=[0.0, 0.5, 1.0], vector_weight=0.3))
    assert (reranked, [h["id"] for h in ranked]) == (True, ["a", "b", "c"])
    assert "rerank_raw" not in ranked[0]
    assert "hybrid_score" not in ranked[0]
    assert [h["rerank_score"] for h in ranked] == pytest.approx([4.0, 2.0, 0.0])


def test_rerank_hits_uses_score_field_as_the_tie_break_when_disabled(monkeypatch):
    """Two candidates with an identical logit keep the legacy ordering rule."""
    from mcp_server.core import rerank as rerank_mod
    _patch_rerank(monkeypatch, [1.0, 1.0])
    hits = _hits(["a", "b"])
    hits[0]["vector_score"] = 0.1
    hits[1]["vector_score"] = 0.8
    ranked, _, _ = _run(rerank_mod.rerank_hits("q", hits, 2))
    assert [h["id"] for h in ranked] == ["b", "a"]


# rerank_hits: post-rerank fusion
def test_vector_weight_changes_the_final_order_after_reranking(monkeypatch):
    """The regression this flag exists for. Before it, the cross-encoder logits were
    the only sort key, so vector_weight could not move a row."""
    from mcp_server.core import rerank as rerank_mod
    from mcp_server.core.config import config
    config.rerank.normalize = True
    _patch_rerank(monkeypatch, [4.0, 2.0, 0.0])
    texts = ["dense winner", "middle", "lexical winner"]

    dense_only, _, _ = _run(rerank_mod.rerank_hits(
        "q", _hits(texts), 3, term_scores=[0.0, 0.5, 1.0], vector_weight=1.0))
    fused, _, _ = _run(rerank_mod.rerank_hits(
        "q", _hits(texts), 3, term_scores=[0.0, 0.5, 1.0], vector_weight=0.3))

    assert [h["id"] for h in dense_only] == [t.lower() for t in texts]
    assert [h["id"] for h in fused] == [t.lower() for t in reversed(texts)]
    assert fused[0]["hybrid_score"] == pytest.approx(0.7)
    assert fused[0]["term_score"] == pytest.approx(1.0)


def test_fused_scores_are_the_announced_weights(monkeypatch):
    from mcp_server.core import rerank as rerank_mod
    from mcp_server.core.config import config
    config.rerank.normalize = True
    _patch_rerank(monkeypatch, [4.0, 2.0, 0.0])
    ranked, _, _ = _run(rerank_mod.rerank_hits(
        "q", _hits(["a", "b", "c"]), 3,
        term_scores=[0.0, 0.5, 1.0], vector_weight=0.3))
    for hit in ranked:
        assert hit["hybrid_score"] == pytest.approx(
            0.3 * hit["rerank_score"] + 0.7 * hit["term_score"], abs=1e-6)


def test_fusion_tolerates_term_scores_from_a_wider_recall(monkeypatch):
    """The caller scores the whole recall set; rerank_hits clamps to max_candidates.
    The extra tail must be dropped, not misaligned."""
    from mcp_server.core import rerank as rerank_mod
    from mcp_server.core.config import config
    config.rerank.normalize = True
    config.rerank.max_candidates = 2
    _patch_rerank(monkeypatch, [4.0, 0.0])
    ranked, reranked, _ = _run(rerank_mod.rerank_hits(
        "q", _hits(["a", "b", "c"]), 3,
        term_scores=[0.0, 1.0, 0.9], vector_weight=0.3))
    assert reranked is True
    assert [h["id"] for h in ranked] == ["b", "a"]
    assert all("c" != h["id"] for h in ranked)


def test_fusion_rejects_a_short_term_score_list(monkeypatch):
    """A silent zip would drop a candidate from the result with nothing saying so."""
    from mcp_server.core import rerank as rerank_mod
    from mcp_server.core.config import config
    config.rerank.normalize = True
    _patch_rerank(monkeypatch, [4.0, 2.0, 0.0])
    with pytest.raises(ValueError, match="must align by chunk index"):
        _run(rerank_mod.rerank_hits("q", _hits(["a", "b", "c"]), 3,
                                    term_scores=[0.1], vector_weight=0.3))


# the flag stops at the fusion path
def test_normalize_leaves_a_non_fusing_caller_on_raw_logits(monkeypatch):
    """blueteam_rag_fp_validate passes no term_scores, so its floor keeps logit units."""
    from mcp_server.core import rerank as rerank_mod
    from mcp_server.core.config import config
    config.rerank.normalize = True
    _patch_rerank(monkeypatch, [-10.2, -3.0, -9.0])
    ranked, _, _ = _run(rerank_mod.rerank_hits("q", _hits(["a", "b", "c"]), 3))
    assert [h["id"] for h in ranked] == ["b", "c", "a"]
    assert ranked[0]["rerank_score"] == pytest.approx(-3.0)
    assert "rerank_raw" not in ranked[0]
    assert "hybrid_score" not in ranked[0]


def test_vector_only_weight_skips_normalization_even_with_term_scores(monkeypatch):
    """vector_weight=1.0 drops the term leg inside term_sim.hybrid, so nothing fuses."""
    from mcp_server.core import rerank as rerank_mod
    from mcp_server.core.config import config
    config.rerank.normalize = True
    _patch_rerank(monkeypatch, [4.0, 2.0, 0.0])
    ranked, _, _ = _run(rerank_mod.rerank_hits(
        "q", _hits(["a", "b", "c"]), 3,
        term_scores=[0.0, 0.5, 1.0], vector_weight=1.0))
    assert [h["rerank_score"] for h in ranked] == pytest.approx([4.0, 2.0, 0.0])
    assert "rerank_raw" not in ranked[0]
    assert "hybrid_score" not in ranked[0]


def test_status_dict_does_not_claim_normalization():
    """Only the fusion path normalizes, and status_dict cannot see the caller, so the
    field belongs to the fusing tool's own response."""
    from mcp_server.core.config import config
    from mcp_server.core.rerank import status_dict
    config.rerank.normalize = True
    assert "rerank_normalized" not in status_dict(None)


def _run(coro):
    import asyncio
    return asyncio.run(coro)


if __name__ == "__main__":
    import sys
    import inspect
    import traceback
    from mcp_server.core.config import config as _cfg

    class _MP:
        """Minimal monkeypatch stand-in so this file also runs as a script."""
        def __init__(self, mod):
            self.mod = mod

        def setattr(self, obj, name, value):
            setattr(obj, name, value)

    tests = [f for f in dir() if f.startswith("test_")
             and not inspect.signature(globals()[f]).parameters]
    passed = 0
    for name in tests:
        saved = (_cfg.rerank.enabled, _cfg.rerank.normalize, _cfg.rerank.max_candidates)
        _cfg.rerank.enabled = True
        _cfg.rerank.normalize = False
        _cfg.rerank.max_candidates = 100
        try:
            globals()[name](_MP(None))
            print(f"PASS {name}")
            passed += 1
        except Exception:
            print(f"FAIL {name}")
            traceback.print_exc()
        finally:
            (_cfg.rerank.enabled, _cfg.rerank.normalize,
             _cfg.rerank.max_candidates) = saved
    print(f"\n{passed}/{len(tests)} passed")
    sys.exit(0 if passed == len(tests) else 1)
