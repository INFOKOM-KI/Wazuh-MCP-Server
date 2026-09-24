#!/usr/bin/env python3
"""Tests for label/backends.py.
No model on disk and no torch: the ONNX backend gets a one-hot fake embedder, and the
Laya backend gets a fake ``laya`` module in sys.modules. The worker-thread offload and
the weight pin are the parts worth testing here, not the model quality.
"""
from __future__ import annotations

import asyncio
import subprocess
import sys
import types
import pytest
from mcp_server.label import criteria
from mcp_server.label.backends import (
    LayaLabeler,
    ONNXPrototypeLabeler,
    _score_payload,
    _tree_sha256,
)

PHRASE_TACTIC = {phrase: tactic for tactic, phrase in criteria.prototypes()}
# Sentinel texts the fake embedder understands. "mixed activity" maps to a vector
# equidistant from every anchor, which is the only way to test the floor path.
MARKERS = {"beacon to c2": "Command and Control", "ransomware note": "Impact",
           "mixed activity": "flat"}


def _one_hot(tactic: str) -> list:
    row = [0.0] * len(criteria.TACTICS)
    row[criteria.TACTICS.index(tactic)] = 1.0
    return row


def _fake_embedder(calls: list):
    async def embed(texts):
        calls.append(list(texts))
        rows = []
        for text in texts:
            tactic = PHRASE_TACTIC.get(text)
            if tactic is None:
                tactic = MARKERS.get(text.strip())
            if tactic is None:
                return None, "unavailable: no vector for this text"
            rows.append([1.0] * len(criteria.TACTICS) if tactic == "flat" else _one_hot(tactic))
        return rows, None

    return embed


def _run(coro):
    return asyncio.run(coro)


def _labeler(calls: list, floor: float = 0.6) -> ONNXPrototypeLabeler:
    return ONNXPrototypeLabeler(floor, embedder=_fake_embedder(calls))


def test_prototype_backend_labels_the_matching_tactic():
    calls: list = []
    verdict = _run(_labeler(calls).classify("beacon to c2"))
    assert verdict.status == "ok"
    assert verdict.label == "Command and Control"
    assert verdict.category == "C"
    assert verdict.scored and not verdict.uncertain
    assert verdict.confidence > 0.9
    assert set(verdict.probabilities) == set(criteria.TACTICS)
    assert abs(sum(verdict.probabilities.values()) - 1.0) < 1e-6


def test_prototype_backend_below_floor_is_uncertain_with_scores():
    calls: list = []
    verdict = _run(_labeler(calls).classify("mixed activity"))
    assert verdict.status == "uncertain"
    assert verdict.label is None
    assert verdict.scored is True
    assert verdict.uncertain is True
    assert "below the floor" in verdict.reason
    assert len(verdict.probabilities) == len(criteria.TACTICS)
    assert max(verdict.probabilities.values()) < 0.6


def test_prototype_anchors_are_embedded_once_per_process():
    calls: list = []
    labeler = _labeler(calls)
    _run(labeler.classify("beacon to c2"))
    _run(labeler.classify("ransomware note"))
    assert len(calls) == 3, "expected one anchor call plus one per classify"
    assert len(calls[0]) == 1, "first call embeds the state text only"
    assert len(calls[1]) == len(criteria.prototypes()), "second call builds the anchors"


def test_unavailable_embedder_reports_a_reason():
    async def embed(texts):
        return None, "disabled"

    verdict = _run(ONNXPrototypeLabeler(0.6, embedder=embed).classify("anything"))
    assert verdict.status == "unavailable"
    assert verdict.reason == "disabled"


def test_default_embedder_bypasses_the_rag_store_gate(monkeypatch):
    """Labeling must not require an enabled RAG corpus: the default embedder has to
    reach rag_store with require_store=False, or every call returns 'disabled'."""
    from mcp_server.core import rag_store
    from mcp_server.label import backends

    seen: dict = {}

    async def spy(texts, *, require_store=True):
        seen["require_store"] = require_store
        return [[0.0]], None

    monkeypatch.setattr(rag_store, "embed_texts", spy)
    _run(backends._default_embedder()(["x"]))
    assert seen["require_store"] is False


def test_laya_refuses_a_pin_mismatch(tmp_path, monkeypatch):
    (tmp_path / "config.json").write_text("{}")
    agent = _install_fake_laya(monkeypatch, {"answers": {"tactic": {"choice": "Impact"}}})
    labeler = LayaLabeler(0.6, str(tmp_path), "0" * 64)
    verdict = _run(labeler.classify("ransomware note"))
    assert verdict.status == "unavailable"
    assert "weight pin mismatch" in verdict.reason
    assert agent.calls == []


def test_laya_refuses_an_unpinned_model(tmp_path, monkeypatch):
    agent = _install_fake_laya(monkeypatch, {"answers": {"tactic": {"choice": "Impact"}}})
    verdict = _run(LayaLabeler(0.6, str(tmp_path), "").classify("ransomware note"))
    assert verdict.status == "unavailable"
    assert "no weight pin" in verdict.reason
    assert agent.calls == []


def test_laya_refuses_a_remote_reference_without_download(tmp_path, monkeypatch):
    agent = _install_fake_laya(monkeypatch, {"answers": {"tactic": {"choice": "Impact"}}})
    labeler = LayaLabeler(0.6, "convaiinnovations/laya-multilingual", "a" * 64)
    verdict = _run(labeler.classify("ransomware note"))
    assert verdict.status == "unavailable"
    assert "not a local directory" in verdict.reason
    assert agent.calls == []


def test_laya_bare_choice_is_unscored_not_confident(tmp_path, monkeypatch):
    (tmp_path / "config.json").write_text("{}")
    _install_fake_laya(monkeypatch, {"answers": {"tactic": {"choice": "Impact"}}})
    labeler = LayaLabeler(0.6, str(tmp_path), _tree_sha256(str(tmp_path)))
    verdict = _run(labeler.classify("ransomware note"))
    assert verdict.status == "uncertain"
    assert verdict.label == "Impact"
    assert verdict.category == "C"
    assert verdict.scored is False
    assert verdict.confidence is None
    assert verdict.probabilities is None
    assert "no scores" in verdict.reason


def test_laya_scores_are_applied_when_they_are_a_distribution(tmp_path, monkeypatch):
    (tmp_path / "config.json").write_text("{}")
    # Built to sum to exactly 1.0: a distribution is the only shape _score_payload
    # accepts, so a fixture that is off by 5% would test the rejection path instead.
    others = [t for t in criteria.TACTICS if t not in ("Impact", "Collection")]
    scores = {tactic: 0.01 for tactic in others}
    scores["Collection"] = 0.06
    scores["Impact"] = 1.0 - 0.06 - 0.01 * len(others)
    assert abs(sum(scores.values()) - 1.0) < 1e-12
    _install_fake_laya(monkeypatch,
                       {"answers": {"tactic": {"choice": "Impact", "scores": scores}}})
    labeler = LayaLabeler(0.6, str(tmp_path), _tree_sha256(str(tmp_path)))
    verdict = _run(labeler.classify("ransomware note"))
    assert verdict.status == "ok"
    assert verdict.label == "Impact"
    assert verdict.scored is True
    assert verdict.confidence == pytest.approx(scores["Impact"], abs=1e-6)


def test_laya_logits_are_not_treated_as_probabilities(tmp_path, monkeypatch):
    (tmp_path / "config.json").write_text("{}")
    _install_fake_laya(monkeypatch, {"answers": {"tactic": {
        "choice": "Impact", "scores": {"Impact": 9.5, "Collection": -2.0}}}})
    labeler = LayaLabeler(0.6, str(tmp_path), _tree_sha256(str(tmp_path)))
    verdict = _run(labeler.classify("ransomware note"))
    assert verdict.scored is False
    assert verdict.confidence is None


def test_laya_unrecognized_shape_is_unavailable(tmp_path, monkeypatch):
    (tmp_path / "config.json").write_text("{}")
    _install_fake_laya(monkeypatch, {"unexpected": True})
    labeler = LayaLabeler(0.6, str(tmp_path), _tree_sha256(str(tmp_path)))
    verdict = _run(labeler.classify("ransomware note"))
    assert verdict.status == "unavailable"
    assert "unrecognized laya response shape" in verdict.reason


def test_laya_import_failure_is_reported_not_raised(tmp_path, monkeypatch):
    (tmp_path / "config.json").write_text("{}")
    monkeypatch.setitem(sys.modules, "laya", None)
    labeler = LayaLabeler(0.6, str(tmp_path), _tree_sha256(str(tmp_path)))
    verdict = _run(labeler.classify("ransomware note"))
    assert verdict.status == "unavailable"
    assert "model load failed" in verdict.reason


def test_tree_sha_matches_the_setup_sh_rule(tmp_path):
    """The pin setup.sh writes and the pin the server verifies must be one algorithm.
    This runs the real shell pipeline rather than a re-implementation."""
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "w.bin").write_bytes(b"weights")
    (tmp_path / "config.json").write_text("{}")
    (tmp_path / "ignored.link").symlink_to(tmp_path / "config.json")
    script = ("cd \"$1\" && find . -type f -printf '%P\\0' | LC_ALL=C sort -z | "
              "xargs -0 sha256sum | sha256sum | awk '{print $1}'")
    result = subprocess.run(["bash", "-c", script, "_", str(tmp_path)],
                            capture_output=True, text=True, check=True)
    assert result.stdout.strip() == _tree_sha256(str(tmp_path))


def test_tree_sha_ignores_symlinks(tmp_path):
    (tmp_path / "config.json").write_text("{}")
    before = _tree_sha256(str(tmp_path))
    (tmp_path / "link.json").symlink_to(tmp_path / "config.json")
    assert _tree_sha256(str(tmp_path)) == before


def test_score_payload_rejects_non_distributions():
    assert _score_payload({"a": 0.7, "b": 0.3}) == {"a": 0.7, "b": 0.3}
    assert _score_payload({"a": 9.5, "b": -2.0}) is None      # logits
    assert _score_payload({"a": 0.7, "b": 0.7}) is None       # does not sum to 1
    assert _score_payload({"a": "high"}) is None
    assert _score_payload({}) is None
    assert _score_payload(None) is None


def _install_fake_laya(monkeypatch, result: dict):
    class _Agent:
        calls: list = []

        def predict(self, payload, questions):
            _Agent.calls.append((payload, questions))
            return result

    _Agent.calls = []
    module = types.SimpleNamespace(load=lambda path: _Agent())
    monkeypatch.setitem(sys.modules, "laya", module)
    return _Agent
