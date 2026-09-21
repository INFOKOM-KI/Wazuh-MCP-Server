#!/usr/bin/env python3
"""Tests for core/rerank.py; optional BM25 -> cross-encoder reranker.
Coverage: the fallback contract (disabled / empty / unavailable / success) and
the reason() status string. The model itself is never loaded fastembed is
absent in CI, so the unavailable path is exercised against that absence.
"""

from __future__ import annotations
import os

# mcp_server/__init__.py calls init_config() at import and hard-fails without
# WAZUH_INDEXER_* (ConfigurationError). Seed them at module level so this file
# passes in isolation, not only when a peer module happens to import first.
# (This module's own later `import os` is left in place; same module object.)
os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")


def _reset():
    from mcp_server.core import rerank
    from mcp_server.core.config import config
    config.rerank.enabled = False
    config.rerank.sha256 = ""
    config.rerank.cache_path = ""
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


# sha256 supply chain pin (BLUETEAM_RERANK_MODEL_SHA256)
import hashlib
import os
import sys
import tempfile
from types import SimpleNamespace


def _install_fake_fastembed(monkeypatch, model_dir):
    """Stub fastembed.rerank.cross_encoder so pin tests run without the dep."""
    captured = {}

    class FakeTextCrossEncoder:
        @classmethod
        def list_supported_models(cls):
            return [{"model": "BAAI/bge-reranker-base", "model_file": "onnx/model.onnx"}]

        def __init__(self, model_name, cache_dir=None, lazy_load=False,
                     local_files_only=False, **kwargs):
            # mirror fastembed: _model_dir sits on the inner encoder - bug has been found during test process;P
            self.model = SimpleNamespace(_model_dir=model_dir)
            captured.update(model_name=model_name, cache_dir=cache_dir,
                            lazy_load=lazy_load, local_files_only=local_files_only)

        def rerank(self, query, docs):
            return [0.5] * len(docs)

    monkeypatch.setitem(sys.modules, "fastembed", SimpleNamespace())
    monkeypatch.setitem(sys.modules, "fastembed.rerank", SimpleNamespace())
    monkeypatch.setitem(sys.modules, "fastembed.rerank.cross_encoder",
                        SimpleNamespace(TextCrossEncoder=FakeTextCrossEncoder))
    return captured


def _write_onnx(model_dir, data=b"fake onnx bytes"):
    onnx_dir = os.path.join(model_dir, "onnx")
    os.makedirs(onnx_dir, exist_ok=True)
    path = os.path.join(onnx_dir, "model.onnx")
    with open(path, "wb") as fh:
        fh.write(data)
    return path, hashlib.sha256(data).hexdigest()


def test_rerank_pin_mismatch_refuses_load(monkeypatch):
    import asyncio
    from mcp_server.core import rerank
    from mcp_server.core.config import config
    _reset()
    model_dir = tempfile.mkdtemp()
    _write_onnx(model_dir, b"tampered bytes")
    _install_fake_fastembed(monkeypatch, model_dir)
    config.rerank.enabled = True
    config.rerank.sha256 = "0" * 64  # wrong pin
    scores, status = asyncio.run(rerank.rerank("query", ["doc"]))
    assert scores == []
    assert status is not None and status.startswith("unavailable:")
    assert "sha256 pin mismatch" in rerank.reason()
    assert rerank._encoder is None
    _reset()


def test_rerank_pin_match_loads_verified_file(monkeypatch):
    import asyncio
    from mcp_server.core import rerank
    from mcp_server.core.config import config
    _reset()
    model_dir = tempfile.mkdtemp()
    path, digest = _write_onnx(model_dir, b"genuine model bytes")
    captured = _install_fake_fastembed(monkeypatch, model_dir)
    config.rerank.enabled = True
    config.rerank.cache_path = model_dir
    config.rerank.sha256 = digest
    scores, status = asyncio.run(rerank.rerank("query", ["doc a", "doc b"]))
    assert status is None
    assert scores == [0.5, 0.5]
    assert captured["lazy_load"] is True
    assert captured["local_files_only"] is True
    assert captured["cache_dir"] == model_dir
    _reset()


def test_rerank_pin_missing_file_fails_closed(monkeypatch):
    from mcp_server.core import rerank
    from mcp_server.core.config import config
    _reset()
    model_dir = tempfile.mkdtemp()  # no onnx written
    _install_fake_fastembed(monkeypatch, model_dir)
    config.rerank.sha256 = "1" * 64
    assert rerank._ensure_loaded() is False
    assert "model file not found" in rerank.reason()
    assert rerank._encoder is None
    _reset()


def test_rerank_pin_rejects_bad_digest_at_startup():
    from mcp_server.core.config import RerankConfig
    from mcp_server.core.exceptions import ConfigurationError
    try:
        RerankConfig(sha256="not-hex").validate()
    except ConfigurationError:
        pass
    else:
        raise AssertionError("expected ConfigurationError for malformed sha256")


# Fail-closed startup validation (config.RerankConfig.validate). A model that
# fastembed cannot load used to surface only as a per-call "unavailable:" status,
# which reads to an analyst as "the cross-encoder ranked this" when BM25 did.
def test_validate_fails_closed_on_unsupported_model():
    from mcp_server.core.config import (RerankConfig, ConfigurationError,
                                        _fastembed_rerank_models)

    class FakeTextCrossEncoder:
        @classmethod
        def list_supported_models(cls):
            return [{"model": "BAAI/bge-reranker-base", "model_file": "onnx/model.onnx"}]

    saved = sys.modules.get("fastembed.rerank.cross_encoder")
    sys.modules["fastembed.rerank.cross_encoder"] = SimpleNamespace(
        TextCrossEncoder=FakeTextCrossEncoder)
    try:
        assert _fastembed_rerank_models() == {"BAAI/bge-reranker-base"}
        try:
            RerankConfig(enabled=True, model="BAAI/bge-reranker-v2-m3").validate()
        except ConfigurationError as exc:
            assert "bge-reranker-v2-m3" in str(exc)
        else:
            raise AssertionError("expected ConfigurationError for an unloadable model")
        # The in registry model must still validate.
        RerankConfig(enabled=True, model="BAAI/bge-reranker-base").validate()
    finally:
        if saved is None:
            sys.modules.pop("fastembed.rerank.cross_encoder", None)
        else:
            sys.modules["fastembed.rerank.cross_encoder"] = saved


def test_validate_fails_closed_when_fastembed_missing():
    from mcp_server.core.config import (RerankConfig, ConfigurationError,
                                        _fastembed_rerank_models)

    saved = sys.modules.get("fastembed")
    sys.modules["fastembed"] = None  # any import of it raises ImportError
    try:
        assert _fastembed_rerank_models() is None
        try:
            RerankConfig(enabled=True, model="BAAI/bge-reranker-base").validate()
        except ConfigurationError as exc:
            assert "fastembed is not installed" in str(exc)
        else:
            raise AssertionError("expected ConfigurationError when fastembed is absent")
        # An explicitly disabled reranker needs no dependency at all.
        RerankConfig(enabled=False, model="who/knows").validate()
    finally:
        if saved is None:
            sys.modules.pop("fastembed", None)
        else:
            sys.modules["fastembed"] = saved


def test_status_dict_names_the_engine_that_actually_ranked():
    from mcp_server.core.rerank import status_dict

    ranked = status_dict(None)
    assert ranked["rerank_used"] is True
    assert ranked["rerank_engine"].startswith("cross-encoder:")
    assert ranked["rerank_status"] == "ok"

    fallback = status_dict("unavailable: model load failed")
    assert fallback["rerank_used"] is False
    assert fallback["rerank_engine"] == "bm25"

    vector = status_dict("disabled", fallback_engine="vector")
    assert vector["rerank_engine"] == "vector"
    assert vector["rerank_status"] == "disabled"

    assert status_dict("not_requested")["rerank_status"] == "not_requested"


if __name__ == "__main__":
    import sys
    import os
    import traceback
    import inspect
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    tests = [f for f in dir() if f.startswith("test_")
             and not inspect.signature(globals()[f]).parameters]
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
