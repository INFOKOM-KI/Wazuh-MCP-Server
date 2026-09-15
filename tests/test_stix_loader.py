#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Tests for the ATT&CK STIX bundle loader: source-scheme validation, atomic cache
write, TTL refresh, single-flight loading, and retry instead of a permanent
error latch.
"""
from __future__ import annotations
import json
import os
import threading
import time

# mcp_server/__init__.py calls init_config() at import and hard-fails without
# WAZUH_INDEXER_* (ConfigurationError). This module imports mcp_server at module
# level, so without these the file errors during collection when run alone.
os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import pytest
import mcp_server.tools.stix_correlation as sc

BUNDLE = {
    "objects": [
        {
            "id": "attack-pattern--a", "type": "attack-pattern", "name": "Test TTP",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "stealth"}],
        },
        {
            "id": "intrusion-set--g", "type": "intrusion-set", "name": "Test Group",
            "external_references": [{"source_name": "mitre-attack", "external_id": "G9998"}],
        },
        {"id": "relationship--r", "type": "relationship", "relationship_type": "uses",
         "source_ref": "intrusion-set--g", "target_ref": "attack-pattern--a"},
    ]
}


class _FakeResp:
    """Minimal urlopen() response: a context manager with a size-limited read."""
    def __init__(self, payload: bytes, delay: float = 0.0):
        self._payload, self._delay = payload, delay

    def read(self, n: int = -1) -> bytes:
        if self._delay:
            time.sleep(self._delay)
        return self._payload if n < 0 else self._payload[:n]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _urlopen(payload: bytes, calls: list, delay: float = 0.0):
    def _open(req, timeout=None):
        calls.append(req.full_url if hasattr(req, "full_url") else req)
        return _FakeResp(payload, delay)
    return _open


def _urlopen_boom(req, timeout=None):
    raise AssertionError("urlopen() must not be called the disk cache is fresh")


@pytest.fixture
def stix_env(tmp_path, monkeypatch):
    """Isolate the loader on a temp bundle + temp cache and reset module state."""
    src = tmp_path / "enterprise-attack.json"
    src.write_text(json.dumps(BUNDLE))
    cache = tmp_path / "cache" / "mitre_enterprise_attack.json"
    monkeypatch.setattr(sc, "_STIX_PATH", str(src))
    monkeypatch.setattr(sc, "_STIX_CACHE", str(cache))
    monkeypatch.setattr(sc, "_stix_data", None)
    monkeypatch.setattr(sc, "_stix_error", None)
    monkeypatch.setattr(sc, "_stix_retry_at", 0.0)
    return src, cache


def test_source_scheme_validation():
    assert sc._validate_stix_source("https://example.com/a.json") is None
    assert sc._validate_stix_source("/var/lib/mitre/enterprise-attack.json") is None
    assert sc._validate_stix_source("enterprise-attack.json") is None
    for bad in ("http://example.com/a.json", "ftp://host/a.json", "file:///etc/passwd"):
        assert sc._validate_stix_source(bad) is not None, bad


def test_local_path_load_and_index(stix_env):
    sc._load_stix()
    assert sc._stix_error is None
    assert sc._stix_data["by_id"]["attack-pattern--a"]["name"] == "Test TTP"
    assert sc._stix_data["rel_index"]["attack-pattern--a"][0]["relationship_type"] == "uses"


def test_atomic_cache_write_leaves_no_tmp_file(stix_env):
    _, cache = stix_env
    sc._write_cache(BUNDLE)
    assert json.loads(cache.read_text())["objects"] == BUNDLE["objects"]
    assert list(cache.parent.glob("*.tmp")) == []


def test_fresh_cache_is_reused_without_fetch(stix_env, monkeypatch):
    _, cache = stix_env
    monkeypatch.setattr(sc, "_STIX_PATH", "https://example.invalid/enterprise-attack.json")
    sc._write_cache(BUNDLE)
    monkeypatch.setattr(sc.urllib.request, "urlopen", _urlopen_boom)
    sc._load_stix()
    assert sc._stix_error is None
    assert sc._stix_data["by_id"]["attack-pattern--a"]["name"] == "Test TTP"


def test_stale_cache_triggers_refresh(stix_env, monkeypatch):
    _, cache = stix_env
    monkeypatch.setattr(sc, "_STIX_PATH", "https://example.invalid/enterprise-attack.json")
    sc._write_cache(BUNDLE)
    age = time.time() - (sc._STIX_MAX_AGE_SECONDS + 86400)
    os.utime(cache, (age, age))
    calls: list = []
    monkeypatch.setattr(sc.urllib.request, "urlopen", _urlopen(json.dumps(BUNDLE).encode(), calls))
    sc._load_stix()
    assert len(calls) == 1, "a stale cache must be refetched"
    assert sc._stix_error is None


def test_concurrent_loads_fetch_once(stix_env, monkeypatch):
    monkeypatch.setattr(sc, "_STIX_PATH", "https://example.invalid/enterprise-attack.json")
    calls: list = []
    monkeypatch.setattr(sc.urllib.request, "urlopen",
                        _urlopen(json.dumps(BUNDLE).encode(), calls, delay=0.05))
    threads = [threading.Thread(target=sc._load_stix) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(calls) == 1, "the load lock must collapse concurrent cold starts"
    assert sc._stix_data is not None


def test_oversized_bundle_is_rejected(stix_env, monkeypatch):
    monkeypatch.setattr(sc, "_STIX_PATH", "https://example.invalid/enterprise-attack.json")
    monkeypatch.setattr(sc, "_STIX_MAX_BYTES", 64)
    monkeypatch.setattr(sc.urllib.request, "urlopen", _urlopen(b"x" * 65, []))
    with pytest.raises(ValueError, match="exceeds"):
        sc._fetch_stix_bundle()


def test_stale_cache_is_fallback_when_fetch_fails(stix_env, monkeypatch):
    _, cache = stix_env
    sc._write_cache(BUNDLE)
    age = time.time() - (sc._STIX_MAX_AGE_SECONDS + 86400)
    os.utime(cache, (age, age))
    monkeypatch.setattr(sc, "_STIX_PATH", "https://example.invalid/enterprise-attack.json")
    monkeypatch.setattr(sc.urllib.request, "urlopen", _urlopen_boom)
    sc._load_stix()
    assert sc._stix_error is None, "a stale bundle must keep STIX tooling online"
    assert sc._stix_data["by_id"]["attack-pattern--a"]["name"] == "Test TTP"


def test_failed_load_retries_instead_of_latching(stix_env, monkeypatch):
    src, _ = stix_env
    monkeypatch.setattr(sc, "_STIX_PATH", "http://example.invalid/a.json")
    sc._load_stix()
    assert sc._stix_error is not None

    monkeypatch.setattr(sc, "_STIX_PATH", str(src))
    sc._load_stix()
    assert sc._stix_error is not None, "retry must be throttled, not hammered per call"

    monkeypatch.setattr(sc, "_stix_retry_at", 0.0)
    sc._load_stix()
    assert sc._stix_error is None, "a fixed config must recover without a restart"
    assert sc._stix_data is not None
