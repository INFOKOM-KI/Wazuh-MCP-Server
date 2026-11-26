#!/usr/bin/env python3
"""Cross-process registry writes: the flock transaction must not lose entries."""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

import pytest

from mcp_server.core import attacker_registry as registry

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Each process registers 25 distinct IOCs with a small pause, so the two
# transactions interleave instead of running one after the other.
WRITER = """
import sys, time
from mcp_server.core.attacker_registry import register_attacker_ioc
prefix = sys.argv[1]
for index in range(25):
    register_attacker_ioc(f"{prefix}{index}", source="manual",
                          evidence={"decision": "accepted"})
    time.sleep(0.002)
"""


def _env(path: pathlib.Path) -> dict[str, str]:
    return {**os.environ,
            "BLUETEAM_ATTACKER_REGISTRY": str(path),
            "BLUETEAM_ATTACKER_REGISTRY_TTL": "604800",
            "WAZUH_INDEXER_URL": "https://indexer:9200",
            "WAZUH_INDEXER_PASSWORD": "test-indexer-pass",
            "BLUETEAM_RERANK_ENABLED": "false",
            "PYTHONPATH": str(ROOT)}


def _run(prefix: str, path: pathlib.Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-c", WRITER, prefix],
                          env=_env(path), cwd=ROOT, capture_output=True,
                          text=True, timeout=120)


def test_two_processes_keep_each_others_entries(tmp_path):
    path = tmp_path / "registry" / "attacker_registry.jsonl"
    first = _run("10.0.0.", path)
    second = _run("10.0.1.", path)
    # Run them again together, this time overlapping.
    procs = [subprocess.Popen([sys.executable, "-c", WRITER, prefix],
                              env=_env(path), cwd=ROOT)
             for prefix in ("10.0.2.", "10.0.3.")]
    for proc in procs:
        proc.wait(timeout=120)
        assert proc.returncode == 0

    assert first.returncode == 0 and second.returncode == 0
    lines = path.read_text(encoding="utf-8").splitlines()
    entries = [json.loads(line) for line in lines]
    registered = {entry["ioc"] for entry in entries}
    for block in ("0", "1", "2", "3"):
        assert {f"10.0.{block}.{i}" for i in range(25)} <= registered
    assert len(entries) == 100
    assert all(entry["evidence"]["decision"] == "accepted" for entry in entries)
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert oct(path.parent.stat().st_mode & 0o777) == "0o700"
    assert oct((path.parent / (path.name + ".lock")).stat().st_mode & 0o777) == "0o600"


def test_interrupted_and_corrupt_writes_keep_existing_evidence(tmp_path):
    path = tmp_path / "registry" / "attacker_registry.jsonl"
    assert _run("10.0.0.", path).returncode == 0
    before = {json.loads(line)["ioc"] for line in
              path.read_text(encoding="utf-8").splitlines()}

    # A crashed writer left a temp file and a half line behind.
    (path.parent / (path.name + ".tmp")).write_text("{not json", encoding="utf-8")
    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"ioc": "10.0.9.1", "ts":')

    assert _run("10.0.1.", path).returncode == 0

    lines = path.read_text(encoding="utf-8").splitlines()
    entries = [json.loads(line) for line in lines]
    registered = {entry["ioc"] for entry in entries}
    assert before <= registered
    assert len(entries) == 50
    assert not (path.parent / (path.name + ".tmp")).exists()


def test_stats_report_file_and_parent_modes(tmp_path, monkeypatch):
    path = tmp_path / "registry" / "attacker_registry.jsonl"
    monkeypatch.setattr(registry, "_REGISTRY_PATH", str(path))
    registry.clear_attacker_registry()
    registry.register_attacker_ioc("8.8.8.8", source="manual",
                                   evidence={"decision": "accepted"})

    stats = registry.registry_stats()
    assert stats["file_mode"] == "0o600"
    assert stats["parent_mode"] == "0o700"
    assert stats["lock_mode"] == "0o600"
