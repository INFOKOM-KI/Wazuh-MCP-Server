#!/usr/bin/env python3
"""Registry persistence, permissions, TTL, and corrupted-entry handling."""
from __future__ import annotations

import json
import os
import threading

import pytest

from mcp_server.core import attacker_registry as registry

EVIDENCE = {"decision": "accepted", "via": "wazuh_alerts", "alert_id": "a",
            "rule_id": "100200", "rule_level": 12, "matched_field": "data.srcip"}


@pytest.fixture
def registry_file(monkeypatch, tmp_path):
    path = tmp_path / "nested" / "attacker_registry.jsonl"
    monkeypatch.setattr(registry, "_REGISTRY_PATH", str(path))
    monkeypatch.setattr(registry, "_REGISTRY_TTL", 604800)
    registry.clear_attacker_registry()
    yield path
    registry.clear_attacker_registry()


def test_file_and_parent_permissions(registry_file):
    registry.register_attacker_ioc("8.8.8.8", source="wazuh_alerts",
                                   evidence=EVIDENCE)

    assert oct(registry_file.stat().st_mode & 0o777) == "0o600"
    assert oct(registry_file.parent.stat().st_mode & 0o777) == "0o700"


def test_evidence_round_trips_through_the_file(registry_file):
    registry.register_attacker_ioc("8.8.8.8", source="wazuh_alerts",
                                   evidence=EVIDENCE)
    registry.reload_registry()

    assert registry.attacker_ioc_provenance("8.8.8.8") == "wazuh_alerts"
    assert registry.attacker_ioc_evidence("8.8.8.8")["rule_level"] == 12


def test_corrupted_lines_are_skipped(registry_file):
    registry_file.parent.mkdir(parents=True, exist_ok=True)
    registry_file.write_text(
        "not json\n"
        + json.dumps({"ioc": "8.8.8.8", "ts": registry.time.time(),
                      "source": "wazuh_alerts", "evidence": EVIDENCE}) + "\n"
        + "[1, 2, 3]\n"
        + json.dumps({"ioc": "", "ts": 1}) + "\n",
        encoding="utf-8")
    registry.reload_registry()

    assert registry.attacker_ioc_provenance("8.8.8.8") == "wazuh_alerts"
    assert registry.registry_stats()["entries"] == 1


def test_expired_evidence_is_not_provenance(registry_file, monkeypatch):
    monkeypatch.setattr(registry, "_REGISTRY_TTL", 60)
    registry.register_attacker_ioc("8.8.8.8", source="wazuh_alerts",
                                   evidence=EVIDENCE)
    with registry._LOCK:
        registry._ENTRIES["8.8.8.8"]["ts"] -= 3600

    assert registry.attacker_ioc_provenance("8.8.8.8") is None


def test_concurrent_writes_leave_a_parseable_file(registry_file):
    def write(index: int) -> None:
        registry.register_attacker_ioc(f"198.51.100.{index}", source="manual",
                                       evidence={"decision": "accepted"})

    threads = [threading.Thread(target=write, args=(i,)) for i in range(1, 21)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    lines = registry_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 20
    for line in lines:
        json.loads(line)
    assert registry.registry_stats()["entries"] == 20


def test_non_mapping_evidence_is_not_provenance(registry_file):
    registry.register_attacker_ioc("8.8.8.8", source="wazuh_alerts",
                                   evidence=EVIDENCE)
    with registry._LOCK:
        registry._ENTRIES["8.8.8.8"]["evidence"] = "trust me"

    assert registry.attacker_ioc_provenance("8.8.8.8") is None
    assert registry.is_attacker_ioc("8.8.8.8") is True


def test_loaded_entries_keep_their_evidence(registry_file):
    registry_file.parent.mkdir(parents=True, exist_ok=True)
    registry_file.write_text(json.dumps({
        "ioc": "8.8.8.8", "ts": registry.time.time(), "source": "wazuh_alerts",
        "evidence": EVIDENCE}) + "\n", encoding="utf-8")
    registry.reload_registry()

    assert registry.attacker_ioc_evidence("8.8.8.8")["alert_id"] == "a"
    assert (registry_file.stat().st_mode & 0o600) == 0o600
