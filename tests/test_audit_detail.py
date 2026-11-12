#!/usr/bin/env python3
"""Bounded structured audit detail, plus the AbuseIPDB report's two events.

``_audit_log`` used to carry only a 200-char preview, so a batch of per-IP report
outcomes could not survive in the JSONL trail. It now takes an optional bounded
``detail`` payload; these tests pin the bounds, the redaction, and the shape of
the prepared/completed pair. Nothing leaves the process.
"""
from __future__ import annotations

import asyncio
import json
import os

import pytest

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

from mcp_server.core import audit


def _capture(monkeypatch):
    """Drain the audit queue instead of writing it to a file."""
    entries: list[dict] = []
    monkeypatch.setattr(audit, "BLUETEAM_AUDIT_LOG", "audit.jsonl")
    monkeypatch.setattr(audit, "_ensure_audit_worker", lambda: None)
    monkeypatch.setattr(audit, "_AUDIT_QUEUE", _ListQueue(entries))
    return entries


class _ListQueue:
    def __init__(self, sink):
        self._sink = sink

    def put(self, item):
        self._sink.append(item)


# Bounds, redaction, compatibility

def test_existing_call_shape_is_unchanged(monkeypatch):
    """A caller that passes only the original three arguments sees five keys."""
    entries = _capture(monkeypatch)
    audit._audit_log("blueteam_example", {"alpha": 1}, "preview")

    assert len(entries) == 1
    entry = entries[0]
    assert set(entry) == {"ts", "tool", "params", "result_preview",
                          "redaction_bypassed"}
    assert entry["tool"] == "blueteam_example"
    assert entry["result_preview"] == "preview"


def test_detail_is_bounded_and_flagged(monkeypatch):
    entries = _capture(monkeypatch)
    payload = {"rows": [{"ip": f"198.51.100.{i}", "status": "reported"}
                        for i in range(60)]}
    audit._audit_log("blueteam_example", {}, detail=payload)

    entry = entries[0]
    assert entry["detail_truncated"] is True
    assert len(entry["detail"]["rows"]) == audit._AUDIT_DETAIL_MAX_ITEMS


def test_long_strings_are_capped_and_marked(monkeypatch):
    entries = _capture(monkeypatch)
    audit._audit_log("blueteam_example", {}, detail={"note": "x" * 400})

    entry = entries[0]
    note = entry["detail"]["note"]
    assert len(note) == audit._AUDIT_DETAIL_MAX_STR
    assert note.endswith("...")
    assert entry["detail_truncated"] is True


def test_detail_strings_are_redacted(monkeypatch):
    entries = _capture(monkeypatch)
    audit._audit_log("blueteam_example", {},
                     detail={"who": "analyst@example.com",
                             "ip": "203.0.113.9"})

    serialised = json.dumps(entries[0])
    assert "analyst@example.com" not in serialised
    assert entries[0]["detail"]["ip"] == "203.0.113.9"


def test_deep_nesting_is_cut_not_raised(monkeypatch):
    entries = _capture(monkeypatch)
    node: dict = {"leaf": 1}
    for _ in range(10):
        node = {"child": node}
    audit._audit_log("blueteam_example", {}, detail=node)

    assert entries[0]["detail_truncated"] is True


def test_phase_and_op_id_are_recorded(monkeypatch):
    entries = _capture(monkeypatch)
    audit._audit_log("blueteam_example", {}, phase="prepared", op_id="op-1",
                     detail={"a": 1})
    audit._audit_log("blueteam_example", {}, phase="completed", op_id="op-1",
                     detail={"b": 2}, record_metric=False)

    assert [e["phase"] for e in entries] == ["prepared", "completed"]
    assert {e["op_id"] for e in entries} == {"op-1"}


# The report tool's prepared/completed pair

@pytest.fixture
def report_env(monkeypatch, tmp_path):
    from mcp_server.threat_intel import abuseipdb
    from mcp_server.tools import abuseipdb as tool

    monkeypatch.setattr(abuseipdb, "ABUSEIPDB_API_KEY", "test-key")
    monkeypatch.setattr(tool, "ABUSEIPDB_REPORTING_ENABLED", False)
    abuseipdb.reset_quota_state()
    entries = _capture(monkeypatch)

    async def no_candidates(params):
        return [], {"source": "alerts", "remaining_candidates": 0,
                    "truncated": False, "role_check": "checked",
                    "provenance": "empty",
                    "window": {"since": "a", "until": "b"}}

    monkeypatch.setattr(tool, "_harvest_candidates", no_candidates)
    return tool, entries


def _events(entries, phase):
    return [e for e in entries if e.get("phase") == phase]


def test_report_emits_prepared_and_completed(report_env):
    tool, entries = report_env
    asyncio.run(tool.blueteam_abuseipdb_report(
        tool.AbuseIPDBReportInput(from_alerts=True, since="24h")))

    prepared, completed = _events(entries, "prepared"), _events(entries, "completed")
    assert len(prepared) == 1 and len(completed) == 1
    assert prepared[0]["op_id"] == completed[0]["op_id"]
    assert completed[0]["detail"]["counts"] == {}
    assert completed[0]["detail"]["source"] == "alerts"


def test_completed_event_fires_when_evaluation_raises(report_env, monkeypatch):
    tool, entries = report_env
    from mcp_server.core.exceptions import ThreatIntelError

    async def boom(candidates, params):
        raise ThreatIntelError("evaluation exploded")

    monkeypatch.setattr(tool, "_evaluate", boom)

    with pytest.raises(ThreatIntelError):
        asyncio.run(tool.blueteam_abuseipdb_report(
            tool.AbuseIPDBReportInput(from_alerts=True)))

    completed = _events(entries, "completed")
    assert len(completed) == 1
    assert completed[0]["detail"]["results"] == []


def test_dry_run_is_distinguished_from_submission(report_env, monkeypatch):
    tool, entries = report_env
    from mcp_server.threat_intel import abuseipdb

    async def one_candidate(params):
        return [{"ip": "198.51.100.7", "alert_count": 9, "first_seen": "",
                 "last_seen": "", "max_level": 12,
                 "rule_ids": ["5710"], "rule_groups": ["sshd"],
                 "source": "alerts", "role": "srcip", "role_check": "checked"}], {
            "source": "alerts", "remaining_candidates": 0, "truncated": False,
            "role_check": "checked", "provenance": "sampled", "window": {}}

    async def fake_check(ip, max_age_days=30, *, verbose=False):
        return {"abuse_confidence_score": 10, "total_reports": 0,
                "last_reported_at": None, "is_whitelisted": False,
                "is_public": True, "cached": True}

    monkeypatch.setattr(tool, "_harvest_candidates", one_candidate)
    monkeypatch.setattr(tool, "check_ip", fake_check, raising=False)
    monkeypatch.setattr(abuseipdb, "check_ip", fake_check)

    asyncio.run(tool.blueteam_abuseipdb_report(
        tool.AbuseIPDBReportInput(from_alerts=True, dry_run=True)))

    detail = _events(entries, "completed")[0]["detail"]
    assert detail["counts"] == {"dry_run": 1}
    assert detail["results"][0]["outcome"] == "dry_run"
    assert "comment" not in detail["results"][0]


def test_outcome_classification_covers_every_state(report_env):
    tool, entries = report_env
    rows = [
        {"ip": "1.1.1.1", "status": "reported", "verified": True,
         "abuse_confidence_score": 90},
        {"ip": "1.1.1.2", "status": "failed", "error_kind": "auth_error",
         "http_status": 401},
        {"ip": "1.1.1.3", "status": "failed", "error_kind": "timeout",
         "http_status": None},
        {"ip": "1.1.1.4", "status": "failed", "error_kind": "quota_exhausted",
         "http_status": None},
        {"ip": "1.1.1.5", "status": "manual_review"},
        {"ip": "1.1.1.6", "status": "skipped_quota"},
        {"ip": "1.1.1.7", "status": "would_report"},
    ]
    detail = tool._completion_detail(rows, {"source": "alerts"},
                                     tool.AbuseIPDBReportInput(
                                         from_alerts=True, dry_run=False,
                                         confirm=True))
    assert [r["outcome"] for r in detail["results"]] == [
        "accepted", "rejected", "unknown", "unsent",
        "manual_review", "skipped", "dry_run"]
    assert detail["counts"] == {"accepted": 1, "rejected": 1, "unknown": 1,
                                "unsent": 1, "manual_review": 1, "skipped": 1,
                                "dry_run": 1}
    # Accepted is not a verdict: the score is reported beside it, not folded in.
    assert detail["results"][0]["verified"] is True
    assert detail["results"][0]["abuse_confidence_score"] == 90


def test_sets_are_serialised_in_a_stable_order(monkeypatch):
    """A forensic trail must not reorder itself between runs."""
    entries = _capture(monkeypatch)
    audit._audit_log("blueteam_example", {},
                     detail={"tags": {"gamma", "alpha", "beta"}})
    assert entries[0]["detail"]["tags"] == ["alpha", "beta", "gamma"]


def test_dropped_keys_are_absent_not_null(monkeypatch):
    """A real null survives; a dropped value must not masquerade as one."""
    entries = _capture(monkeypatch)
    deep = {"keep": None, "drop": {"a": {"b": {"c": {"d": {"e": 1}}}}}}
    audit._audit_log("blueteam_example", {}, detail=deep)

    detail = entries[0]["detail"]
    assert detail["keep"] is None                  # a genuine null is preserved
    assert detail["drop"]["a"]["b"] == {}          # the cut leaf is absent, not null
    assert "c" not in detail["drop"]["a"]["b"]
    assert entries[0]["detail_truncated"] is True


def test_completion_audit_failure_does_not_mask_the_real_error(report_env,
                                                               monkeypatch):
    from mcp_server.core.exceptions import ThreatIntelError

    tool, entries = report_env

    async def boom(params):
        raise ThreatIntelError("harvest exploded")

    def explode(*args, **kwargs):
        raise RuntimeError("detail builder failed")

    monkeypatch.setattr(tool, "_harvest_candidates", boom)
    monkeypatch.setattr(tool, "_completion_detail", explode)

    with pytest.raises(ThreatIntelError, match="harvest exploded"):
        asyncio.run(tool.blueteam_abuseipdb_report(
            tool.AbuseIPDBReportInput(from_alerts=True)))
