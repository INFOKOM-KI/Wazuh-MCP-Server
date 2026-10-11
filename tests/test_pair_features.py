#!/usr/bin/env python3
"""Tests for mcp_server/correlation/pair_features.py. Pure functions only:
no store, no engine call, no alert payload."""
from __future__ import annotations

import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://idx:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "pw")
os.environ.setdefault("BLUETEAM_REDACTION_POLICY", "full")

import pytest

from mcp_server.correlation import pair_features as pf


def _alert(alert_id: str, **fields) -> dict:
    alert = {"alert_id": alert_id, "srcip": "203.0.113.10", "agent": "agent-1",
             "timestamp": "2026-03-01T00:00:00+00:00", "tactics": ["Credential Access"],
             "domains": [], "urls": [], "analyst_iocs": [], "engine_iocs": []}
    alert.update(fields)
    return alert


def _record(alert_a: dict, alert_b: dict) -> dict:
    return pf.build_pair_record(alert_a, alert_b, group_id="grp-1", split="test",
                                label="same_incident", label_source="adjudicated",
                                recorded_by="reviewer-a")


def test_pair_id_is_order_insensitive_and_stable():
    left, right = _alert("alert-a"), _alert("alert-b")
    assert pf.pair_id(left, right) == pf.pair_id(right, left)
    assert pf.pair_id(left, right) == pf.pair_id(dict(left), dict(right))


def test_pair_id_refuses_self_pair():
    alert = _alert("alert-a")
    with pytest.raises(ValueError):
        pf.pair_id(alert, dict(alert))


def test_extract_marks_unmeasured_values_as_none():
    features = pf.extract_pair_features({"alert_id": "a1"}, {"alert_id": "b1"})
    assert features["same_subject"] is None
    assert features["time_delta_seconds"] is None
    assert features["same_agent"] is None
    assert features["tactic_overlap_ratio"] is None
    assert features["shared_tactics"] == []
    assert features["shared_analyst_iocs"] == []


def test_subject_and_temporal_features():
    left = _alert("a1", srcip="203.0.113.10", timestamp="2026-03-01T00:00:00+00:00")
    right = _alert("b1", srcip="203.0.113.10", timestamp="2026-03-01T01:00:00Z")
    features = pf.extract_pair_features(left, right)
    assert features["same_subject"] is True
    assert features["time_delta_seconds"] == 3600.0
    far = _alert("c1", srcip="198.51.100.3", timestamp="not-a-timestamp")
    other = pf.extract_pair_features(left, far)
    assert other["same_subject"] is False
    assert other["time_delta_seconds"] is None


def test_tactic_overlap_ratio_uses_the_union():
    left = _alert("a1", tactics=["Credential Access", "Discovery"])
    right = _alert("b1", tactics=["Credential Access", "Execution"])
    features = pf.extract_pair_features(left, right)
    assert features["shared_tactics"] == ["credential access"]
    assert features["tactic_overlap_ratio"] == 0.3333


def test_shared_entity_families_are_intersections():
    left = _alert("a1", domains=["Evil.Example"], urls=["http://evil.example/a"])
    right = _alert("b1", domains=["evil.example", "other.example"],
                   urls=["http://evil.example/a", "http://other.example/b"])
    features = pf.extract_pair_features(left, right)
    assert features["shared_domains"] == ["evil.example"]
    assert features["shared_urls"] == ["http://evil.example/a"]


def test_analyst_and_engine_iocs_stay_separate():
    left = _alert("a1", analyst_iocs=["203.0.113.9"], engine_iocs=["198.51.100.7"])
    right = _alert("b1", analyst_iocs=[], engine_iocs=["198.51.100.7"])
    features = pf.extract_pair_features(left, right)
    assert features["shared_analyst_iocs"] == []
    assert features["shared_engine_iocs"] == ["198.51.100.7"]


def test_build_pair_record_matches_the_schema():
    record = _record(_alert("a1"), _alert("b1"))
    assert set(record) == set(pf.RECORD_KEYS)
    assert record["schema_version"] == pf.PAIR_SCHEMA_VERSION
    assert record["feature_version"] == pf.PAIR_FEATURE_VERSION
    assert record["features"] == pf.extract_pair_features(_alert("a1"), _alert("b1"))


def test_build_pair_record_rejects_unknown_alert_fields():
    with pytest.raises(ValueError):
        _record(_alert("a1", ruling="extra"), _alert("b1"))


def test_build_pair_record_requires_attribution():
    with pytest.raises(ValueError):
        pf.build_pair_record(_alert("a1"), _alert("b1"), group_id="grp-1", split="test",
                             label="same_incident", label_source="adjudicated",
                             recorded_by="  ")
