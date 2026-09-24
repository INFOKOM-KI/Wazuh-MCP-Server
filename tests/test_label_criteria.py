#!/usr/bin/env python3
"""Tests for label/criteria.py.
The point of these is drift: the vocabulary must be the one the correlation engine
scores, every tactic must have prototypes for the ONNX backend, and the version stamp
must move when the wording does.
"""
from __future__ import annotations

import re
import pytest
from mcp_server.core.constants import MITRE_TACTIC_TO_CATEGORY
from mcp_server.label import criteria


def test_vocabulary_matches_constants():
    assert criteria.TACTICS == tuple(sorted(MITRE_TACTIC_TO_CATEGORY))


def test_every_tactic_has_criteria_and_two_prototypes():
    for tactic in criteria.TACTICS:
        entry = criteria._TABLE[tactic]
        assert entry["criteria"].strip(), tactic
        assert len(entry["prototypes"]) >= 2, tactic
        assert all(phrase.strip() for phrase in entry["prototypes"]), tactic


def test_criteria_map_covers_every_tactic():
    assert set(criteria.criteria_map()) == set(criteria.TACTICS)


def test_prototypes_are_grouped_by_tactic_in_order():
    rows = criteria.prototypes()
    seen = []
    for tactic, phrase in rows:
        assert tactic in criteria.TACTICS
        assert phrase
        if not seen or seen[-1] != tactic:
            seen.append(tactic)
    assert seen == list(criteria.TACTICS)


def test_version_is_stable_and_carries_the_hash():
    assert criteria.version() == criteria.version()
    assert re.fullmatch(r"v1:[0-9a-f]{8}", criteria.version())


def test_version_changes_when_a_phrase_changes(monkeypatch):
    before = criteria.version()
    monkeypatch.setitem(criteria._TABLE, "Impact",
                        {"criteria": "damage or disruption",
                         "prototypes": ("mass file encryption", "a service offline")})
    assert criteria._hash() != before.split(":")[1]


def test_vocabulary_guard_raises_on_a_missing_entry(monkeypatch):
    monkeypatch.delitem(criteria._TABLE, "Impact")
    with pytest.raises(RuntimeError, match="out of sync"):
        criteria._assert_vocabulary()


def test_vocabulary_guard_raises_on_an_unknown_entry(monkeypatch):
    monkeypatch.setitem(criteria._TABLE, "Not A Real Tactic",
                        {"criteria": "x", "prototypes": ("y", "z")})
    with pytest.raises(RuntimeError, match="Not A Real Tactic"):
        criteria._assert_vocabulary()
