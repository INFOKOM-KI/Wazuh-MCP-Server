#!/usr/bin/env python3
"""
Tests for mcp_server/core/cluster_features.py the entity vector layout.
The dimension contract is what the store enforces, so the vector shape and the
Elasticsearch bucket flattening get explicit cases.
"""
from __future__ import annotations
import os
import pytest

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

from mcp_server.core.cluster_features import (
    FEATURE_DIM,
    FEATURE_VERSION,
    SCALAR_KEYS,
    TACTIC_ORDER,
    build_vector,
    normalize_entity_key,
    tactic_map,
)


def test_vector_is_sixteen_tactics_plus_four_scalars():
    assert len(TACTIC_ORDER) == 16
    assert len(SCALAR_KEYS) == 4
    assert FEATURE_DIM == 20
    assert FEATURE_VERSION == "v2"


def test_tactic_map_flattens_es_buckets():
    raw = [
        {"key": "Command and Control", "level_sum": {"value": 24}},
        {"key": "Discovery", "level_sum": {"value": 6}},
    ]
    assert tactic_map(raw) == {"Command and Control": 24.0, "Discovery": 6.0}


def test_tactic_map_accepts_flat_mapping_and_bare_numbers():
    assert tactic_map({"Impact": 5, "Collection": {"value": 7}}) == {
        "Impact": 5.0, "Collection": 7.0,
    }


def test_build_vector_places_tactics_and_scalars():
    profile = {
        "tactics": [{"key": "Command and Control", "level_sum": {"value": 30}}],
        "score_a": 1, "score_b": 2, "score_c": 3, "total": 6,
    }
    vector = build_vector(profile, window_minutes=1440)
    assert len(vector) == FEATURE_DIM
    idx = TACTIC_ORDER.index("Command and Control")
    assert vector[idx] == 30.0
    assert vector[-4:] == [1.0, 2.0, 3.0, 6.0]


def test_missing_fields_are_zero_not_an_error():
    assert build_vector({}, window_minutes=1440) == [0.0] * FEATURE_DIM


def test_build_vector_scales_by_window_to_a_rate_per_day():
    profile = {"tactics": {"Discovery": 30.0}, "score_a": 3.0, "score_b": 0.0,
               "score_c": 0.0, "total": 30.0}
    vector = build_vector(profile, window_minutes=1440)
    assert vector[TACTIC_ORDER.index("Discovery")] == 30.0
    assert vector[-4:] == [3.0, 0.0, 0.0, 30.0]


def test_build_vector_is_invariant_to_window_length():
    """The same alert rate over 30 days must give the same vector as over one.
    Without this, a centroid fitted at 14 days sits ~14x further from the origin
    than a live one-day vector, so every assignment lands inside the radius.
    """
    one_day = {"tactics": {"Discovery": 30.0}, "score_a": 3.0,
               "score_b": 0.0, "score_c": 0.0, "total": 30.0}
    thirty_days = {"tactics": {"Discovery": 30.0 * 30}, "score_a": 3.0 * 30,
                   "score_b": 0.0, "score_c": 0.0, "total": 30.0 * 30}
    assert build_vector(thirty_days, window_minutes=43200) == pytest.approx(
        build_vector(one_day, window_minutes=1440))


def test_build_vector_requires_an_explicit_window():
    """A defaulted window would let a caller score an entity in the wrong space."""
    with pytest.raises(TypeError):
        build_vector({})


def test_build_vector_rejects_a_nonpositive_window():
    for minutes in (0, -1440):
        with pytest.raises(ValueError):
            build_vector({}, window_minutes=minutes)


def test_normalize_entity_key_trims_and_lowercases():
    assert normalize_entity_key(" 203.0.113.7 ") == "203.0.113.7"
    assert normalize_entity_key("") == ""
