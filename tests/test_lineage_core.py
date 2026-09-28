#!/usr/bin/env python3
"""
Tests for mcp_server/correlation/lineage_core.py.
Pure computation over synthetic fit records: no store, no Indexer. The cases
that matter are the identity contract (one-to-one matches, new and ended
lineages) and the no-fabrication contract (missing history yields None or
insufficient_history, never a zero or a claimed shift).
"""
from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

from mcp_server.core.cluster_features import TACTIC_ORDER
from mcp_server.correlation.lineage_core import (
    _l1,
    _zscore,
    build_lineages,
    lineage_behavior,
    tactic_shares,
    top_tactics,
)

C2 = "Command and Control"
IMPACT = "Impact"


def _centroid(weights: dict[str, float]) -> list[float]:
    vector = [0.0] * (len(TACTIC_ORDER) + 4)
    for tactic, weight in weights.items():
        vector[TACTIC_ORDER.index(tactic)] = weight
    return vector


def _cluster(label: int, centroid: list[float], size: int = 3, radius: float = 5.0) -> dict:
    return {"label": label, "centroid": centroid, "size": size, "radius": radius}


def _fit(fit_id: str, created: float, clusters: list[dict]) -> dict:
    return {"fit_id": fit_id, "created_at": created, "entity_count": 10, "clusters": clusters}


def _lineages(fits: list[dict], factor: float = 1.5) -> dict:
    result = build_lineages(fits, factor)
    assert result["status"] == "ok"
    return result


def test_match_within_radius_keeps_one_lineage():
    result = _lineages([
        _fit("f1", 1.0, [_cluster(0, _centroid({C2: 10.0}))]),
        _fit("f2", 2.0, [_cluster(0, _centroid({C2: 12.0}))]),
    ])
    assert [record["id"] for record in result["lineages"]] == ["L1"]
    lineage = result["lineages"][0]
    assert lineage["step_count"] == 2
    assert lineage["active"] is True
    assert lineage["steps"][1]["distance_from_previous"] == 2.0
    assert result["born_in_latest"] == []
    assert result["ended_lineages"] == []


def test_drift_outside_radius_ends_and_starts_lineages():
    result = _lineages([
        _fit("f1", 1.0, [_cluster(0, _centroid({C2: 10.0}))]),
        _fit("f2", 2.0, [_cluster(0, _centroid({C2: 60.0}))]),
    ])
    assert [record["id"] for record in result["lineages"]] == ["L1", "L2"]
    assert result["ended_lineages"] == ["L1"]
    assert result["born_in_latest"] == ["L2"]
    assert result["lineages"][0]["active"] is False
    assert result["lineages"][1]["active"] is True


def test_matching_is_one_to_one():
    previous = _cluster(0, _centroid({C2: 10.0}))
    previous_second = _cluster(1, _centroid({C2: 12.0}))
    new_first = _cluster(0, _centroid({C2: 11.0}))
    new_second = _cluster(1, _centroid({C2: 11.5}))
    result = _lineages([
        _fit("f1", 1.0, [previous, previous_second]),
        _fit("f2", 2.0, [new_first, new_second]),
    ])
    assert len(result["lineages"]) == 2
    assert all(record["step_count"] == 2 for record in result["lineages"])
    assert result["born_in_latest"] == []
    assert result["ended_lineages"] == []


def test_one_fit_is_insufficient_for_lineage():
    result = build_lineages([_fit("f1", 1.0, [_cluster(0, _centroid({C2: 10.0}))])])
    assert result["status"] == "insufficient_data"
    assert "at least 2" in result["reason"]


def test_tactic_shares_normalises_and_handles_zero_block():
    shares = tactic_shares(_centroid({C2: 3.0, IMPACT: 1.0}))
    assert shares == {C2: 0.75, IMPACT: 0.25}
    assert tactic_shares([0.0] * 20) == {}
    assert top_tactics(shares) == [C2, IMPACT]


def test_l1_distance_bounds():
    assert _l1({}, {}) == 0.0
    assert _l1({C2: 1.0}, {IMPACT: 1.0}) == 2.0
    assert _l1({C2: 0.5, IMPACT: 0.5}, {C2: 1.0}) == 1.0


def test_zscore_guards():
    assert _zscore(5.0, [1.0]) is None
    assert _zscore(5.0, [5.0, 5.0]) == 0.0
    assert _zscore(9.0, [1.0, 3.0]) > 0


def test_behavior_flags_tactic_shift_and_gates_on_history():
    fits = [
        _fit("f1", 1.0, [_cluster(0, _centroid({C2: 10.0}))]),
        _fit("f2", 2.0, [_cluster(0, _centroid({C2: 10.0}))]),
        _fit("f3", 3.0, [_cluster(0, _centroid({C2: 7.0, IMPACT: 3.0}))]),
    ]
    result = _lineages(fits)
    behaviors = lineage_behavior(result["lineages"], {"f1": 0.1, "f2": 0.1, "f3": 0.1},
                                 min_points=3)
    lineage = behaviors[0]
    assert lineage["tactic_shift"] is True
    assert lineage["tactic_l1"] == 0.6
    assert lineage["signals"] == ["tactic_shift"]
    assert lineage["behavior_risk"] == "elevated"

    strict = lineage_behavior(result["lineages"], {"f1": 0.1, "f2": 0.1, "f3": 0.1},
                              min_points=4)
    assert strict[0]["behavior_risk"] == "insufficient_history"
    assert strict[0]["signals"] == []


def test_behavior_zero_variance_size_is_stable():
    fits = [
        _fit("f1", 1.0, [_cluster(0, _centroid({C2: 10.0}), size=5)]),
        _fit("f2", 2.0, [_cluster(0, _centroid({C2: 10.0}), size=5)]),
        _fit("f3", 3.0, [_cluster(0, _centroid({C2: 10.0}), size=5)]),
    ]
    result = _lineages(fits)
    behaviors = lineage_behavior(result["lineages"], {}, min_points=3)
    lineage = behaviors[0]
    assert lineage["size_z"] == 0.0
    assert lineage["size_direction"] == "stable"
    assert lineage["novelty_z"] is None
    assert lineage["behavior_risk"] == "stable"


def test_behavior_flags_novelty_jump():
    fits = [
        _fit("f1", 1.0, [_cluster(0, _centroid({C2: 10.0}))]),
        _fit("f2", 2.0, [_cluster(0, _centroid({C2: 10.0}))]),
        _fit("f3", 3.0, [_cluster(0, _centroid({C2: 10.0}))]),
    ]
    result = _lineages(fits)
    behaviors = lineage_behavior(result["lineages"],
                                 {"f1": 0.1, "f2": 0.15, "f3": 0.9}, min_points=3)
    lineage = behaviors[0]
    assert lineage["novelty_rate"] == 0.9
    assert lineage["novelty_z"] > 2.5
    assert "novelty_jump" in lineage["signals"]
    assert lineage["behavior_risk"] == "elevated"
