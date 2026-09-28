#!/usr/bin/env python3
"""
Tests for tools/cluster_lineage.py.
Fits are seeded directly through cluster_store, so the suite covers lineage
matching, behavior rendering and the gates without an Indexer or scikit-learn.
The tool body runs through ``__wrapped__``; the decorator pipeline has its own
test.
"""
from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import asyncio
import json
import time

import pytest
from mcp_server.core.cluster_features import TACTIC_ORDER
from mcp_server.core.cluster_store import save_fit
from mcp_server.core.config import config
from mcp_server.core.exceptions import BlueTeamMCPError
from mcp_server.tools import cluster_lineage

_run = asyncio.run
_lineage = cluster_lineage.blueteam_cluster_lineage.__wrapped__

C2 = "Command and Control"


def _centroid(weight: float) -> list[float]:
    vector = [0.0] * (len(TACTIC_ORDER) + 4)
    vector[TACTIC_ORDER.index(C2)] = weight
    return vector


def _save(fit_id: str, weight: float, size: int = 3, radius: float = 5.0) -> None:
    centroid = _centroid(weight)
    save_fit(fit_id, {"min_cluster_size": 2},
             [{"label": 0, "centroid": centroid, "medoid": centroid,
               "size": size, "radius": radius}],
             entity_count=10, noise_count=1)


def _seed_drift() -> None:
    _save("f1", 10.0)
    time.sleep(0.02)
    _save("f2", 12.0)


@pytest.fixture(autouse=True)
def _setup(tmp_path):
    config.cluster.enabled = True
    config.cluster.store_path = str(tmp_path / "clusters.db")
    config.cluster.lineage_min_fits = 2
    config.cluster.lineage_match_factor = 1.5
    config.cluster.lineage_min_points = 3
    config.cluster.lineage_shift_z = 2.5
    config.cluster.lineage_tactic_shift = 0.25
    yield
    config.cluster.enabled = False
    config.cluster.store_path = ""


def _params(**overrides):
    return cluster_lineage.ClusterLineageInput(response_format="json", **overrides)


def test_disabled_tool_raises_enable_hint():
    config.cluster.enabled = False
    with pytest.raises(BlueTeamMCPError):
        _run(_lineage(_params(mode="status")))


def test_no_fits_is_insufficient():
    payload = json.loads(_run(_lineage(_params(mode="lineage"))))
    assert payload["status"] == "insufficient_data"
    assert payload["fit_count"] == 0


def test_one_fit_is_insufficient():
    _save("f1", 10.0)
    payload = json.loads(_run(_lineage(_params(mode="lineage"))))
    assert payload["status"] == "insufficient_data"
    assert "at least 2" in payload["reason"]


def test_lineage_mode_matches_a_drifting_cluster():
    _seed_drift()
    payload = json.loads(_run(_lineage(_params(mode="lineage"))))
    assert payload["status"] == "ok"
    assert payload["fit_count"] == 2
    assert len(payload["lineages"]) == 1
    lineage = payload["lineages"][0]
    assert lineage["id"] == "L1"
    assert lineage["step_count"] == 2
    assert lineage["active"] is True
    assert lineage["latest_top_tactics"] == [C2]
    assert payload["born_in_latest"] == []
    assert payload["ended_lineages"] == []


def test_behavior_mode_reports_series_and_gates_on_history():
    _seed_drift()
    payload = json.loads(_run(_lineage(_params(mode="behavior"))))
    assert payload["status"] == "ok"
    lineage = payload["lineages"][0]
    assert len(lineage["series"]) == 2
    assert lineage["series"][0]["fit_id"] == "f1"
    assert lineage["series"][0]["novelty_rate"] == 0.0
    assert lineage["behavior_risk"] == "insufficient_history"
    assert lineage["signals"] == []


def test_behavior_mode_computes_with_a_lower_point_floor():
    _seed_drift()
    payload = json.loads(_run(_lineage(_params(mode="behavior", min_points=2))))
    lineage = payload["lineages"][0]
    assert lineage["behavior_risk"] in ("stable", "watch", "elevated")
    assert lineage["size_z"] is None
    assert lineage["tactic_l1"] == 0.0


def test_tight_match_factor_splits_lineages():
    _seed_drift()
    payload = json.loads(_run(_lineage(_params(mode="lineage", match_factor=0.01))))
    assert len(payload["lineages"]) == 2
    assert payload["ended_lineages"] == ["L1"]
    assert payload["born_in_latest"] == ["L2"]


def test_output_carries_no_entity_keys_or_medoids():
    _seed_drift()
    payload = json.loads(_run(_lineage(_params(mode="behavior"))))
    serialized = json.dumps(payload)
    assert "entity_key" not in serialized
    assert "medoid" not in serialized


def test_status_reports_fit_depth():
    _seed_drift()
    payload = json.loads(_run(_lineage(_params(mode="status"))))
    assert payload["status"] == "ok"
    assert payload["fits"] == 2
    assert payload["hint"] is None
