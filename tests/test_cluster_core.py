#!/usr/bin/env python3
"""
Tests for mcp_server/correlation/cluster_core.py HDBSCAN fit and nearest-centroid assignment.
scikit-learn is injected as a fake clusterer, so the full path is exercised on
a machine where the optional dependency is absent, which is also the path that must return an enable hint instead of raising.
"""
from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

from mcp_server.correlation.cluster_core import (
    assign_vector,
    cluster_medoids,
    fit_clusters,
)

VECTORS = [[0.0, 0.0], [0.1, 0.0], [0.0, 0.1], [5.0, 5.0], [5.1, 5.0], [9.0, 9.0]]


class _FakeModel:
    def __init__(self, labels):
        self._labels = labels

    def fit_predict(self, vectors):
        assert len(vectors) == len(self._labels)
        return self._labels


def _clusterer(labels):
    return lambda **kwargs: _FakeModel(labels)


def test_insufficient_population_is_reported_not_empty():
    result = fit_clusters([[0.0, 0.0], [1.0, 1.0]], min_cluster_size=5)
    assert result["status"] == "insufficient_data"
    assert "min_cluster_size" in result["reason"]


def test_fit_builds_clusters_and_noise_ratio():
    result = fit_clusters(
        VECTORS, min_cluster_size=3,
        clusterer=_clusterer([0, 0, 0, 1, 1, -1]),
    )
    assert result["status"] == "ok"
    assert [c["label"] for c in result["clusters"]] == [0, 1]
    assert result["noise_count"] == 1
    assert result["noise_ratio"] == round(1 / 6, 3)
    assert result["clusters"][0]["size"] == 3


def test_medoid_is_a_member_of_its_cluster():
    result = fit_clusters(VECTORS, min_cluster_size=3, clusterer=_clusterer([0, 0, 0, 1, 1, -1]))
    cluster = result["clusters"][0]
    assert cluster["medoid"] in [[0.0, 0.0], [0.1, 0.0], [0.0, 0.1]]


def test_assign_inside_radius_returns_cluster_label():
    clusters = [{"label": 0, "centroid": [0.0, 0.0], "radius": 1.0}]
    result = assign_vector([0.2, 0.2], clusters)
    assert result["label"] == 0
    assert result["novelty"] is False


def test_assign_outside_radius_is_novel_with_nearest_label():
    clusters = [{"label": 0, "centroid": [0.0, 0.0], "radius": 1.0}]
    result = assign_vector([4.0, 4.0], clusters)
    assert result["label"] == -1
    assert result["novelty"] is True
    assert result["nearest_label"] == 0


def test_assign_with_no_clusters_is_novel():
    result = assign_vector([1.0], [])
    assert result["novelty"] is True
    assert result["reason"] == "no clusters in the stored fit"


def test_medoids_exposed_for_labeling():
    fit = {"clusters": [{"label": 0, "medoid": [1.0, 2.0], "size": 4}]}
    assert cluster_medoids(fit) == [{"label": 0, "medoid": [1.0, 2.0], "size": 4}]
