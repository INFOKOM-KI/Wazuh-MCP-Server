#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
HDBSCAN fit and nearest centroid assignment for blueteam_alert_cluster.

HDBSCAN has no inductive ``predict`` (verified on the pinned scikit-learn: the
class exposes ``fit_predict`` only), so a new entity is assigned to the nearest
stored centroid when it falls inside that cluster's radius, the 95th
percentile of member distances - and reported as ``novel`` otherwise. That
keeps real-time assignment O(clusters x dims) with no refit and no label churn
under an open investigation.

Pure-Python arithmetic with a lazily imported scikit-learn: this module must
import cleanly where the optional dependency is absent, because the tool has to
answer with an enable hint rather than fail at startup.
"""
from __future__ import annotations
import logging
import math
from typing import Any, Optional

logger = logging.getLogger("blue_team_mcp.cluster_core")

DEFAULT_MIN_CLUSTER_SIZE = 5
DEFAULT_MIN_SAMPLES = 3
RADIUS_PERCENTILE = 0.95
NOISE_LABEL = -1


def _clusterer_class():
    from sklearn.cluster import HDBSCAN
    return HDBSCAN


def _centroid(vectors: list[list[float]]) -> list[float]:
    n = len(vectors)
    dim = len(vectors[0])
    return [sum(v[i] for v in vectors) / n for i in range(dim)]


def _radius(centroid: list[float], members: list[list[float]]) -> float:
    """95th percentile member distance. The maximum would let a single outlier
    define the acceptance boundary for the whole cluster."""
    distances = sorted(math.dist(centroid, m) for m in members)
    idx = min(len(distances) - 1, int(round(RADIUS_PERCENTILE * (len(distances) - 1))))
    return distances[idx]


def fit_clusters(vectors: list[list[float]], min_cluster_size: int = DEFAULT_MIN_CLUSTER_SIZE,
                 min_samples: int = DEFAULT_MIN_SAMPLES,
                 clusterer: Optional[Any] = None) -> dict:
    """Cluster entity vectors and describe each cluster by centroid, medoid, size
    and radius. ``clusterer`` is an injection point for tests: any object with
    ``fit_predict(vectors)``. ``None`` loads scikit-learn lazily. A population
    smaller than ``min_cluster_size`` returns ``insufficient_data`` instead of an
    empty cluster list, which would read as "no clusters exist" when the truth is
    "not enough entities to say".
    """
    entity_count = len(vectors)
    if entity_count == 0:
        return {"status": "insufficient_data", "entity_count": 0,
                "reason": "no entity vectors in the window"}
    if entity_count < max(2, int(min_cluster_size)):
        return {"status": "insufficient_data", "entity_count": entity_count,
                "reason": f"{entity_count} entities < min_cluster_size {min_cluster_size}"}
    if clusterer is None:
        try:
            clusterer = _clusterer_class()
        except ImportError:
            return {"status": "unavailable", "entity_count": entity_count,
                    "reason": "scikit-learn is not installed - run setup.sh with "
                              "BLUETEAM_INSTALL_CLUSTER=1 or pip install scikit-learn"}
    # copy=False: the caller's vectors are not reused, and the default copy doubles
    # peak memory on a large population.
    labels = [int(label) for label in clusterer(
        min_cluster_size=int(min_cluster_size), min_samples=int(min_samples),
        metric="euclidean", copy=False,
    ).fit_predict(vectors)]

    clusters: list[dict] = []
    for label in sorted(set(labels)):
        if label == NOISE_LABEL:
            continue
        members = [v for v, item in zip(vectors, labels) if item == label]
        centroid = _centroid(members)
        medoid = min(members, key=lambda m: math.dist(centroid, m))
        clusters.append({
            "label": label, "centroid": centroid, "medoid": medoid,
            "size": len(members), "radius": _radius(centroid, members),
        })
    noise_count = sum(1 for label in labels if label == NOISE_LABEL)
    return {
        "status": "ok", "labels": labels, "clusters": clusters,
        "entity_count": entity_count, "noise_count": noise_count,
        "noise_ratio": round(noise_count / entity_count, 3),
        "params": {"min_cluster_size": int(min_cluster_size),
                   "min_samples": int(min_samples), "metric": "euclidean"},
    }


def assign_vector(vector: list[float], clusters: list[dict],
                  factor: float = 1.0) -> dict:
    """Assign one vector to the nearest stored cluster.
    Returns ``label=-1`` plus ``novelty=True`` when the nearest centroid is
    further than ``radius x factor``: the point is not merely unlabelled, it is
    evidence the stored fit does not describe the current window.
    """
    if not clusters:
        return {"label": NOISE_LABEL, "distance": None, "novelty": True,
                "nearest_label": None, "limit": None, "reason": "no clusters in the stored fit"}
    nearest = min(clusters, key=lambda c: math.dist(vector, c["centroid"]))
    distance = math.dist(vector, nearest["centroid"])
    limit = float(nearest["radius"]) * float(factor)
    if distance <= limit:
        return {"label": int(nearest["label"]), "distance": round(distance, 4),
                "novelty": False, "nearest_label": int(nearest["label"]),
                "limit": round(limit, 4)}
    return {"label": NOISE_LABEL, "distance": round(distance, 4),
            "novelty": True, "nearest_label": int(nearest["label"]),
            "limit": round(limit, 4)}


def cluster_medoids(fit: dict) -> list[dict]:
    """Medoid vectors from a stored fit, for labeling one representative per
    cluster instead of every entity."""
    return [{"label": int(c["label"]), "medoid": list(c["medoid"]), "size": int(c["size"])}
            for c in fit.get("clusters", [])]
