#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Feature construction for alert entity clustering (blueteam_alert_cluster).
The vector reuses what the 3-Sum engine already scores per source IP rather
than adding an embedding model:
16 dims  sum of rule.level per MITRE tactic (``by_tactic`` buckets from the
           existing ``multi_terms`` aggregation)
4 dims  ``score_a``, ``score_b``, ``score_c``, ``total`` (engine scores)
Raw sums scaled to a rate per day, no per-dimension normalisation. HDBSCAN is
density-based; z-scoring flattens the sparse tactic signal, because most
entities populate one or two tactics.
``FEATURE_VERSION`` is persisted with every fit. Bump it whenever
``TACTIC_ORDER``, the scalar block, or the window scaling changes, so centroids
written under one vector layout can never be read under another - the same
refusal ``rag_store`` applies to mixed vector dimensions.
"""
from __future__ import annotations
from typing import Any
from mcp_server.core.constants import MITRE_TACTIC_WEIGHTS

FEATURE_VERSION = "v2"

REFERENCE_WINDOW_MINUTES = 1440

TACTIC_ORDER: tuple[str, ...] = tuple(sorted(MITRE_TACTIC_WEIGHTS))
SCALAR_KEYS: tuple[str, ...] = ("score_a", "score_b", "score_c", "total")
FEATURE_DIM = len(TACTIC_ORDER) + len(SCALAR_KEYS)


def normalize_entity_key(value: str) -> str:
    """Canonical entity key for store lookups. Empty string is invalid and the
    caller must reject it rather than storing an unassignable row."""
    return (value or "").strip().lower()


def tactic_map(raw: Any) -> dict[str, float]:
    """Normalise ``by_tactic`` aggregation output into ``{tactic: level_sum}``.
    Accepts both shapes the aggregation can produce: the Elasticsearch bucket
    list (``[{"key": ..., "level_sum": {"value": n}}]``) and an already-flattened
    mapping. Unknown keys are kept, not dropped, so a tactic the local taxonomy
    does not list yet still contributes to nothing rather than silently
    erroring.
    """
    out: dict[str, float] = {}
    if isinstance(raw, dict):
        for key, value in raw.items():
            if isinstance(value, dict):
                value = value.get("value", 0)
            out[str(key)] = float(value or 0)
        return out
    if isinstance(raw, list):
        for bucket in raw:
            if not isinstance(bucket, dict) or not bucket.get("key"):
                continue
            level_sum = bucket.get("level_sum")
            if isinstance(level_sum, dict):
                level_sum = level_sum.get("value", 0)
            out[str(bucket["key"])] = float(level_sum or 0)
    return out


def build_vector(profile: dict, window_minutes: int) -> list[float]:
    """Build one entity vector as a rate per day over ``window_minutes``. Missing
    fields are zero, never an error: an entity whose alerts carry no MITRE
    annotation is a legitimate zero-tactic point, not a malformed one.
    ``window_minutes`` is required rather than defaulted: a vector scaled by the
    wrong window sits at the wrong distance from every stored centroid.
    """
    if window_minutes <= 0:
        raise ValueError("window_minutes must be positive")
    scale = REFERENCE_WINDOW_MINUTES / float(window_minutes)
    tactics = tactic_map(profile.get("tactics") or {})
    vector = [tactics.get(tactic, 0.0) * scale for tactic in TACTIC_ORDER]
    vector.extend(float(profile.get(key, 0) or 0) * scale for key in SCALAR_KEYS)
    return vector
