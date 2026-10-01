#!/usr/bin/env python3
"""
Tests for the curated-report geo bounding box.
Range queries on GeoLocation.location.lat/.lon matched every document count of
zero against a live 24h window; a geo_bounding_box filter is the form that works.
"""
from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

from mcp_server.tools.alert_compare import CuratedReportFilters, _build_curated_query


def _clauses(**kwargs) -> list[dict]:
    return _build_curated_query("2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z",
                                CuratedReportFilters(**kwargs))


def _bbox(clauses: list[dict]) -> dict:
    return next(c for c in clauses if "geo_bounding_box" in c)["geo_bounding_box"]


def test_geo_bbox_emits_a_bounding_box_not_a_range():
    clauses = _clauses(geo_bbox="49.5,7.9,50.7,9.4")
    assert [c for c in clauses if "geo_bounding_box" in c]
    assert all("@timestamp" in c["range"] for c in clauses if "range" in c)
    assert "GeoLocation.location.lat" not in str(clauses)
    assert "GeoLocation.location.lon" not in str(clauses)


def test_geo_bbox_corners_are_normalised_whichever_way_round_they_are_given():
    """top_left is north-west, so latitude takes the larger value."""
    expect = {"top_left": {"lat": 50.7, "lon": 7.9},
              "bottom_right": {"lat": 49.5, "lon": 9.4}}
    assert _bbox(_clauses(geo_bbox="49.5,7.9,50.7,9.4"))["GeoLocation.location"] == expect
    assert _bbox(_clauses(geo_bbox="50.7,9.4,49.5,7.9"))["GeoLocation.location"] == expect


def test_geo_bbox_matches_the_documented_indonesia_example():
    corners = _bbox(_clauses(geo_bbox="-7.0,106.5,-5.5,107.0"))["GeoLocation.location"]
    assert corners == {"top_left": {"lat": -5.5, "lon": 106.5},
                       "bottom_right": {"lat": -7.0, "lon": 107.0}}


def test_a_malformed_bbox_adds_no_geo_clause():
    assert not [c for c in _clauses(geo_bbox="49.5,7.9,50.7") if "geo_bounding_box" in c]
