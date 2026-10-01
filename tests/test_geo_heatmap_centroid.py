#!/usr/bin/env python3
"""
Tests for the geo heatmap city centroid.
The deployment maps GeoLocation.latitude/longitude but populates only
GeoLocation.location, so an average over the scalar fields returns null. Those
nulls previously rendered as 0, putting every city at 0,0.
"""
from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import asyncio
import json
import pytest
from mcp_server.tools import wazuh_scanning


_heatmap = getattr(wazuh_scanning.blueteam_wazuh_geo_heatmap, "__wrapped__",
                   wazuh_scanning.blueteam_wazuh_geo_heatmap)

_CALLS: list[dict] = []

BUCKETS = [
    {"key": "Frankfurt am Main", "doc_count": 579,
     "centroid": {"location": {"lat": 50.118746091852955, "lon": 8.684298905876943},
                  "count": 579},
     "unique_ips": {"value": 14}},
    {"key": "Almaty", "doc_count": 200,
     "centroid": {"location": {"lat": 43.26379998587072, "lon": 76.92929992452264},
                  "count": 200},
     "unique_ips": {"value": 1}},
]


@pytest.fixture(autouse=True)
def _stub_indexer(monkeypatch):
    async def _fake_post(body):
        _CALLS.append(body)
        return {"hits": {"total": {"value": 779}},
                "aggregations": {"by_city": {"buckets": BUCKETS}}}

    _CALLS.clear()
    monkeypatch.setattr(wazuh_scanning, "_wazuh_indexer_post", _fake_post)


def _run(coro):
    return asyncio.run(coro)


def test_city_coordinates_come_from_the_geo_centroid():
    payload = json.loads(_run(_heatmap(wazuh_scanning.GeoHeatmapInput(
        response_format="json"))))
    cities = {c["city"]: c for c in payload["cities"]}
    assert cities["Frankfurt am Main"]["lat"] == pytest.approx(50.1187, abs=1e-3)
    assert cities["Frankfurt am Main"]["lon"] == pytest.approx(8.6843, abs=1e-3)
    assert cities["Almaty"]["lat"] == pytest.approx(43.2638, abs=1e-3)


def test_aggregation_does_not_touch_the_unpopulated_scalar_fields():
    _run(_heatmap(wazuh_scanning.GeoHeatmapInput(response_format="json")))
    body = json.dumps(_CALLS[0])
    assert "GeoLocation.latitude" not in body
    assert "GeoLocation.longitude" not in body
    assert "geo_centroid" in body


def test_markdown_row_renders_the_centroid():
    rendered = _run(_heatmap(wazuh_scanning.GeoHeatmapInput(response_format="markdown")))
    assert "| Almaty | 200 | 43.26 | 76.93 | 1 |" in rendered


def test_absent_centroid_is_unmeasured_not_zero():
    """0 would place the city in the Gulf of Guinea; absent means unmeasured."""
    assert wazuh_scanning._centroid_coord({}, "lat") is None
    assert wazuh_scanning._centroid_coord({"centroid": {}}, "lon") is None
    assert wazuh_scanning._centroid_coord(
        {"centroid": {"location": {"lat": None, "lon": None}}}, "lat") is None
