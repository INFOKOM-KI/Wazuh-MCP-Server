#!/usr/bin/env python3
"""
Tests for tools/geo.py blueteam_wazuh_geo_concentration.
Bucket shapes mirror a live 24h window: a single-IP datacenter bucket, a
mid-concentration one, a diffuse one, and alerts no city resolved.
"""
from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import asyncio
import json
import pytest
from mcp_server.tools import geo


_tool = getattr(geo.blueteam_wazuh_geo_concentration, "__wrapped__",
                geo.blueteam_wazuh_geo_concentration)

_CALLS: list[dict] = []


def _bucket(key, alerts, ips, level=10.0, rule="31151", lat=None, lon=None):
    bucket = {"key": key, "doc_count": alerts,
              "unique_ips": {"value": ips},
              "max_level": {"value": level},
              "top_rule": {"buckets": [{"key": rule}][:1] if rule else []}}
    if lat is not None:
        bucket["centroid"] = {"location": {"lat": lat, "lon": lon}, "count": alerts}
    return bucket


BUCKETS = [
    _bucket("Frankfurt am Main", 602, 14, level=12.0, lat=50.1187, lon=8.6843),
    _bucket("Almaty", 200, 1, level=3.0, lat=43.2638, lon=76.9293),
    _bucket("Bandung", 101, 12, level=7.0),
    _bucket("Tangerang", 18, 18, level=5.0),
    _bucket("Thin Bucket", 4, 1, level=2.0),
    _bucket(geo._UNRESOLVED, 500, 3, level=14.0),
]


@pytest.fixture(autouse=True)
def _stub_indexer(monkeypatch):
    async def _fake_post(body):
        _CALLS.append(body)
        return {"aggregations": {
            "by_geo": {"buckets": list(BUCKETS)},
            "total_with_geo": {"value": 921},
            "total_with_country": {"value": 1400},
            "total_alerts": {"value": 1421},
        }}

    _CALLS.clear()
    monkeypatch.setattr(geo, "_wazuh_indexer_post", _fake_post)


def _run(coro):
    return asyncio.run(coro)


def _rows(**kwargs) -> list[dict]:
    payload = json.loads(_run(_tool(geo.GeoConcentrationInput(
        response_format="json", **kwargs))))
    return payload["ranking"]


def test_ranking_is_ordered_by_alerts_per_source_ip():
    rows = _rows()
    assert [r["geo"] for r in rows] == ["Almaty", geo._UNRESOLVED, "Frankfurt am Main",
                                        "Bandung", "Tangerang"]
    assert rows[0]["alerts_per_ip"] == 200.0
    assert rows[1]["alerts_per_ip"] == pytest.approx(166.67, abs=0.01)


def test_the_floor_drops_thin_buckets_before_ranking():
    assert "Thin Bucket" not in [r["geo"] for r in _rows()]
    assert "Thin Bucket" in [r["geo"] for r in _rows(min_alerts=1)]


def test_a_bucket_without_source_ips_is_unmeasured_not_zero(monkeypatch):
    """A 0 divisor must not raise and must not rank as an infinite ratio."""
    async def _no_ips(body):
        return {"aggregations": {"by_geo": {"buckets": [
                    _bucket("Somewhere", 50, 0), _bucket("Almaty", 200, 1)]},
                "total_with_geo": {"value": 250},
                "total_with_country": {"value": 250},
                "total_alerts": {"value": 250}}}
    monkeypatch.setattr(geo, "_wazuh_indexer_post", _no_ips)
    rows = _rows()
    assert [r["geo"] for r in rows] == ["Almaty", "Somewhere"]
    assert rows[1]["alerts_per_ip"] is None


def test_top_n_caps_the_rows_returned():
    assert len(_rows(top_n=3)) == 3


def test_candidate_fetch_hitting_its_ceiling_reports_truncated(monkeypatch):
    many = [_bucket(f"City {i}", 100 + i, 5) for i in range(50)]

    async def _fifty(body):
        return {"aggregations": {"by_geo": {"buckets": many},
                "total_with_geo": {"value": 5000},
                "total_with_country": {"value": 5000},
                "total_alerts": {"value": 5000}}}

    monkeypatch.setattr(geo, "_wazuh_indexer_post", _fifty)
    payload = json.loads(_run(_tool(geo.GeoConcentrationInput(
        response_format="json", max_buckets=50))))
    assert payload["candidates_fetched"] == 50
    assert payload["truncated"] is True
    assert "raise `max_buckets`" in _run(_tool(geo.GeoConcentrationInput(
        response_format="markdown", max_buckets=50)))


def test_coverage_counts_reach_the_output():
    payload = json.loads(_run(_tool(geo.GeoConcentrationInput(response_format="json"))))
    assert payload["coverage"] == {"alerts": 1421, "fields_resolved": 921,
                                   "unresolved": 500}


def test_markdown_carries_the_interpretation_caveat():
    rendered = _run(_tool(geo.GeoConcentrationInput(response_format="markdown")))
    assert "not a verdict" in rendered
    assert "| Almaty | 200 | 1 | 200.00 | 3 | `31151` |" in rendered
    assert "unresolved" in rendered


def test_the_aggregation_asks_for_centroid_not_the_scalar_lat_lon_fields():
    _run(_tool(geo.GeoConcentrationInput(response_format="json")))
    body = json.dumps(_CALLS[0])
    assert "geo_centroid" in body
    assert "GeoLocation.latitude" not in body and "GeoLocation.longitude" not in body
    assert '"missing"' in body
