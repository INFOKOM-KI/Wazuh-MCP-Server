#!/usr/bin/env python3
"""
Tests for the shard-partial marker on indexer responses.
A failed shard returns HTTP 200 with no error key, so an aggregation silently
covers fewer documents than the caller believes.
"""
from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import asyncio
import pytest
from mcp_server.wazuh import indexer


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


def _stub(payload, monkeypatch):
    async def _api_call(*args, **kwargs):
        return _Resp(payload)

    monkeypatch.setattr(indexer, "_api_call", _api_call)
    monkeypatch.setattr(indexer, "_INDEXER_CACHE", {})
    monkeypatch.setattr(indexer, "_INDEXER_CACHE_TTL", 0.0)


def _run(body):
    return asyncio.run(indexer._wazuh_indexer_post(body))


def test_failed_shards_are_flagged(monkeypatch):
    _stub({"_shards": {"total": 784, "successful": 771, "failed": 13},
           "aggregations": {"by_rule": {"buckets": []}}}, monkeypatch)
    raw = _run({"size": 0, "query": {"match_all": {}}})
    assert raw["_partial"] is True
    assert raw["_failed_shards"] == 13


def test_a_clean_response_carries_no_marker(monkeypatch):
    _stub({"_shards": {"total": 784, "successful": 784, "failed": 0},
           "aggregations": {}}, monkeypatch)
    raw = _run({"size": 0, "track_total_hits": True})
    assert "_partial" not in raw
    assert "_failed_shards" not in raw


def test_a_response_without_shard_metadata_is_not_flagged(monkeypatch):
    _stub({"aggregations": {}}, monkeypatch)
    raw = _run({"size": 0, "aggs": {}})
    assert "_partial" not in raw


def test_the_marker_survives_the_response_cache(monkeypatch):
    _stub({"_shards": {"total": 4, "successful": 3, "failed": 1},
           "aggregations": {}}, monkeypatch)
    monkeypatch.setattr(indexer, "_INDEXER_CACHE_TTL", 30.0)
    first = _run({"size": 0, "from": 0})
    second = _run({"size": 0, "from": 0})
    assert first["_failed_shards"] == 1
    assert second["_failed_shards"] == 1
