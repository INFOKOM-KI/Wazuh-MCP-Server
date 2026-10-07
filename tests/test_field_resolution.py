#!/usr/bin/env python3
"""Mapping-aware field resolution for aggregations and exact filters (W2)."""
from __future__ import annotations

import asyncio
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

from mcp_server.wazuh import indexer


def _run(coro):
    return asyncio.run(coro)


def _patch_mapping(monkeypatch, mapping):
    async def _get(index_pattern=None):
        return mapping
    monkeypatch.setattr(indexer, "_wazuh_indexer_mapping", _get)


def _index(shape):
    if shape == "keyword":
        return {"data": {"properties": {"domain": {"type": "keyword"}}}}
    if shape == "text+keyword":
        return {"data": {"properties": {"domain": {
            "type": "text", "fields": {"keyword": {"type": "keyword"}}}}}}
    return {"data": {"properties": {"domain": {"type": "text"}}}}


def test_keyword_mapping_keeps_plain_name(monkeypatch):
    _patch_mapping(monkeypatch, {"idx": {"mappings": {"properties": _index("keyword")}}})
    assert _run(indexer._resolve_agg_fields(["data.domain"])) == {"data.domain": "data.domain"}


def test_text_with_keyword_subfield_resolves_subfield(monkeypatch):
    _patch_mapping(monkeypatch, {"idx": {"mappings": {"properties": _index("text+keyword")}}})
    assert _run(indexer._resolve_agg_fields(["data.domain"])) == {"data.domain": "data.domain.keyword"}


def test_mixed_keyword_and_text_with_subfield_resolves_none(monkeypatch):
    """Neither name spans: `.keyword` does not exist on the keyword index."""
    _patch_mapping(monkeypatch, {
        "idx-1": {"mappings": {"properties": _index("keyword")}},
        "idx-2": {"mappings": {"properties": _index("text+keyword")}},
    })
    assert _run(indexer._resolve_agg_fields(["data.domain"])) == {"data.domain": None}


def test_mixed_layout_without_subfield_resolves_none(monkeypatch):
    _patch_mapping(monkeypatch, {
        "idx-1": {"mappings": {"properties": _index("keyword")}},
        "idx-2": {"mappings": {"properties": _index("text")}},
    })
    assert _run(indexer._resolve_agg_fields(["data.domain"])) == {"data.domain": None}


def test_mapping_error_resolves_none(monkeypatch):
    _patch_mapping(monkeypatch, {"error": "Indexer API error: 503"})
    assert _run(indexer._resolve_agg_fields(["data.domain"])) == {"data.domain": None}


def test_agg_safe_paths_keeps_both_dual_mapping_names():
    caps = {"data.srcip": "keyword", "data.srcip.keyword": "keyword"}
    assert indexer._agg_safe_paths("data.srcip", caps) == ["data.srcip", "data.srcip.keyword"]


def test_agg_safe_paths_falls_back_to_subfield_on_text():
    caps = {"data.domain": "text", "data.domain.keyword": "keyword"}
    assert indexer._agg_safe_paths("data.domain", caps) == ["data.domain.keyword"]


def test_agg_safe_paths_skips_unaggregatable_text():
    assert indexer._agg_safe_paths("data.domain", {"data.domain": "text"}) == []
