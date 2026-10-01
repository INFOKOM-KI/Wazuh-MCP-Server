#!/usr/bin/env python3
"""Tests for index schema explorer."""
from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import asyncio
import json


def test_flatten_props_nested():
    from mcp_server.tools.index_schema import _flatten_props
    props = {
        "data": {"properties": {"srcip": {"type": "keyword"},
                                 "url": {"type": "text", "fields": {"keyword": {"type": "keyword"}}}}},
        "rule": {"properties": {"id": {"type": "keyword"}}},
    }
    out = {}
    _flatten_props("", props, out)
    assert "data.srcip" in out
    assert "data.url" in out
    assert "rule.id" in out


def test_field_info_keyword():
    from mcp_server.tools.index_schema import _field_info
    info = _field_info({"type": "keyword"})
    assert info["type"] == "keyword"
    assert info["has_keyword_subfield"] is False
    assert info["agg_safe"] is True


def test_field_info_text_with_keyword_subfield():
    from mcp_server.tools.index_schema import _field_info
    info = _field_info({"type": "text", "fields": {"keyword": {"type": "keyword"}}})
    assert info["type"] == "text"
    assert info["has_keyword_subfield"] is True
    # The sub-field aggregates, but the bare name is text: a terms agg on
    # `rule.id` fails on that index, which is what the shard failures showed.
    assert info["agg_safe"] is False


def test_field_info_text_no_keyword():
    from mcp_server.tools.index_schema import _field_info
    info = _field_info({"type": "text"})
    assert info["has_keyword_subfield"] is False
    assert info["agg_safe"] is False  # text without .keyword is NOT agg-safe


def test_input_model():
    from mcp_server.tools.index_schema import IndexSchemaInput
    inp = IndexSchemaInput(fields=["data.srcip", "rule.groups"])
    assert inp.fields == ["data.srcip", "rule.groups"]
    inp2 = IndexSchemaInput()  # default
    assert inp2.index == "wazuh-alerts-*"
    assert inp2.fields == []


def _merged_schema(mapping, fields, monkeypatch):
    from mcp_server.tools import index_schema

    async def _fake_mapping(index_pattern=None):
        return mapping

    monkeypatch.setattr(index_schema, "_wazuh_indexer_mapping", _fake_mapping)
    tool = getattr(index_schema.blueteam_index_schema, "__wrapped__",
                   index_schema.blueteam_index_schema)
    payload = asyncio.run(tool(index_schema.IndexSchemaInput(
        fields=fields, response_format="json")))
    return {r["field"]: r for r in json.loads(payload)["results"]}


def _mapping(**per_index_types):
    return {name: {"mappings": {"properties": {
                "rule": {"properties": {"id": {"type": ftype}}}}}}
            for name, ftype in per_index_types.items()}


def test_field_mapped_differently_across_indices_is_not_agg_safe(monkeypatch):
    """A text index behind a keyword index fails the aggregation on its shards and
    says nothing, so the merged mapping has to report the disagreement."""
    mapping = _mapping(**{"wazuh-alerts-2026.05.21": "keyword",
                          "wazuh-alerts-2026.06.04": "text"})
    row = _merged_schema(mapping, ["rule.id"], monkeypatch)["rule.id"]
    assert row["agg_safe"] is False
    assert row["mixed_mapping"] == {"keyword": 1, "text": 1}


def test_uniform_mapping_reports_no_mix(monkeypatch):
    mapping = _mapping(**{"wazuh-alerts-2026.05.21": "keyword",
                          "wazuh-alerts-2026.06.04": "keyword"})
    row = _merged_schema(mapping, ["rule.id"], monkeypatch)["rule.id"]
    assert row["agg_safe"] is True
    assert "mixed_mapping" not in row


def test_keyword_mixed_with_text_leaves_no_aggregatable_name(monkeypatch):
    """Neither `rule.id` nor `rule.id.keyword` spans a corpus that mixes the two:
    the bare name fails on the text indices, .keyword does not exist on the others."""
    mapping = {
        "newer": {"mappings": {"properties": {"rule": {"properties": {
            "id": {"type": "keyword"}}}}}},
        "older": {"mappings": {"properties": {"rule": {"properties": {
            "id": {"type": "text", "fields": {"keyword": {"type": "keyword"}}}}}}}},
    }
    row = _merged_schema(mapping, ["rule.id"], monkeypatch)["rule.id"]
    assert row["agg_safe"] is False
    assert row["agg_safe_field"] is None
    assert row["mixed_mapping"] == {"keyword": 1, "text+keyword": 1}


def test_uniform_text_with_keyword_names_the_subfield(monkeypatch):
    mapping = {name: {"mappings": {"properties": {"rule": {"properties": {
                "id": {"type": "text", "fields": {"keyword": {"type": "keyword"}}}}}}}}
            for name in ("old-a", "old-b")}
    row = _merged_schema(mapping, ["rule.id"], monkeypatch)["rule.id"]
    assert row["agg_safe"] is False
    assert row["agg_safe_field"] == "rule.id.keyword"


def test_the_diverging_indices_are_named(monkeypatch):
    mapping = {}
    for day in (1, 2, 3):
        mapping[f"wazuh-alerts-2026.10.0{day}"] = {"mappings": {"properties": {
            "rule": {"properties": {"id": {"type": "keyword"}}}}}}
    for day in (21, 22):
        mapping[f"wazuh-alerts-2026.05.{day}"] = {"mappings": {"properties": {
            "rule": {"properties": {"id": {
                "type": "text", "fields": {"keyword": {"type": "keyword"}}}}}}}}
    row = _merged_schema(mapping, ["rule.id"], monkeypatch)["rule.id"]
    assert row["agg_safe"] is False
    assert row["mixed_mapping"] == {"keyword": 3, "text+keyword": 2}
    assert row["mixed_indices"] == ["wazuh-alerts-2026.05.21", "wazuh-alerts-2026.05.22"]


def test_markdown_warns_when_a_field_is_mixed(monkeypatch):
    from mcp_server.tools import index_schema
    mapping = _mapping(**{"wazuh-alerts-2026.05.21": "keyword",
                          "wazuh-alerts-2026.06.04": "text"})

    async def _fake_mapping(index_pattern=None):
        return mapping

    monkeypatch.setattr(index_schema, "_wazuh_indexer_mapping", _fake_mapping)
    tool = getattr(index_schema.blueteam_index_schema, "__wrapped__",
                   index_schema.blueteam_index_schema)
    rendered = asyncio.run(tool(index_schema.IndexSchemaInput(fields=["rule.id"])))
    assert "no field name spans every index" in rendered
    assert "reindex the divergent indices" in rendered
    assert "`rule.id`:" in rendered


if __name__ == "__main__":
    import sys, traceback
    tests = [f for f in dir() if f.startswith("test_")]
    passed = 0
    for t in tests:
        try:
            globals()[t]()
            print(f"  PASS {t}")
            passed += 1
        except Exception:
            print(f"  FAIL {t}")
            traceback.print_exc()
    print(f"\n{passed}/{len(tests)} passed")
    sys.exit(0 if passed == len(tests) else 1)
