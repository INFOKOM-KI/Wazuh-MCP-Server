#!/usr/bin/env python3
"""W6 syscheck field coverage through the validated field-selection path."""
from __future__ import annotations

import asyncio
import json
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import pytest

from mcp_server.tools import wazuh_scanning
from mcp_server.wazuh import indexer


def _run(coro):
    return asyncio.run(coro)


def _tool(fn):
    return getattr(fn, "__wrapped__", fn)


def _capture(monkeypatch, response=None):
    captured = {}
    posted = []

    async def _post(body, index_pattern=None):
        captured["body"] = body
        posted.append(body)
        return response if response is not None else {
            "hits": {"total": {"value": 0}}, "aggregations": {}}

    monkeypatch.setattr(wazuh_scanning, "_wazuh_indexer_post", _post)
    monkeypatch.setattr(wazuh_scanning, "_parse_time_window",
                        lambda since, until: ("2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"))
    captured["posted"] = posted
    return captured


def _filters(body):
    return body["query"]["bool"]["filter"]


def _run_syscheck(params):
    return _run(_tool(wazuh_scanning.blueteam_wazuh_syscheck)(params))


@pytest.mark.parametrize("field", sorted(indexer._SYSCHECK_FIELD_PATHS))
def test_every_template_syscheck_leaf_is_accepted(field):
    params = wazuh_scanning.SyscheckInput(syscheck_field=field, syscheck_value="x")
    assert params.syscheck_field == field


def test_syscheck_field_set_is_the_template_size():
    assert len(indexer._SYSCHECK_FIELD_PATHS) == 45
    assert all(f.startswith("syscheck.") for f in indexer._SYSCHECK_FIELD_PATHS)


@pytest.mark.parametrize("field", ["syscheck.nope", "rule.id", "data.url", "syscheck.", ""])
def test_non_syscheck_fields_are_rejected(field):
    with pytest.raises(ValueError):
        wazuh_scanning.SyscheckInput(syscheck_field=field, syscheck_value="x")


def test_field_and_value_must_travel_together():
    with pytest.raises(ValueError):
        wazuh_scanning.SyscheckInput(syscheck_value="x")
    with pytest.raises(ValueError):
        wazuh_scanning.SyscheckInput(syscheck_field="syscheck.md5_after")


def test_syscheck_field_builds_exact_term_filter(monkeypatch):
    captured = _capture(monkeypatch)
    _run_syscheck(wazuh_scanning.SyscheckInput(
        syscheck_field="syscheck.md5_after", syscheck_value="abc123", response_format="json"))
    assert {"term": {"syscheck.md5_after": "abc123"}} in _filters(captured["body"])


def test_syscheck_field_value_wildcards_switch_to_wildcard(monkeypatch):
    captured = _capture(monkeypatch)
    _run_syscheck(wazuh_scanning.SyscheckInput(
        syscheck_field="syscheck.path", syscheck_value="/etc/*", response_format="json"))
    assert {"wildcard": {"syscheck.path": "/etc/*"}} in _filters(captured["body"])


def test_changed_attribute_builds_contains_wildcard(monkeypatch):
    captured = _capture(monkeypatch)
    _run_syscheck(wazuh_scanning.SyscheckInput(changed_attribute="md5", response_format="json"))
    assert {"wildcard": {"syscheck.changed_attributes": "*md5*"}} in _filters(captured["body"])


@pytest.mark.parametrize("field,value", [
    ("syscheck.value_name", "HKLM\\Software\\Run"),
    ("syscheck.arch", "[x64]"),
    ("syscheck.value_type", "REG_SZ"),
])
def test_registry_fields_are_queried(monkeypatch, field, value):
    captured = _capture(monkeypatch)
    _run_syscheck(wazuh_scanning.SyscheckInput(syscheck_field=field, syscheck_value=value,
                                               response_format="json"))
    assert {"term": {field: value}} in _filters(captured["body"])


@pytest.mark.parametrize("field", [
    "syscheck.md5_after", "syscheck.sha1_after", "syscheck.sha256_after",
    "syscheck.md5_before", "syscheck.sha1_before", "syscheck.sha256_before"])
def test_hash_fields_are_queried(monkeypatch, field):
    captured = _capture(monkeypatch)
    _run_syscheck(wazuh_scanning.SyscheckInput(syscheck_field=field, syscheck_value="d41d8cd9",
                                               response_format="json"))
    assert {"term": {field: "d41d8cd9"}} in _filters(captured["body"])


@pytest.mark.parametrize("field", [
    "syscheck.uid_after", "syscheck.uname_after", "syscheck.gid_after",
    "syscheck.gname_after", "syscheck.perm_after", "syscheck.mode"])
def test_ownership_and_permission_fields_are_queried(monkeypatch, field):
    captured = _capture(monkeypatch)
    _run_syscheck(wazuh_scanning.SyscheckInput(syscheck_field=field, syscheck_value="0",
                                               response_format="json"))
    assert {"term": {field: "0"}} in _filters(captured["body"])


@pytest.mark.parametrize("field,value", [
    ("syscheck.mtime_before", "2026-01-01T00:00:00Z"),
    ("syscheck.size_after", "4096"),
])
def test_before_after_fields_are_queried(monkeypatch, field, value):
    captured = _capture(monkeypatch)
    _run_syscheck(wazuh_scanning.SyscheckInput(syscheck_field=field, syscheck_value=value,
                                               response_format="json"))
    assert {"term": {field: value}} in _filters(captured["body"])


def test_include_diff_requests_and_returns_diff(monkeypatch):
    response = {"hits": {"total": {"value": 1}}, "aggregations": {"diff_samples": {"hits": {"hits": [
        {"_source": {"syscheck": {"path": "/tmp/app.conf", "event": "modified",
                                  "diff": "-old_line +new_line"}}}]}}}}
    captured = _capture(monkeypatch, response)

    out = _run_syscheck(wazuh_scanning.SyscheckInput(include_diff=True))

    includes = captured["body"]["aggs"]["diff_samples"]["top_hits"]["_source"]["includes"]
    assert "syscheck.diff" in includes
    assert "-old_line +new_line" in out


def test_by_field_aggregates_on_a_validated_leaf(monkeypatch):
    async def _caps(fields, index_pattern=None):
        return {"syscheck.uid_after": "keyword"}

    monkeypatch.setattr(wazuh_scanning, "_wazuh_indexer_field_caps", _caps)
    response = {"hits": {"total": {"value": 3}},
                "aggregations": {"by_field": {"buckets": [{"key": "1000", "doc_count": 3}]}}}
    captured = _capture(monkeypatch, response)

    out = json.loads(_run_syscheck(wazuh_scanning.SyscheckInput(
        by_field="syscheck.uid_after", response_format="json")))

    assert captured["body"]["aggs"]["by_field"]["terms"]["field"] == "syscheck.uid_after"
    assert out["aggregations"]["by_field"]["buckets"][0]["key"] == "1000"


def test_by_field_rejects_unmapped_field_without_querying(monkeypatch):
    async def _caps(fields, index_pattern=None):
        return {}

    monkeypatch.setattr(wazuh_scanning, "_wazuh_indexer_field_caps", _caps)
    captured = _capture(monkeypatch)

    out = json.loads(_run_syscheck(wazuh_scanning.SyscheckInput(by_field="syscheck.uid_after")))

    assert "not aggregatable" in out["error"]
    assert captured["posted"] == []


def test_by_field_masks_identity_bucket_keys(monkeypatch):
    async def _caps(fields, index_pattern=None):
        return {"syscheck.uname_after": "keyword"}

    monkeypatch.setattr(wazuh_scanning, "_wazuh_indexer_field_caps", _caps)
    response = {"hits": {"total": {"value": 2}},
                "aggregations": {"by_field": {"buckets": [
                    {"key": "webserver-01", "doc_count": 2}]}}}
    _capture(monkeypatch, response)

    out = _run_syscheck(wazuh_scanning.SyscheckInput(by_field="syscheck.uname_after"))

    assert "webserver-01" not in out


def test_validated_field_on_absent_mapping_does_not_fail(monkeypatch):
    async def _caps(fields, index_pattern=None):
        return {}

    monkeypatch.setattr(wazuh_scanning, "_wazuh_indexer_field_caps", _caps)
    captured = _capture(monkeypatch)

    out = json.loads(_run_syscheck(wazuh_scanning.SyscheckInput(
        syscheck_field="syscheck.value_name", syscheck_value="Run", response_format="json")))

    assert captured["posted"], "filter query should still run"
    assert out["total"] == 0
