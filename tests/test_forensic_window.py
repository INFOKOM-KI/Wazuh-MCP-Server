#!/usr/bin/env python3
"""Automatic document paging and windowed forensic retrieval.

Paging may return fewer documents, never part of a document. A single field
longer than CHARACTER_LIMIT is retrieved through blueteam_wazuh_forensic_window,
whose windows concatenate to the complete post-redaction value.
"""
from __future__ import annotations

import asyncio
import json
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import pytest

from mcp_server.core import audit
from mcp_server.core.redact import _redact_alert_data
from mcp_server.tools import forensic_window, wazuh_focused, wazuh_siem
from mcp_server.wazuh import indexer


def _run(coro):
    return asyncio.run(coro)


def _tool(fn):
    return getattr(fn, "__wrapped__", fn)


def _big_doc(i: int, size: int = 50000) -> dict:
    return {
        "@timestamp": f"2026-01-0{i + 1}T00:00:00Z",
        "rule": {"id": "5710", "description": f"doc-{i}", "level": 5},
        "data": {"srcip": "203.0.113.7",
                 "url": f"http://203.0.113.7/a/b/c/d/e/page{i}.php?q=first&r=second",
                 "user_agent": "curl/8.0 " + "U" * 300},
        "full_log": f"DOC{i} " + "L" * size + " END",
    }


def _indexer_fake(docs: list[dict]):
    async def _post(body, index_pattern=None):
        after = body.get("search_after")
        start = int(after[0]) + 1 if after else 0
        hits = [{"_id": f"id{i}", "_source": docs[i], "sort": [i]}
                for i in range(start, len(docs))]
        return {"hits": {"total": {"value": len(docs), "relation": "eq"}, "hits": hits}}
    return _post


def _exhausted_fake(docs: list[dict]):
    """First request returns the page; any cursor follow-up returns no hits."""
    async def _post(body, index_pattern=None):
        total = {"value": len(docs), "relation": "eq"}
        if body.get("search_after"):
            return {"hits": {"total": total, "hits": []}}
        hits = [{"_id": f"id{i}", "_source": docs[i], "sort": [i]}
                for i in range(len(docs))]
        return {"hits": {"total": total, "hits": hits}}
    return _post


def _collect_pages(call, make_input, extract, parse=json.loads):
    """Walk next_cursor pages; return the concatenated items and page sizes."""
    items, sizes, cursor, pages = [], [], None, 0
    while True:
        out = call(make_input(cursor))
        sizes.append(len(out))
        data = parse(out)
        items.extend(extract(data))
        cursor = data.get("next_cursor")
        pages += 1
        assert pages < 20, "paging did not terminate"
        if not cursor:
            return items, sizes


def test_focused_json_pages_whole_documents(monkeypatch):
    docs = [_big_doc(i) for i in range(3)]
    monkeypatch.setattr(wazuh_focused, "_wazuh_indexer_post", _indexer_fake(docs))

    def call(params):
        return _run(_tool(wazuh_focused.wazuh_alert_focused_crawl)(params))

    def make_input(cursor):
        return wazuh_focused.FocusedCrawlInput(
            src_ip="203.0.113.7", response_format="json", sample_size=3, cursor=cursor)

    items, sizes = _collect_pages(call, make_input, lambda d: d["alerts"])
    assert all(size <= audit.CHARACTER_LIMIT for size in sizes)
    assert [item["_id"] for item in items] == ["id0", "id1", "id2"]
    assert len(items) == 3
    for i, item in enumerate(items):
        assert item["full_log"] == f"DOC{i} " + "L" * 50000 + " END"


def test_focused_markdown_pages_whole_documents(monkeypatch):
    docs = [_big_doc(i) for i in range(3)]
    monkeypatch.setattr(wazuh_focused, "_wazuh_indexer_post", _indexer_fake(docs))

    def call(params):
        return _run(_tool(wazuh_focused.wazuh_alert_focused_crawl)(params))

    def make_input(cursor):
        return wazuh_focused.FocusedCrawlInput(
            src_ip="203.0.113.7", response_format="markdown", sample_size=3, cursor=cursor)

    bodies, sizes, cursor, pages = [], [], None, 0
    while True:
        out = call(make_input(cursor))
        sizes.append(len(out))
        bodies.append(out)
        cursor = None
        for line in out.splitlines():
            if line.startswith("**next_cursor**"):
                cursor = line.split("`")[1]
        pages += 1
        assert pages < 20
        if not cursor:
            break
    joined = "\n".join(bodies)
    assert all(size <= audit.CHARACTER_LIMIT for size in sizes)
    for i in range(3):
        assert f"- Log: `{docs[i]['full_log']}`" in joined


def test_indexer_search_json_pages_whole_documents(monkeypatch):
    docs = [_big_doc(i) for i in range(3)]
    monkeypatch.setattr(indexer, "_wazuh_indexer_post", _indexer_fake(docs))

    def call(params):
        return _run(_tool(wazuh_siem.blueteam_wazuh_indexer_search)(params))

    def make_input(cursor):
        return wazuh_siem.WazuhIndexerSearchInput(
            limit=3, response_format="json", cursor=cursor)

    items, sizes = _collect_pages(call, make_input, lambda d: d["alerts"])
    assert all(size <= audit.CHARACTER_LIMIT for size in sizes)
    assert [item["_id"] for item in items] == ["id0", "id1", "id2"]
    assert all(item["full_log"].endswith(" END") for item in items)


def test_indexer_search_toon_pages_whole_documents(monkeypatch):
    from toon_format import decode as toon_decode

    docs = [_big_doc(i) for i in range(3)]
    monkeypatch.setattr(indexer, "_wazuh_indexer_post", _indexer_fake(docs))

    def call(params):
        return _run(_tool(wazuh_siem.blueteam_wazuh_indexer_search)(params))

    def make_input(cursor):
        return wazuh_siem.WazuhIndexerSearchInput(
            limit=3, response_format="toon", cursor=cursor)

    items, sizes = _collect_pages(call, make_input, lambda d: d["alerts"], parse=toon_decode)
    assert all(size <= audit.CHARACTER_LIMIT for size in sizes)
    assert [item["_id"] for item in items] == ["id0", "id1", "id2"]


def test_indexer_search_empty_page_terminates(monkeypatch):
    docs = [_big_doc(i) for i in range(3)]
    monkeypatch.setattr(indexer, "_wazuh_indexer_post", _exhausted_fake(docs))

    def call(params):
        return _run(_tool(wazuh_siem.blueteam_wazuh_indexer_search)(params))

    first = json.loads(call(wazuh_siem.WazuhIndexerSearchInput(
        limit=3, response_format="json")))
    assert first["alerts"]
    assert first["next_cursor"]

    second = json.loads(call(wazuh_siem.WazuhIndexerSearchInput(
        limit=3, response_format="json", cursor=first["next_cursor"])))
    assert second["alerts"] == []
    assert second["next_cursor"] is None
    assert second["has_more"] is False


def test_indexer_search_toon_empty_page_terminates(monkeypatch):
    from toon_format import decode as toon_decode

    docs = [_big_doc(i) for i in range(3)]
    monkeypatch.setattr(indexer, "_wazuh_indexer_post", _exhausted_fake(docs))

    def call(params):
        return _run(_tool(wazuh_siem.blueteam_wazuh_indexer_search)(params))

    first = toon_decode(call(wazuh_siem.WazuhIndexerSearchInput(
        limit=3, response_format="toon")))
    assert first["alerts"]
    assert first["next_cursor"]

    second = toon_decode(call(wazuh_siem.WazuhIndexerSearchInput(
        limit=3, response_format="toon", cursor=first["next_cursor"])))
    assert second["alerts"] == []
    assert second["next_cursor"] is None
    assert second["has_more"] is False


def test_indexer_search_initially_empty(monkeypatch):
    async def _post(body, index_pattern=None):
        return {"hits": {"total": {"value": 0, "relation": "eq"}, "hits": []}}

    monkeypatch.setattr(indexer, "_wazuh_indexer_post", _post)
    data = json.loads(_run(_tool(wazuh_siem.blueteam_wazuh_indexer_search)(
        wazuh_siem.WazuhIndexerSearchInput(limit=3, response_format="json"))))
    assert data["alerts"] == []
    assert data["next_cursor"] is None
    assert data["has_more"] is False


def test_focused_empty_page_terminates(monkeypatch):
    docs = [_big_doc(i) for i in range(3)]
    monkeypatch.setattr(wazuh_focused, "_wazuh_indexer_post", _exhausted_fake(docs))

    def call(params):
        return _run(_tool(wazuh_focused.wazuh_alert_focused_crawl)(params))

    first = json.loads(call(wazuh_focused.FocusedCrawlInput(
        src_ip="203.0.113.7", response_format="json", sample_size=3)))
    assert first["alerts"]
    assert first["next_cursor"]

    second = json.loads(call(wazuh_focused.FocusedCrawlInput(
        src_ip="203.0.113.7", response_format="json", sample_size=3,
        cursor=first["next_cursor"])))
    assert second["alerts"] == []
    assert second["next_cursor"] is None


def test_oversized_document_is_exposed_with_its_id(monkeypatch):
    huge = _big_doc(0, size=audit.CHARACTER_LIMIT + 5_000)
    small = _big_doc(1)
    monkeypatch.setattr(wazuh_focused, "_wazuh_indexer_post", _indexer_fake([huge, small]))

    out = _run(_tool(wazuh_focused.wazuh_alert_focused_crawl)(
        wazuh_focused.FocusedCrawlInput(src_ip="203.0.113.7", response_format="json",
                                        sample_size=2)))
    data = json.loads(out)
    assert len(out) <= audit.CHARACTER_LIMIT
    assert data["truncated"] is True
    assert data["alerts"] == []
    assert data["oversized_documents"][0]["_id"] == "id0"
    assert data["next_cursor"]

    out2 = _run(_tool(wazuh_focused.wazuh_alert_focused_crawl)(
        wazuh_focused.FocusedCrawlInput(src_ip="203.0.113.7", response_format="json",
                                        sample_size=2, cursor=data["next_cursor"])))
    data2 = json.loads(out2)
    assert [a["_id"] for a in data2["alerts"]] == ["id1"]


def test_local_alerts_paging_with_real_file(monkeypatch, tmp_path):
    docs = [_big_doc(i) for i in range(2)]
    alerts_file = tmp_path / "alerts.json"
    alerts_file.write_text("\n".join(json.dumps(d) for d in docs) + "\n", encoding="utf-8")
    monkeypatch.setattr(wazuh_siem, "_WAZUH_ALERTS_PATH", str(alerts_file))

    def call(params):
        return _run(_tool(wazuh_siem.blueteam_wazuh_alerts)(params))

    def make_input(cursor):
        return wazuh_siem.WazuhAlertsInput(limit=2, response_format="json", cursor=cursor)

    items, sizes = _collect_pages(call, make_input, lambda d: d["alerts"])
    assert all(size <= audit.CHARACTER_LIMIT for size in sizes)
    assert [item["rule"]["description"] for item in items] == ["doc-0", "doc-1"]
    assert all(item["full_log"].endswith(" END") for item in items)


def _window_doc() -> dict:
    return {
        "full_log": ("start " + "P" * 60000 + " path=/var/www/html/a/b/c/deep.php?cmd=id "
                     + "private=10.0.0.5 " + "Q" * 60000 + " ENDW"),
        "data": {"url": "http://203.0.113.7/a/b/c/d/e.php?token=abc&cmd=id&z=" + "z" * 3000,
                 "user_agent": "Mozilla/5.0 " + "U" * 3000 + " UA_TAIL"},
    }


def _window_fake(doc: dict):
    async def _post(body, index_pattern=None):
        return {"hits": {"hits": [{"_id": "idw", "_source": doc}]}}
    return _post


def _collect_windows(field: str, expected_len: int) -> list[str]:
    chunks, offset, calls = [], 0, 0
    while True:
        out = _run(forensic_window.blueteam_wazuh_forensic_window(
            forensic_window.ForensicWindowInput(doc_id="idw", field=field,
                                                offset=offset, max_chars=20000)))
        data = json.loads(out)
        assert data["offset"] == offset
        assert data["max_chars"] == 20000
        assert data["field_length"] == expected_len
        chunks.append(data["window"])
        calls += 1
        assert calls < 30
        if not data["has_more"]:
            assert data["next_offset"] is None
            return chunks
        assert data["next_offset"] == offset + len(data["window"])
        offset = data["next_offset"]


def test_forensic_window_full_log_equals_post_redaction_value(monkeypatch):
    doc = _window_doc()
    monkeypatch.setattr(forensic_window, "_wazuh_indexer_post", _window_fake(doc))
    expected = _redact_alert_data(doc)["full_log"]

    joined = "".join(_collect_windows("full_log", len(expected)))

    assert joined == expected
    assert "10.***.***.5" in joined
    assert "10.0.0.5" not in joined
    assert "/var/www/html/a/b/c/deep.php?cmd=id" in joined
    assert "..." not in joined


def test_forensic_window_user_agent_and_url(monkeypatch):
    doc = _window_doc()
    monkeypatch.setattr(forensic_window, "_wazuh_indexer_post", _window_fake(doc))
    redacted = _redact_alert_data(doc)

    ua = "".join(_collect_windows("user_agent", len(redacted["data"]["user_agent"])))
    url = "".join(_collect_windows("data.url", len(redacted["data"]["url"])))

    assert ua == redacted["data"]["user_agent"]
    assert ua.endswith(" UA_TAIL")
    assert url == redacted["data"]["url"]
    assert url.endswith("z" * 20)


def test_forensic_window_offset_past_end(monkeypatch):
    doc = _window_doc()
    monkeypatch.setattr(forensic_window, "_wazuh_indexer_post", _window_fake(doc))
    expected = _redact_alert_data(doc)["full_log"]

    out = _run(forensic_window.blueteam_wazuh_forensic_window(
        forensic_window.ForensicWindowInput(doc_id="idw", field="full_log",
                                            offset=len(expected) + 100)))
    data = json.loads(out)
    assert data["window"] == ""
    assert data["has_more"] is False
    assert data["next_offset"] is None


def test_forensic_window_missing_document(monkeypatch):
    async def _post(body, index_pattern=None):
        return {"hits": {"hits": []}}

    monkeypatch.setattr(forensic_window, "_wazuh_indexer_post", _post)
    data = json.loads(_run(forensic_window.blueteam_wazuh_forensic_window(
        forensic_window.ForensicWindowInput(doc_id="missing", field="full_log"))))
    assert data["error"] == "document not found"


def test_forensic_window_rejects_arbitrary_field():
    with pytest.raises(Exception):
        forensic_window.ForensicWindowInput(doc_id="idw", field="data.command")
