#!/usr/bin/env python3
"""No user-visible field is length-truncated by the output layer.

Redaction may mask content, never shorten it. Each test feeds a long value and
asserts the full value reaches the rendered output.
"""
from __future__ import annotations

import asyncio
import json
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import pytest

from mcp_server.core import audit
from mcp_server.tools import alert_summarize, alert_threat_card, dsl_query, wazuh_focused, wazuh_siem
from mcp_server.wazuh import indexer


def _run(coro):
    return asyncio.run(coro)


def _tool(fn):
    return getattr(fn, "__wrapped__", fn)


LONG_DESC = "Long rule description segment " * 8 + "DESC_TAIL"
LONG_UA = "curl/8.0 " + "U" * 200 + " UA_TAIL"
LONG_URL = "http://203.0.113.7/download/" + "p" * 200 + "?q=URL_TAIL"
LONG_LOG = "context: " + "L" * 300 + " LOG_TAIL"

DOC = {
    "@timestamp": "2026-01-01T00:00:00Z",
    "rule": {"id": "5710", "description": LONG_DESC, "level": 5},
    "data": {"srcip": "203.0.113.7", "user_agent": LONG_UA, "url": LONG_URL},
    "full_log": LONG_LOG,
}


def _hits():
    return {"hits": {"total": {"value": 1, "relation": "eq"},
                     "hits": [{"_source": DOC}]}}


def test_focused_markdown_keeps_the_full_log(monkeypatch):
    async def _post(body, index_pattern=None):
        return _hits()

    monkeypatch.setattr(wazuh_focused, "_wazuh_indexer_post", _post)

    out = _run(_tool(wazuh_focused.wazuh_alert_focused_crawl)(
        wazuh_focused.FocusedCrawlInput(src_ip="203.0.113.7", response_format="markdown")))

    assert LONG_LOG in out
    assert "LOG_TAIL" in out


def test_summarize_markdown_keeps_full_description_ua_and_url(monkeypatch):
    async def _post(body, index_pattern=None):
        return _hits()

    monkeypatch.setattr(alert_summarize, "_wazuh_indexer_post", _post)

    out = _run(_tool(alert_summarize.blueteam_wazuh_alert_summarize)(
        alert_summarize.AlertSummarizeInput(srcip="203.0.113.7", response_format="markdown")))

    assert "DESC_TAIL" in out
    assert "UA_TAIL" in out
    assert "URL_TAIL" in out


def test_threat_card_markdown_keeps_full_description_and_url(monkeypatch):
    async def _post(body, index_pattern=None):
        return _hits()

    monkeypatch.setattr(alert_threat_card, "_wazuh_indexer_post", _post)

    out = _run(_tool(alert_threat_card.blueteam_threat_card)(
        alert_threat_card.ThreatCardInput(srcip="45.33.32.156", include_threat_intel=False,
                                          response_format="markdown")))

    assert "DESC_TAIL" in out
    assert "URL_TAIL" in out


DEEP_URL = ("http://203.0.113.7/a/b/c/d/e/f/download.php"
            "?token=abc&cmd=id&payload=" + "z" * 300)
DEEP_LOG = ("attacker GET /var/www/html/uploads/2026/01/a/b/c/shell.php?x=1 "
            "then read /etc/passwd " + "L" * 300)
DEEP_UA = "Mozilla/5.0 " + "U" * 2000 + " UA_TAIL"


def _deep_doc():
    return {"@timestamp": "2026-01-01T00:00:00Z",
            "rule": {"id": "5710", "description": "rule", "level": 5},
            "data": {"srcip": "203.0.113.7", "url": DEEP_URL, "user_agent": DEEP_UA},
            "full_log": DEEP_LOG,
            "location": "/var/ossec/logs/alerts/alerts.json"}


def _deep_hits():
    return {"hits": {"total": {"value": 1, "relation": "eq"},
                     "hits": [{"_id": "id-deep", "sort": [0], "_source": _deep_doc()}]}}


def _assert_forensic_values_present(out: str) -> None:
    assert DEEP_LOG in out
    assert DEEP_URL in out
    assert DEEP_UA in out
    # The ordinary location field still takes the hash marker; the forensic
    # fields above must not.
    assert ".../alerts.json [h:" in out


def test_focused_json_preserves_deep_forensic_values(monkeypatch):
    async def _post(body, index_pattern=None):
        return _deep_hits()

    monkeypatch.setattr(wazuh_focused, "_wazuh_indexer_post", _post)

    out = _run(_tool(wazuh_focused.wazuh_alert_focused_crawl)(
        wazuh_focused.FocusedCrawlInput(src_ip="203.0.113.7", response_format="json")))

    _assert_forensic_values_present(out)


def test_focused_markdown_preserves_the_full_log(monkeypatch):
    async def _post(body, index_pattern=None):
        return _deep_hits()

    monkeypatch.setattr(wazuh_focused, "_wazuh_indexer_post", _post)

    out = _run(_tool(wazuh_focused.wazuh_alert_focused_crawl)(
        wazuh_focused.FocusedCrawlInput(src_ip="203.0.113.7", response_format="markdown")))

    # Markdown renders the log line only; URL and UA are JSON-only fields here.
    assert f"- Log: `{DEEP_LOG}`" in out


def test_indexer_search_toon_preserves_deep_forensic_values(monkeypatch):
    from toon_format import decode as toon_decode

    async def _post(body, index_pattern=None):
        return _deep_hits()

    monkeypatch.setattr(indexer, "_wazuh_indexer_post", _post)

    out = _run(_tool(wazuh_siem.blueteam_wazuh_indexer_search)(
        wazuh_siem.WazuhIndexerSearchInput(response_format="toon", limit=10)))

    data = toon_decode(out)
    doc = data["alerts"][0]
    assert doc["full_log"] == DEEP_LOG
    assert doc["data"]["url"] == DEEP_URL
    assert doc["data"]["user_agent"] == DEEP_UA


def test_dsl_query_markdown_over_cap_returns_a_notice(monkeypatch):
    huge_key = "u" * (audit.CHARACTER_LIMIT + 5_000)

    async def _post(body, index_pattern=None):
        return {"aggregations": {"by_url": {"buckets": [{"key": huge_key, "doc_count": 1}]}}}

    monkeypatch.setattr(dsl_query, "_wazuh_indexer_post", _post)

    out = _run(_tool(dsl_query.wazuh_alert_dsl_query)(
        dsl_query.DslQueryInput(aggs={"by_url": {"terms": {"field": "data.url", "size": 10}}},
                                response_format="markdown")))

    assert "exceeds the character limit" in out
    assert huge_key not in out
    assert "Narrow the aggregation" in out
    assert "response_format='json'" in out
    assert "blueteam_wazuh_forensic_window" not in out


def test_dsl_query_markdown_full_output_returns_the_body(monkeypatch):
    huge_key = "u" * (audit.CHARACTER_LIMIT + 5_000)

    async def _post(body, index_pattern=None):
        return {"aggregations": {"by_url": {"buckets": [{"key": huge_key, "doc_count": 1}]}}}

    monkeypatch.setattr(dsl_query, "_wazuh_indexer_post", _post)
    monkeypatch.setattr(audit, "BLUETEAM_ALLOW_UNTRUNCATED", True)
    monkeypatch.setattr(audit, "BLUETEAM_FORENSIC_TOKEN", "tok-12345678")

    out = _run(_tool(dsl_query.wazuh_alert_dsl_query)(
        dsl_query.DslQueryInput(aggs={"by_url": {"terms": {"field": "data.url", "size": 10}}},
                                response_format="markdown",
                                forensic_full_output=True,
                                forensic_token="tok-12345678")))

    assert "exceeds the character limit" not in out
    assert huge_key in out


def test_summarize_markdown_over_cap_returns_a_notice(monkeypatch):
    huge_desc = "D" * (audit.CHARACTER_LIMIT + 5_000)

    async def _post(body, index_pattern=None):
        return {"hits": {"total": {"value": 1, "relation": "eq"},
                         "hits": [{"_id": "id1", "sort": [0],
                                   "_source": {"@timestamp": "2026-01-01T00:00:00Z",
                                               "rule": {"id": "5710", "description": huge_desc,
                                                        "level": 5},
                                               "data": {"srcip": "203.0.113.7"}}}]}}

    monkeypatch.setattr(alert_summarize, "_wazuh_indexer_post", _post)

    out = _run(_tool(alert_summarize.blueteam_wazuh_alert_summarize)(
        alert_summarize.AlertSummarizeInput(srcip="203.0.113.7", response_format="markdown")))

    assert "exceeds the character limit" in out
    assert huge_desc not in out
    assert "blueteam_wazuh_indexer_search" in out


def _oversized_log():
    return "A" * (audit.CHARACTER_LIMIT + 5_000) + "END_MARKER"


def test_above_character_limit_returns_explicit_envelope(monkeypatch):
    def _hits_oversized():
        doc = _deep_doc()
        doc["full_log"] = _oversized_log()
        return {"hits": {"total": {"value": 1, "relation": "eq"},
                         "hits": [{"_id": "id-deep", "sort": [0], "_source": doc}]}}

    async def _post_oversized(body, index_pattern=None):
        return _hits_oversized()

    monkeypatch.setattr(wazuh_focused, "_wazuh_indexer_post", _post_oversized)

    out = _run(_tool(wazuh_focused.wazuh_alert_focused_crawl)(
        wazuh_focused.FocusedCrawlInput(src_ip="203.0.113.7", response_format="json")))

    parsed = json.loads(out)
    assert parsed["truncated"] is True
    assert "END_MARKER" not in out


def test_above_character_limit_markdown_omits_the_whole_oversized_document(monkeypatch):
    async def _post_oversized(body, index_pattern=None):
        doc = _deep_doc()
        doc["full_log"] = _oversized_log()
        return {"hits": {"total": {"value": 1, "relation": "eq"},
                         "hits": [{"_id": "id-deep", "sort": [0], "_source": doc}]}}

    monkeypatch.setattr(wazuh_focused, "_wazuh_indexer_post", _post_oversized)

    out = _run(_tool(wazuh_focused.wazuh_alert_focused_crawl)(
        wazuh_focused.FocusedCrawlInput(src_ip="203.0.113.7", response_format="markdown")))

    assert "END_MARKER" not in out
    assert "documents omitted to stay under the response limit" in out
    assert "oversized document" in out
    assert "blueteam_wazuh_forensic_window" in out
    assert "**next_cursor**" in out


def test_forensic_full_output_is_default_deny(monkeypatch):
    async def _post(body, index_pattern=None):
        return _deep_hits()

    monkeypatch.setattr(wazuh_focused, "_wazuh_indexer_post", _post)
    monkeypatch.setattr(audit, "BLUETEAM_ALLOW_UNTRUNCATED", False)

    with pytest.raises(ValueError, match="BLUETEAM_ALLOW_UNTRUNCATED"):
        _run(_tool(wazuh_focused.wazuh_alert_focused_crawl)(
            wazuh_focused.FocusedCrawlInput(src_ip="203.0.113.7", response_format="json",
                                            forensic_full_output=True,
                                            forensic_token="tok-12345678")))


def test_forensic_full_output_requires_matching_token(monkeypatch):
    async def _post(body, index_pattern=None):
        return _deep_hits()

    monkeypatch.setattr(wazuh_focused, "_wazuh_indexer_post", _post)
    monkeypatch.setattr(audit, "BLUETEAM_ALLOW_UNTRUNCATED", True)
    monkeypatch.setattr(audit, "BLUETEAM_FORENSIC_TOKEN", "tok-12345678")

    with pytest.raises(ValueError, match="forensic token"):
        _run(_tool(wazuh_focused.wazuh_alert_focused_crawl)(
            wazuh_focused.FocusedCrawlInput(src_ip="203.0.113.7", response_format="json",
                                            forensic_full_output=True,
                                            forensic_token="wrong-token")))

    async def _post_oversized(body, index_pattern=None):
        doc = _deep_doc()
        doc["full_log"] = _oversized_log()
        return {"hits": {"total": {"value": 1, "relation": "eq"},
                         "hits": [{"_id": "id-deep", "sort": [0], "_source": doc}]}}

    monkeypatch.setattr(wazuh_focused, "_wazuh_indexer_post", _post_oversized)

    out = _run(_tool(wazuh_focused.wazuh_alert_focused_crawl)(
        wazuh_focused.FocusedCrawlInput(src_ip="203.0.113.7", response_format="json",
                                        forensic_full_output=True,
                                        forensic_token="tok-12345678")))

    assert "END_MARKER" in out
    assert len(out) > audit.CHARACTER_LIMIT
