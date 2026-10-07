#!/usr/bin/env python3
"""No user-visible field is length-truncated by the output layer.

Redaction may mask content, never shorten it. Each test feeds a long value and
asserts the full value reaches the rendered output.
"""
from __future__ import annotations

import asyncio
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

from mcp_server.tools import alert_summarize, alert_threat_card, wazuh_focused


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
