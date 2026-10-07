#!/usr/bin/env python3
"""Default-path compatibility for the syscheck tool (W6).

The existing call with no W6-specific parameters must produce the same query body
and response contract as before the new options landed.
"""
from __future__ import annotations

import asyncio
import json
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

from mcp_server.tools import wazuh_scanning


def _run(coro):
    return asyncio.run(coro)


def _tool(fn):
    return getattr(fn, "__wrapped__", fn)


def test_default_syscheck_query_body_is_unchanged(monkeypatch):
    captured = {}

    async def _post(body, index_pattern=None):
        captured["body"] = body
        return {"hits": {"total": {"value": 0}}, "aggregations": {}}

    monkeypatch.setattr(wazuh_scanning, "_wazuh_indexer_post", _post)
    monkeypatch.setattr(wazuh_scanning, "_parse_time_window",
                        lambda since, until: ("2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"))

    out = json.loads(_run(_tool(wazuh_scanning.blueteam_wazuh_syscheck)(
        wazuh_scanning.SyscheckInput(response_format="json"))))

    assert captured["body"] == {
        "size": 0,
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": "2026-01-01T00:00:00Z",
                                      "lt": "2026-01-02T00:00:00Z",
                                      "format": "strict_date_optional_time"}}},
        ]}},
        "aggs": {
            "by_agent": {"terms": {"field": "agent.name", "size": 20}},
            "by_event": {"terms": {"field": "syscheck.event", "size": 3}},
            "by_path": {"terms": {"field": "syscheck.path", "size": 20,
                                  "order": {"_count": "desc"}}},
        },
    }
    assert out == {"total": 0, "aggregations": {}}


def test_default_markdown_has_no_w6_sections(monkeypatch):
    async def _post(body, index_pattern=None):
        return {"hits": {"total": {"value": 0}}, "aggregations": {}}

    monkeypatch.setattr(wazuh_scanning, "_wazuh_indexer_post", _post)

    out = _run(_tool(wazuh_scanning.blueteam_wazuh_syscheck)(wazuh_scanning.SyscheckInput()))

    assert "Sampled Diffs" not in out
    assert "By `" not in out
    assert "No FIM events found" in out
