#!/usr/bin/env python3
"""Alert-data tools must run their output through the redaction pipeline.

Covers the three raw @mcp.tool handlers that read the Wazuh Indexer directly:
victim agent names in agents[]/top_agents[] are masked under protect_victim.
"""
from __future__ import annotations

import asyncio
import json
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

from mcp_server.core import redact as redact_mod
from mcp_server.tools import alert_compare, correlation


def _run(coro):
    return asyncio.run(coro)


def _tool(fn):
    return getattr(fn, "__wrapped__", fn)


def _profile_body():
    return {
        "hits": {"total": {"value": 5, "relation": "eq"}},
        "aggregations": {
            "top_rules": {"buckets": [{"key": "5710", "doc_count": 5}]},
            "by_level": {"buckets": [{"key": "high", "doc_count": 5}]},
            "top_agents": {"buckets": [{"key": "web01", "doc_count": 5}]},
        },
    }


def test_alert_compare_masks_agent_bucket_names(monkeypatch):
    async def _post(body, index_pattern=None):
        return _profile_body()

    monkeypatch.setattr(alert_compare, "_wazuh_indexer_post", _post)
    monkeypatch.setattr(redact_mod, "BLUETEAM_REDACTION_POLICY", "protect_victim")
    out = json.loads(_run(_tool(alert_compare.blueteam_wazuh_alert_compare)(
        alert_compare.AlertCompareInput(srcip_a="1.1.1.1", srcip_b="2.2.2.2",
                                        response_format="json"))))
    assert out["ip_a"]["agents"][0]["name"].startswith("w***1")
    assert out["ip_a"]["top_rules"][0]["id"] == "5710"


def test_investigate_ip_masks_top_agents(monkeypatch):
    async def _post(body, index_pattern=None):
        return {
            "hits": {"total": {"value": 5}},
            "aggregations": {
                "top_rules": {"buckets": [{"key": "5710", "doc_count": 5}]},
                "top_agents": {"buckets": [{"key": "web01", "doc_count": 5}]},
                "severity": {"buckets": [{"key": "high", "doc_count": 5}]},
                "over_time": {"buckets": []},
                "by_country": {"buckets": []},
            },
        }

    monkeypatch.setattr(correlation, "_wazuh_indexer_post", _post)
    monkeypatch.setattr(redact_mod, "BLUETEAM_REDACTION_POLICY", "protect_victim")
    out = json.loads(_run(_tool(correlation.blueteam_investigate_ip)(
        correlation.InvestigateIpInput(srcip="203.0.113.7", response_format="json"))))
    assert out["top_agents"][0]["name"].startswith("w***1")


def test_aggregate_analysis_masks_agent_buckets(monkeypatch):
    async def _post(body, index_pattern=None):
        return {
            "hits": {"total": {"value": 5}},
            "aggregations": {
                "top_rules": {"buckets": []},
                "top_agents": {"buckets": [{"key": "web01", "doc_count": 5}]},
                "severity_bands": {"buckets": []},
            },
        }

    async def _merged(*args, **kwargs):
        return {}, [], []

    async def _noop(*args, **kwargs):
        return None

    monkeypatch.setattr(correlation, "_wazuh_indexer_post", _post)
    monkeypatch.setattr(correlation, "_srcip_aggs_merged", _merged)
    monkeypatch.setattr(correlation, "_correct_srcip_counts", _noop)
    out = json.loads(_run(_tool(correlation.wazuh_alert_aggregate_analysis)(
        correlation.AggregateAnalysisInput(response_format="json",
                                           redaction_policy="protect_victim"))))
    assert out["aggregations"]["top_agents"]["buckets"][0]["key"].startswith("w***1")


def test_reveal_identities_field_is_accepted():
    params = correlation.AggregateAnalysisInput(reveal_identities=True,
                                                forensic_token="tok-12345678")
    assert params.reveal_identities is True
    assert params.forensic_token == "tok-12345678"
