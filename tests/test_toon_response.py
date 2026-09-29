#!/usr/bin/env python3
"""
PY-TOON response_format contract.
Covers the opt-in path end to end: encoding after redaction, the oversize
refusal, the missing-encoder degradation, and the JSON/markdown defaults the
in-process graph orchestrators json.loads.
"""
from __future__ import annotations
import json
import os
import sys
from types import SimpleNamespace

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "pw")

import pytest
from mcp_server.core.toon import encode_toon
from mcp_server.core.tool_decorator import blueteam_tool

toon_format = pytest.importorskip("toon_format")

_TOON = SimpleNamespace(response_format="toon")
_DEFAULT = SimpleNamespace()


@blueteam_tool(name="blueteam_test_toon_dict", audit=False, truncate=True, redact=True)
async def _dict_tool(params=None) -> dict:
    return {"rows": [{"ip": "10.1.2.3", "email": "analyst@csirt.local", "n": 1}]}


@blueteam_tool(name="blueteam_test_toon_plain", audit=False, truncate=True, redact=False)
async def _plain_tool(params=None) -> str:
    return "degraded: upstream unavailable"


@pytest.mark.asyncio
async def test_toon_dict_encodes_after_redaction():
    out = await _dict_tool(_TOON)
    data = toon_format.decode(out)
    assert data["rows"][0]["ip"] != "10.1.2.3"
    assert data["rows"][0]["email"] != "analyst@csirt.local"
    assert data["rows"][0]["n"] == 1


@pytest.mark.asyncio
async def test_default_format_still_json_for_dicts():
    out = await _dict_tool(_DEFAULT)
    assert json.loads(out)["rows"][0]["n"] == 1


@pytest.mark.asyncio
async def test_toon_string_result_passes_through():
    assert await _plain_tool(_TOON) == "degraded: upstream unavailable"


def test_encode_toon_refuses_oversize_with_json_error():
    out = encode_toon({"rows": list(range(20))}, limit=5)
    data = json.loads(out)
    assert data["truncated"] is True
    assert "exceeds" in data["error"]


def test_encode_toon_missing_encoder_degrades(monkeypatch):
    monkeypatch.setitem(sys.modules, "toon_format", None)
    data = json.loads(encode_toon({"n": 1}))
    assert "unavailable" in data["error"]


def test_high_volume_tools_accept_toon():
    from mcp_server.tools.wazuh_siem import WazuhAlertsInput, WazuhIndexerSearchInput
    from mcp_server.tools.dsl_query import DslQueryInput
    from mcp_server.tools.wazuh_timeline import WazuhAlertTimelineInput
    from mcp_server.tools.ioc_tools import IocExtractInput, IocLifecycleInput
    from mcp_server.tools.urlhaus import UrlhausLookupInput, UrlhausHashInput, UrlhausBulkInput
    from mcp_server.tools.otx_lookup import OtxLookupInput, OtxBulkInput
    from mcp_server.tools.cluster import AlertClusterInput, AlertClusterAssignInput
    from mcp_server.tools.correlation import (
        AggregateAnalysisInput, ThreeSumCorrelationInput, InvestigateIpInput,
    )

    cases = [
        WazuhAlertsInput(response_format="toon"),
        WazuhIndexerSearchInput(response_format="toon"),
        DslQueryInput(aggs={"by_agent": {"terms": {"field": "agent.name"}}}, response_format="toon"),
        WazuhAlertTimelineInput(response_format="toon"),
        IocExtractInput(text="srcip=1.2.3.4", response_format="toon"),
        IocLifecycleInput(response_format="toon"),
        UrlhausLookupInput(url="http://evil.example/x", response_format="toon"),
        UrlhausHashInput(file_hash="a" * 32, response_format="toon"),
        UrlhausBulkInput(urls=["http://evil.example/x"], response_format="toon"),
        OtxLookupInput(indicator="evil.example.com", response_format="toon"),
        OtxBulkInput(indicators=["evil.example.com"], response_format="toon"),
        AlertClusterInput(response_format="toon"),
        AlertClusterAssignInput(srcip="10.0.0.1", response_format="toon"),
        AggregateAnalysisInput(response_format="toon"),
        ThreeSumCorrelationInput(response_format="toon"),
        InvestigateIpInput(srcip="10.0.0.1", response_format="toon"),
    ]
    assert all(c.response_format == "toon" for c in cases)


@pytest.mark.asyncio
async def test_timeline_toon_branch_roundtrips(monkeypatch):
    from mcp_server.tools import wazuh_timeline as tl

    async def _fake_post(body, index_pattern=None):
        return {
            "hits": {"total": {"value": 3, "relation": "eq"}},
            "aggregations": {"over_time": {"buckets": [{
                "key_as_string": "2026-09-29T00:00:00.000Z", "key": 1, "doc_count": 3,
                "by_level": {"buckets": [{"key": "high", "doc_count": 2}]},
                "top_rules": {"buckets": [{"key": "5710", "doc_count": 3}]},
                "top_srcips": {"buckets": [{"key": "10.1.2.3", "doc_count": 3}]},
                "top_agents": {"buckets": [{"key": "web01", "doc_count": 3}]},
            }]}},
        }

    monkeypatch.setattr(tl, "_wazuh_indexer_post", _fake_post)
    out = await tl.wazuh_alert_timeline(tl.WazuhAlertTimelineInput(
        since="24h", bucket="1h", response_format="toon"))
    data = toon_format.decode(out)
    assert data["total_alerts"] == 3
    assert data["buckets"][0]["doc_count"] == 3

    default_out = await tl.wazuh_alert_timeline(tl.WazuhAlertTimelineInput(
        since="24h", bucket="1h"))
    assert default_out.startswith("# Alert Timeline")

    json_out = await tl.wazuh_alert_timeline(tl.WazuhAlertTimelineInput(
        since="24h", bucket="1h", response_format="json"))
    assert json.loads(json_out)["total_alerts"] == 3
