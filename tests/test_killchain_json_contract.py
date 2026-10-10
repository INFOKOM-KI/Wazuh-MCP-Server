#!/usr/bin/env python3
"""Killchain JSON contract: a skip from missing MITRE data is not a failure."""
from __future__ import annotations

import asyncio
import json
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")


def _run(coro):
    return asyncio.run(coro)


def test_json_response_when_no_mitre_techniques(monkeypatch):
    from mcp_server.tools import stix_correlation

    async def _fetch(srcip, since, until):
        return 7, [], None

    monkeypatch.setattr(stix_correlation, "_fetch_techniques_for_srcip", _fetch)

    raw = _run(stix_correlation.blueteam_stix_killchain(
        stix_correlation.StixKillchainInput(srcip="203.0.113.7", response_format="json")))

    payload = json.loads(raw)
    assert payload["status"] == "no_mitre_data"
    assert payload["total_alerts"] == 7
    assert payload["techniques"] == []
    assert payload["tactics_seen"] == []
    assert "error" not in payload


def test_indexer_error_is_reported_as_error_not_skipped(monkeypatch):
    from mcp_server.tools import stix_correlation

    async def _fetch(srcip, since, until):
        return 0, [], "Indexer API error: 503"

    monkeypatch.setattr(stix_correlation, "_fetch_techniques_for_srcip", _fetch)

    raw = _run(stix_correlation.blueteam_stix_killchain(
        stix_correlation.StixKillchainInput(srcip="203.0.113.7", response_format="json")))

    payload = json.loads(raw)
    assert payload["status"] == "error"
    assert "Indexer query failed" in payload["error"]


def test_json_success_carries_ok_status(monkeypatch):
    from mcp_server.tools import stix_correlation

    async def _fetch(srcip, since, until):
        return 3, ["T1110"], None

    monkeypatch.setattr(stix_correlation, "_fetch_techniques_for_srcip", _fetch)
    monkeypatch.setattr(stix_correlation, "_build_killchain",
                        lambda tids, top_n=20: {"tactics_seen": ["Credential Access"],
                                                "techniques": [{"mitre_id": "T1110"}]})

    raw = _run(stix_correlation.blueteam_stix_killchain(
        stix_correlation.StixKillchainInput(srcip="203.0.113.7", response_format="json")))

    payload = json.loads(raw)
    assert payload["status"] == "ok"
    assert payload["techniques"] == [{"mitre_id": "T1110"}]


def test_fetch_helper_returns_indexer_error(monkeypatch):
    from mcp_server.tools import stix_correlation

    async def _post(body, index_pattern=None):
        return {"error": "Indexer API error: 503"}

    monkeypatch.setattr(stix_correlation, "_wazuh_indexer_post", _post)

    total, tids, fetch_error = _run(stix_correlation._fetch_techniques_for_srcip(
        "203.0.113.7", None, None))

    assert (total, tids) == (0, [])
    assert fetch_error == "Indexer API error: 503"


def test_analytics_step_reports_skipped_not_degraded(monkeypatch):
    from mcp_server.agents import investigation_graph as ig
    from mcp_server.tools import attack_graph, stix_correlation

    async def _killchain(params):
        assert params.response_format == "json"
        return json.dumps({"status": "no_mitre_data", "srcip": "203.0.113.7",
                           "tactics_seen": [], "techniques": []})

    async def _graph(params):
        return json.dumps({"status": "ok", "nodes": 0})

    monkeypatch.setattr(stix_correlation, "blueteam_stix_killchain", _killchain)
    monkeypatch.setattr(attack_graph, "blueteam_attack_graph", _graph)

    update = _run(ig.analytics_step({"srcip": "203.0.113.7", "window": "24h"}))

    assert update["errors"] == []
    assert update["killchain"]["status"] == "no_mitre_data"
    assert "killchain: skipped (no rule.mitre.id in window)" in update["steps"]


def test_analytics_step_keeps_killchain_error(monkeypatch):
    from mcp_server.agents import investigation_graph as ig
    from mcp_server.tools import attack_graph, stix_correlation

    async def _killchain(params):
        return json.dumps({"error": "STIX bundle not loaded", "status": "error"})

    async def _graph(params):
        return json.dumps({"status": "ok"})

    monkeypatch.setattr(stix_correlation, "blueteam_stix_killchain", _killchain)
    monkeypatch.setattr(attack_graph, "blueteam_attack_graph", _graph)

    update = _run(ig.analytics_step({"srcip": "203.0.113.7", "window": "24h"}))

    assert any("killchain" in e for e in update["errors"])
    assert "killchain: degraded" in update["steps"]


def test_attack_graph_surfaces_stix_fetch_errors(monkeypatch):
    import networkx as nx
    from mcp_server.core import attack_graph
    from mcp_server.tools import stix_correlation

    async def _fetch(ip, since, until):
        return 0, [], "Indexer API error: 503"

    monkeypatch.setattr(stix_correlation, "_load_stix", lambda: None)
    monkeypatch.setattr(stix_correlation, "_fetch_techniques_for_srcip", _fetch)

    G = nx.Graph()
    G.add_node("203.0.113.7", kind="ip", confirmed=True)

    _run(attack_graph._add_stix_edges(G, cap=3))

    expected = [{"ip": "203.0.113.7", "error": "Indexer API error: 503"}]
    assert G.graph["stix_fetch_errors"] == expected
    assert attack_graph.analyze_attack_graph(G, top_n=5)["stix_fetch_errors"] == expected


def test_attack_graph_omits_error_field_when_no_technique_data(monkeypatch):
    import networkx as nx
    from mcp_server.core import attack_graph
    from mcp_server.tools import stix_correlation

    async def _fetch(ip, since, until):
        return 4, [], None

    monkeypatch.setattr(stix_correlation, "_load_stix", lambda: None)
    monkeypatch.setattr(stix_correlation, "_fetch_techniques_for_srcip", _fetch)

    G = nx.Graph()
    G.add_node("203.0.113.7", kind="ip", confirmed=True)

    _run(attack_graph._add_stix_edges(G, cap=3))

    assert "stix_fetch_errors" not in G.graph
    assert "stix_fetch_errors" not in attack_graph.analyze_attack_graph(G, top_n=5)


def test_missing_indexer_credentials_return_error_status(monkeypatch):
    from mcp_server.tools import stix_correlation

    monkeypatch.setattr(stix_correlation, "WAZUH_INDEXER_URL", "")

    raw = _run(stix_correlation.blueteam_stix_killchain(
        stix_correlation.StixKillchainInput(srcip="203.0.113.7", response_format="json")))

    payload = json.loads(raw)
    assert payload["status"] == "error"
    assert "WAZUH_INDEXER_URL" in payload["error"]


def test_attack_graph_records_unexpected_exception(monkeypatch):
    import networkx as nx
    from mcp_server.core import attack_graph
    from mcp_server.tools import stix_correlation

    async def _fetch(ip, since, until):
        raise RuntimeError("boom")

    monkeypatch.setattr(stix_correlation, "_load_stix", lambda: None)
    monkeypatch.setattr(stix_correlation, "_fetch_techniques_for_srcip", _fetch)

    G = nx.Graph()
    G.add_node("203.0.113.7", kind="ip", confirmed=True)

    _run(attack_graph._add_stix_edges(G, cap=3))

    expected = [{"ip": "203.0.113.7", "error": "RuntimeError: boom"}]
    assert G.graph["stix_fetch_errors"] == expected
    assert attack_graph.analyze_attack_graph(G, top_n=5)["stix_fetch_errors"] == expected
