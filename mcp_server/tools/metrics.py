#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Prometheus /metrics resource - exposes blue-team-mcp telemetry in Prometheus
text exposition format via the `metrics://prometheus` MCP resource.
"""
from __future__ import annotations
from mcp_server import mcp
from mcp_server.core.metrics import render_prometheus, snapshot


@mcp.resource("metrics://prometheus")
async def prometheus_metrics() -> str:
    """Prometheus text exposition of server telemetry.

    Counter/gauge families:
      - blue_team_mcp_tool_calls_total{tool}        - audit-path call counters
      - blue_team_mcp_pipeline_calls_total{tool}    - response_pipeline executions
      - blue_team_mcp_pipeline_duration_ms_total{tool}
      - blue_team_mcp_redaction_gate_failures_total - forensic bypass rejections
      - blue_team_mcp_rate_limit_hits_total
      - blue_team_mcp_attacker_registry_entries     - gauge
      - blue_team_mcp_ioc_store_entries             - gauge

    Consumable directly by Prometheus (text/plain; version=0.0.4) or via the
    JSON snapshot at `metrics://prometheus/json`.
    """
    return render_prometheus()


@mcp.resource("metrics://prometheus/json")
async def prometheus_metrics_json() -> str:
    """JSON snapshot of server telemetry (machine-readable variant)."""
    import json
    return json.dumps(snapshot(), indent=2, ensure_ascii=False)
