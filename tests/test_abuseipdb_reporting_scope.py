#!/usr/bin/env python3
"""Read-only and write-scope isolation for the AbuseIPDB reporting tool.

The middleware is exercised directly with a synthetic HTTP request. No server
socket, Wazuh endpoint, or AbuseIPDB endpoint is contacted.
"""
from __future__ import annotations

import asyncio
import json
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer.invalid")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

from starlette.requests import Request
from starlette.responses import JSONResponse

from mcp_server.core import server_auth
from mcp_server.core.server_auth import (APIAuthMiddleware, READ_SCOPE,
                                         REPORT_SCOPE, ServerAuthManager,
                                         WRITE_SCOPE)

KEY = "btm_" + "a" * 43


def _run(coro):
    return asyncio.run(coro)


def _request(tool: str, arguments: dict) -> Request:
    body = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }).encode()
    sent = {"done": False}

    async def receive():
        if not sent["done"]:
            sent["done"] = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    scope = {
        "type": "http", "method": "POST", "path": "/mcp",
        "headers": [(b"authorization", f"Bearer {KEY}".encode()),
                    (b"content-type", b"application/json")],
        "client": ("127.0.0.1", 12345), "server": ("testserver", 80),
        "scheme": "http", "query_string": b"",
    }
    return Request(scope, receive)


def _middleware(monkeypatch, scopes: str) -> APIAuthMiddleware:
    monkeypatch.setenv("MCP_API_KEY", KEY)
    monkeypatch.setenv("MCP_API_KEY_SCOPES", scopes)
    manager = ServerAuthManager()
    monkeypatch.setattr(server_auth, "auth_manager", manager)
    mw = APIAuthMiddleware.__new__(APIAuthMiddleware)
    mw._write_tools = frozenset({"blueteam_abuseipdb_report"})
    return mw


def _dispatch(monkeypatch, scopes: str, tool: str, arguments: dict):
    mw = _middleware(monkeypatch, scopes)
    called = {"n": 0}

    async def call_next(_request):
        called["n"] += 1
        return JSONResponse({"ok": True})

    response = _run(mw.dispatch(_request(tool, arguments), call_next))
    return response, called["n"]


def test_read_only_client_cannot_report_even_with_both_flags(monkeypatch):
    response, called = _dispatch(
        monkeypatch, READ_SCOPE, "blueteam_abuseipdb_report",
        {"from_alerts": True, "dry_run": False, "confirm": True})
    assert response.status_code == 403
    assert called == 0
    assert "threatintel:report" in response.body.decode()


def test_wazuh_write_alone_cannot_report(monkeypatch):
    response, called = _dispatch(
        monkeypatch, WRITE_SCOPE, "blueteam_abuseipdb_report",
        {"dry_run": False, "confirm": True})
    assert response.status_code == 403
    assert called == 0


def test_report_scope_can_reach_the_report_tool(monkeypatch):
    response, called = _dispatch(
        monkeypatch, REPORT_SCOPE, "blueteam_abuseipdb_report",
        {"dry_run": False, "confirm": True})
    assert response.status_code == 200
    assert called == 1


def test_read_only_client_can_reach_the_check_tool(monkeypatch):
    response, called = _dispatch(
        monkeypatch, READ_SCOPE, "blueteam_abuseipdb_check",
        {"ip": "8.8.8.8"})
    assert response.status_code == 200
    assert called == 1
