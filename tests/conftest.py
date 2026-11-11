#!/usr/bin/env python3
"""
Shared pytest fixtures for Wazuh-MCP-Server tests.
Provides mock httpx clients, config objects, and async event loop support
following the REF repository's conftest.py pattern.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import tempfile
import pytest
import httpx
from unittest.mock import AsyncMock, MagicMock

# fastembed is absent in CI, and the reranker is fail-closed at startup when
# BLUETEAM_RERANK_ENABLED=true without it. Pin the reranker off before any test
# module imports mcp_server, so the default suite exercises the BM25 path. Tests
# that need the reranker flip config.rerank.enabled themselves (tests/test_rerank.py).
os.environ.setdefault("BLUETEAM_RERANK_ENABLED", "false")

# init_config() runs when mcp_server is first imported, so every value Config owns is
# frozen at that moment. A setdefault inside a test module loses to whichever module
# imported the package first, and test_stix_export then writes into a temp dir while the
# allowlist still holds the production default. Set it here, before any module imports.
os.environ.setdefault("BLUETEAM_EXPORT_DIR", tempfile.mkdtemp(prefix="mcp-export-test-"))

# false_positive_kb reads its TTL at module import, and another test module imports it
# before test_false_positive_kb.py's own env block runs, so that file's 1s TTL lost the
# race and _expired(now-10) came back False. Same freeze as BLUETEAM_EXPORT_DIR above.
os.environ.setdefault("BLUETEAM_FALSE_POSITIVE_TTL", "5")


@pytest.fixture(autouse=True)
def _clean_env():
    """Reset env vars before each test to prevent cross-test leakage."""
    saved = dict(os.environ)
    yield
    os.environ.clear()
    os.environ.update(saved)


_BLOCKED_NETWORK_ATTEMPTS: list[str] = []


@pytest.fixture(autouse=True)
def _offline_wazuh_indexer(monkeypatch):
    """Make an unmocked Indexer call fail locally, never by DNS resolution.
    Tests that need a response replace ``_wazuh_indexer_post`` or ``_api_call``.
    """
    from mcp_server.wazuh import indexer

    async def offline(*args, **kwargs):
        raise httpx.ConnectError("indexer disabled in unit tests")

    monkeypatch.setattr(indexer, "_api_call", offline)


@pytest.fixture(autouse=True)
def _block_external_network(monkeypatch):
    """Block non-loopback connect/connect_ex/sendto/getaddrinfo and record attempts.
    Loopback and AF_UNIX are allowed; subprocesses are outside this guard.
    """
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_sendto = socket.socket.sendto
    real_getaddrinfo = socket.getaddrinfo

    def _literal(host):
        try:
            return ipaddress.ip_address(str(host))
        except ValueError:
            return None

    def _allowed(host):
        if host in ("localhost", "127.0.0.1", "::1"):
            return True
        ip = _literal(host)
        return ip is not None and ip.is_loopback

    def _record(message):
        _BLOCKED_NETWORK_ATTEMPTS.append(
            f"{os.environ.get('PYTEST_CURRENT_TEST', '?')}: {message}")
        raise RuntimeError(message)

    def guarded_connect(self, address):
        if self.family == socket.AF_UNIX:
            return real_connect(self, address)
        host = address[0] if isinstance(address, tuple) else None
        if _allowed(host):
            return real_connect(self, address)
        _record(f"external network blocked in tests: {address!r}")

    def guarded_connect_ex(self, address):
        if self.family == socket.AF_UNIX:
            return real_connect_ex(self, address)
        host = address[0] if isinstance(address, tuple) else None
        if _allowed(host):
            return real_connect_ex(self, address)
        _record(f"external connect_ex blocked in tests: {address!r}")

    def guarded_sendto(self, data, *args):
        address = args[-1] if args else None
        if not isinstance(address, tuple):
            return real_sendto(self, data, *args)
        host = address[0]
        if _allowed(host):
            return real_sendto(self, data, *args)
        _record(f"external sendto blocked in tests: {address!r}")

    def guarded_getaddrinfo(host, *args, **kwargs):
        if _allowed(host) or _literal(host) is not None:
            return real_getaddrinfo(host, *args, **kwargs)
        _record(f"DNS lookup blocked in tests: {host!r}")

    _BLOCKED_NETWORK_ATTEMPTS.clear()
    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
    monkeypatch.setattr(socket.socket, "sendto", guarded_sendto)
    monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)
    yield
    attempts = list(_BLOCKED_NETWORK_ATTEMPTS)
    _BLOCKED_NETWORK_ATTEMPTS.clear()
    assert not attempts, "blocked external network attempt(s): " + "; ".join(attempts)


@pytest.fixture
def minimal_env():
    """Minimal environment for tests that need Wazuh config."""
    os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
    os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")
    os.environ.setdefault("WAZUH_API_URL", "https://manager:55000")
    os.environ.setdefault("WAZUH_API_PASSWORD", "test-manager-pass")
    os.environ.setdefault("BLUETEAM_REDACTION_POLICY", "full")


@pytest.fixture
def mock_httpx_client():
    """Return an AsyncMock that mimics httpx.AsyncClient.
    Use this to intercept API calls without network access.
    """
    client = AsyncMock(spec=httpx.AsyncClient)
    client.is_closed = False
    return client


@pytest.fixture
def mock_response():
    """Factory for creating mock httpx.Response objects."""

    def _make(status_code=200, json_data=None, text="", headers=None):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = status_code
        resp.json.return_value = json_data or {}
        resp.text = text
        resp.headers = headers or httpx.Headers({})
        resp.raise_for_status = MagicMock()
        if status_code >= 400:
            resp.raise_for_status.side_effect = httpx.HTTPStatusError(
                "error", request=MagicMock(), response=resp
            )
        return resp

    return _make


@pytest.fixture
def config_singleton():
    """Return a validated Config singleton for tests.
    Requires minimal_env fixture values to be set.
    """
    from mcp_server.core.config import Config

    return Config.from_env()


class ConsentContext:
    """Minimal FastMCP Context stand-in for tool-level consent tests.

    Exposes `session.elicit_form`, the path production code uses to keep the
    raw form content: an empty form must stay distinguishable from approve=false.
    """

    def __init__(self, approve: bool = True, action: str | None = None,
                 content=None) -> None:
        from types import SimpleNamespace

        self.approve = approve
        self.action = action or ("accept" if approve else "decline")
        self.content = content
        self.messages: list[str] = []
        self.session = SimpleNamespace(elicit_form=self._elicit_form,
                                       client_params=None)
        self._ns = SimpleNamespace

    async def _elicit_form(self, message, requestedSchema, related_request_id=None):
        self.messages.append(message)
        content = self.content if self.content is not None else (
            {"approve": self.approve} if self.action == "accept" else None)
        return self._ns(action=self.action, content=content)

    async def elicit(self, message, schema):
        return await self._elicit_form(message, None)


@pytest.fixture
def consent_approval():
    return ConsentContext(approve=True)
