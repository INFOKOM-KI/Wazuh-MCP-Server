#!/usr/bin/env python3
"""
Tests for mcp_server/core/http_client.py; retry logic, client pool, error handling.
"""
from __future__ import annotations
import os

# mcp_server/__init__.py calls init_config() at import and hard-fails without
# WAZUH_INDEXER_* (ConfigurationError). This module imports mcp_server at module
# level, so without these the file errors during collection when run alone.
os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import asyncio
import pytest
import httpx
from unittest.mock import AsyncMock, MagicMock, patch
from mcp_server.core.http_client import (
    _get_client,
    _get_breaker,
    _api_call,
    CircuitOpenError,
    _handle_api_error,
    _api_error_text,
    _retry_after_seconds,
    _is_private_or_reserved,
    _validate_public_ip,
    _host_resolves_public,
    _domain_allowed,
    _host_pins,
    _resolve_host_ips,
    ValidPublicIp,
)
from mcp_server.core.exceptions import ThreatIntelError


class TestClientPool:
    """Tests for _get_client pooled httpx.AsyncClient management."""
    @pytest.mark.asyncio
    async def test_creates_client_lazily(self):
        """_get_client creates a new client on first call."""
        client = await _get_client("test-pool", verify=True)
        assert isinstance(client, httpx.AsyncClient)
        assert not client.is_closed

    @pytest.mark.asyncio
    async def test_reuses_client_same_name(self):
        """Same pool name returns the same client instance."""
        c1 = await _get_client("reuse-test", verify=True)
        c2 = await _get_client("reuse-test", verify=True)
        assert c1 is c2

    @pytest.mark.asyncio
    async def test_different_names_different_clients(self):
        """Different pool names create different clients."""
        c1 = await _get_client("pool-a", verify=True)
        c2 = await _get_client("pool-b", verify=False)
        assert c1 is not c2

    @pytest.mark.asyncio
    async def test_recreates_closed_client(self):
        """If client.is_closed, a new one is created."""
        c1 = await _get_client("recreate-test", verify=True)
        await c1.aclose()  # is_closed is a read only property close for real
        c2 = await _get_client("recreate-test", verify=True)
        assert c1 is not c2

    @pytest.mark.asyncio
    async def test_verify_is_part_of_pool_key(self):
        """A verify=False client must never be handed to a verify=True caller."""
        verified = await _get_client("verify-key-test", verify=True)
        unverified = await _get_client("verify-key-test", verify=False)
        assert verified is not unverified


class TestPoolNaming:
    """_api_call names the pool after the upstream, never a catch-all default."""
    @pytest.mark.asyncio
    async def test_client_name_derived_from_url_host(self):
        """No client_name -> breaker keyed by URL host, and the error says so."""
        breaker = _get_breaker("pool-key-probe.invalid")
        for _ in range(breaker.failure_threshold):
            breaker.on_failure()
        with pytest.raises(CircuitOpenError) as exc:
            await _api_call("get", "https://pool-key-probe.invalid/analysis/1.2.3.4")
        assert "pool-key-probe.invalid" in str(exc.value)
        assert "'http'" not in str(exc.value)
        breaker.on_success()


class TestRetryLogic:
    """Tests for _api_call retry on 5xx, 429, and network errors."""
    @pytest.mark.asyncio
    async def test_success_first_attempt(self, mock_response):
        """Returns response on first successful attempt."""
        resp = mock_response(status_code=200, json_data={"ok": True})
        with patch.object(httpx.AsyncClient, "get", AsyncMock(return_value=resp)):
            result = await _api_call("get", "http://test/api", client_name="retry-ok")
            assert result.json() == {"ok": True}

    @pytest.mark.asyncio
    async def test_retries_on_5xx(self, mock_response):
        """Retries once on 5xx, succeeds on second attempt."""
        fail = mock_response(status_code=503)
        ok = mock_response(status_code=200, json_data={"recovered": True})
        mock_get = AsyncMock(side_effect=[fail, ok])
        with patch.object(httpx.AsyncClient, "get", mock_get):
            fail.raise_for_status.side_effect = httpx.HTTPStatusError(
                "503", request=MagicMock(), response=fail
            )
            with patch("asyncio.sleep", AsyncMock()):
                result = await _api_call("get", "http://test/api", client_name="retry-5xx")
                assert result.json() == {"recovered": True}
                assert mock_get.call_count == 2

    @pytest.mark.asyncio
    async def test_raises_after_two_5xx(self, mock_response):
        """Raises after two consecutive 5xx responses."""
        fail1 = mock_response(status_code=503)
        fail2 = mock_response(status_code=503)
        fail1.raise_for_status.side_effect = httpx.HTTPStatusError(
            "503a", request=MagicMock(), response=fail1
        )
        fail2.raise_for_status.side_effect = httpx.HTTPStatusError(
            "503b", request=MagicMock(), response=fail2
        )
        mock_get = AsyncMock(side_effect=[fail1, fail2])
        with patch.object(httpx.AsyncClient, "get", mock_get):
            with patch("asyncio.sleep", AsyncMock()):
                with pytest.raises(httpx.HTTPStatusError):
                    await _api_call("get", "http://test/api", client_name="retry-fail")

    @pytest.mark.asyncio
    async def test_retries_on_429_with_retry_after(self, mock_response):
        """Honors Retry-After header on 429, retries once."""
        fail = mock_response(
            status_code=429,
            headers=httpx.Headers({"Retry-After": "2"}),
        )
        ok = mock_response(status_code=200, json_data={"throttled": False})
        fail.raise_for_status.side_effect = httpx.HTTPStatusError(
            "429", request=MagicMock(), response=fail
        )
        mock_get = AsyncMock(side_effect=[fail, ok])
        sleep_mock = AsyncMock()
        with patch.object(httpx.AsyncClient, "get", mock_get):
            with patch("asyncio.sleep", sleep_mock):
                result = await _api_call("get", "http://test/api", client_name="retry-429")
                sleep_mock.assert_called_once_with(2.0)
                assert result.json() == {"throttled": False}

    @pytest.mark.asyncio
    async def test_429_with_long_retry_after_raises_without_retry(self, mock_response):
        """A Retry-After longer than 30s is reported, not slept through then re-throttled.
        Regression: this used to clamp 999s to 30s and retry anyway, spending more
        of an already-exhausted quota.
        """
        fail = mock_response(
            status_code=429,
            headers=httpx.Headers({"Retry-After": "999"}),
        )
        fail.raise_for_status.side_effect = httpx.HTTPStatusError(
            "429", request=MagicMock(), response=fail
        )
        mock_get = AsyncMock(side_effect=[fail])
        sleep_mock = AsyncMock()
        with patch.object(httpx.AsyncClient, "get", mock_get):
            with patch("asyncio.sleep", sleep_mock):
                with pytest.raises(httpx.HTTPStatusError):
                    await _api_call("get", "http://test/api", client_name="retry-429-long")
                assert mock_get.call_count == 1  # no retry
                sleep_mock.assert_not_called()

    @pytest.mark.asyncio
    async def test_429_without_retry_after_raises_without_retry(self, mock_response):
        """No Retry-After -> fail fast. A blind 0.2s retry doubles the throttle."""
        fail = mock_response(status_code=429)
        fail.raise_for_status.side_effect = httpx.HTTPStatusError(
            "429", request=MagicMock(), response=fail
        )
        mock_get = AsyncMock(side_effect=[fail])
        with patch.object(httpx.AsyncClient, "get", mock_get):
            with patch("asyncio.sleep", AsyncMock()):
                with pytest.raises(httpx.HTTPStatusError):
                    await _api_call("get", "http://test/api", client_name="retry-429-bare")
                assert mock_get.call_count == 1  # no retry

    @pytest.mark.asyncio
    async def test_retries_on_timeout(self):
        """Retries once on TimeoutException."""
        ok_resp = MagicMock(spec=httpx.Response)
        ok_resp.status_code = 200
        ok_resp.json.return_value = {"ok": True}
        ok_resp.raise_for_status = MagicMock()
        mock_get = AsyncMock(side_effect=[httpx.TimeoutException("timeout"), ok_resp])
        with patch.object(httpx.AsyncClient, "get", mock_get):
            with patch("asyncio.sleep", AsyncMock()):
                result = await _api_call("get", "http://test/api", client_name="retry-timeout")
                assert result.json() == {"ok": True}

    @pytest.mark.asyncio
    async def test_no_retry_on_4xx_except_429(self, mock_response):
        """Does NOT retry on 4xx errors other than 429."""
        fail = mock_response(status_code=400)
        fail.raise_for_status.side_effect = httpx.HTTPStatusError(
            "400", request=MagicMock(), response=fail
        )
        mock_get = AsyncMock(side_effect=[fail])
        with patch.object(httpx.AsyncClient, "get", mock_get):
            with pytest.raises(httpx.HTTPStatusError):
                await _api_call("get", "http://test/api", client_name="retry-4xx")
            assert mock_get.call_count == 1  # no retry

    @pytest.mark.asyncio
    async def test_configurable_max_retries(self, mock_response):
        """max_retries=2 -> up to 3 attempts before giving up. LoL"""
        fail1 = mock_response(status_code=503)
        fail2 = mock_response(status_code=503)
        ok = mock_response(status_code=200, json_data={"ok": True})
        for f in (fail1, fail2):
            f.raise_for_status.side_effect = httpx.HTTPStatusError("503", request=MagicMock(), response=f)
        mock_get = AsyncMock(side_effect=[fail1, fail2, ok])
        with patch.object(httpx.AsyncClient, "get", mock_get):
            with patch("asyncio.sleep", AsyncMock()):
                result = await _api_call("get", "http://test/api", client_name="retry-max", max_retries=2)
                assert result.json() == {"ok": True}
                assert mock_get.call_count == 3


class TestErrorHandling:
    """_api_error_text formats; _handle_api_error raises.
    A tool that returns error *text* is reported to the MCP client as
    ``isError: false``, so an LLM can read a hard upstream failure as a finding.
    """
    @staticmethod
    def _status_error(status_code: int, *, headers=None, body: bytes = b"") -> httpx.HTTPStatusError:
        """A real httpx error carrying a real response (headers/body/url readable)."""
        req = httpx.Request(
            "GET",
            "https://ip-blacklist-lookup-api-apiverve.p.rapidapi.com/v1/ipblacklistlookup?ip=1.2.3.4",
        )
        resp = httpx.Response(status_code, headers=headers or {}, content=body, request=req)
        return httpx.HTTPStatusError("boom", request=req, response=resp)

    def test_400_bad_request(self):
        msg = _api_error_text(self._status_error(400))
        assert "400" in msg
        assert "parameters" in msg.lower()

    def test_401_unauthorized(self):
        msg = _api_error_text(self._status_error(401))
        assert "401" in msg
        assert "api key" in msg.lower()

    def test_403_names_the_unsubscribed_cause_and_keeps_the_body(self):
        # The verbatim 403 an unsubscribed RapidAPI product returns.
        exc = self._status_error(403, body=b'{"message":"You are not subscribed to this API."}')
        msg = _api_error_text(exc, context="blueteam_ip_blacklist")
        assert "403" in msg
        assert "not subscribed" in msg
        assert 'You are not subscribed to this API.' in msg  # upstream body preserved
        # Host label is masked by the redaction boundary, but the path survives and
        # identifies which RapidAPI product was called.
        assert "/v1/ipblacklistlookup" in msg
        assert ".p.rapidapi.com" in msg

    def test_404_not_found(self):
        assert "404" in _api_error_text(self._status_error(404))

    def test_429_preserves_ratelimit_headers(self):
        exc = self._status_error(429, headers=httpx.Headers({
            "Retry-After": "2",
            "x-ratelimit-requests-remaining": "0",
        }))
        msg = _api_error_text(exc)
        assert "429" in msg
        assert "Retry after 2 seconds." in msg
        assert "x-ratelimit-requests-remaining: 0" in msg

    def test_diagnostics_redact_a_victim_email_in_the_body(self):
        # The uniform redaction boundary must cover error text on its way to the LLM.
        exc = self._status_error(500, body=b"quota exceeded for csirt@tangerangkota.go.id")
        msg = _api_error_text(exc, context="blueteam_breach_check")
        assert "csirt@tangerangkota.go.id" not in msg
        assert "quota exceeded for" in msg  # non-PII still present

    def test_timeout(self):
        msg = _api_error_text(httpx.TimeoutException("timed out"))
        assert "timed out" in msg.lower()
        # No request recorded -> the global budget is the honest fallback.
        assert "30.0s" in msg

    def test_timeout_names_the_host_and_the_applied_budget(self):
        # A per-call 90s override (Netra fan out) must not be reported as the 30s
        # client default: the message has to name the upstream and the real budget.
        req = httpx.Client(timeout=90.0).build_request(
            "GET", "https://netra.example.com:8013/api/v1/analysis/180.93.3.100"
        )
        msg = _api_error_text(httpx.ReadTimeout("read timed out", request=req), context="netra")
        assert msg.startswith("[netra]")
        assert "timed out" in msg.lower()
        assert "90.0s" in msg
        assert "netra.example.com" in msg
        assert "30.0s" not in msg

    def test_runtime_error(self):
        assert "custom error" in _api_error_text(RuntimeError("custom error"))

    def test_context_prefix(self):
        assert _api_error_text(RuntimeError("something"), context="crowdsec").startswith("[crowdsec]")

    def test_handle_api_error_raises_with_body_and_cause(self):
        exc = self._status_error(500, body=b"upstream exploded")
        with pytest.raises(ThreatIntelError) as ei:
            _handle_api_error(exc, context="blueteam_ip_blacklist")
        assert "500" in str(ei.value)
        assert "upstream exploded" in str(ei.value)
        assert ei.value.__cause__ is exc

    def test_handle_api_error_raises_on_missing_key(self):
        # A missing credential is a hard failure, not a successful call with text.
        with pytest.raises(ThreatIntelError):
            _handle_api_error(RuntimeError("RAPIDAPI_KEY not set"))

    @pytest.mark.parametrize("header,expected", [
        (None, None),
        ("", None),
        ("abc", None),
        ("Mon, 14 Sep 2026 04:06:02 GMT", None),  # HTTP-date form is not parsed
        ("-1", None),
        ("999", None),  # too long to sit through fail fast instead
        ("0", 0.0),
        ("2", 2.0),
        ("30", 30.0),
    ])
    def test_retry_after_seconds(self, header, expected):
        assert _retry_after_seconds(header) == expected


def test_http_timeout_env_override(monkeypatch):
    """HTTP_TIMEOUT is env-configurable; the global default stays 30s when unset."""
    from mcp_server.core.config import LimitsConfig

    monkeypatch.delenv("HTTP_TIMEOUT", raising=False)
    assert LimitsConfig.from_env().http_timeout == 30.0
    monkeypatch.setenv("HTTP_TIMEOUT", "90")
    assert LimitsConfig.from_env().http_timeout == 90.0


class TestIPValidation:
    """Tests for SSRF guard - _is_private_or_reserved, _validate_public_ip."""
    def test_private_ipv4_detected(self):
        assert _is_private_or_reserved("192.168.1.1") is True
        assert _is_private_or_reserved("10.0.0.1") is True
        assert _is_private_or_reserved("172.16.0.1") is True
        assert _is_private_or_reserved("127.0.0.1") is True

    def test_public_ipv4_passes(self):
        assert _is_private_or_reserved("8.8.8.8") is False
        assert _is_private_or_reserved("1.1.1.1") is False

    def test_cgnat_detected(self):
        # 100.64.0.0/10 (RFC 6598) is neither is_private nor is_reserved in
        # ipaddress, only caught by is_global=False.
        assert _is_private_or_reserved("100.64.0.1") is True

    def test_link_local_metadata_detected(self):
        assert _is_private_or_reserved("169.254.169.254") is True
        assert _is_private_or_reserved("::1") is True

    def test_host_resolves_public_literal(self):
        assert _host_resolves_public("127.0.0.1") is False
        assert _host_resolves_public("8.8.8.8") is True

    def test_host_resolves_public_hostname_private(self, monkeypatch):
        # A hostname that resolves to loopback must be rejected (DNS-rebinding gap).
        import socket

        def fake_getaddrinfo(host, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        assert _host_resolves_public("evil.example.com") is False

    def test_ipv4_mapped_cgnat_detected(self):
        # ::ffff:100.64.0.1 is misreported as global unless unmasked to IPv4 first.
        assert _is_private_or_reserved("::ffff:100.64.0.1") is True
        assert _is_private_or_reserved("::ffff:127.0.0.1") is True
        assert _is_private_or_reserved("::ffff:8.8.8.8") is False

    def test_domain_allowed(self):
        allowed = ["tangerangkota.go.id", "example.gov.id"]
        assert _domain_allowed("tangerangkota.go.id", allowed) is True
        assert _domain_allowed("sub.tangerangkota.go.id", allowed) is True
        assert _domain_allowed("evil.com", allowed) is False
        assert _domain_allowed("tangerangkota.go.id.evil.com", allowed) is False

    def test_host_pins_allowlist_permits_internal(self, monkeypatch):
        import socket

        def fake_getaddrinfo(host, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.7", 0))]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        ips, err = _host_pins("sub.tangerangkota.go.id", ["tangerangkota.go.id"])
        assert err is None
        assert ips == ["10.0.0.7"]

    def test_host_pins_rejects_internal_not_allowlisted(self, monkeypatch):
        import socket

        def fake_getaddrinfo(host, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.7", 0))]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        ips, err = _host_pins("evil.example.com", [])
        assert err is not None
        assert ips == []

    def test_invalid_ip_returns_false(self):
        """Invalid IP strings are not private - they fail format validation elsewhere."""
        assert _is_private_or_reserved("not-an-ip") is False

    def test_validate_public_ip_accepts_public(self):
        assert _validate_public_ip("8.8.8.8") == "8.8.8.8"

    def test_validate_public_ip_rejects_private(self):
        with pytest.raises(ValueError, match="private/reserved"):
            _validate_public_ip("192.168.1.1")

    def test_valid_public_ip_type(self):
        """ValidPublicIp annotated type works with Pydantic."""
        from pydantic import BaseModel

        class TestModel(BaseModel):
            ip: ValidPublicIp

        m = TestModel(ip="8.8.8.8")
        assert m.ip == "8.8.8.8"

        with pytest.raises(ValueError):
            TestModel(ip="10.0.0.1")
