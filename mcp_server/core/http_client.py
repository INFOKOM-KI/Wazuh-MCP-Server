#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
HTTP client pool, unified API call helper, error handling, IP validation.
"""
from __future__ import annotations
import asyncio, ipaddress, json, logging, random
from typing import Any, Dict, Optional, Annotated
import httpx
from pydantic import AfterValidator
from mcp_server import WAZUH_INDEXER_VERIFY_SSL
from mcp_server import HTTP_TIMEOUT, WAZUH_API_VERIFY_SSL, WAZUH_INDEXER_VERIFY_SSL, ARGUS_VERIFY_SSL

logger = logging.getLogger("blue_team_mcp.http")

# http2 requires the optional 'h2' package (httpx[http2] extra). Degrade to
# http/1.1 gracefully when it's absent (e.g. minimal test/CI environments), so
# the server never fails to boot just because the optional dependency is missing.
try:
    import h2  # noqa: F401
    _HTTP2 = True
except ImportError:
    _HTTP2 = False

# Private / reserved IP ranges threat-intel tools are for public IPs only
_PRIVATE_NETWORKS: list = []

# Shared HTTP clients by name, pooled per SSL trust domain.
_clients: dict[str, httpx.AsyncClient] = {}

_MSEARCH_FALLBACK_ERROR: dict = {"error": "_msearch_failed"}

# Client pool
async def _get_client(
    name: str,
    verify: bool = True,
    max_keepalive: int = 20,
    max_connections: int = 100,
) -> httpx.AsyncClient:
    """Return a pooled httpx.AsyncClient by name"""
    if name not in _clients or _clients[name].is_closed:
        _clients[name] = httpx.AsyncClient(
            timeout=httpx.Timeout(HTTP_TIMEOUT),
            limits=httpx.Limits(max_keepalive_connections=max_keepalive, max_connections=max_connections),
            verify=verify,
            http2=_HTTP2,
        )
    return _clients[name]

# Unified API call
async def _api_call(method: str, url: str, *, client_name: str = "http", verify: bool = True,
                    max_retries: int = 1, backoff: float = 0.2, **kw) -> httpx.Response:
    """Unified async HTTP helper. Returns raw response - caller calls .json() or .text.
    Retries (default once, configurable via max_retries) on 5xx server errors, network
    failures (jittered backoff), and 429 rate limits (honors Retry-After when present).
    """
    client = await _get_client(client_name, verify=verify)
    last_exc: Exception | None = None
    for attempt in range(1 + max_retries):
        try:
            resp = await getattr(client, method.lower())(url, **kw)
            resp.raise_for_status()
            return resp
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429 and attempt < max_retries:
                retry_after = e.response.headers.get("Retry-After")
                try:
                    delay = min(float(retry_after), 30.0) if retry_after else backoff
                except ValueError:
                    delay = backoff
                await asyncio.sleep(delay)
                last_exc = e
                continue
            if e.response.status_code >= 500 and attempt < max_retries:
                await asyncio.sleep(backoff + random.uniform(0, 0.2))
                last_exc = e
                continue
            raise
        except (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError) as e:
            if attempt < max_retries:
                await asyncio.sleep(backoff + random.uniform(0, 0.2))
                last_exc = e
                continue
            raise
    raise last_exc  # type: ignore[misc]


# Error handling
def _handle_api_error(e: Exception, context: str = "") -> str:
    """Consistent, actionable error formatting for all API-based tools."""
    prefix = f"[{context}] " if context else ""
    if isinstance(e, httpx.HTTPStatusError):
        status = e.response.status_code
        if status == 400:
            return f"{prefix}Error: Bad request (400) - the API rejected the parameters. Try a smaller limit."
        if status == 401:
            return f"{prefix}Error: Invalid or missing API key (401). Check your environment variables."
        if status == 404:
            return f"{prefix}Error: No data found for this target (404)."
        if status == 429:
            retry_after = e.response.headers.get("Retry-After")
            hint = f"Retry after {retry_after} seconds." if retry_after else ""
            return f"{prefix}Error: Rate limit reached (429).{hint}"
        return f"{prefix}Error: API request failed with status {status}."
    if isinstance(e, httpx.TimeoutException):
        return f"{prefix}Error: Request timed out after {HTTP_TIMEOUT}s. Try again."
    if isinstance(e, RuntimeError):
        return f"{prefix}Error: {e}"
    logger.exception("Unexpected error in %s", context)
    return f"{prefix}Error: Unexpected error ({type(e).__name__})."


# IP validation
def _is_private_or_reserved(ip: str) -> bool:
    """Check whether an IP belongs to a private or reserved range (not routable)."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _validate_public_ip(v: str) -> str:
    """Reject private/reserved IP for public threat-intel tools (SSRF guard/prevention)."""
    if _is_private_or_reserved(v):
        raise ValueError(
            f"'{v}' is a private/reserved IP address."
            "This tool only accepts public IPs for threat intelligence lookup."
        )
    return v


ValidPublicIp = Annotated[str, AfterValidator(_validate_public_ip)]
