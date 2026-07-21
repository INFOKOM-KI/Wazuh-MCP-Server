#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Wazuh Manager JWT authentication + API GET helper.
"""
from __future__ import annotations
import time, logging
from typing import Optional, Dict
import httpx
from mcp_server import (WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASSWORD,
                         WAZUH_API_VERIFY_SSL)
from mcp_server.core.http_client import _get_client

logger = logging.getLogger("blue_team_mcp.wazuh")

_wazuh_token: Optional[str] = None
_wazuh_token_expiry: float = 0.0
_WAZUH_TOKEN_TTL = 300


async def _wazuh_get_token() -> Optional[str]:
    """Obtain JWT token from Wazuh API with 300s TTL cache."""
    global _wazuh_token, _wazuh_token_expiry
    if not WAZUH_API_URL or not WAZUH_API_PASSWORD:
        return None
    now = time.monotonic()
    if _wazuh_token and now < _wazuh_token_expiry:
        return _wazuh_token
    try:
        url = f"{WAZUH_API_URL}/security/user/authenticate?raw=true"
        resp = await _api_call("post", url, client_name="wazuh", verify=WAZUH_API_VERIFY_SSL,
                                auth=(WAZUH_API_USER, WAZUH_API_PASSWORD))
        _wazuh_token = resp.text.strip().strip('"')
        _wazuh_token_expiry = now + _WAZUH_TOKEN_TTL
        return _wazuh_token
    except httpx.HTTPStatusError as e:
        logger.warning("Wazuh auth failed: HTTP %s", e.response.status_code)
        _wazuh_token = None
        _wazuh_token_expiry = 0.0
        return None
    except Exception as e:
        logger.warning("Wazuh auth failed: %s", e)
        _wazuh_token = None
        _wazuh_token_expiry = 0.0
        return None

# Import _api_call here to avoid circular import at module level
from mcp_server.core.http_client import _api_call


async def _wazuh_api_get(path: str, params: Dict[str, str] = None) -> Dict:
    """Call Wazuh Manager API GET endpoint. path must start with /."""
    if not WAZUH_API_URL or not WAZUH_API_PASSWORD:
        return {"error": "WAZUH_API_URL and WAZUH_API_PASSWORD must be set."}
    token = await _wazuh_get_token()
    if not token:
        return {"error": "Wazuh API authentication failed",
                "detail": f"Could not authenticate to {WAZUH_API_URL} as '{WAZUH_API_USER}'."}
    url = f"{WAZUH_API_URL}{path}"
    try:
        resp = await _api_call("get", url, client_name="wazuh", verify=WAZUH_API_VERIFY_SSL,
                                headers={"Authorization": f"Bearer {token}"},
                                params=params or {})
        return resp.json()
    except httpx.HTTPStatusError as e:
        return {"error": f"Wazuh API error: {e.response.status_code}", "detail": e.response.text[:500]}
    except Exception as e:
        return {"error": str(e)}
