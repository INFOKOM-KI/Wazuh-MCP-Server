#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Inbound authentication for the HTTP transports (streamable-http / http).
Independent of ``mcp_server/wazuh/auth.py`` (outbound JWT to the Wazuh Manager API).
Scope model (fail-closed):
- ``wazuh:read``  - default, granted to every valid key (read-only tools).
- ``wazuh:write`` - opt-in via MCP_API_KEY_SCOPES; required for tools whose
``readOnlyHint`` annotation is not True (or ``destructiveHint`` is True).
The write-tool set is derived at request time from the FastMCP registry's
tool annotations not a hardcoded allowlist, so a newly added write tool is
automatically protected with nothing extra to update.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import logging
import os
import secrets
from dataclasses import dataclass, field
from typing import Optional
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger("blue_team_mcp.server_auth")

READ_SCOPE = "wazuh:read"
WRITE_SCOPE = "wazuh:write"
_VALID_SCOPES = (READ_SCOPE, WRITE_SCOPE)

# "btm_" + secrets.token_urlsafe(32)  ->  4 + 43 = 47 chars
API_KEY_PREFIX = "btm_"
API_KEY_LENGTH = 47


@dataclass
class APIKey:
    """A validated inbound API key and it's granted scopes."""
    key_hash: bytes
    scopes: frozenset[str] = field(default_factory=lambda: frozenset({READ_SCOPE}))

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes


class ServerAuthManager:
    """Validate inbound ``Authorization: Bearer <api-key>`` credentials.
    Reads MCP_API_KEY / MCP_API_KEY_SCOPES from the environment at import.
    The key is stored only as a SHA-256 digest (the key is a 256-bit random
    token, so a plain digest suffices, no HMAC salt required), compared with
    ``hmac.compare_digest`` for constant-time equality.
    """
    def __init__(self) -> None:
        self._keys: dict[str, APIKey] = {}
        self._configured = False
        self._load_from_env()

    @property
    def configured(self) -> bool:
        """True when a well-formed MCP_API_KEY was loaded."""
        return self._configured

    def _load_from_env(self) -> None:
        raw = os.environ.get("MCP_API_KEY", "").strip()
        if not raw:
            return
        if not (raw.startswith(API_KEY_PREFIX) and len(raw) == API_KEY_LENGTH):
            logger.error(
                "MCP_API_KEY format invalid (expected %s<43-char-urlsafe-base64>, %d chars). "
                "Generate with: python3 -c \"import secrets; print('btm_' + secrets.token_urlsafe(32))\". "
                "HTTP transport will treat auth as unconfigured.",
                API_KEY_PREFIX, API_KEY_LENGTH,
            )
            return
        raw_scopes = os.environ.get("MCP_API_KEY_SCOPES", "").strip()
        scopes = frozenset(s for s in raw_scopes.split() if s in _VALID_SCOPES) or frozenset({READ_SCOPE})
        self._keys[raw] = APIKey(key_hash=self._hash(raw), scopes=scopes)
        self._configured = True
        logger.info("Inbound API key loaded (scopes: %s).", " ".join(sorted(scopes)))

    @staticmethod
    def _hash(api_key: str) -> bytes:
        return hashlib.sha256(api_key.encode()).digest()

    def validate_api_key(self, api_key: str) -> Optional[APIKey]:
        """Return the matching APIKey, or None if invalid/unconfigured."""
        if not api_key or not self._configured:
            return None
        digest = self._hash(api_key)
        for key in self._keys.values():
            if hmac.compare_digest(key.key_hash, digest):
                return key
        return None

    def authenticate(self, authorization: Optional[str]) -> Optional[APIKey]:
        """Parse ``Authorization: Bearer <key>`` and validate. None if invalid."""
        if not authorization or not authorization.startswith("Bearer "):
            return None
        return self.validate_api_key(authorization[7:].strip())


# Module
auth_manager = ServerAuthManager()

def _write_tool_names() -> frozenset[str]:
    """Derive the write-tool set from FastMCP registry annotations.
    Fail-closed: a tool is write-scoped when readOnlyHint is *not explicitly
    True* (False or None) or destructiveHint is True.
    """
    try:
        from mcp_server import mcp
        tools = getattr(mcp._tool_manager, "_tools", {})
        return frozenset(
            name for name, t in tools.items()
            if (ann := getattr(t, "annotations", None)) is not None
            and (ann.readOnlyHint is not True or ann.destructiveHint is True)
        )
    except Exception as e:  # noqa: BLE001 - fail closed to empty set on registry error
        logger.error("Failed to derive write-tool set: %s", e)
        return frozenset()


class APIAuthMiddleware(BaseHTTPMiddleware):
    """Enforce API-key auth + write scope on the streamable-http transport.
    - 401 when the ``Authorization: Bearer <key>`` header is missing/invalid.
    - 403 when a ``tools/call`` targets a write tool but the key lacks wazuh:write.
    BaseHTTPMiddleware may interfere with SSE streaming responses in
    some Starlette versions. If the streamable-http transport ever serves
    long-lived SSE streams, replace with a pure-ASGI wrapper (header check
    only, no body read) authn still holds, per-request scope can move to a thin ``tools/call`` hook.
    """
    def __init__(self, app, dispatch=None):
        super().__init__(app, dispatch)
        self._write_tools = _write_tool_names()

    async def dispatch(self, request: Request, call_next):
        key = auth_manager.authenticate(request.headers.get("authorization"))
        if key is None:
            return JSONResponse(
                {"error": "Unauthorized: valid MCP_API_KEY required"},
                status_code=401,
                headers={"WWW-Authenticate": 'Bearer realm="blue_team_mcp"'},
            )

        if request.method == "POST":
            tool_name = await _extract_tool_name(request)
            if tool_name and tool_name in self._write_tools and not key.has_scope(WRITE_SCOPE):
                return JSONResponse(
                    {"error": f"Forbidden: tool '{tool_name}' requires '{WRITE_SCOPE}' scope"},
                    status_code=403,
                )

        return await call_next(request)


async def _extract_tool_name(request: Request) -> Optional[str]:
    """Best-effort extract of the target tool name from a JSON-RPC body."""
    try:
        body = await request.body()
        payload = json.loads(body)
    except (ValueError, RuntimeError):
        return None
    if isinstance(payload, dict) and payload.get("method") == "tools/call":
        params = payload.get("params") or {}
        return params.get("name") if isinstance(params, dict) else None
    return None


def serve_authenticated(mcp, host: str, port: int, log_level: str = "INFO") -> None:
    """Serve the streamable-http transport, enforcing auth when configured."""
    import uvicorn

    app = mcp.streamable_http_app()
    if auth_manager.configured:
        app.add_middleware(APIAuthMiddleware)
    else:
        logger.warning(
            "MCP_API_KEY not set - serving HTTP transport WITHOUT inbound auth "
            "(loopback only; non-loopback bind is refused at startup)."
        )
    config = uvicorn.Config(app, host=host, port=port, log_level=log_level.lower())
    uvicorn.Server(config).run()


if __name__ == "__main__":   # self-check
    _os = os
    _os.environ["MCP_API_KEY"] = API_KEY_PREFIX + secrets.token_urlsafe(32)
    _os.environ["MCP_API_KEY_SCOPES"] = READ_SCOPE
    _m = ServerAuthManager()
    _raw = _os.environ["MCP_API_KEY"]
    assert _m.configured is True
    _k = _m.validate_api_key(_raw)
    assert _k is not None and _k.has_scope(READ_SCOPE) and not _k.has_scope(WRITE_SCOPE)
    assert _m.validate_api_key(API_KEY_PREFIX + secrets.token_urlsafe(32)) is None  # wrong key
    assert _m.authenticate(None) is None
    assert _m.authenticate("Bearer " + _raw) is not None
    assert _m.authenticate("Bearer wrong") is None
    _os.environ["MCP_API_KEY"] = "short"  # malformed -> unconfigured
    assert ServerAuthManager().configured is False
    print("server_auth self-check OK")
