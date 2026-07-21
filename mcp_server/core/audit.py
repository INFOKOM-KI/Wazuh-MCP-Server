#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Audit logging, response truncation, markdown escaping, rate limiting, response pipeline.
"""
from __future__ import annotations
import functools, json, os, time, hashlib
from datetime import datetime

from mcp_server import CHARACTER_LIMIT, BLUETEAM_AUDIT_LOG, BLUETEAM_ALLOW_UNTRUNCATED, BLUETEAM_RATE_LIMIT

from mcp_server.core.redact import _redact_alert_data

# Audit logging
def _audit_log(tool_name: str, params: dict, result_preview: str = "") -> None:
    """Append audit entry to BLUETEAM_AUDIT_LOG if configured."""
    if not BLUETEAM_AUDIT_LOG:
        return
    try:
        entry = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "tool": tool_name,
            "params": {k: str(v)[:100] for k, v in params.items() if k not in ("api_key", "key")},
            "result_preview": (result_preview or "")[:200],
            "redaction_bypassed": params.get("bypass_redaction", False),
        }
        with open(BLUETEAM_AUDIT_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


# Response truncation
def _truncate_if_needed(text: str, *, bypass: bool = False) -> str:
    """Cap response at CHARACTER_LIMIT. When bypass=True, prepends forensic warning."""
    if bypass:
        banner = "⚠️ UNREDACTED — FORENSIC USE ONLY. Contains PII/internal IPs.\n"
        text = banner + text
        if BLUETEAM_AUDIT_LOG:
            try:
                with open(BLUETEAM_AUDIT_LOG, "a") as f:
                    f.write(json.dumps({
                        "ts": datetime.utcnow().isoformat() + "Z",
                        "event": "forensic_bypass_response",
                        "response_sha256": hashlib.sha256(text.encode()).hexdigest(),
                        "response_bytes": len(text.encode()),
                    }) + "\n")
            except Exception:
                pass
        if BLUETEAM_ALLOW_UNTRUNCATED:
            return text
    if len(text) <= CHARACTER_LIMIT:
        return text
    truncated = text[:CHARACTER_LIMIT]
    return (
        truncated
        + f"\n\n... [truncated — response exceeds {CHARACTER_LIMIT} characters. "
        "Use a smaller limit per page (e.g. limit=50) or iterate with the next_cursor "
        "to process results incrementally.]"
    )


# Markdown escaping
def _escape_md_table(value: str) -> str:
    """Escape pipe and newline characters for safe markdown table rendering."""
    return value.replace("|", "\\|").replace("\n", " ").replace("\r", "")


# Rate limiting
_rate_limit_count = 0
_rate_limit_reset_time = 0.0


def _check_rate_limit() -> bool:
    """Return True if allowed, False if rate limited."""
    if BLUETEAM_RATE_LIMIT <= 0:
        return True
    global _rate_limit_count, _rate_limit_reset_time
    now = time.time()
    if now > _rate_limit_reset_time:
        _rate_limit_count = 0
        _rate_limit_reset_time = now + 60
    _rate_limit_count += 1
    return _rate_limit_count <= BLUETEAM_RATE_LIMIT


# Response pipeline decorator
# For tools returning structured data (dict/list). Automates: redact -> json.dumps -> truncate -> audit
# String-returning tools should use _audit_log() + _truncate_if_needed() directly.

def response_pipeline(tool_name: str):
    """Decorator: auto-applies redact → json.dumps → truncate → audit.

    For async tool handlers that return structured data (dict/list).
    String-returning tools should call _audit_log()/_truncate_if_needed() directly.
    """
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            result = await func(*args, **kwargs)
            params = args[0] if args else None

            bypass_redact = getattr(params, "bypass_redaction", False) if params is not None else False
            bypass_char = getattr(params, "bypass_character_limit", False) if params is not None else False

            if isinstance(result, (dict, list)):
                result = _redact_alert_data(result, bypass=bypass_redact)
                result = json.dumps(result, indent=2, ensure_ascii=False)

            result_str = result if isinstance(result, str) else str(result)
            result = _truncate_if_needed(result_str, bypass=bypass_char)

            params_dict: dict = {}
            if params is not None:
                try:
                    params_dict = params.model_dump() if hasattr(params, "model_dump") else {}
                except Exception:
                    pass
            _audit_log(tool_name, params_dict, result[:200] if isinstance(result, str) else "")

            return result
        return wrapper
    return decorator
