#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Short-lived, indicator-bound consent for VirusTotal IoC sharing.

The MCP host is asked through Context.elicit. The resulting server-side token is
single-use, bound to a provider kind and normalized indicator, and consumed
before the VirusTotal cache or quota gate. An LLM-supplied boolean is not
treated as consent; it only requests that the host ask the user.
"""
from __future__ import annotations

import secrets
import threading
import time
from typing import Any

from pydantic import BaseModel, Field, StrictBool
from mcp.shared.version import SUPPORTED_PROTOCOL_VERSIONS
from mcp.types import (
    LATEST_PROTOCOL_VERSION,
    ClientCapabilities,
    ElicitationCapability,
)

_CONSENT_TTL_SECONDS = 120.0
# Direct Context.elicit is defined only for these revisions; older ones predate it.
# 2026-07-28 MRTR needs Resolve(Elicit), which the pinned SDK does not provide.
_DIRECT_ELICIT_PROTOCOLS = frozenset({"2025-06-18", "2025-11-25"})
_LOCK = threading.Lock()
_TOKENS: dict[str, tuple[str, str, float]] = {}


class IocSharingApproval(BaseModel):
    approve: StrictBool = Field(
        default=False,
        description=("Approve sending the listed indicator to VirusTotal and adding "
                     "it to its community dataset."),
    )


def consent_message(kind: str, values: list[str] | str) -> str:
    """Build the exact provider, operation, and indicator prompt."""
    items = [values] if isinstance(values, str) else list(values)
    joined = ", ".join(items[:15])
    if len(items) > 15:
        joined += f", and {len(items) - 15} more"
    subject = "these indicators" if len(items) > 1 else "this indicator"
    operation = {
        "ip_addresses": "IP address report lookup",
        "domains": "domain report lookup",
        "files": "file hash report lookup",
    }.get(kind, "indicator report lookup")
    return (
        f"Approve sending {subject} to VirusTotal for {operation}?\n"
        f"Indicator(s): {joined}\n"
        "VirusTotal adds queried IoCs to its dataset, where they become accessible "
        "to the community. A public indicator is not automatically non-sensitive. "
        "Do not approve confidential, sensitive, or personally identifiable indicators."
    )


def _negotiated_protocol(ctx: Any) -> str | None:
    """Return the revision the installed server would negotiate, if visible.

    ``None`` means a direct/fake Context (unit tests) or an uninitialized
    session, not a production protocol decision.
    """
    try:
        session = ctx.request_context.session
    except (AttributeError, TypeError, ValueError):
        return None
    try:
        params = session.client_params
    except Exception:
        return "unsupported"
    if params is None:
        return "unsupported"
    requested = getattr(params, "protocolVersion", None)
    if not isinstance(requested, str):
        return LATEST_PROTOCOL_VERSION
    if requested in SUPPORTED_PROTOCOL_VERSIONS:
        return requested
    return LATEST_PROTOCOL_VERSION


def _client_supports_elicitation(ctx: Any) -> bool:
    """True only when the negotiated client advertises elicitation support."""
    try:
        session = ctx.request_context.session
    except (AttributeError, TypeError, ValueError):
        # Direct/fake Context used by unit tests. A production Context always
        # supplies a session; anything below this point fails closed.
        return True
    try:
        if session.client_params is None:
            return False
        return session.check_client_capability(
            ClientCapabilities(elicitation=ElicitationCapability()))
    except Exception:
        return False


async def request_ioc_sharing(ctx: Any | None, message: str) -> bool:
    """Ask the MCP host/user; return true only for an explicit approval.

    A client that cannot elicit, uses an unsupported protocol revision,
    declines, cancels, or returns a non-boolean approval is treated as refusal.
    The server cannot prove the client showed the prompt to a human if the
    client is an autonomous agent.
    """
    if ctx is None:
        return False
    protocol = _negotiated_protocol(ctx)
    if protocol is not None and protocol not in _DIRECT_ELICIT_PROTOCOLS:
        return False
    if not _client_supports_elicitation(ctx):
        return False
    try:
        result = await ctx.elicit(message, schema=IocSharingApproval)
    except Exception:
        return False
    action = getattr(result, "action", None)
    action = getattr(action, "value", action)
    data = getattr(result, "data", None)
    if isinstance(data, dict):
        approved = data.get("approve")
    else:
        approved = getattr(data, "approve", None)
    return action == "accept" and approved is True


def issue_consent(kind: str, value: str, ttl: float = _CONSENT_TTL_SECONDS) -> str:
    """Issue a single-use token bound to one provider kind and normalized value."""
    token = secrets.token_urlsafe(32)
    with _LOCK:
        _TOKENS[token] = (kind, value, time.monotonic() + max(0.0, ttl))
    return token


def consume_consent(token: str | None, kind: str, value: str) -> None:
    """Consume one token, or raise a typed consent refusal.

    A mismatch consumes the token as well, preventing reuse for another
    indicator or operation.
    """
    from mcp_server.threat_intel.virustotal import VirusTotalError

    if not token:
        raise VirusTotalError(
            "VirusTotal IoC sharing acknowledgement is required", "consent_required")
    with _LOCK:
        entry = _TOKENS.pop(token, None)
    if entry is None:
        raise VirusTotalError(
            "VirusTotal consent token is missing or already used", "consent_required")
    bound_kind, bound_value, expiry = entry
    if time.monotonic() > expiry:
        raise VirusTotalError(
            "VirusTotal consent token has expired", "consent_required")
    if bound_kind != kind or bound_value != value:
        raise VirusTotalError(
            "VirusTotal consent token is bound to a different indicator or operation",
            "consent_required")


def reset_consent_state() -> None:
    """Clear process-local consent tokens; tests and process reset only."""
    with _LOCK:
        _TOKENS.clear()
