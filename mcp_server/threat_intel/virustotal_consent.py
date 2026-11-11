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

import logging
import re
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, Field, StrictBool
from mcp.shared.version import SUPPORTED_PROTOCOL_VERSIONS
from mcp.types import (
    LATEST_PROTOCOL_VERSION,
    ClientCapabilities,
    ElicitationCapability,
)

logger = logging.getLogger("blue_team_mcp.virustotal_consent")

_CONSENT_TTL_SECONDS = 120.0
# Direct Context.elicit is defined only for these revisions; older ones predate it.
# 2026-07-28 MRTR needs Resolve(Elicit), which the pinned SDK does not provide.
_DIRECT_ELICIT_PROTOCOLS = frozenset({"2025-06-18", "2025-11-25"})
_LOCK = threading.Lock()
_TOKENS: dict[str, tuple[str, str, float]] = {}


@dataclass(frozen=True)
class ConsentDecision:
    """Outcome of one approval attempt.

    ``reason`` is a stable token for logs and JSON consumers. ``detail`` carries
    the evidence that picked the branch (the requested revision, the exception
    class, the client action) and never the prompt text or the indicator.
    """
    approved: bool
    reason: str
    detail: str = ""

    def __bool__(self) -> bool:
        return self.approved


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
        "Review the disclosure below, tick the approval checkbox, then submit. "
        "Submitting the form untouched does not authorize sharing.\n"
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


_UNSAFE_DETAIL = re.compile(r"[^\x20-\x7e]")


def _safe_detail(value: object, limit: int = 40) -> str:
    """One printable line of client-supplied text.

    Protocol revisions and client actions come from the peer, so they reach log
    lines and the tool's error text. A newline there would forge a second log
    entry or break the Markdown table.
    """
    return _UNSAFE_DETAIL.sub("?", str(value))[:limit]


def _requested_protocol(ctx: Any) -> str | None:
    """The revision the client asked for. Diagnostics only."""
    try:
        params = ctx.request_context.session.client_params
    except (AttributeError, TypeError, ValueError):
        return None
    requested = getattr(params, "protocolVersion", None)
    return requested if isinstance(requested, str) else None


def _capability_state(ctx: Any) -> tuple[bool, str]:
    """Report whether the client advertises elicitation, and the evidence used."""
    try:
        session = ctx.request_context.session
    except (AttributeError, TypeError, ValueError):
        # Direct/fake Context used by unit tests. A production Context always
        # supplies a session; anything below this point fails closed.
        return True, "direct_context"
    try:
        if session.client_params is None:
            return False, "client_params_missing"
        advertised = bool(session.check_client_capability(
            ClientCapabilities(elicitation=ElicitationCapability())))
        return advertised, "advertised" if advertised else "capability_missing"
    except Exception as exc:
        return False, type(exc).__name__


def _host_facts(ctx: Any) -> tuple[str, str, str]:
    """Client name, version, requested revision. Never the indicator."""
    try:
        params = ctx.session.client_params
    except (AttributeError, TypeError, ValueError):
        return "unknown", "unknown", "unknown"
    if params is None:
        return "unknown", "unknown", "unknown"
    info = getattr(params, "clientInfo", None)
    return (_safe_detail(getattr(info, "name", "unknown") or "unknown", 40),
            _safe_detail(getattr(info, "version", "unknown") or "unknown", 40),
            _safe_detail(getattr(params, "protocolVersion", "unknown") or "unknown"))


async def request_ioc_sharing_detailed(ctx: Any | None,
                                       message: str) -> ConsentDecision:
    """Ask the MCP host/user and name the branch that decided the outcome.

    Reasons: ``context_missing``, ``unsupported_protocol`` (with the revision the
    client *requested*; the pinned SDK does not retain a negotiated revision),
    ``elicitation_capability_missing``, ``elicitation_error``, ``user_declined``,
    ``user_cancelled``, ``approval_not_given`` (accepted form, box unticked),
    ``approval_field_missing``, ``empty_content``, ``invalid_approval_response``,
    ``approved``.

    A client that cannot elicit, uses an older revision, declines, cancels,
    leaves the box unticked, or returns a non-boolean approval is a refusal.
    The server cannot prove the client showed the prompt to a human if the
    client is an autonomous agent.
    """
    def decision(approved: bool, reason: str, detail: str = "") -> ConsentDecision:
        # Log the branch only: never the prompt text or the indicator.
        logger.info("VirusTotal consent %s%s", reason,
                    f" ({detail})" if detail else "")
        return ConsentDecision(approved, reason, detail)

    if ctx is None:
        return decision(False, "context_missing")
    name, version, asked = _host_facts(ctx)
    logger.info("VirusTotal consent host=%s/%s requested=%s elicitation=%s",
                name, version, asked, _capability_state(ctx)[0])
    requested = _negotiated_protocol(ctx)
    if requested == "unsupported":
        return decision(False, "context_missing", "client_params_missing")
    if requested is not None and requested not in _DIRECT_ELICIT_PROTOCOLS:
        raw_requested = _requested_protocol(ctx)
        return decision(False, "unsupported_protocol",
                        f"requested={_safe_detail(raw_requested or 'unknown')}")
    supported, evidence = _capability_state(ctx)
    if not supported:
        return decision(False, "elicitation_capability_missing", evidence)
    try:
        # Raw form response: FastMCP's ctx.elicit() coerces content through the
        # model, which turns a missing field into the default False.
        result = await ctx.session.elicit_form(
            message=message,
            requestedSchema=IocSharingApproval.model_json_schema())
    except Exception as exc:
        return decision(False, "elicitation_error", type(exc).__name__)
    action = getattr(result, "action", None)
    action = getattr(action, "value", action)
    if action == "decline":
        return decision(False, "user_declined")
    if action == "cancel":
        return decision(False, "user_cancelled")
    if action != "accept":
        return decision(False, "invalid_approval_response",
                        f"action={_safe_detail(action)}")
    content = getattr(result, "content", None)
    if content is None:
        return decision(False, "invalid_approval_response", "content=none")
    if not isinstance(content, dict):
        return decision(False, "invalid_approval_response",
                        f"content_type={type(content).__name__}")
    if not content:
        return decision(False, "empty_content", "content=empty")
    if "approve" not in content:
        return decision(False, "approval_field_missing",
                        "content=present approve_field=missing")
    approved = content["approve"]
    if approved is True:
        # Manual checks classify the refusal; the model is the final gate so a
        # hand-built dict cannot drift from the schema the prompt advertises.
        try:
            IocSharingApproval.model_validate(content)
        except Exception:
            return decision(False, "invalid_approval_response", "schema=rejected")
        return decision(True, "approved", "content=present approve=true")
    if approved is False:
        # Accepted form with the box off: a different fix from a decline.
        return decision(False, "approval_not_given",
                        "content=present approve=false")
    return decision(False, "invalid_approval_response",
                    f"approve_type={type(approved).__name__}")


async def request_ioc_sharing(ctx: Any | None, message: str) -> bool:
    """Boolean form of :func:`request_ioc_sharing_detailed`."""
    return (await request_ioc_sharing_detailed(ctx, message)).approved


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
