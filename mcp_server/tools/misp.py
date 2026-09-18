#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
MISP threat intelligence lookup, version agnostic IOC search.
Scope: READ-ONLY attribute lookup against a configured MISP instance. No push/publish/sighting writes.

Adaptive by design (MISP 2.4.x, 2.5+):
  * ``/attributes/restSearch`` is called over REST with a JSON body. No
    ``pymisp`` dependency: ``_api_call`` + the shared TTL cache + the shared
    ``AsyncRateLimiter`` already provide retry, per-upstream circuit breaking
    and request spacing. PyMISP would add a synchronous ``requests`` client
    that blocks the event loop.
  * ``_extract_attributes()`` accepts every response shape MISP has emitted
    (``{"response": {"Attribute": [...]}}``, ``{"response": [...]}``,
    ``{"Attribute": [...]}``, a bare list, and events with nested attributes).
  * ``_ensure_capabilities()`` probes ``/servers/getVersion.json`` exactly once,
    survives a 403/404/timeout, and only records a note. A failed probe never
    disables the lookup it always degrades to generic REST search.

``@blueteam_tool(redact=False)`` is deliberate. The default pipeline masks the
return value, which for an IOC lookup would mask the indicator the analyst is
asking about the same trap documented for ``sigma_rules.py``.

Compensating controls:
  * ``_strip_misp_attributes()`` is an ALLOWLIST reducer. Free-text fields
    (``comment``, galaxy descriptions) are dropped, so an analyst or registrant
    name inside a MISP comment cannot reach LLM context. Same class of control
    as ``_strip_whois_pii()`` the shape-based layers match emails/IPs/domains, not names in prose.
  * ``event.info`` is kept only when the active redaction policy is
    ``protect_victim`` or ``raw``; under ``full`` it is dropped.
  * The MISP URL is internal infrastructure, so no public-IP SSRF guard is applied to it. The lookup value is validated
    as a bounded non-empty string and sent only as a JSON field, never interpolated into a URL path.

NOTE: No ``from __future__ import annotations`` deferred annotation evaluation (PEP 563) breaks @blueteam_tool type resolution.
"""

import json
import logging
from typing import Any, Literal, Optional
import httpx
from pydantic import BaseModel, ConfigDict, Field
from mcp_server.core.audit import _escape_md_table
from mcp_server.core.config import config
from mcp_server.core.exceptions import ThreatIntelError
from mcp_server.core.http_client import _api_call, _handle_api_error
from mcp_server.core.tool_decorator import blueteam_tool
from mcp_server.threat_intel._cache import cache_get, cache_set, get_limiter

logger = logging.getLogger("blue_team_mcp.misp")

# MISP attribute value can be a multi-KB base64 payload; a tag list
# can run to dozens of entries. Both are capped before they reach LLM context.
_MAX_VALUE_CHARS = 512
_MAX_TAGS = 20
_MAX_TAG_CHARS = 120

# Attribute allowlist. Anything not named here is dropped, so a MISP field
# added in a later release never leaks by default.
_ATTR_KEEP = (
    "uuid", "id", "event_id", "type", "category", "value",
    "to_ids", "timestamp", "first_seen", "last_seen", "deleted",
)
# Event metadata subset. ``info`` is free text and policy-gated separately.
_EVENT_KEEP = ("id", "uuid", "date", "threat_level_id", "analysis", "published")

# Keys that indicate a restSearch body actually carries data. Used to tell a
# real response from a MISP logic error delivered with HTTP 200.
_DATA_KEYS = ("response", "Attribute", "attribute", "Event", "event", "data", "result")


# Config + request plumbing
def _misp_config():
    """Return the MispConfig, or raise when the config singleton is absent."""
    if config is None:
        raise ThreatIntelError("Config not initialised MISP tools unavailable.")
    return config.misp


def _misp_headers() -> dict:
    """MISP auth headers. MISP takes the automation key as a bare ``Authorization``"""
    return {
        "Authorization": _misp_config().api_key,
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "blue-team-mcp/1.0.0 (TangerangKota-CSIRT)",
    }


def _check_misp_error(payload: Any, endpoint: str) -> None:
    """Raise on a MISP logic error delivered with HTTP 200.
    MISP answers a rejected restSearch with ``{"errors": ...}`` or
    ``{"name": ..., "message": ..., "url": ...}`` while the status stays 200.
    ``_api_call`` only inspects the HTTP status, so this body has to be checked
    explicitly - otherwise a hard failure reads as "no results found".
    """
    if not isinstance(payload, dict):
        return
    errors = payload.get("errors")
    if errors:
        detail = json.dumps(errors, ensure_ascii=False)[:300]
        raise ThreatIntelError(f"MISP {endpoint} rejected the query: {detail}")
    if "message" in payload and not any(k in payload for k in _DATA_KEYS):
        raise ThreatIntelError(
            f"MISP {endpoint} returned an error: {str(payload.get('message'))[:300]}"
        )


async def _misp_search(endpoint: str, payload: dict) -> Any:
    """POST a restSearch payload to MISP and return the parsed body.
    Successful responses only are cached; an error is never cached, so a stale
    403 cannot outlive the credential fix. Spacing, retry and circuit breaking
    come from the shared limiter + per-upstream breaker keyed ``"misp"``.
    """
    cfg = _misp_config()
    if not cfg.enabled:
        raise ThreatIntelError(
            "MISP_URL and MISP_API_KEY must both be set to use MISP tools."
        )
    cache_key = json.dumps({"endpoint": endpoint, "payload": payload}, sort_keys=True, default=str)
    cached = cache_get("misp", cache_key)
    if cached is not None:
        return cached

    limiter = get_limiter("misp", max_concurrent=cfg.max_concurrent,
                          min_interval=cfg.min_interval)
    async with limiter:
        response = await _api_call(
            "post",
            f"{cfg.url}/{endpoint.lstrip('/')}",
            client_name="misp",
            verify=cfg.verify_ssl,
            headers=_misp_headers(),
            json=payload,
            timeout=cfg.timeout,
        )
    try:
        data = response.json()
    except ValueError as exc:
        raise ThreatIntelError(
            f"MISP {endpoint} returned non-JSON content "
            f"(HTTP {response.status_code}, {len(response.text)} bytes). "
            "Check that MISP_URL points at the MISP API root."
        ) from exc

    _check_misp_error(data, endpoint)
    cache_set("misp", cache_key, data, cfg.cache_ttl)
    return data


# Capability probe (non-blocking, once per process)
_CAPABILITIES: dict = {"probed": False, "version": None, "note": ""}


async def _ensure_capabilities() -> dict:
    """Probe ``/servers/getVersion.json`` once; never raise, never disable.
    Restricted, missing or slow version endpoints are recorded as a ``note`` and
    the caller proceeds with generic REST search. The probe uses a 5s timeout
    and no retry so a dead endpoint cannot delay a lookup by a retry ladder.
    """
    if _CAPABILITIES["probed"]:
        return _CAPABILITIES
    _CAPABILITIES["probed"] = True

    cfg = _misp_config()
    if not cfg.enabled:
        return _CAPABILITIES
    try:
        response = await _api_call(
            "get",
            f"{cfg.url}/servers/getVersion.json",
            client_name="misp",
            verify=cfg.verify_ssl,
            headers=_misp_headers(),
            timeout=5.0,
            max_retries=0,
        )
        body = response.json()
        version = None
        if isinstance(body, dict):
            version = body.get("version")
            if not version and isinstance(body.get("response"), dict):
                version = body["response"].get("version")
        if version:
            _CAPABILITIES["version"] = str(version)[:40]
    except Exception as exc:
        _CAPABILITIES["note"] = f"version probe skipped ({type(exc).__name__})"
        logger.debug("MISP version probe failed: %s", exc)
    return _CAPABILITIES


# Adaptive JSON normalizer
def _as_dict_list(value: Any) -> list:
    """Coerce a MISP container value into a list of dicts. Never raises."""
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    if isinstance(value, dict):
        return [value]
    return []


def _event_record(event: dict) -> dict:
    """Metadata for an event that carried no attribute list."""
    return {k: event.get(k) for k in _EVENT_KEEP if event.get(k) is not None}


def _extract_attributes(payload: Any) -> list:
    """Extract attribute dicts from any MISP response shape.
    Handles ``{"response": {"Attribute": [...]}}``, ``{"response": [...]}``,
    ``{"Attribute": [...]}``, a bare list, and events carrying a nested
    ``Attribute`` list. Unknown wrappers are traversed; anything that is not an
    attribute record is dropped rather than rendered.
    """
    if payload is None:
        return []
    if isinstance(payload, list):
        collected: list = []
        for item in payload:
            collected.extend(_extract_attributes(item))
        return collected
    if not isinstance(payload, dict):
        return []

    for key in ("Attribute", "attribute", "attributes", "Attribute[]"):
        if key in payload:
            return _as_dict_list(payload[key])

    for key in ("Event", "event", "events"):
        if key in payload:
            collected = []
            for event in _as_dict_list(payload[key]):
                inner = _extract_attributes(event)
                if inner:
                    collected.extend(inner)
                else:
                    collected.append(_event_record(event))
            return collected

    for key in ("response", "data", "result", "results"):
        if key in payload:
            return _extract_attributes(payload[key])

    if "value" in payload:
        return [payload]

    for child in payload.values():
        if isinstance(child, list) and child:
            return _extract_attributes(child)
    return []


# PII allowlist reducer
def _redaction_policy() -> str:
    """Active redaction policy; ``full`` when the singleton is absent."""
    if config is None:
        return "full"
    return config.redaction.policy


def _bounded(value: Any) -> Any:
    """Cap a JSON scalar so one field cannot take over the response."""
    if isinstance(value, bool) or isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        return value[:_MAX_VALUE_CHARS]
    if isinstance(value, list):
        return [_bounded(v) for v in value[:5]]
    return str(value)[:120]


def _tag_names(tags: Any) -> list:
    """Flatten MISP ``Tag`` objects to bounded name strings."""
    names: list = []
    for tag in _as_dict_list(tags):
        name = tag.get("name")
        if isinstance(name, str) and name:
            names.append(name[:_MAX_TAG_CHARS])
        if len(names) >= _MAX_TAGS:
            break
    return names


def _strip_event(event: dict, keep_info: bool) -> dict:
    """Reduce an event to technical metadata.
    ``Orgc.name`` is an organisation label (abuse-escalation context), kept.
    ``info`` is free text and only kept when the policy keeps victim context.
    """
    record = {k: _bounded(event.get(k)) for k in _EVENT_KEEP if event.get(k) is not None}
    org = event.get("Orgc") or event.get("Org")
    if isinstance(org, dict) and isinstance(org.get("name"), str):
        record["org"] = org["name"][:120]
    if keep_info and isinstance(event.get("info"), str):
        record["info"] = event["info"][:_MAX_VALUE_CHARS]
    return record


def _strip_misp_attributes(attributes: list) -> list:
    """Allowlist-reduce MISP attributes before they reach LLM context.
    Drops free-text (``comment``, galaxy descriptions) that the shape-based
    redaction layers cannot inspect. Keeps the technical fields an analyst
    needs to pivot on, plus tag names for MITRE/galaxy context.
    """
    keep_info = _redaction_policy() in ("protect_victim", "raw")
    stripped: list = []
    for attr in attributes:
        if not isinstance(attr, dict):
            continue
        record = {k: _bounded(attr[k]) for k in _ATTR_KEEP if k in attr}
        tags = _tag_names(attr.get("Tag") or attr.get("tags"))
        if tags:
            record["tags"] = tags
        event = attr.get("Event")
        if isinstance(event, dict):
            record["event"] = _strip_event(event, keep_info)
        if not record:
            continue
        stripped.append(record)
    return stripped


# Rendering
def _cell(value: Any) -> str:
    """Markdown table cell: escape separators, dash out empty values."""
    if value is None or value == "":
        return "-"
    return _escape_md_table(str(value))


def _format_misp_markdown(indicator: str, attributes: list, capabilities: dict) -> str:
    """Render the stripped attributes as a compact markdown table."""
    lines = [
        f"# MISP IOC Lookup `{_escape_md_table(indicator)}`",
        "",
        f"**Matches**: {len(attributes)}",
    ]
    if capabilities.get("version"):
        lines.append(f"**MISP version**: `{capabilities['version']}`")
    if capabilities.get("note"):
        lines.append(f"**Capability probe**: {capabilities['note']} - lookup unaffected")
    if not attributes:
        lines.extend(["", "No matching MISP attributes returned."])
        return "\n".join(lines)

    lines.extend([
        "",
        "| Type | Category | Value | To IDS | Event | First seen | Last seen | Tags |",
        "|------|----------|-------|--------|-------|------------|-----------|------|",
    ])
    for attr in attributes:
        event = attr.get("event") or {}
        lines.append(
            "| {} | {} | {} | {} | {} | {} | {} | {} |".format(
                _cell(attr.get("type")),
                _cell(attr.get("category")),
                _cell(attr.get("value")),
                "yes" if attr.get("to_ids") else "no",
                _cell(event.get("id") or attr.get("event_id")),
                _cell(attr.get("first_seen")),
                _cell(attr.get("last_seen")),
                _cell(", ".join(attr.get("tags", [])[:3])),
            )
        )
    return "\n".join(lines)


class MispIocLookupInput(BaseModel):
    """Input model for blueteam_misp_ioc_lookup."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    value: str = Field(
        ..., min_length=1, max_length=2048,
        description="Indicator to search for: IP, domain, hostname, URL, email, or file hash.",
    )
    type_attribute: Optional[str] = Field(
        default=None, max_length=64,
        description="Optional MISP attribute type filter, e.g. 'ip-src', 'domain', 'sha256'.",
    )
    to_ids: Optional[bool] = Field(
        default=None,
        description="Optional IDS-flag filter. True returns only attributes flagged for detection.",
    )
    limit: int = Field(
        default=50, ge=1, le=500,
        description="Max attributes per page. MISP default is 50, hard cap here is 500.",
    )
    page: int = Field(default=1, ge=1, description="1-indexed result page.")
    metadata: Optional[bool] = Field(
        default=None,
        description="Optional MISP 'metadata' flag, omitted by default. MISP's own attribute "
                    "search (PyMISP search_attributes) does not send it; only the event "
                    "controller uses it. Set only if your instance accepts it.",
    )
    response_format: Literal["markdown", "json"] = Field(
        default="markdown", description="'markdown' (default) or 'json'.")


@blueteam_tool(
    name="blueteam_misp_ioc_lookup",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
    audit=True, truncate=True, redact=False,
)
async def blueteam_misp_ioc_lookup(params: MispIocLookupInput) -> str:
    """Look up an indicator in MISP attributes (events, IOCs, sightings context).
    Read-only. Queries ``/attributes/restSearch`` over REST, so the tool works
    against MISP 2.4.x and 2.5+ without a PyMISP dependency or a version check
    that can fail closed. If ``/servers/getVersion.json`` is restricted, the
    lookup still runs and the markdown notes the probe was skipped.
    Free text fields (``comment``, galaxy descriptions) are dropped before the
    result reaches you, and ``event.info`` is dropped unless the deployment's
    redaction policy keeps victim context. Tag names and technical attribute
    fields are kept.
    Args:
        params.value: Indicator to search for (IP, domain, hostname, URL, email, hash).
        params.type_attribute: Optional MISP attribute type filter.
        params.to_ids: Optional IDS-flag filter.
        params.limit: Attributes per page (default 50, max 500).
        params.page: 1-indexed page.
        params.metadata: Optional MISP 'metadata' flag, omitted by default.
        params.response_format: 'markdown' (default) or 'json'.
    Returns:
        markdown table or JSON object with match_count and the stripped attributes.
    Worked Examples:
        1. Check an IP seen in a Wazuh alert:
           ``blueteam_misp_ioc_lookup(value="45.83.12.9")``
        2. Domain plus event context as JSON:
           ``blueteam_misp_ioc_lookup(value="evil-c2.example.com", response_format="json")``
        3. Detection-flagged SHA256 only:
           ``blueteam_misp_ioc_lookup(value="<sha256>", to_ids=True, type_attribute="sha256")``
    Permissions: MISP read-only automation key (``MISP_API_KEY``). A write-scoped
    key is not needed and should not be used.
    Rate limits: governed by the instance. Requests are spaced by
    ``MISP_MIN_INTERVAL`` (default 1s) with at most ``MISP_MAX_CONCURRENT``
    (default 2) in flight, and successful responses are cached for
    ``MISP_CACHE_TTL`` (default 900s).
    """
    capabilities = await _ensure_capabilities()
    payload: dict = {
        "returnFormat": "json",
        "value": params.value,
        "limit": params.limit,
        "page": params.page,
        "enforceWarninglist": True,
    }
    if params.type_attribute:
        payload["type"] = params.type_attribute
    if params.to_ids is not None:
        payload["to_ids"] = params.to_ids
    if params.metadata is not None:
        payload["metadata"] = params.metadata

    try:
        raw = await _misp_search("attributes/restSearch", payload)
    except ThreatIntelError:
        raise
    except (httpx.HTTPStatusError, httpx.TimeoutException, httpx.ConnectError) as exc:
        _handle_api_error(exc, context="blueteam_misp_ioc_lookup")

    attributes = _strip_misp_attributes(_extract_attributes(raw))

    if params.response_format == "json":
        return json.dumps({
            "indicator": params.value,
            "misp_version": capabilities.get("version"),
            "capability_note": capabilities.get("note") or None,
            "match_count": len(attributes),
            "attributes": attributes,
        }, indent=2, ensure_ascii=False, default=str)

    return _format_misp_markdown(params.value, attributes, capabilities)
