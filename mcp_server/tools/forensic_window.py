#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Windowed retrieval for the approved forensic payload fields.

A single full_log, data.url or data.user_agent can exceed CHARACTER_LIMIT on
its own, which document paging cannot fit. This tool returns one window of one
approved field from one alert. next_offset reconstructs the complete
post-redaction value.
"""
from __future__ import annotations

import json
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from mcp_server import (mcp, WAZUH_INDEXER_URL, WAZUH_INDEXER_PASSWORD,
                        _REDACTION_POLICY_DESC, _REVEAL_OWNED_DESC,
                        _REVEAL_IDENTITIES_DESC, _FORENSIC_TOKEN_DESC)
from mcp_server.core.audit import _audit_log
from mcp_server.core.redact import _redact_alert_data
from mcp_server.wazuh.indexer import _wazuh_indexer_post, _WAZUH_INDEX_PATTERNS

# The approved forensic fields. No other field name is accepted, and the paths
# are fixed here rather than taken from the request.
_FIELD_PATHS = {
    "full_log": ("full_log",),
    "user_agent": ("data", "user_agent"),
    "data.url": ("data", "url"),
}


class ForensicWindowInput(BaseModel):
    """Input model for blueteam_wazuh_forensic_window."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    doc_id: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Elasticsearch _id of one alert, as returned in the _id field of "
                    "blueteam_wazuh_indexer_search or wazuh_alert_focused_crawl results.",
    )
    field: Literal["full_log", "user_agent", "data.url"] = Field(
        ...,
        description="Approved forensic field to window.",
    )
    offset: int = Field(
        default=0,
        ge=0,
        le=10_000_000,
        description="Character offset into the post-redaction field value.",
    )
    max_chars: int = Field(
        default=40000,
        ge=1,
        le=80000,
        description="Window size in characters; bounded so the response stays under "
                    "CHARACTER_LIMIT.",
    )
    redaction_policy: Optional[Literal["full", "protect_victim", "raw"]] = Field(
        default=None,
        description=_REDACTION_POLICY_DESC,
    )
    reveal_owned: bool = Field(default=False, description=_REVEAL_OWNED_DESC)
    reveal_identities: bool = Field(default=False, description=_REVEAL_IDENTITIES_DESC)
    forensic_token: Optional[str] = Field(default=None, max_length=128, description=_FORENSIC_TOKEN_DESC)


@mcp.tool(
    name="blueteam_wazuh_forensic_window",
    annotations={"readOnlyHint": True, "destructiveHint": False,
                 "idempotentHint": True, "openWorldHint": False},
)
async def blueteam_wazuh_forensic_window(params: ForensicWindowInput) -> str:
    """Retrieve one window of one approved forensic field from one alert.

    Use this when a document paging response reports an oversized document or
    when a single field is longer than the response limit. The returned window is
    taken from the post-redaction value, so the active security policy still
    masks credentials, private IPs, domains, emails and identities.

    Args:
        params.doc_id: Elasticsearch document _id of the alert.
        params.field: One of 'full_log', 'user_agent', 'data.url'.
        params.offset: Character offset into the post-redaction field value.
        params.max_chars: Window size in characters (default 40000, max 80000).
        params.redaction_policy: Optional policy override for this call.
        params.reveal_owned: Forensics only; exposes owned-domain values unmasked.
        params.reveal_identities: Forensics only; requires BLUETEAM_ALLOW_IDENTITY_REVEAL.
        params.forensic_token: Operator token for the forensic gates.

    Returns:
        JSON with doc_id, field, offset, max_chars, field_length, window,
        has_more and next_offset. Reconstruct the complete value by passing
        next_offset back as offset until has_more is false.

    **Worked Examples**

    1. First window of a long log:
       ``blueteam_wazuh_forensic_window(doc_id="abc123", field="full_log")``

    2. Continue where the previous call stopped:
       ``blueteam_wazuh_forensic_window(doc_id="abc123", field="full_log", offset=40000)``

    3. Retrieve a long user agent under protect_victim:
       ``blueteam_wazuh_forensic_window(doc_id="abc123", field="user_agent",
       max_chars=20000, redaction_policy="protect_victim")``

    **Permissions**: Wazuh Indexer read access.

    **Rate limits**: one single-document Indexer query per call; use the largest
    max_chars needed to reduce round trips.
    """
    _audit_log("blueteam_wazuh_forensic_window",
               {"doc_id": params.doc_id, "field": params.field, "offset": params.offset})
    if not WAZUH_INDEXER_URL or not WAZUH_INDEXER_PASSWORD:
        return json.dumps({"error": "WAZUH_INDEXER_URL and WAZUH_INDEXER_PASSWORD must be set."})

    body = {"size": 1, "query": {"ids": {"values": [params.doc_id]}}}
    raw = await _wazuh_indexer_post(body, index_pattern=_WAZUH_INDEX_PATTERNS["alerts"])
    if isinstance(raw.get("error"), str):
        return json.dumps({"error": raw["error"], "doc_id": params.doc_id})
    hits = raw.get("hits", {}).get("hits", [])
    if not hits:
        return json.dumps({"error": "document not found", "doc_id": params.doc_id})

    doc = hits[0].get("_source", hits[0])
    redacted = _redact_alert_data(doc, policy=params.redaction_policy,
                                  reveal_owned=params.reveal_owned,
                                  reveal_identities=params.reveal_identities,
                                  forensic_token=params.forensic_token)
    value = redacted
    for part in _FIELD_PATHS[params.field]:
        value = value.get(part) if isinstance(value, dict) else None
    if not isinstance(value, str):
        return json.dumps({"error": f"field '{params.field}' is absent or not a string",
                           "doc_id": params.doc_id, "field": params.field})

    total = len(value)
    window = value[params.offset:params.offset + params.max_chars]
    next_offset = params.offset + len(window)
    has_more = next_offset < total
    return json.dumps({
        "doc_id": params.doc_id,
        "field": params.field,
        "offset": params.offset,
        "max_chars": params.max_chars,
        "field_length": total,
        "window": window,
        "has_more": has_more,
        "next_offset": next_offset if has_more else None,
    }, ensure_ascii=False)
