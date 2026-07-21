#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Shared Pydantic validators and Annotated type aliases.
"""
from __future__ import annotations
import re
from typing import Optional, Annotated
from pydantic import AfterValidator
from mcp_server import _AGENT_NAME_DESC
from mcp_server import _SINCE_DESC
from mcp_server import _UNTIL_DESC
from mcp_server import _RESPONSE_FORMAT_DESC

from mcp_server import _BYPASS_REDACTION_DESC, _RESPONSE_FORMAT_DESC, _SINCE_DESC, _UNTIL_DESC, _AGENT_NAME_DESC

_AGENT_NAME_SAFE_RE = re.compile(r"^[a-zA-Z0-9_\-\.]+$")

# Practical email regex for extraction from log fields - covers >99% of real addresses
# Handles dots-in-local-part, plus-sign aliases, and multi-level TLDs
_EMAIL_RE = re.compile(
    r'[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
    r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}'
)

def _validate_keyword_field(v: Optional[str]) -> Optional[str]:
    """Shared keyword validator — strip, reject null bytes / control chars."""
    if v is not None:
        v = v.strip()
        if not v:
            return None
        if len(v) > 1024:
            raise ValueError("keyword too long (max 1024)")
        if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", v):
            raise ValueError("keyword contains invalid control characters")
    return v

def _validate_agent_name_field(v: Optional[str]) -> Optional[str]:
    """Shared agent_name validator — strip, length-check, safe-chars-only."""
    if v is not None:
        v = v.strip()
        if not v:
            return None
        if len(v) > 64:
            raise ValueError("agent_name too long (max 64)")
        if not _AGENT_NAME_SAFE_RE.match(v):
            raise ValueError("agent_name: use only letters, numbers, hyphen, underscore, dot")
    return v


def _validate_rule_groups_field(v: Optional[str]) -> Optional[str]:
    """Shared rule_groups validator - comma-split, strip, safe-chars-only."""
    if v is not None:
        v = v.strip()
        if not v:
            return None
        for g in v.split(","):
            g = g.strip()
            if not g:
                raise ValueError("Empty rule group name in comma-separated list")
            if not _AGENT_NAME_SAFE_RE.match(g):
                raise ValueError(f"Invalid rule group name: '{g}'")
    return v

# Annotated types for reusable field validation (replaces per-model validators)
ValidKeyword = Annotated[Optional[str], AfterValidator(_validate_keyword_field)]
ValidAgentName = Annotated[Optional[str], AfterValidator(_validate_agent_name_field)]
ValidRuleGroups = Annotated[Optional[str], AfterValidator(_validate_rule_groups_field)]
