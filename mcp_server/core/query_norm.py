#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Deterministic query normalization for the retrieval paths.

Both retrieval entry points, ``tools/rag_kb.blueteam_rag_query`` and
``agents/fp_validator_graph.assemble_evidence``, run the caller's text through
``query_for_retrieval``. NFKC is a no-op for every code point at or below U+007E, so no
indicator shape can be rewritten and an ASCII query is returned byte-identical.
Pure stdlib, no model, no network.
"""
from __future__ import annotations
import re
import unicodedata
from mcp_server.core.config import config

_WHITESPACE = re.compile(r"\s+")


def normalize_query(text: str) -> str:
    """Fold compatibility forms to ASCII and collapse whitespace runs.
    NFKC leaves every code point at or below U+007E alone, so a pure-ASCII query comes
    back unchanged. Empty and whitespace-only input returns an empty string.
    """
    if not text:
        return ""
    return _WHITESPACE.sub(" ", unicodedata.normalize("NFKC", text)).strip()


def query_for_retrieval(text: str) -> str:
    """The string a retrieval stage should receive, honouring the normalization flag.
    With ``config.rag.query_normalize`` off (the default) the input is returned
    unchanged, so the raw-query path is untouched.
    """
    if not config.rag.query_normalize:
        return text
    return normalize_query(text)
