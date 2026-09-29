#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Opt-in PY-TOON encoding for LLM-facing tool output.
TOON (Token-Oriented Object Notation) declares array fields once in a header
instead of repeating the keys on every row, which cuts both tokens and the
row-count errors that hit large uniform JSON arrays. Only tools advertising
``response_format="toon"`` reach this module.
The encoder is imported inside the call, so a partial install degrades to a
JSON error envelope instead of failing server startup at import time.
"""
from __future__ import annotations
import json
import logging
from typing import Any

logger = logging.getLogger("blue_team_mcp.toon")


def toon_available() -> bool:
    """True when the optional ``toon_format`` encoder can be imported."""
    try:
        import toon_format
        return True
    except ImportError:
        return False


def _error_envelope(reason: str, hint: str, **extra: Any) -> str:
    """JSON error object for a TOON request that cannot be encoded.
    JSON on purpose: this path runs when the encoder is missing or failed, and a
    hand-built partial TOON document would be the one payload nobody can parse.
    The ``error`` key mirrors the JSON-mode truncation envelope.
    """
    payload = {"error": reason, "hint": hint}
    payload.update(extra)
    return json.dumps(payload, indent=2, ensure_ascii=False)


def encode_toon(data: Any, *, limit: int | None = None) -> str:
    """Serialize ``data`` as TOON, or a JSON error envelope when it cannot.
    Args:
        data: JSON-safe payload (dict, list, or scalar).
        limit: Character cap. Over the cap returns an error envelope instead of
            truncating, because a sliced TOON document parses as garbage; the
            JSON path makes the same refusal through ``_truncate_if_needed``.
    Returns:
        TOON text, or a JSON object with an ``error`` key.
    """
    try:
        from toon_format import encode
    except ImportError:
        return _error_envelope(
            "unavailable: toon_format is not installed",
            "pip install toon_format==0.9.0b1, or call with response_format='json'",
        )
    try:
        text = encode(data)
    except (TypeError, ValueError, RecursionError) as e:
        logger.warning("toon encoding failed: %s", e)
        return _error_envelope("toon encoding failed", "call with response_format='json'")
    if limit is not None and len(text) > limit:
        return _error_envelope(
            f"response exceeds {limit} characters",
            "narrow the query (smaller window or limit) and retry",
            truncated=True,
            response_chars=len(text),
        )
    return text
