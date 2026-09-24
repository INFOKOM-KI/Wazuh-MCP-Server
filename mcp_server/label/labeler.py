#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Backend selection, concurrency gate and alert-to-text conversion for
``blueteam_incident_label``.

One backend is built per process and never rebuilt: the choice comes from config,
which is frozen at import, and a mid-flight swap would leave two models resident.
Every classify call passes the same semaphore, so ``BLUETEAM_LAYA_MAX_CONCURRENCY``
is the ceiling on concurrent inference regardless of which backend is active.

``build_state_text`` is the only path from an alert payload to model input. It reads
an allowlist of fields, refuses nested structures, caps every value, and never
touches ``full_log`` - the alert body is adversary-controlled text and this function
is the boundary.
"""
from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any, List, Optional, Tuple

from mcp_server.core.config import config
from mcp_server.core.exceptions import BlueTeamMCPError
from mcp_server.label.backends import (
    LabelVerdict,
    LayaLabeler,
    ONNXPrototypeLabeler,
    _BaseLabeler,
)

logger = logging.getLogger("blue_team_mcp.label")

STATE_FIELDS: Tuple[str, ...] = (
    "rule.id", "rule.level", "rule.description", "rule.groups",
    "rule.mitre.id", "rule.mitre.tactic", "agent.name",
    "data.srcip", "data.dstip", "data.url", "data.proto",
)
MAX_STATE_CHARS = 4000
MAX_FIELD_CHARS = 400
MAX_LIST_ITEMS = 20

_backend: Optional[_BaseLabeler] = None
_gate: Optional[asyncio.Semaphore] = None
_lock = threading.Lock()


def labeler_enabled() -> bool:
    label = getattr(config, "label", None) if config is not None else None
    return bool(getattr(label, "enabled", False))


def require_enabled() -> None:
    if labeler_enabled():
        return
    backend = getattr(getattr(config, "label", None), "backend", "onnx")
    hint = ("Install CPU torch and vendor the weights (setup.sh "
            "BLUETEAM_INSTALL_LAYA=1) and set BLUETEAM_LAYA_BACKEND=laya."
            if backend == "laya" else
            "The default backend needs the RAG embedder bootstrapped: run setup.sh "
            "with BLUETEAM_RAG_ENABLED=true once so the ONNX model is cached.")
    raise BlueTeamMCPError(
        f"Incident labeling is disabled. Set BLUETEAM_LAYA_ENABLED=true, then restart "
        f"the server. {hint}"
    )


def _build() -> _BaseLabeler:
    if config.label.backend == "laya":
        return LayaLabeler(config.label.confidence_floor, config.label.model_path,
                           config.label.model_sha256, config.label.allow_download)
    return ONNXPrototypeLabeler(config.label.confidence_floor)


def _ensure() -> Tuple[_BaseLabeler, asyncio.Semaphore]:
    global _backend, _gate
    if _backend is not None and _gate is not None:
        return _backend, _gate
    with _lock:
        if _backend is None:
            _backend = _build()
        if _gate is None:
            _gate = asyncio.Semaphore(max(1, int(config.label.max_concurrency)))
        return _backend, _gate


async def classify_state(state_text: str) -> LabelVerdict:
    """Label one piece of state text. The gate wraps the whole call, including the
    backend's own thread offload, so at most ``max_concurrency`` inferences run."""
    backend, gate = _ensure()
    async with gate:
        return await backend.classify(state_text)


def _lookup(alert: Any, path: str) -> Any:
    """Nested lookup with a flat fallback: an alert may carry ``data.srcip`` as
    nested objects or as a literal dotted key, and both shapes reach here."""
    if not isinstance(alert, dict):
        return None
    node: Any = alert
    for part in path.split("."):
        if not isinstance(node, dict):
            node = None
            break
        node = node.get(part)
    return alert.get(path) if node is None else node


def _scalar(value: Any) -> Optional[str]:
    """Strings, numbers and boolean/lists of them only. A nested object returns
    None: model input built from arbitrary JSON is an injection surface, not a
    feature."""
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value.strip()[:MAX_FIELD_CHARS]
    if isinstance(value, list):
        items = [str(item) for item in value[:MAX_LIST_ITEMS]
                 if isinstance(item, (str, int, float, bool))]
        return ", ".join(items)[:MAX_FIELD_CHARS]
    return None


def build_state_text(alert: Any) -> Tuple[str, List[str]]:
    """Allowlisted fields to ``key=value`` text. Returns the text and the field
    names that contributed; the text is never echoed back to the caller."""
    parts: List[str] = []
    used: List[str] = []
    total = 0
    for path in STATE_FIELDS:
        value = _scalar(_lookup(alert, path))
        if not value:
            continue
        parts.append(f"{path}={value}")
        used.append(path)
        total += len(parts[-1]) + 1
        if total >= MAX_STATE_CHARS:
            break
    return " ".join(parts)[:MAX_STATE_CHARS], used
