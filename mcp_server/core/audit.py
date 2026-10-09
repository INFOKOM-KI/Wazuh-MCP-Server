#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Audit logging, response truncation, markdown escaping, rate limiting, response pipeline.
"""
from __future__ import annotations
import functools, json, os, time, hashlib, logging, queue, threading, atexit, signal
from datetime import datetime
from typing import Any
from mcp_server import (CHARACTER_LIMIT, BLUETEAM_AUDIT_LOG, BLUETEAM_ALLOW_UNTRUNCATED,
                        BLUETEAM_RATE_LIMIT, BLUETEAM_FORENSIC_TOKEN)
from mcp_server.core.redact import _redact_alert_data
from mcp_server.core import metrics

logger = logging.getLogger("blue_team_mcp.audit")

# Async audit writer
# _audit_log is called synchronously from every tool handler (a hot path, the
# 1 god node). Synchronous open().write() per call blocks the event loop on disk
# I/O. Instead we enqueue onto a thread-safe queue and a single daemon writer
# thread drains it in batches, so the hot path is a non-blocking queue.put().
_AUDIT_QUEUE: "queue.Queue[dict]" = queue.Queue()
_AUDIT_WORKER_STARTED = False
_AUDIT_WORKER_LOCK = threading.Lock()


def _audit_worker_loop() -> None:
    """Drain the audit queue and write entries in batches (runs on a daemon thread)."""
    while True:
        batch = [_AUDIT_QUEUE.get()]  # block until the first entry
        # Opportunistically drain anything else queued to amortize the file open.
        while True:
            try:
                batch.append(_AUDIT_QUEUE.get_nowait())
            except queue.Empty:
                break
        try:
            with open(BLUETEAM_AUDIT_LOG, "a") as f:
                for e in batch:
                    f.write(json.dumps(e) + "\n")
        except Exception:
            logger.warning("audit log write failed (dropping %d entries)", len(batch), exc_info=True)


def _ensure_audit_worker() -> None:
    global _AUDIT_WORKER_STARTED
    if _AUDIT_WORKER_STARTED or not BLUETEAM_AUDIT_LOG:
        return
    with _AUDIT_WORKER_LOCK:
        if _AUDIT_WORKER_STARTED:
            return
        threading.Thread(target=_audit_worker_loop, daemon=True, name="blue-team-audit-writer").start()
        _AUDIT_WORKER_STARTED = True


def flush_audit_log() -> None:
    """Synchronously drain any queued audit entries (graceful shutdown / tests).
    Best-effort: races with the daemon writer are possible, so it is only
    guaranteed to flush entries the writer has not yet consumed.
    """
    batch = []
    while True:
        try:
            batch.append(_AUDIT_QUEUE.get_nowait())
        except queue.Empty:
            break
    if not batch:
        return
    try:
        with open(BLUETEAM_AUDIT_LOG, "a") as f:
            for e in batch:
                f.write(json.dumps(e) + "\n")
    except Exception:
        logger.warning("audit log flush failed", exc_info=True)


# Drain queued audit entries on normal exit and on SIGTERM/SIGINT,
# then re-raise the signal so the process still terminates normally. Without
# this, the daemon writer thread is killed abruptly and queued entries are lost.
def _flush_audit_on_shutdown(*_args) -> None:
    try:
        flush_audit_log()
    except Exception:
        pass


def _flush_audit_on_signal(signum, _frame) -> None:
    _flush_audit_on_shutdown()
    signal.signal(signum, signal.SIG_DFL)
    os.kill(os.getpid(), signum)


atexit.register(_flush_audit_on_shutdown)
for _sig in (signal.SIGTERM, signal.SIGINT):
    try:
        signal.signal(_sig, _flush_audit_on_signal)
    except (ValueError, OSError):
        pass  # not the main thread (e.g. under a test runner)


# Audit logging
def _audit_log(tool_name: str, params: dict, result_preview: str = "") -> None:
    """Enqueue an audit entry for async, batched write to BLUETEAM_AUDIT_LOG."""
    metrics.record_call(tool_name)
    if not BLUETEAM_AUDIT_LOG:
        return
    try:
        entry = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "tool": tool_name,
            "params": {k: _redact_alert_data(str(v)[:100])
                        for k, v in params.items() if k not in ("api_key", "key")},
            "result_preview": _redact_alert_data((result_preview or "")[:200]),
            "redaction_bypassed": params.get("bypass_redaction", False),
        }
        _ensure_audit_worker()
        _AUDIT_QUEUE.put(entry)
    except Exception:
        pass


# Response truncation
def _resolve_forensic_full_output(params: Any) -> bool:
    """Validate a forensic full-output request; raise when the gate is closed."""
    if params is None or not getattr(params, "forensic_full_output", False):
        return False
    if not BLUETEAM_ALLOW_UNTRUNCATED:
        raise ValueError(
            "forensic_full_output requested but BLUETEAM_ALLOW_UNTRUNCATED is not enabled."
        )
    token = getattr(params, "forensic_token", None)
    if not BLUETEAM_FORENSIC_TOKEN or token != BLUETEAM_FORENSIC_TOKEN:
        raise ValueError(
            "forensic_full_output requires the operator forensic token "
            "(BLUETEAM_FORENSIC_TOKEN). Pass forensic_token=<token>."
        )
    return True


def _fit_document_prefix(render, count: int, limit: int | None = None) -> int:
    """Largest k in [0, count] whose rendered response fits the character limit.

    render(k) returns the complete serialized response for the first k documents,
    including paging metadata for that boundary. A document is never split.
    """
    cap = CHARACTER_LIMIT if limit is None else limit
    if count <= 0:
        return 0
    if len(render(count)) <= cap:
        return count
    lo, hi = 0, count
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if len(render(mid)) <= cap:
            lo = mid
        else:
            hi = mid - 1
    return lo


def _document_stub(doc: dict) -> dict:
    """Minimal locator for a document too large to page whole."""
    rule = doc.get("rule") if isinstance(doc.get("rule"), dict) else {}
    return {"_id": doc.get("_id", ""), "@timestamp": doc.get("@timestamp", ""),
            "rule_id": rule.get("id", "")}


def _truncate_if_needed(text: str, *, bypass: bool = False, params: Any = None,
                        recovery_hint: str = "") -> str:
    """Cap response at CHARACTER_LIMIT. When bypass=True, prepends forensic warning.
    params.forensic_full_output returns the full response when the gate is open.
    An over-limit non-JSON body is replaced by a complete size notice, never sliced."""
    forensic_full = _resolve_forensic_full_output(params)
    if bypass:
        banner = "⚠️ UNREDACTED - FORENSIC USE ONLY. Contains PII/internal IP.\n"
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
    if forensic_full:
        if BLUETEAM_AUDIT_LOG:
            try:
                with open(BLUETEAM_AUDIT_LOG, "a") as f:
                    f.write(json.dumps({
                        "ts": datetime.utcnow().isoformat() + "Z",
                        "event": "forensic_full_output",
                        "response_sha256": hashlib.sha256(text.encode()).hexdigest(),
                        "response_bytes": len(text.encode()),
                        "limit": CHARACTER_LIMIT,
                    }) + "\n")
            except Exception:
                pass
        return text
    if text.lstrip()[:1] in ("{", "["):
        try:
            json.loads(text)
        except ValueError:
            pass
        else:
            # A sliced JSON document is not JSON: the caller's json.loads fails on
            # the banner instead of reading a status. Hand back a valid document.
            return json.dumps({
                "error": f"response exceeds {CHARACTER_LIMIT} characters",
                "truncated": True,
                "response_chars": len(text),
                "hint": "narrow the query (smaller window or limit) and retry",
            })
    lines = [
        "# Response exceeds the character limit",
        "",
        f"This response is {len(text):,} characters, above the {CHARACTER_LIMIT:,} character "
        "limit, so the body was not returned. Nothing was cut from the underlying data.",
        "",
        "To retrieve it:",
        "- Narrow the query and retry.",
    ]
    if recovery_hint:
        lines.append(f"- {recovery_hint}")
    if params is not None and hasattr(params, "forensic_full_output"):
        lines.append(
            "- When the server sets BLUETEAM_ALLOW_UNTRUNCATED=true, request "
            "forensic_full_output=true with forensic_token=<token>."
        )
    return "\n".join(lines)


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
    allowed = _rate_limit_count <= BLUETEAM_RATE_LIMIT
    if not allowed:
        metrics.record_rate_limit_hit()
    return allowed


# Response pipeline decorator
# For tools returning structured data (dict/list). Automates: redact -> json.dumps -> truncate -> audit
# String-returning tools should use _audit_log() + _truncate_if_needed() directly.
def response_pipeline(tool_name: str):
    """Decorator: auto-applies redact -> json.dumps -> truncate -> audit.
    For async tool handlers that return structured data (dict/list).
    String-returning tools should call _audit_log()/_truncate_if_needed() directly.
    """
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            _t0 = time.monotonic()
            result = await func(*args, **kwargs)
            metrics.record_timing(tool_name, (time.monotonic() - _t0) * 1000)
            params = args[0] if args else None

            bypass_redact = getattr(params, "bypass_redaction", False) if params is not None else False
            bypass_char = getattr(params, "bypass_character_limit", False) if params is not None else False

            if isinstance(result, (dict, list)):
                result = _redact_alert_data(result, params=params)
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
