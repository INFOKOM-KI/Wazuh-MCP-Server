#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Time window parsing, relative deltas, auto bucket intervals.
"""
from __future__ import annotations
import re
from datetime import datetime, timedelta
from typing import Optional

_RELATIVE_TIME_RE = re.compile(r"^(\d+)([smhdw])$")
_ISO_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}")

_UNIT_MAP = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}


def _relative_delta(n: int, unit: str) -> timedelta:
    if unit not in _UNIT_MAP:
        return timedelta(days=365)
    return timedelta(**{_UNIT_MAP[unit]: n})


def _parse_time_window(
    since: Optional[str], until: Optional[str], default_back: timedelta = timedelta(days=365),
) -> tuple[str, str]:
    now = datetime.utcnow()
    until_dt = now
    if until and until.strip():
        u = until.strip()
        if _ISO_TIME_RE.match(u):
            until_dt = datetime.fromisoformat(u.replace("Z", "+00:00").rstrip("Z"))
        else:
            m = _RELATIVE_TIME_RE.match(u)
            if m:
                until_dt = now - _relative_delta(int(m.group(1)), m.group(2))
    if since and since.strip():
        s = since.strip()
        if _ISO_TIME_RE.match(s):
            since_dt = datetime.fromisoformat(s.replace("Z", "+00:00").rstrip("Z"))
        else:
            m = _RELATIVE_TIME_RE.match(s)
            if m:
                since_dt = now - _relative_delta(int(m.group(1)), m.group(2))
            else:
                since_dt = now - default_back
    else:
        since_dt = now - default_back
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    return since_dt.strftime(fmt), until_dt.strftime(fmt)


def _duration_minutes(since: str, until: str) -> float:
    try:
        s = datetime.fromisoformat(since.replace("Z", "+00:00").rstrip("Z"))
        u = datetime.fromisoformat(until.replace("Z", "+00:00").rstrip("Z"))
        return (u - s).total_seconds() / 60.0
    except Exception:
        return 60.0


def _auto_bucket_interval(window_duration_minutes: float) -> str:
    raw = window_duration_minutes / 100
    if raw <= 1: return "1m"
    elif raw <= 5: return "5m"
    elif raw <= 15: return "15m"
    elif raw <= 60: return "1h"
    elif raw <= 360: return "6h"
    else: return "1d"
