#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Versioned pair features for offline same-incident evaluation.

``PAIR_FEATURE_VERSION`` pins the feature layout: a record written under one
version is never scored under another, and a version bump is required whenever
a key, a normalization, or a comparison changes.

The extractor is pure. It performs no I/O, calls no engine, and imports no
config, so an offline harness can run it on fixtures or exports without the
server bootstrap. Alert records are the offline export shape (``alert_id``,
``srcip``, ``agent``, ``timestamp``, ``tactics``, ``domains``, ``urls``,
``analyst_iocs``, ``engine_iocs``), not the Wazuh payload.

``analyst_iocs`` and ``engine_iocs`` stay separate families on purpose. The
attacker registry writes engine trigger IPs as IOC entries, so an engine-derived
flag must never feed the same-incident prediction the engine is later scored
with. ``build_pair_record`` writes one reviewable record: schema version, pair
id, incident group, split, label, label source, reviewer attribution, the two
alert records, and the extracted features.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

PAIR_FEATURE_VERSION = "v1"
PAIR_SCHEMA_VERSION = "v1"

ALERT_FIELDS = (
    "alert_id", "srcip", "agent", "timestamp", "tactics",
    "domains", "urls", "analyst_iocs", "engine_iocs",
)
FEATURE_KEYS = (
    "alert_a_id", "alert_b_id",
    "same_subject", "time_delta_seconds", "same_agent",
    "shared_tactics", "tactic_overlap_ratio",
    "shared_domains", "shared_urls",
    "shared_analyst_iocs", "shared_engine_iocs",
)
RECORD_KEYS = (
    "schema_version", "pair_id", "group_id", "split", "label", "label_source",
    "recorded_by", "reviewed_at", "alert_a", "alert_b",
    "feature_version", "features", "notes",
)


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _token(value: Any) -> str | None:
    text = _text(value)
    return text.lower() if text else None


def _tokens(value: Any) -> list[str]:
    """Sorted, de-duplicated lowercase tokens. Missing input yields ``[]``."""
    if value is None:
        return []
    if isinstance(value, str):
        token = value.strip().lower()
        return [token] if token else []
    return sorted({str(item).strip().lower() for item in value if str(item).strip()})


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _alert_id(alert: Any) -> str:
    if not isinstance(alert, dict):
        raise ValueError("alert record must be an object")
    alert_id = _text(alert.get("alert_id"))
    if not alert_id:
        raise ValueError("alert record needs a non-empty alert_id")
    return alert_id


def pair_id(alert_a: dict, alert_b: dict) -> str:
    """Order-insensitive deterministic id for two distinct alert records."""
    left, right = _alert_id(alert_a), _alert_id(alert_b)
    if left == right:
        raise ValueError("a pair needs two distinct alert_ids")
    joined = "|".join(sorted((left, right)))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]


def extract_pair_features(alert_a: dict, alert_b: dict) -> dict[str, Any]:
    """Deterministic v1 pair features for two offline alert records.

    Unmeasured values stay ``None`` (subject or timestamp missing, unparseable
    timestamp) and are never fabricated as zero. List families are intersections
    and an empty list means no shared token was observed in the export.
    """
    left_id, right_id = _alert_id(alert_a), _alert_id(alert_b)
    if left_id == right_id:
        raise ValueError("a pair needs two distinct alert_ids")

    subject_a, subject_b = _token(alert_a.get("srcip")), _token(alert_b.get("srcip"))
    same_subject = None if subject_a is None or subject_b is None else subject_a == subject_b

    agent_a, agent_b = _token(alert_a.get("agent")), _token(alert_b.get("agent"))
    same_agent = None if agent_a is None or agent_b is None else agent_a == agent_b

    stamp_a, stamp_b = _parse_timestamp(alert_a.get("timestamp")), _parse_timestamp(alert_b.get("timestamp"))
    time_delta = None if stamp_a is None or stamp_b is None else abs((stamp_b - stamp_a).total_seconds())

    tactics_a, tactics_b = set(_tokens(alert_a.get("tactics"))), set(_tokens(alert_b.get("tactics")))
    shared_tactics = sorted(tactics_a & tactics_b)
    union = tactics_a | tactics_b
    tactic_overlap_ratio = round(len(shared_tactics) / len(union), 4) if union else None

    return {
        "alert_a_id": left_id,
        "alert_b_id": right_id,
        "same_subject": same_subject,
        "time_delta_seconds": None if time_delta is None else round(time_delta, 3),
        "same_agent": same_agent,
        "shared_tactics": shared_tactics,
        "tactic_overlap_ratio": tactic_overlap_ratio,
        "shared_domains": sorted(set(_tokens(alert_a.get("domains"))) & set(_tokens(alert_b.get("domains")))),
        "shared_urls": sorted(set(_tokens(alert_a.get("urls"))) & set(_tokens(alert_b.get("urls")))),
        "shared_analyst_iocs": sorted(set(_tokens(alert_a.get("analyst_iocs"))) & set(_tokens(alert_b.get("analyst_iocs")))),
        "shared_engine_iocs": sorted(set(_tokens(alert_a.get("engine_iocs"))) & set(_tokens(alert_b.get("engine_iocs")))),
    }


def _check_alert(alert: Any, side: str) -> None:
    if not isinstance(alert, dict):
        raise ValueError(f"{side} must be an object")
    unknown = sorted(set(alert) - set(ALERT_FIELDS))
    if unknown:
        raise ValueError(f"{side} has fields outside the offline schema: {unknown}")
    _alert_id(alert)


def build_pair_record(alert_a: dict, alert_b: dict, *, group_id: str, label: str,
                      label_source: str, recorded_by: str, split: str,
                      reviewed_at: str | None = None, notes: str = "") -> dict[str, Any]:
    """Assemble one versioned pair record for review, storage, or evaluation."""
    _check_alert(alert_a, "alert_a")
    _check_alert(alert_b, "alert_b")
    for name, value in (("group_id", group_id), ("label", label), ("label_source", label_source),
                        ("recorded_by", recorded_by), ("split", split)):
        if not _text(value):
            raise ValueError(f"{name} is required")
    return {
        "schema_version": PAIR_SCHEMA_VERSION,
        "pair_id": pair_id(alert_a, alert_b),
        "group_id": _text(group_id),
        "split": _text(split),
        "label": _text(label),
        "label_source": _text(label_source),
        "recorded_by": _text(recorded_by),
        "reviewed_at": _text(reviewed_at),
        "alert_a": dict(alert_a),
        "alert_b": dict(alert_b),
        "feature_version": PAIR_FEATURE_VERSION,
        "features": extract_pair_features(alert_a, alert_b),
        "notes": _text(notes) or "",
    }
