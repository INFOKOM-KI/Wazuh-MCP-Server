#!/usr/bin/env python3
# © NAuliajati - TangerangKota-CSIRT
"""Read-only inventory of the stores that could support a correlation evaluation.
Phase 0 of the correlation evaluation. It answers one question before any
preprocessing, F1 or feature work is built: *is there any independently labelled
ground truth to score a same-incident correlation against, and if not, what is
missing?* It reads configured stores and prints aggregate counts. It never writes
to a store, never calls the Wazuh Indexer, never loads a model, and never emits
raw IPs, notes, titles or record contents.

Why the separation matters
The 3-Sum engine auto-registers its own trigger IPs as attacker IOCs
(``correlation.py`` ``register_attacker_ips(source="engine_a")``), and
``is_attacker_ioc`` cannot tell an engine lead from an analyst verdict. A
correlation F1 whose "ground truth" is that flag would score the engine against
its own output. This tool therefore reports operator-verified labels and
engine-derived confirmations as separate, non-interchangeable numbers, and
returns ``not_evaluable`` rather than a nominal F1 when independent labels are
missing. It does not generalise that caveat to the labeler's tactic corpus,
which has its own independent review path (``scripts/export_case_labels.py``,
``mcp_server/label/criteria.py``).

Environment (all read-only; no positional paths, no directory scanning)
``BLUETEAM_INVENTORY_ROOT``      required. Absolute staging root. Every configured
                                 store path must resolve inside it. Missing root,
                                 relative paths, symlink escapes, duplicate store
                                 paths, or anything under a known production
                                 location are refused (exit 2).
``BLUETEAM_CASE_STORE``          case JSONL (``core/case_store.py``)
``BLUETEAM_INVESTIGATION_HISTORY`` verdict JSONL (``tools/investigation_history.py``)
``BLUETEAM_MEM_DB``              memory SQLite (``core/memory_store.py``); read only
                                 when ``BLUETEAM_MEM_ENABLED`` and
                                 ``BLUETEAM_INVENTORY_MEMORY_QUIESCENT`` are truthy
``BLUETEAM_ATTACKER_REGISTRY``   attacker registry JSONL (``core/attacker_registry.py``)
``BLUETEAM_IOC_STORE``           IOC JSONL (``core/ioc_store.py``)
``BLUETEAM_INVENTORY_MEMORY_QUIESCENT``
                                 required for the memory store: an operator assertion
                                 that the server is stopped and nothing is writing.
                                 A store with ``-wal``/``-shm`` side files is refused,
                                 because the main file alone is not the committed state.
                                 The read is a no-lock immutable snapshot; side files
                                 before it refuse the store, side files after it
                                 discard the result. Those checks narrow the race, they
                                 do not close it, so the quiescence declaration is the
                                 operator's precondition to make.

Root trust. The declared root is the primary trust boundary: a path is read only
when the operator names the containing directory. The production markers cover
known locations, not every possible one, so a layout they do not know is accepted
only when the operator declares it. ``/`` is rejected as ambiguous.

Provenance. Nothing is counted as operator-verified today. Registry: a source
qualifies only when a traced writer records analyst provenance, and ``verdict``
does not (it is registered for every true-positive verdict, including the
workflow's ``recorded_by="workflow"`` call); untraced sources are ``unverified``.
Memory: ``recorded_by`` is caller-supplied. HTTP auth is one shared write-scope
API key with no per-analyst identity (``core/server_auth.py``) and the stdio
transport has no auth (``main.py``), so memory rows are reported as
``analyst_declared`` and never as independent labels.

Usage
-----
    BLUETEAM_INVENTORY_ROOT=/srv/staging/blue-team \
    BLUETEAM_CASE_STORE=/srv/staging/blue-team/cases.jsonl \
    BLUETEAM_MEM_DB=/srv/staging/blue-team/memory.db \
    BLUETEAM_INVENTORY_MEMORY_QUIESCENT=true \
    python3 scripts/correlation_label_inventory.py [--json]

Aggregate-only output. Exit 0 = inventory produced (even when the status is
``not_evaluable``); exit 2 = target refused or ambiguous.
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

TOOL_VERSION = "v1"
ROOT_ENV = "BLUETEAM_INVENTORY_ROOT"
MEMORY_ENABLED_ENV = "BLUETEAM_MEM_ENABLED"
MEMORY_QUIESCENT_ENV = "BLUETEAM_INVENTORY_MEMORY_QUIESCENT"

# Traced writers for the registry sources this repository can produce. A source
# is operator_verified only when a writer records analyst provenance; a value
# that merely looks analyst-ish is unverified. Traced 2026-10 on this checkout:
# core/ioc_store.py:77 (auto_promote), tools/correlation.py:665 (engine_a),
# tools/correlation.py:878 (enrichment), tools/webshell_check.py:304,
# tools/investigation_history.py:64 (verdict).
REGISTRY_SOURCE_EVIDENCE: dict[str, dict] = {
    "engine_a": {"class": "engine_derived",
                 "writer": "tools/correlation.py 3-Sum trigger registration"},
    "enrichment": {"class": "engine_derived",
                   "writer": "tools/correlation.py _enrich_ips"},
    "auto_promote": {"class": "engine_derived",
                     "writer": "core/ioc_store.py _maybe_promote"},
    "webshell_check": {"class": "engine_derived",
                       "writer": "tools/webshell_check.py"},
    "verdict": {"class": "unverified",
                "writer": "tools/investigation_history.py",
                "reason": ("registered for every true-positive verdict, including "
                           "recorded_by='workflow'; analyst and workflow are not "
                           "distinguishable in the entry")},
    "manual": {"class": "unverified",
               "writer": "register_attacker_ioc default; no in-repo caller",
               "reason": "no demonstrated writer records manual provenance"},
    "analyst": {"class": "unverified",
                "writer": "none in this repository",
                "reason": "no demonstrated writer emits this source"},
}

STORE_ENV = {
    "case_store": "BLUETEAM_CASE_STORE",
    "investigation_history": "BLUETEAM_INVESTIGATION_HISTORY",
    "memory_store": "BLUETEAM_MEM_DB",
    "attacker_registry": "BLUETEAM_ATTACKER_REGISTRY",
    "ioc_store": "BLUETEAM_IOC_STORE",
}

# Kept in sync with mcp_server.core.attacker_registry.ANALYST_SOURCES and
# mcp_server.core.memory_store.AUTO_VERDICT_NOTE; tests assert parity so a store
# vocabulary change fails the suite instead of silently reclassifying labels.
ANALYST_SOURCES = frozenset({"manual", "verdict", "analyst"})
WORKFLOW_NOTE = "auto investigation workflow"
KNOWN_VERDICTS = ("true_positive", "false_positive", "suspicious", "clean", "unknown")

# Paths that identify the production deployment. A staging inventory must never
# read these, and a staging root must not live under one.
PRODUCTION_MARKERS = (
    "/opt/blue-team-mcp",
    "/var/ossec",
    "/var/lib/wazuh",
    "/etc/blue-team-mcp",
)

# Columns every provenance decision needs. A store missing one is reported as
# schema_incomplete, never guessed at.
_MEMORY_REQUIRED_COLUMNS = (
    "subject", "kind", "value", "case_id", "source",
    "type", "provenance", "tainted", "first_seen", "last_seen",
)


class Refused(Exception):
    """The selected target is unsafe or ambiguous. Fail closed, print, exit 2.

    ``stores`` carries the store entries resolved before the failure, when any.
    """

    def __init__(self, message: str, stores: dict | None = None):
        super().__init__(message)
        self.stores = stores


def _truthy(value) -> bool:
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def _is_production(path: Path) -> bool:
    """Known production marker, matched on component boundaries. This is a
    secondary check, not a production detector: a location outside the list is
    accepted only when the operator has explicitly declared it as the root."""
    text = str(path)
    return any(text == marker or text.startswith(marker + "/")
               for marker in PRODUCTION_MARKERS)


def _resolve_checked(raw: str, root: Path, label: str) -> Path:
    """Absolute path inside ``root``, symlinks resolved, production refused.

    Order matters: absolute check, production-marker check, then containment.
    A production path is refused by name even when it also sits outside the
    staging root, so the operator sees *why* rather than "outside root".
    """
    candidate = Path(raw)
    if not candidate.is_absolute():
        raise Refused(f"{label}: path is not absolute ({raw!r})")
    resolved = candidate.resolve(strict=False)
    if _is_production(resolved):
        raise Refused(f"{label}: path resolves under a production location ({resolved})")
    try:
        resolved.relative_to(root)
    except ValueError:
        raise Refused(f"{label}: path resolves outside BLUETEAM_INVENTORY_ROOT ({resolved})")
    return resolved


def resolve_store_paths(env: dict, root: str | None = None) -> dict:
    """Resolve every known store env var under one staging root.

    Returns ``{"root": str, "stores": {name: {"env", "status", "path"}}}``.
    ``status`` is ``configured`` or ``not_configured``; reading happens later.
    Raises ``Refused`` when the root is missing/relative/production, or when a
    configured store is unsafe, ambiguous, or duplicated.
    """
    raw_root = (root if root is not None else env.get(ROOT_ENV, "")) or ""
    raw_root = raw_root.strip()
    if not raw_root:
        raise Refused(
            f"{ROOT_ENV} is not set. Point it at the absolute staging directory that "
            "contains the stores; this tool never scans for them.")
    root_path = Path(raw_root)
    if not root_path.is_absolute():
        raise Refused(f"{ROOT_ENV} must be absolute (got {raw_root!r})")
    root_path = root_path.resolve(strict=False)
    if _is_production(root_path):
        raise Refused(f"{ROOT_ENV} resolves under a production location ({root_path})")
    if root_path == Path("/"):
        raise Refused(f"{ROOT_ENV} must not be the filesystem root; "
                      "an undeclared layout is ambiguous")
    if not root_path.is_dir():
        raise Refused(f"{ROOT_ENV} is not an existing directory ({root_path})")

    stores: dict[str, dict] = {}
    seen: dict[str, str] = {}
    for name, env_name in STORE_ENV.items():
        raw = (env.get(env_name, "") or "").strip()
        if not raw:
            stores[name] = {"env": env_name, "status": "not_configured", "path": None}
            continue
        try:
            resolved = _resolve_checked(raw, root_path, f"{name} ({env_name})")
        except Refused as exc:
            raise Refused(str(exc), stores=stores) from exc
        key = str(resolved)
        if key in seen:
            raise Refused(f"{name} and {seen[key]} resolve to the same file; "
                          "refusing an ambiguous inventory target", stores=stores)
        seen[key] = name
        stores[name] = {"env": env_name, "status": "configured", "path": key}
    return {"root": str(root_path), "root_declared_by": "operator",
            "production_marker_check": "known markers only; not exhaustive",
            "stores": stores}


def preflight(env: dict, root: str | None = None) -> dict:
    """Root gate first, store configuration second, no store touched.

    On success the map matches ``resolve_store_paths`` plus ``status: ok``. On
    refusal it returns a report: ``blocked_by_root`` for every store when the
    root gate failed before any store variable was read, or ``not_checked`` when
    the root passed and a later store path raised. A store variable is read only
    after the root passes, so ``not_configured`` always means checked.
    """
    try:
        resolved = resolve_store_paths(env, root=root)
    except Refused as exc:
        if str(exc).startswith(ROOT_ENV):
            stores = {name: {"env": env_name, "status": "blocked_by_root", "path": None}
                      for name, env_name in STORE_ENV.items()}
        else:
            checked = exc.stores or {}
            stores = {
                name: checked.get(name) or {"env": env_name,
                                            "status": "not_checked", "path": None}
                for name, env_name in STORE_ENV.items()}
        return {
            "status": "refused",
            "reason": str(exc),
            "root": None,
            "root_declared_by": None,
            "production_marker_check": None,
            "stores": stores,
        }
    return {**resolved, "status": "ok", "reason": None}


def _read_jsonl(path: Path) -> tuple[list[dict], int]:
    """Rows and malformed-line count. Blank lines are not malformed."""
    rows: list[dict] = []
    malformed = 0
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except ValueError:
                malformed += 1
                continue
            if isinstance(row, dict):
                rows.append(row)
            else:
                malformed += 1
    return rows, malformed


def _parse_dt(value) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _span(values: list) -> dict:
    """Date-only coverage. Unmeasured stays null, never a zero-length span."""
    parsed = [dt for dt in (_parse_dt(v) for v in values) if dt is not None]
    if not parsed:
        return {"measured": False, "first_date": None, "last_date": None, "span_days": None}
    first, last = min(parsed), max(parsed)
    return {"measured": True, "first_date": first.date().isoformat(),
            "last_date": last.date().isoformat(), "span_days": (last - first).days}


def _verdict_counts(values: list) -> dict:
    counts = Counter()
    for value in values:
        text = str(value or "").strip().lower()
        counts[text if text in KNOWN_VERDICTS else "unrecognized"] += 1
    return dict(sorted(counts.items()))


def _norm_subject(value) -> str:
    return str(value or "").strip().lower()


def inventory_case_store(path: Path | None) -> dict:
    """Aggregate case-store facts. No titles, notes or srcips are returned."""
    base = {"status": "not_configured", "reason": None, "records": None,
            "malformed_lines": None, "cases_with_verdicts": None,
            "cases_without_verdicts": None, "case_verdicts": None,
            "verdict_distribution": None, "cases_with_multiple_verdicts": None,
            "cases_with_conflicting_verdicts": None, "cases_with_mixed_verdicts": None,
            "duplicate_case_ids": None, "duplicate_verdict_entries": None,
            "cases_engine_title_heuristic": None, "temporal": None}
    if path is None:
        return base
    if not path.exists():
        return {**base, "status": "absent", "reason": "configured path does not exist"}
    try:
        rows, malformed = _read_jsonl(path)
    except OSError as exc:
        return {**base, "status": "unreadable", "reason": type(exc).__name__}

    verdicts_per_case: dict[str, list[tuple[str, str, str]]] = {}
    titles = 0
    case_verdicts = 0
    case_ids: list[str] = []
    for row in rows:
        case_id = str(row.get("case_id") or "")
        if case_id:
            case_ids.append(case_id)
        entries = row.get("verdicts") or []
        if not isinstance(entries, list):
            entries = []
        pair_list: list[tuple[str, str, str]] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            pair_list.append((_norm_subject(entry.get("srcip")),
                              str(entry.get("verdict") or "").strip().lower(),
                              str(entry.get("ts") or "")))
            case_verdicts += 1
        if case_id:
            verdicts_per_case.setdefault(case_id, []).extend(pair_list)
        if str(row.get("title") or "").startswith("3-Sum APT"):
            titles += 1

    conflicting = 0
    mixed = 0
    for pairs in verdicts_per_case.values():
        by_subject: dict[str, set[str]] = {}
        for subject, verdict, _ts in pairs:
            by_subject.setdefault(subject, set()).add(verdict)
        if any({"true_positive", "false_positive"} <= values for values in by_subject.values()):
            conflicting += 1
        values = {verdict for _s, verdict, _ts in pairs}
        if {"true_positive", "false_positive"} <= values:
            mixed += 1

    case_id_counts = Counter(case_ids)
    verdict_keys = [(case_id, subject, verdict, ts)
                    for case_id, pairs in verdicts_per_case.items()
                    for subject, verdict, ts in pairs]
    verdict_key_counts = Counter(verdict_keys)
    with_verdicts = sum(1 for pairs in verdicts_per_case.values() if pairs)
    return {
        "status": "ok", "reason": None,
        "records": len(rows),
        "malformed_lines": malformed,
        "cases_with_verdicts": with_verdicts,
        "cases_without_verdicts": len(verdicts_per_case) - with_verdicts,
        "case_verdicts": case_verdicts,
        "verdict_distribution": _verdict_counts(
            [verdict for pairs in verdicts_per_case.values() for _s, verdict, _ts in pairs]),
        "cases_with_multiple_verdicts": sum(1 for pairs in verdicts_per_case.values()
                                            if len(pairs) > 1),
        "cases_with_conflicting_verdicts": conflicting,
        "cases_with_mixed_verdicts": mixed,
        "duplicate_case_ids": sum(count - 1 for count in case_id_counts.values()
                                  if count > 1),
        "duplicate_verdict_entries": sum(count - 1 for count in verdict_key_counts.values()
                                         if count > 1),
        "cases_engine_title_heuristic": titles,
        "temporal": _span([row.get("created_at") for row in rows]),
    }


def inventory_history(path: Path | None) -> dict:
    """Aggregate investigation-history facts, including missing provenance."""
    base = {"status": "not_configured", "reason": None, "records": None,
            "malformed_lines": None, "unique_subjects": None,
            "repeated_subject_records": None, "repeated_subject_rate": None,
            "exact_duplicate_records": None, "exact_duplicate_rate": None,
            "verdict_distribution": None, "case_id_field_present": None,
            "entries_with_case_id": None, "recorded_by_field_present": None,
            "entries_with_recorded_by": None, "missing_provenance_entries": None,
            "workflow_marker_entries": None, "analyst_attributed_entries": None,
            "temporal": None}
    if path is None:
        return base
    if not path.exists():
        return {**base, "status": "absent", "reason": "configured path does not exist"}
    try:
        rows, malformed = _read_jsonl(path)
    except OSError as exc:
        return {**base, "status": "unreadable", "reason": type(exc).__name__}

    subjects = [_norm_subject(row.get("srcip")) for row in rows]
    unique = len({s for s in subjects if s})
    exact_duplicates = sum(count - 1 for count in Counter(
        json.dumps(row, sort_keys=True, default=str) for row in rows).values()
        if count > 1)
    with_case = sum(1 for row in rows if str(row.get("case_id") or "").strip())
    with_recorded_by = sum(1 for row in rows if str(row.get("recorded_by") or "").strip())
    workflow = sum(1 for row in rows
                   if WORKFLOW_NOTE in str(row.get("notes") or "").lower())
    return {
        "status": "ok", "reason": None,
        "records": len(rows),
        "malformed_lines": malformed,
        "unique_subjects": unique,
        "repeated_subject_records": len(rows) - unique,
        "repeated_subject_rate": (None if not rows
                                  else round(1.0 - unique / len(rows), 4)),
        "exact_duplicate_records": exact_duplicates,
        "exact_duplicate_rate": (None if not rows
                                 else round(exact_duplicates / len(rows), 4)),
        "verdict_distribution": _verdict_counts([row.get("verdict") for row in rows]),
        "case_id_field_present": any("case_id" in row for row in rows),
        "entries_with_case_id": with_case,
        "recorded_by_field_present": any("recorded_by" in row for row in rows),
        "entries_with_recorded_by": with_recorded_by,
        "missing_provenance_entries": len(rows) - with_recorded_by,
        "workflow_marker_entries": workflow,
        "analyst_attributed_entries": len(rows) - workflow,
        "temporal": _span([row.get("ts") for row in rows]),
    }


def _side_files(path: Path) -> list[str]:
    """WAL side files next to the store. Their absence means the main file holds
    the committed state; a running or uncleanly-closed writer leaves them."""
    return [suffix for suffix in ("-wal", "-shm")
            if path.with_name(path.name + suffix).exists()]


def _read_memory_rows(path: Path, enabled: bool,
                      quiescent: bool) -> tuple[list[dict] | None, dict]:
    """Read-only provenance rows, or ``(None, status)``.

    A SQLite WAL store cannot be read from the main file alone while a writer
    holds uncommitted state, and a no-lock immutable read can race a checkpoint
    into a torn view. The smallest safe contract: the operator declares
    quiescence (``BLUETEAM_INVENTORY_MEMORY_QUIESCENT``), no ``-wal``/``-shm``
    side file exists, and a side file appearing during the read discards the
    result. The two checks narrow the race window, they do not close it: a
    writer that commits and checkpoints between them can still leave the read
    untrusted, so the declaration is the real precondition. No lock is taken and
    no side file is created.
    """
    status = {"status": "ok", "reason": None, "read_mode": None,
              "schema_missing_columns": None}
    if not enabled:
        return None, {**status, "status": "disabled",
                      "reason": f"{MEMORY_ENABLED_ENV} is not truthy; the store is not live"}
    if not path.exists():
        return None, {**status, "status": "absent",
                      "reason": "configured path does not exist"}
    if not quiescent:
        return None, {**status, "status": "refused",
                      "reason": (f"{MEMORY_QUIESCENT_ENV} is not truthy: a live WAL store "
                                 "cannot be shown to be consistent, so it is refused "
                                 "rather than reported as a stale view")}
    side_before = _side_files(path)
    if side_before:
        return None, {**status, "status": "refused",
                      "reason": (f"store has side files {side_before}: it is live or was "
                                 "not closed cleanly, so the main file is not the "
                                 "committed state")}
    status["read_mode"] = "immutable"
    try:
        conn = sqlite3.connect(f"{path.as_uri()}?mode=ro&immutable=1", uri=True)
        conn.execute("PRAGMA query_only=ON")
        tables = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        if "units" not in tables:
            conn.close()
            return None, {**status, "status": "schema_missing",
                          "reason": "no units table in the store"}
        columns = {row[1] for row in conn.execute("PRAGMA table_info(units)")}
        missing = sorted(set(_MEMORY_REQUIRED_COLUMNS) - columns)
        if missing:
            conn.close()
            return None, {**status, "status": "schema_incomplete",
                          "reason": "units table is missing provenance columns",
                          "schema_missing_columns": missing}
        projection = list(_MEMORY_REQUIRED_COLUMNS)
        if "invalidated_by" in columns:
            projection.append("invalidated_by")
        rows = [dict(zip(projection, values)) for values in conn.execute(
            f"SELECT {', '.join(projection)} FROM units")]
        conn.close()
    except sqlite3.Error as exc:
        return None, {**status, "status": "unreadable",
                      "reason": f"sqlite3.{type(exc).__name__}"}
    side_after = _side_files(path)
    if side_after:
        return None, {**status, "status": "refused",
                      "reason": (f"a writer created side files {side_after} during the "
                                 "read; the snapshot is discarded")}
    return rows, status


def inventory_memory(path: Path | None, enabled: bool, quiescent: bool) -> dict:
    """Aggregate memory-store decision provenance. Read-only SQLite."""
    base = {"status": "not_configured", "reason": None, "read_mode": None,
            "schema_missing_columns": None, "decision_units": None, "reason_units": None,
            "analyst_declared_decisions": None, "advisory_decisions": None,
            "analyst_declared_verdict_distribution": None, "decisions_with_case_id": None,
            "analyst_declared_decisions_with_case_id": None,
            "distinct_analyst_declared_case_ids": None,
            "analyst_declared_case_scoped_conflicting_subjects": None,
            "analyst_declared_subjects_with_mixed_verdicts_without_case_context": None,
            "invalidated_units": None, "temporal": None}
    if path is None:
        return base
    rows, status = _read_memory_rows(path, enabled, quiescent)
    if rows is None:
        return {**base, **status}

    decisions = [row for row in rows if str(row.get("kind") or "") == "decision"]
    reasons = len(rows) - len(decisions)
    analyst = [row for row in decisions if _is_analyst_declared_decision(row)]
    case_scoped: dict[tuple[str, str], set[str]] = {}
    no_case_verdicts: dict[str, set[str]] = {}
    for row in analyst:
        subject = _norm_subject(row.get("subject"))
        verdict = str(row.get("value") or "").strip().lower()
        case_id = str(row.get("case_id") or "").strip()
        if case_id:
            case_scoped.setdefault((case_id, subject), set()).add(verdict)
        else:
            no_case_verdicts.setdefault(subject, set()).add(verdict)
    case_conflicts = sum(1 for values in case_scoped.values()
                         if {"true_positive", "false_positive"} <= values)
    # A subject-level TP/FP disagreement with no case context is a data-quality
    # flag, never a conflict claim: the events may be unrelated in time.
    no_case_mixed = sum(1 for values in no_case_verdicts.values()
                        if {"true_positive", "false_positive"} <= values)
    analyst_case_ids = [str(row.get("case_id") or "").strip() for row in analyst]
    return {
        "status": "ok", "reason": None,
        "read_mode": status.get("read_mode"),
        "schema_missing_columns": None,
        "decision_units": len(decisions),
        "reason_units": reasons,
        "analyst_declared_decisions": len(analyst),
        "advisory_decisions": len(decisions) - len(analyst),
        "analyst_declared_verdict_distribution": _verdict_counts(
            [row.get("value") for row in analyst]),
        "decisions_with_case_id": sum(1 for row in decisions
                                      if str(row.get("case_id") or "").strip()),
        "analyst_declared_decisions_with_case_id": sum(1 for cid in analyst_case_ids if cid),
        "distinct_analyst_declared_case_ids": len({cid for cid in analyst_case_ids if cid}),
        "analyst_declared_case_scoped_conflicting_subjects": case_conflicts,
        "analyst_declared_subjects_with_mixed_verdicts_without_case_context": no_case_mixed,
        "invalidated_units": sum(1 for row in rows
                                 if str(row.get("invalidated_by") or "").strip()),
        "temporal": _span([stamp for row in rows
                           for stamp in (row.get("first_seen"), row.get("last_seen"))]),
    }


def _is_analyst_declared_decision(row: dict) -> bool:
    """Memory row shaped like the writer's trusted path: source/provenance/type =
    verdict/analyst/world and tainted = 0. Those fields are derived from the
    caller-supplied ``recorded_by`` (``memory_store.record_decision``), and no
    server-side identity binds that value: HTTP auth is a single shared
    write-scope API key (``core/server_auth.py``) with no principal propagated
    to tools, and stdio has no auth (``main.py``). This is a declaration, not
    an authenticated analyst action."""
    source = str(row.get("source") or "").strip().lower()
    provenance = str(row.get("provenance") or "").strip().lower()
    kind = str(row.get("type") or "").strip().lower()
    tainted = bool(row.get("tainted"))
    return source in ANALYST_SOURCES and provenance == "analyst" \
        and kind == "world" and not tainted


def _registry_source_class(source: str) -> tuple[str, str | None, str]:
    """``(class, reason, writer)`` for one registry source value."""
    entry = REGISTRY_SOURCE_EVIDENCE.get(source)
    if entry is None:
        return "unknown", "source has no documented writer in this repository", ""
    return entry["class"], entry.get("reason"), entry.get("writer", "")


def inventory_registry(path: Path | None) -> dict:
    """Attacker-registry provenance split against traced writers.

    ``operator_verified`` is reserved for a source whose traced writer records
    analyst provenance. No current source qualifies: ``verdict`` is registered
    for workflow verdicts too, and ``manual``/``analyst`` have no demonstrated
    writer. Those are reported as ``unverified`` with evidence, never promoted.
    """
    base = {"status": "not_configured", "reason": None, "records": None,
            "malformed_lines": None, "by_source": None, "source_evidence": None,
            "operator_verified": None, "engine_derived": None,
            "unverified": None, "unknown": None, "source_missing": None}
    if path is None:
        return base
    if not path.exists():
        return {**base, "status": "absent", "reason": "configured path does not exist"}
    try:
        rows, malformed = _read_jsonl(path)
    except OSError as exc:
        return {**base, "status": "unreadable", "reason": type(exc).__name__}
    by_source: Counter = Counter()
    for row in rows:
        source = str(row.get("source") or "").strip().lower()
        by_source[source or "source_missing"] += 1
    evidence: dict[str, dict] = {}
    totals = {"operator_verified": 0, "engine_derived": 0,
              "unverified": 0, "unknown": 0}
    for source, count in sorted(by_source.items()):
        klass, reason, writer = _registry_source_class(source)
        totals[klass] += count
        evidence[source] = {"class": klass, "count": count, "writer": writer}
        if reason:
            evidence[source]["reason"] = reason
    return {
        "status": "ok", "reason": None,
        "records": len(rows),
        "malformed_lines": malformed,
        "by_source": dict(sorted(by_source.items())),
        "source_evidence": evidence,
        "operator_verified": totals["operator_verified"],
        "engine_derived": totals["engine_derived"],
        "unverified": totals["unverified"],
        "unknown": totals["unknown"],
        "source_missing": by_source.get("source_missing", 0),
    }


def inventory_ioc_store(path: Path | None) -> dict:
    """IOC store aggregate, including co-occurrence-only associations."""
    base = {"status": "not_configured", "reason": None, "records": None,
            "malformed_lines": None, "cooccurrence_bearing_iocs": None}
    if path is None:
        return base
    if not path.exists():
        return {**base, "status": "absent", "reason": "configured path does not exist"}
    try:
        rows, malformed = _read_jsonl(path)
    except OSError as exc:
        return {**base, "status": "unreadable", "reason": type(exc).__name__}
    batch_members: Counter = Counter()
    for row in rows:
        for batch in row.get("batches") or []:
            batch_members[str(batch)] += 1
    shared = sum(1 for row in rows
                 if any(batch_members[str(batch)] > 1 for batch in row.get("batches") or []))
    return {
        "status": "ok", "reason": None,
        "records": len(rows),
        "malformed_lines": malformed,
        "cooccurrence_bearing_iocs": shared,
    }


def build_inventory(resolved: dict, env: dict) -> dict:
    """Read every configured store and synthesise the aggregate inventory."""
    paths = resolved["stores"]
    case = inventory_case_store(_path(paths, "case_store"))
    history = inventory_history(_path(paths, "investigation_history"))
    mem_enabled = _truthy(env.get(MEMORY_ENABLED_ENV))
    mem_quiescent = _truthy(env.get(MEMORY_QUIESCENT_ENV))
    memory = inventory_memory(_path(paths, "memory_store"), mem_enabled, mem_quiescent)
    registry = inventory_registry(_path(paths, "attacker_registry"))
    ioc = inventory_ioc_store(_path(paths, "ioc_store"))

    groups = _analyst_declared_case_groups(_path(paths, "memory_store"), mem_enabled,
                                           mem_quiescent)
    group_count = len(groups) if groups is not None else None
    groups_with_pairs = (sum(1 for subjects in groups.values() if len(subjects) >= 2)
                         if groups is not None else None)
    candidate_pairs = (sum(len(subjects) * (len(subjects) - 1) // 2
                           for subjects in groups.values()) if groups is not None else None)

    stock = _label_stock(history, memory, registry)
    blocking = []
    if memory.get("status") != "ok":
        blocking.append(f"memory store status is '{memory.get('status')}': "
                        "case-link provenance is unavailable")
    elif not group_count:
        blocking.append("no analyst-declared incident group exists in the memory store")
    if groups_with_pairs == 0:
        blocking.append("no analyst-declared group contains multiple subjects")
    blocking.append("case links are analyst-declared (recorded_by is caller-supplied, "
                    "not authenticated), not independently verified labels")
    blocking.append("no pair-level same-incident adjudication: candidate pairs are "
                    "grouped by case and are not independently labelled pairs")
    blocking.append("no independently labelled negative pairs in any store")
    return {
        "tool": "correlation_label_inventory",
        "version": TOOL_VERSION,
        "environment": resolved,
        "definitions": {
            "operator_verified": (
                "a label backed by an authenticated analyst identity or a traced "
                "writer that records one. No source qualifies today: the memory "
                "writer trusts the caller-supplied recorded_by, and no registry "
                "writer records analyst provenance"),
            "analyst_declared": (
                "memory decision whose caller-supplied recorded_by was 'analyst' "
                "(source/provenance/type = verdict/analyst/world, tainted = 0). A "
                "declaration, not authentication: HTTP auth is one shared "
                "write-scope API key with no per-analyst identity "
                "(core/server_auth.py) and stdio has no auth (main.py). Counted "
                "separately and never as an independent label"),
            "analyst_attributed": (
                "history entry whose notes lack the workflow marker, so it is "
                "attributed to an analyst by absence of the automation marker; "
                "the JSONL does not persist recorded_by, so this is an inference, "
                "not authentication"),
            "engine_derived": ("automated registrations and flags with a traced "
                               "engine writer: engine_a, enrichment, auto_promote, "
                               "webshell_check, workflow"),
            "unverified": ("a value that looks analyst-ish but whose origin cannot "
                           "be demonstrated, e.g. registry source 'verdict' "
                           "(registered for workflow true-positives too), 'manual' "
                           "and 'analyst' (no in-repo writer), or any untraced "
                           "source. Never counted as a label"),
            "independent_incident_group": ("distinct case_id with at least one "
                                           "analyst-declared decision"),
            "candidate_same_incident_pair": ("two distinct operator-labelled "
                                             "subjects under one case. C(k,2) "
                                             "pairs, not adjudicated pairs"),
            "repeated_subject_rate": "1 - unique_subjects / records (null at 0)",
            "exact_duplicate_records": ("rows whose full canonical JSON repeats an "
                                        "earlier row; distinct from a subject "
                                        "appearing in multiple events"),
            "conflicting_verdicts": ("the same subject carries both true_positive "
                                     "and false_positive within one case_id. A "
                                     "subject-level disagreement without case "
                                     "context is reported separately and is not "
                                     "a conflict claim"),
        },
        "case_store": case,
        "investigation_history": history,
        "memory_store": memory,
        "attacker_registry": registry,
        "ioc_store": ioc,
        "independent_labels": {
            "operator_verified_indicator_labels": registry.get("operator_verified"),
            "unverified_indicator_registrations": (
                (registry.get("unverified") or 0) + (registry.get("unknown") or 0)
                if registry.get("status") == "ok" else None),
            "analyst_declared_case_linked_decisions": memory.get("analyst_declared_decisions_with_case_id"),
            "analyst_declared_cases": memory.get("distinct_analyst_declared_case_ids"),
            "analyst_declared_incident_groups": group_count,
            "analyst_declared_incident_groups_with_multiple_subjects": groups_with_pairs,
            "candidate_same_incident_pairs": candidate_pairs,
            "engine_derived_confirmed_flags": registry.get("engine_derived"),
            "shared_ip_or_ioc_associations": ioc.get("cooccurrence_bearing_iocs"),
        },
        "pairing_frame": {
            "same_incident_candidate_pairs": {
                "available": candidate_pairs,
                "status": "measured" if candidate_pairs is not None else "unavailable",
                "source": "C(k,2) over analyst-declared subjects per case",
            },
            "same_incident_labelled_pairs": {
                "available": None,
                "status": "unavailable",
                "reason": ("no store records pair-level same-incident adjudication; "
                           "case grouping labels subjects, not pairs"),
            },
            "same_incident_negative_pairs": {
                "available": None,
                "status": "unavailable",
                "reason": ("no store records independently labelled non-incident pairs; "
                           "negatives must be sampled and adjudicated"),
            },
            "retrieval_queries": {
                "available": None,
                "status": "unavailable",
                "reason": "no query-to-case relevance labels exist",
            },
        },
        "positive_label_stock": stock,
        "evaluability": {
            "status": "not_evaluable" if blocking else "candidate_dataset_available",
            "blocking": blocking,
            "required_label_collection": [
                "adjudicate same-incident positive pairs with a reviewer independent of "
                "the engine that produced the trigger",
                "sample and adjudicate negative pairs from co-observed entities that are "
                "not part of the same incident",
                "persist case_id and recorded_by in the investigation-history JSONL at "
                "write time so case links survive export",
                "label query-to-case relevance for historical-case retrieval",
                "review conflicting and duplicate verdict records before they enter a corpus",
            ],
        },
    }


def _analyst_declared_case_groups(path: Path | None, enabled: bool,
                                  quiescent: bool) -> dict[str, set[str]] | None:
    """case_id -> distinct analyst-declared subjects. None when the store cannot
    be read; {} is a measured empty result. Subjects stay in memory only."""
    if path is None:
        return None
    rows, _status = _read_memory_rows(path, enabled, quiescent)
    if rows is None:
        return None
    groups: dict[str, set[str]] = {}
    for row in rows:
        if str(row.get("kind") or "") != "decision" or not _is_analyst_declared_decision(row):
            continue
        case_id = str(row.get("case_id") or "").strip()
        subject = _norm_subject(row.get("subject"))
        if case_id and subject:
            groups.setdefault(case_id, set()).add(subject)
    return groups


def _label_stock(history: dict, memory: dict, registry: dict) -> str:
    """Coarse statement of what kind of labels exist, most independent first.
    No current source is independently verified; ``independently_registered_only``
    is reserved for a future writer that records analyst provenance."""
    if memory.get("status") == "ok" and memory.get("analyst_declared_decisions_with_case_id"):
        return "analyst_declared"
    if history.get("status") == "ok" and history.get("analyst_attributed_entries"):
        return "analyst_attributed"
    # Kept for a future writer that records analyst provenance; no registry
    # source qualifies today, so this branch is unreachable in practice.
    if registry.get("status") == "ok" and registry.get("operator_verified"):
        return "independently_registered_only"
    if (history.get("records") or 0) or (memory.get("decision_units") or 0) \
            or (registry.get("records") or 0):
        return "engine_derived_only"
    return "none"


def _path(stores: dict, name: str) -> Path | None:
    entry = stores.get(name) or {}
    return Path(entry["path"]) if entry.get("path") else None


def render_preflight(report: dict) -> str:
    """Refusal report. Unresolved stores are shown as such, never as configured."""
    lines = ["# Preflight refused", "",
             f"- **Reason**: {report['reason']}",
             "- Stores marked `blocked_by_root` or `not_checked` were never resolved.",
             "", "| store | env | status |", "|---|---|---|"]
    for name, entry in report["stores"].items():
        lines.append(f"| {name} | {entry['env']} | {entry['status']} |")
    return "\n".join(lines) + "\n"


def render_markdown(payload: dict) -> str:
    """Human-readable aggregate table. Counts only, never record contents."""
    lines = ["# Correlation-label inventory", "",
             f"- **Verdict**: `{payload['evaluability']['status']}`",
             f"- **Positive-label stock**: `{payload['positive_label_stock']}`",
             f"- **Staging root**: `{payload['environment']['root']}`", "",
             "## Stores", "",
             "| store | status | records | malformed |",
             "|---|---|---|---|"]
    for name in ("case_store", "investigation_history", "memory_store",
                 "attacker_registry", "ioc_store"):
        section = payload[name]
        records = section.get("records") if section.get("records") is not None \
            else section.get("decision_units")
        lines.append(f"| {name} | {section.get('status')} | "
                     f"{records if records is not None else 'n/a'} | "
                     f"{section.get('malformed_lines') if section.get('malformed_lines') is not None else 'n/a'} |")
    labels = payload["independent_labels"]
    pair = payload["pairing_frame"]["same_incident_candidate_pairs"]
    pair_status = ("measured" if pair["status"] == "measured"
                   else pair["status"])
    labelled = payload["pairing_frame"]["same_incident_labelled_pairs"]
    lines += ["", "## Labels by provenance (nothing independently verified today)", "",
              f"- Operator-verified indicator labels: {_n(labels['operator_verified_indicator_labels'])}",
              f"- Unverified indicator registrations (not labels): {_n(labels['unverified_indicator_registrations'])}",
              f"- Analyst-declared case-linked decisions: {_n(labels['analyst_declared_case_linked_decisions'])}",
              f"- Analyst-declared cases: {_n(labels['analyst_declared_cases'])}",
              f"- Analyst-declared incident groups: {_n(labels['analyst_declared_incident_groups'])}",
              f"- Groups with multiple declared subjects: {_n(labels['analyst_declared_incident_groups_with_multiple_subjects'])}",
              f"- Candidate same-incident pairs (not adjudicated): {_n(labels['candidate_same_incident_pairs'])}",
              f"- Same-incident labelled pairs: {_n(labelled['available'])} ({labelled['status']})",
              f"- Same-incident candidate-pair status: {pair_status}",
              f"- Engine-derived `confirmed` flags (not labels): {_n(labels['engine_derived_confirmed_flags'])}",
              f"- Shared-IP/IOC-only associations: {_n(labels['shared_ip_or_ioc_associations'])}",
              "", "## Blocking items", ""]
    for item in payload["evaluability"]["blocking"]:
        lines.append(f"- {item}")
    lines += ["", "## Required label collection", ""]
    for item in payload["evaluability"]["required_label_collection"]:
        lines.append(f"- {item}")
    return "\n".join(lines) + "\n"


def _n(value) -> str:
    return "not measured" if value is None else str(value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true",
                        help="print the full aggregate JSON instead of markdown")
    args = parser.parse_args(argv)
    env = dict(os.environ)
    report = preflight(env)
    if report["status"] == "refused":
        print(f"refused: {report['reason']}", file=sys.stderr)
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            print(render_preflight(report))
        return 2
    payload = build_inventory(report, env)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(render_markdown(payload))
    return 0


if __name__ == "__main__":
    sys.exit(main())
