#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Evidence pack builder for the paper pipeline.

The pack is a hashed snapshot of what the server can prove about itself:
registered tools, telemetry, case aggregates, and caller-supplied evaluation
results. Case titles, notes, IOCs, and srcips are never serialized. A per-entity
cell backed by fewer than K_THRESHOLD distinct source IPs is suppressed, and no
two tables partition the same entity population, which is what blocks recovery
by subtraction.

The claim IDs written to claims.json are the only values a manuscript may cite.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp_server.core.subprocess import _run

# Privacy: per-entity cells below this many distinct source IPs are suppressed.
K_ANONYMITY = 5
# Citation: a claim below this sample size is proof the pipeline ran, not a result.
MIN_EVIDENCE_N = 5
SCHEMA_VERSION = 1
GIT_TIMEOUT = 10
CLAIM_TOKEN = re.compile(r"\{\{(C-\d{3})\}\}")
NUMBER_RE = re.compile(r"(?<![\w.])(\d+(?:\.\d+)?)(%?)")
# A structural reference skips only its own identifier: "Table 5 shows 8888"
# drops 5 and flags 8888. Spans are matched whole, so Section 2.3 drops both parts.
STRUCTURAL_REF = re.compile(
    r"\b(?:section|table|figure|equation|eqs?|appendix|algorithm|listing)\.?\s+\d+(?:\.\d+)*",
    re.IGNORECASE)
SECURITY_ID = re.compile(
    r"\b(?:CVE-\d{4}-\d{4,7}|CWE-\d+|TA?\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)
RULE_ID = re.compile(r"\brule(?:\s*id|_id|\.id)?\s*[:=#]?\s*\d+\b", re.IGNORECASE)
# Protocol/algorithm names are identifiers: TLS 1.3, AES-256, FIPS 140-2, HTTP/2, IPv4.
# Add a branch when a new spelling appears.
PROTOCOL_ID = re.compile(
    r"\b(?:(?:TLS|SSL)\s*\d+(?:\.\d+)?(?:/\d+(?:\.\d+)?)?"
    r"|(?:AES|RSA|SHA|ECDSA|EdDSA)[- ]\d{1,4}"
    r"|FIPS\s+\d+(?:-\d+)?"
    r"|HTTP/\d(?:\.\d)?"
    r"|IPv[46])\b",
    re.IGNORECASE)


def _ignored_spans(text: str) -> list[tuple[int, int]]:
    return [(match.start(), match.end())
            for pattern in (STRUCTURAL_REF, SECURITY_ID, RULE_ID, PROTOCOL_ID)
            for match in pattern.finditer(text)]


def load_claims(path: str) -> tuple[dict[str, dict], str]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {}, f"claims manifest unreadable: {exc}"
    claims = data.get("claims") if isinstance(data, dict) else data
    if not isinstance(claims, list):
        return {}, "claims manifest has no claims list"
    return {c["claim_id"]: c for c in claims
            if isinstance(c, dict) and isinstance(c.get("claim_id"), str)}, ""


def load_manifest(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _claim_numbers(claim: dict) -> set[str]:
    out: set[str] = set()
    for source in (claim.get("display"), claim.get("value")):
        for number, percent in NUMBER_RE.findall(str(source)):
            out.add(number + percent)
            out.add(number)
    return out


def check_draft(draft: str, claims: dict[str, dict], pack_status: str) -> dict:
    """Resolve claim tokens and every bare number against citable claims only.
    Structural references and security identifiers are skipped by span, never by
    the word that precedes them."""
    errors: list[dict] = []
    resolved = 0

    def replace(match: re.Match) -> str:
        nonlocal resolved
        claim = claims.get(match.group(1))
        if claim is None:
            errors.append({"claim_id": match.group(1), "reason": "unknown claim id"})
            return ""
        if claim.get("citable") is not True:
            errors.append({"claim_id": match.group(1),
                           "reason": claim.get("reason") or "not citable"})
            return ""
        resolved += 1
        return str(claim.get("display", ""))

    text = CLAIM_TOKEN.sub(replace, draft)
    allowed: set[str] = set()
    for claim in claims.values():
        if claim.get("citable") is True:
            allowed |= _claim_numbers(claim)

    ignored = _ignored_spans(text)
    unsupported = []
    for match in NUMBER_RE.finditer(text):
        raw = match.group(1) + match.group(2)
        if raw in allowed or match.group(1) in allowed:
            continue
        if not match.group(2) and 1900 <= int(float(match.group(1))) <= 2100:
            continue
        if any(start <= match.start() and match.end() <= end for start, end in ignored):
            continue
        unsupported.append({
            "number": raw,
            "context": text[max(0, match.start() - 40):match.end() + 40],
        })

    return {
        "pack_status": pack_status,
        "claims_resolved": resolved,
        "unsupported_numbers": unsupported,
        "errors": errors,
        "ok": not errors and not unsupported,
    }


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
                    encoding="utf-8")


def _git_state(repo_root: Path) -> dict:
    head = _run(["git", "-C", str(repo_root), "rev-parse", "HEAD"], timeout=GIT_TIMEOUT)
    if head["returncode"] != 0:
        return {"commit": "unknown", "dirty": None}
    status = _run(["git", "-C", str(repo_root), "status", "--porcelain",
                   "--untracked-files=no"], timeout=GIT_TIMEOUT)
    dirty = bool(status["stdout"].strip()) if status["returncode"] == 0 else None
    return {"commit": head["stdout"].strip(), "dirty": dirty}


def _annotation(tool: Any, key: str):
    ann = getattr(tool, "annotations", None)
    if ann is None:
        return None
    if isinstance(ann, dict):
        return ann.get(key)
    return getattr(ann, key, None)


def _tool_inventory(tools: dict[str, Any]) -> list[dict]:
    inventory = []
    for name in sorted(tools):
        tool = tools[name]
        fn = getattr(tool, "fn", None)
        description = " ".join(str(getattr(tool, "description", "") or "").split())
        inventory.append({
            "name": name,
            "module": getattr(fn, "__module__", "").rsplit(".", 1)[-1],
            "description": description[:200],
            "read_only": _annotation(tool, "readOnlyHint"),
            "destructive": _annotation(tool, "destructiveHint"),
            "idempotent": _annotation(tool, "idempotentHint"),
            "open_world": _annotation(tool, "openWorldHint"),
        })
    return inventory


def _format_window(minutes: int) -> str:
    if minutes <= 0:
        return "unknown"
    if minutes >= 2880 and minutes % 1440 == 0:
        return f"{minutes // 1440}d"
    if minutes % 60 == 0:
        return f"{minutes // 60}h"
    return f"{minutes}m"


def _case_summary(cases: list[dict], k: int = K_ANONYMITY) -> dict:
    counts: Counter[str] = Counter()
    entities: dict[str, set[str]] = {}
    for case in cases:
        for verdict in case.get("verdicts") or []:
            label = str(verdict.get("verdict") or "unknown")[:40]
            counts[label] += 1
            srcip = verdict.get("srcip")
            if srcip:
                entities.setdefault(label, set()).add(str(srcip))

    rows = []
    for label in sorted(counts):
        distinct = len(entities.get(label, ()))
        row: dict[str, Any] = {"verdict": label, "verdicts": counts[label]}
        if distinct >= k:
            row["distinct_srcips"] = distinct
        else:
            row["distinct_srcips"] = f"<{k}"
            row["suppressed"] = True
        rows.append(row)

    summary: dict[str, Any] = {"total_cases": len(cases), "by_verdict": rows}
    if len(cases) >= k:
        dates = sorted(str(c.get("created_at") or "")[:10]
                       for c in cases if c.get("created_at"))
        summary["window"] = ({"first_date": dates[0], "last_date": dates[-1]}
                             if dates else None)
    else:
        summary["window"] = None
        summary["window_suppressed"] = True
    return summary


def _claims(inventory: list[dict], cases: dict, metrics: dict,
            hashes: dict[str, str], alerts: dict) -> list[dict]:
    def claim(cid: str, metric: str, value: Any, display: str, unit: str,
              source: str, derivation: str, *, n: int, n_kind: str,
              reason_override: str = "", window_minutes: int | None = None) -> dict:
        citable = n >= MIN_EVIDENCE_N
        reason = "" if citable else (
            reason_override or f"n<{MIN_EVIDENCE_N}: below the evidence floor")
        return {
            "claim_id": cid,
            "metric": metric,
            "value": value,
            "display": display,
            "unit": unit,
            "n": n,
            "n_kind": n_kind,
            **({"window_minutes": window_minutes} if window_minutes is not None else {}),
            "source": source,
            "artifact_sha256": hashes.get(source, ""),
            "derivation": derivation,
            "citable": citable,
            "reason": reason,
        }

    total = len(inventory)
    modules = len({t["module"] for t in inventory})
    read_only = sum(1 for t in inventory if t.get("read_only") is True)
    share = round(100 * read_only / total, 1) if total else 0.0
    tool_calls = sum((metrics.get("tool_calls") or {}).values())
    pipeline = metrics.get("pipeline") or {}
    pipeline_calls = sum((pipeline.get("tools") or {}).values())
    pipeline_ms = round(sum((pipeline.get("duration_ms_total") or {}).values()), 1)

    case_count = cases["total_cases"]
    available = alerts.get("available") is True
    alert_total = int(alerts.get("total") or 0) if available else 0
    high_severity = int(alerts.get("high_severity_count") or 0) if available else 0
    top_share = float(alerts.get("top_rule_share") or 0.0) if available else 0.0
    alert_reason = "" if available else (
        f"indexer unavailable: {alerts.get('error_kind') or 'not_collected'}")
    window_minutes = int(alerts.get("window_minutes") or 0)
    window = _format_window(window_minutes)
    index_pattern = str(alerts.get("index_pattern") or "unknown")
    return [
        claim("C-001", "tool_count", total, str(total), "tools",
              "tool_inventory.json", "count of entries in tool_inventory.json",
              n=total, n_kind="population"),
        claim("C-002", "tool_module_count", modules, str(modules), "modules",
              "tool_inventory.json", "distinct module values",
              n=total, n_kind="population"),
        claim("C-003", "read_only_tool_count", read_only, str(read_only), "tools",
              "tool_inventory.json", "entries with read_only=true",
              n=total, n_kind="population"),
        claim("C-004", "read_only_share", share, f"{read_only}/{total} ({share}%)",
              "percent", "tool_inventory.json", "read_only / tool_count * 100",
              n=total, n_kind="population"),
        claim("C-005", "case_count", case_count, str(case_count),
              "cases", "cases.json", "total_cases", n=case_count, n_kind="sample"),
        claim("C-006", "tool_calls_total", tool_calls, str(tool_calls), "calls",
              "metrics.json", "sum of tool_calls values",
              n=tool_calls, n_kind="sample"),
        claim("C-007", "pipeline_calls_total", pipeline_calls, str(pipeline_calls), "calls",
              "metrics.json", "sum of pipeline.tools values",
              n=pipeline_calls, n_kind="sample"),
        claim("C-008", "pipeline_duration_ms_total", pipeline_ms,
              f"{pipeline_ms} ms", "milliseconds", "metrics.json",
              "sum of pipeline.duration_ms_total values",
              n=pipeline_calls, n_kind="sample"),
        claim("C-009", "alert_count", alert_total,
              f"{alert_total} alerts ({window} window)", "alerts",
              "alerts.json", f"count over {index_pattern} where rule.level exists",
              n=alert_total, n_kind="sample", reason_override=alert_reason,
              window_minutes=window_minutes),
        claim("C-010", "high_severity_count", high_severity,
              f"{high_severity} alerts ({window} window)", "alerts",
              "alerts.json", f"rule.level >= 10 over {index_pattern}",
              n=alert_total, n_kind="sample", reason_override=alert_reason,
              window_minutes=window_minutes),
        claim("C-011", "top_rule_share", top_share, f"{top_share}% ({window} window)",
              "percent", "alerts.json",
              f"top rule count / total over {index_pattern} * 100",
              n=alert_total, n_kind="sample", reason_override=alert_reason,
              window_minutes=window_minutes),
    ]


def build_evidence_pack(output_dir: str, run_id: str, *,
                        tools: dict[str, Any],
                        metrics_snapshot: dict,
                        cases: list[dict],
                        evaluations: list[dict],
                        repo_root: Path,
                        gating: dict | None = None,
                        alerts: dict | None = None) -> dict:
    """Write the pack and return its manifest. Manifest is written last, so a pack
    without one is incomplete rather than silently short."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "figures").mkdir(exist_ok=True)
    # A rerun into the same directory must not inherit a previous manifest or a
    # stray file that the current run did not produce.
    (out / "manifest.json").unlink(missing_ok=True)

    inventory = _tool_inventory(tools)
    case_doc = _case_summary(cases)
    eval_doc = sorted(evaluations, key=lambda e: e.get("name", ""))
    alert_doc = alerts or {"available": False, "window_minutes": 0,
                           "error_kind": "not_collected"}
    alert_view = {key: alert_doc[key] for key in (
        "available", "window_minutes", "total", "severity", "high_severity_count",
        "top_rules", "top_rule_share", "truncated", "partial",
        "index_pattern", "filter", "per_entity_claims", "canonical_srcip_field")
        if key in alert_doc}

    _write_json(out / "tool_inventory.json", inventory)
    _write_json(out / "metrics.json", metrics_snapshot)
    _write_json(out / "cases.json", case_doc)
    _write_json(out / "evaluations.json", eval_doc)
    _write_json(out / "alerts.json", alert_view)

    modules = Counter(t["module"] for t in inventory)
    csv_rows = "\n".join(f"{module},{modules[module]}" for module in sorted(modules))
    (out / "figures" / "tool_modules.csv").write_text(
        "module,tools\n" + csv_rows + "\n", encoding="utf-8")

    artifacts = [out / "tool_inventory.json", out / "metrics.json",
                 out / "cases.json", out / "evaluations.json",
                 out / "alerts.json", out / "figures" / "tool_modules.csv"]
    hashes = {str(p.relative_to(out)): _sha256(p) for p in artifacts}
    claims = _claims(inventory, case_doc, metrics_snapshot, hashes, alert_doc)
    _write_json(out / "claims.json", claims)
    artifacts.append(out / "claims.json")

    files = [{"path": str(p.relative_to(out)), "bytes": p.stat().st_size,
              "sha256": _sha256(p)} for p in artifacts]
    content_hash = hashlib.sha256(
        "\n".join(f"{f['path']}\t{f['sha256']}" for f in files).encode("utf-8")
    ).hexdigest()

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "pack_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "git": _git_state(repo_root),
        "gating": gating or {},
        "alerts": {"available": bool(alert_doc.get("available")),
                   "window_minutes": int(alert_doc.get("window_minutes") or 0),
                   "error_kind": alert_doc.get("error_kind") or "",
                   "index_pattern": alert_doc.get("index_pattern") or "",
                   "filter": alert_doc.get("filter") or "",
                   "per_entity_claims": bool(alert_doc.get("per_entity_claims", False)),
                   "canonical_srcip_field": alert_doc.get("canonical_srcip_field") or ""},
        "pack_status": "complete" if all(c["citable"] for c in claims) else "degraded",
        "k_anonymity": K_ANONYMITY,
        "min_evidence_n": MIN_EVIDENCE_N,
        "claims": {"total": len(claims),
                   "citable": sum(1 for c in claims if c["citable"])},
        "content_hash": content_hash,
        "files": files,
    }
    _write_json(out / "manifest.json", manifest)
    return manifest
