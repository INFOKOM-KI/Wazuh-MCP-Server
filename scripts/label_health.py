#!/usr/bin/env python3
"""Label health gate over the audit JSONL log.
Computes label coverage and the uncertain ratio for the current window, compares
the uncertain ratio with the previous window of the same size, and can fail a
cron/CI run when coverage drops or the ratio drifts more than the allowed points.
The audit log is the only input: `blueteam_incident_label` rows carry `status`,
and `blueteam_investigation_workflow` rows count the investigations the labels
belong to. No runtime state is read or written.

python3 scripts/label_health.py --window-days 7 --fail
"""
from __future__ import annotations
import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone

LABEL_TOOL = "blueteam_incident_label"
WORKFLOW_TOOL = "blueteam_investigation_workflow"
COVERED_STATUSES = ("ok", "uncertain")


def iter_entries(path: str):
    """Yield audit entries, skipping blank, torn and non-object lines."""
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if isinstance(entry, dict):
                yield entry


def _parse_ts(value) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _blank() -> dict:
    return {"labels": 0, "covered": 0, "uncertain": 0, "unavailable": 0, "investigations": 0}


def summarize(entries, now: datetime, window_days: float = 7.0) -> dict:
    """Split the log into the current and previous windows and score both."""
    window = timedelta(days=window_days)
    current_start, previous_start = now - window, now - 2 * window
    buckets = {"current": _blank(), "previous": _blank()}
    for entry in entries:
        tool = entry.get("tool")
        if tool not in (LABEL_TOOL, WORKFLOW_TOOL):
            continue
        ts = _parse_ts(entry.get("ts"))
        if ts is None:
            continue
        if current_start < ts <= now:
            bucket = "current"
        elif previous_start < ts <= current_start:
            bucket = "previous"
        else:
            continue
        if tool == WORKFLOW_TOOL:
            buckets[bucket]["investigations"] += 1
            continue
        status = str((entry.get("params") or {}).get("status", ""))
        buckets[bucket]["labels"] += 1
        if status in COVERED_STATUSES:
            buckets[bucket]["covered"] += 1
        if status == "uncertain":
            buckets[bucket]["uncertain"] += 1
        elif status == "unavailable":
            buckets[bucket]["unavailable"] += 1
    return _finalize(buckets, window_days)


def _finalize(buckets: dict, window_days: float) -> dict:
    summary = {"window_days": window_days}
    for key, stats in buckets.items():
        labels, covered = stats["labels"], stats["covered"]
        stats["coverage"] = covered / labels if labels else 0.0
        stats["uncertain_ratio"] = stats["uncertain"] / covered if covered else 0.0
        stats["labels_per_investigation"] = (labels / stats["investigations"]
                                             if stats["investigations"] else None)
        summary[key] = stats
    summary["coverage_drift_points"] = (
        (summary["current"]["coverage"] - summary["previous"]["coverage"]) * 100
        if summary["previous"]["labels"] else None)
    summary["uncertain_drift_points"] = (
        (summary["current"]["uncertain_ratio"] - summary["previous"]["uncertain_ratio"]) * 100
        if summary["previous"]["labels"] else None)
    return summary


def health_failures(summary: dict, min_coverage: float = 0.8,
                    max_drift_points: float = 10.0) -> list[str]:
    """Gate reasons. Drift needs a previous window with data to mean anything."""
    current = summary["current"]
    failures: list[str] = []
    if not current["labels"]:
        failures.append("no label calls in the current window")
    elif current["coverage"] < min_coverage:
        failures.append(f"coverage {current['coverage']:.1%} is below {min_coverage:.0%}")
    if summary["uncertain_drift_points"] is not None and \
            abs(summary["uncertain_drift_points"]) > max_drift_points:
        failures.append(f"uncertain ratio drifted {summary['uncertain_drift_points']:+.1f}pp "
                        f"(limit {max_drift_points:g}pp)")
    return failures


def render(summary: dict, min_coverage: float = 0.8,
           max_drift_points: float = 10.0) -> str:
    current, previous = summary["current"], summary["previous"]
    per_inv = current["labels_per_investigation"]
    prev_per_inv = previous["labels_per_investigation"]
    fmt_per_inv = lambda value: "-" if value is None else format(value, ".2f")
    fmt_drift = lambda value: ("n/a (no previous labels)" if value is None
                               else f"{value:+.1f}pp")
    lines = [f"# Label health - last {summary['window_days']:g}d vs previous "
             f"{summary['window_days']:g}d", "",
             "| Metric | Current | Previous |", "|---|---|---|",
             f"| Label calls | {current['labels']} | {previous['labels']} |",
             f"| Covered (ok + uncertain) | {current['covered']} | {previous['covered']} |",
             f"| Coverage | {current['coverage']:.1%} | {previous['coverage']:.1%} |",
             f"| Uncertain | {current['uncertain']} | {previous['uncertain']} |",
             f"| Uncertain ratio | {current['uncertain_ratio']:.1%} | "
             f"{previous['uncertain_ratio']:.1%} |",
             f"| Unavailable | {current['unavailable']} | {previous['unavailable']} |",
             f"| Investigation runs | {current['investigations']} | {previous['investigations']} |",
             f"| Labels per investigation | {fmt_per_inv(per_inv)} | {fmt_per_inv(prev_per_inv)} |",
             "",
             f"Gate: coverage >= {min_coverage:.0%}, uncertain drift <= {max_drift_points:g}pp",
             f"- coverage drift: {fmt_drift(summary['coverage_drift_points'])}",
             f"- uncertain ratio drift: {fmt_drift(summary['uncertain_drift_points'])}"]
    failures = health_failures(summary, min_coverage, max_drift_points)
    lines.append(f"Status: {'FAIL - ' + '; '.join(failures) if failures else 'OK'}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default=os.environ.get("BLUETEAM_AUDIT_LOG", ""))
    parser.add_argument("--window-days", type=float, default=7.0)
    parser.add_argument("--min-coverage", type=float, default=0.8)
    parser.add_argument("--max-drift-points", type=float, default=10.0)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--fail", action="store_true", help="exit 1 on any gate failure")
    args = parser.parse_args()
    if not args.input:
        print("BLUETEAM_AUDIT_LOG is not set and --input was not given", file=sys.stderr)
        return 2
    summary = summarize(iter_entries(args.input), datetime.now(timezone.utc), args.window_days)
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(render(summary, args.min_coverage, args.max_drift_points))
    failures = health_failures(summary, args.min_coverage, args.max_drift_points)
    if failures:
        print("FAIL: " + "; ".join(failures), file=sys.stderr)
        return 1 if args.fail else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
