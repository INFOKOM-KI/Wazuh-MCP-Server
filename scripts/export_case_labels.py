#!/usr/bin/env python3
"""Export candidate calibration rows from the false-positive KB and the
investigation history.
Neither store keeps the original Wazuh alert body, so each row carries a short
context line built from the stored fields (indicator, verdict, notes, reason).
The analyst edits the text if needed and fills `ground_truth_tactic`, after which
the file can be fed to `scripts/calibrate_labeler.py`.
Output is JSONL, one candidate per line: {"id": "...", "source": "...", "text": "...", "ground_truth_tactic": ""}
A row with an empty `ground_truth_tactic` is intentionally invalid for the
calibration harness: it is incomplete until a human labels it.

python3 scripts/export_case_labels.py --out /var/lib/blue-team-mcp/calibration/candidates.jsonl
"""
from __future__ import annotations
import argparse
import json
import os
import sys
from datetime import datetime, timezone


def _iter_jsonl(path: str):
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict):
                yield row


def load_false_positive_kb(path: str) -> list[dict]:
    """Rows are {"ioc", "ts", "source", "reason"}; entries without an ioc are skipped."""
    rows = []
    for row in _iter_jsonl(path):
        ioc = str(row.get("ioc", "")).strip()
        if ioc:
            rows.append({"ioc": ioc, "ts": row.get("ts"),
                         "reason": str(row.get("reason", "")).strip()})
    return rows


def load_history(path: str) -> list[dict]:
    """Rows are the blueteam_mark_investigated entries: {"ts", "srcip", "verdict", "notes"}."""
    rows = []
    for row in _iter_jsonl(path):
        srcip = str(row.get("srcip", "")).strip()
        if srcip:
            rows.append({"srcip": srcip, "ts": row.get("ts"),
                         "verdict": str(row.get("verdict", "")).strip(),
                         "notes": str(row.get("notes", "")).strip()})
    return rows


def _date(value) -> str:
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc).date().isoformat()
        except (OSError, OverflowError, ValueError):
            return ""
    return ""


def _fp_row(entry: dict) -> dict:
    date = _date(entry.get("ts"))
    line = f"srcip={entry['ioc']} false-positive reason={entry['reason'] or 'not recorded'}"
    if date:
        line += f" since={date}"
    return {"id": f"false_positive_kb:{entry['ioc']}", "source": "false_positive_kb",
            "text": line, "ground_truth_tactic": ""}


def _history_row(entry: dict) -> dict:
    return {"id": f"investigation_history:{entry['srcip']}", "source": "investigation_history",
            "text": (f"srcip={entry['srcip']} analyst verdict={entry['verdict'] or 'unknown'} "
                     f"notes={entry['notes'] or 'none'}"),
            "ground_truth_tactic": ""}


def build_rows(fp_rows: list[dict], history_rows: list[dict],
               limit: int | None = None) -> list[dict]:
    """One row per indicator. A history entry replaces an FP entry for the same
    IP because it carries the analyst verdict and notes."""
    latest: dict[str, dict] = {}
    for entry in fp_rows:
        latest.setdefault(entry["ioc"], _fp_row(entry))
    for entry in history_rows:
        latest[entry["srcip"]] = _history_row(entry)
    rows = sorted(latest.values(), key=lambda row: row["id"])
    return rows[:limit] if limit else rows


def write_rows(rows: list[dict], out: str | None) -> None:
    text = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)
    if out:
        with open(out, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--false-positive-kb",
                        default=os.environ.get("BLUETEAM_FALSE_POSITIVE_KB", ""))
    parser.add_argument("--history", default=os.environ.get("BLUETEAM_INVESTIGATION_HISTORY", ""))
    parser.add_argument("--out", default="", help="default: stdout")
    parser.add_argument("--limit", type=int, default=None, help="optional cap; default: all")
    args = parser.parse_args()
    sources = [path for path in (args.false_positive_kb, args.history) if path]
    if not sources:
        print("Set BLUETEAM_FALSE_POSITIVE_KB / BLUETEAM_INVESTIGATION_HISTORY or pass the paths",
              file=sys.stderr)
        return 2
    fp_rows = load_false_positive_kb(args.false_positive_kb) if args.false_positive_kb else []
    history_rows = load_history(args.history) if args.history else []
    rows = build_rows(fp_rows, history_rows, args.limit)
    if not rows:
        print("No source rows found; nothing exported.", file=sys.stderr)
        return 1
    write_rows(rows, args.out or None)
    print(f"exported {len(rows)} candidate row(s)"
          + (f" to {args.out}" if args.out else ""), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
