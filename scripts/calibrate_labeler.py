#!/usr/bin/env python3
"""Calibrate the ONNX labeler's confidence floor and softmax temperature.
Reads analyst-labeled cases from a JSONL file, labels each one in-process over a
grid of (floor, temperature), and writes a markdown report with top-1 accuracy,
per-tactic support, a confusion matrix, the uncertain ratio and suggested values.
Cases are embedded once per temperature and every floor is applied to the returned
vectors, so a 1,000-row set costs one batch embedding call per temperature, not one
call per grid point. The script never writes env files or code: suggestions are printed in the report
and the operator applies them with BLUETEAM_LAYA_CONFIDENCE_FLOOR /
BLUETEAM_LAYA_TEMPERATURE.

Row schema, one JSON object per line:
  {"id": "case-1", "text": "mass file encryption ...", "ground_truth_tactic": "Impact"}
  {"id": "case-2", "alert": {...}, "ground_truth_tactic": "Command and Control"}
Exactly one of ``text`` or ``alert`` per row. ``alert`` uses the same 11-field
allowlist as the tool, so an exported Wazuh alert can be pasted unchanged.

Run it on the controlled stage, where the embedder cache exists:
  python3 scripts/calibrate_labeler.py --input /var/lib/blue-team-mcp/calibration/labels.jsonl
"""
from __future__ import annotations
import argparse
import asyncio
import json
from pathlib import Path

DEFAULT_FLOORS = (0.4, 0.5, 0.6, 0.7, 0.8)
DEFAULT_TEMPERATURES = (0.02, 0.05, 0.1, 0.2)


def load_cases(path: str | Path) -> list[dict]:
    """Parse and validate the JSONL corpus. Raises ValueError with the line number."""
    from mcp_server.label.criteria import TACTICS
    from mcp_server.label.labeler import MAX_STATE_CHARS, build_state_text

    cases: list[dict] = []
    for lineno, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            row = json.loads(line)
        except ValueError as exc:
            raise ValueError(f"{path}:{lineno}: invalid JSON: {exc}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"{path}:{lineno}: row must be a JSON object")
        text, alert = row.get("text"), row.get("alert")
        if bool(text) == bool(alert):
            raise ValueError(f"{path}:{lineno}: set exactly one of 'text' or 'alert'")
        truth = row.get("ground_truth_tactic")
        if truth not in TACTICS:
            raise ValueError(f"{path}:{lineno}: ground_truth_tactic {truth!r} is not one of the 16 tactics")
        state_text = text or build_state_text(alert)[0]
        if not state_text:
            raise ValueError(f"{path}:{lineno}: alert carries none of the fields the labeler reads")
        cases.append({"id": row.get("id") or f"line-{lineno}",
                      "state_text": state_text[:MAX_STATE_CHARS], "truth": truth})
    if not cases:
        raise ValueError(f"{path}: no cases found")
    return cases


def score(cases: list[dict], predictions: list[dict],
          floor: float, temperature: float) -> dict:
    """One grid point. ``top1`` counts only verdicts that cleared the floor."""
    n = len(cases)
    correct = answered = uncertain = unavailable = 0
    support: dict[str, dict] = {}
    confusion: dict[str, dict] = {}
    for case, pred in zip(cases, predictions):
        truth, status, label = case["truth"], pred.get("status"), pred.get("label")
        bucket = support.setdefault(truth, {"support": 0, "correct": 0})
        bucket["support"] += 1
        if status in ("ok", "uncertain"):
            answered += 1
        if status == "uncertain":
            uncertain += 1
        if status == "unavailable":
            unavailable += 1
        key = label if status == "ok" else status
        confusion.setdefault(truth, {})[key] = confusion.setdefault(truth, {}).get(key, 0) + 1
        if status == "ok" and label == truth:
            correct += 1
            bucket["correct"] += 1
    return {"floor": floor, "temperature": temperature, "cases": n, "correct": correct,
            "answered": answered, "uncertain": uncertain, "unavailable": unavailable,
            "top1": correct / n if n else 0.0,
            "top1_answered": correct / answered if answered else 0.0,
            "support": support, "confusion": confusion}


def suggest(rows: list[dict], default_floor: float = 0.6,
            default_temperature: float = 0.05) -> dict:
    """Most correct, then least uncertain, then nearest the current defaults."""
    return min(rows, key=lambda r: (
        -r["correct"], r["uncertain"],
        abs(r["floor"] - default_floor) + abs(r["temperature"] - default_temperature)))


def _floor_verdict(verdict, floor: float) -> dict:
    """Apply a floor to a verdict that already carries its probability vector."""
    if isinstance(verdict, dict):
        probabilities = verdict.get("probabilities") or {}
        status, label = verdict.get("status"), verdict.get("label")
    else:
        probabilities = getattr(verdict, "probabilities", None) or {}
        status = getattr(verdict, "status", "unavailable")
        label = getattr(verdict, "label", None)
    if not probabilities:
        return {"status": status, "label": label}
    top = max(probabilities, key=probabilities.get)
    if probabilities[top] >= floor:
        return {"status": "ok", "label": top}
    return {"status": "uncertain", "label": None}


def _default_factory(floor: float, temperature: float):
    from mcp_server.label.backends import ONNXPrototypeLabeler
    return ONNXPrototypeLabeler(floor, temperature=temperature)


def render_report(rows: list[dict], best: dict, source: str, criteria_version: str) -> str:
    lines = [f"# Labeler calibration - {best['cases']} cases", "",
             f"- Source: `{source}`",
             f"- Criteria version: `{criteria_version}`",
             f"- Grid: {len(rows)} points "
             f"({len({r['floor'] for r in rows})} floors x "
             f"{len({r['temperature'] for r in rows})} temperatures)", "",
             "## Sweep", "",
             "| floor | temperature | top-1 | top-1 answered | uncertain | unavailable |",
             "|---|---|---|---|---|---|"]
    for row in rows:
        lines.append(f"| {row['floor']} | {row['temperature']} | {row['top1']:.2f} "
                     f"({row['correct']}/{row['cases']}) | {row['top1_answered']:.2f} | "
                     f"{row['uncertain']} | {row['unavailable']} |")
    lines += ["", "## Suggested values", "",
              f"- **floor**: `{best['floor']}`",
              f"- **temperature**: `{best['temperature']}`",
              f"- top-1: {best['correct']}/{best['cases']} ({best['top1']:.0%}), "
              f"uncertain {best['uncertain']}, unavailable {best['unavailable']}", "",
              "Apply manually, then restart the server:", "",
              "```bash",
              f"export BLUETEAM_LAYA_CONFIDENCE_FLOOR={best['floor']}",
              f"export BLUETEAM_LAYA_TEMPERATURE={best['temperature']}",
              "```", "", "## Per-tactic support (suggested row)", "",
              "| tactic | support | correct | recall |", "|---|---|---|---|"]
    for tactic, bucket in sorted(best["support"].items()):
        recall = bucket["correct"] / bucket["support"] if bucket["support"] else 0.0
        lines.append(f"| {tactic} | {bucket['support']} | {bucket['correct']} | {recall:.2f} |")
    columns = sorted({key for row in best["confusion"].values() for key in row})
    lines += ["", "## Confusion matrix (suggested row)", "",
              "| truth \\ predicted | " + " | ".join(columns) + " |",
              "|---" * (len(columns) + 1) + "|"]
    for truth, row in sorted(best["confusion"].items()):
        lines.append(f"| {truth} | " + " | ".join(str(row.get(col, 0)) for col in columns) + " |")
    return "\n".join(lines) + "\n"


async def run(input_path: str | Path, out_path: str | Path,
              floors: tuple[float, ...] = DEFAULT_FLOORS,
              temperatures: tuple[float, ...] = DEFAULT_TEMPERATURES,
              factory=None) -> dict:
    from mcp_server.label.criteria import version
    cases = load_cases(input_path)
    factory = factory or _default_factory
    texts = [case["state_text"] for case in cases]
    rows: list[dict] = []
    for temperature in temperatures:
        # Floor 0.0 returns the full vector on every row; each floor is then applied
        # in memory, so the model sees each case once per temperature.
        classifier = factory(0.0, temperature)
        verdicts = await classifier.classify_many(texts)
        for floor in floors:
            predictions = [_floor_verdict(verdict, floor) for verdict in verdicts]
            rows.append(score(cases, predictions, floor, temperature))
    rows.sort(key=lambda row: (row["floor"], row["temperature"]))
    best = suggest(rows)
    Path(out_path).write_text(render_report(rows, best, str(input_path), version()),
                              encoding="utf-8")
    print(f"wrote {out_path} ({len(cases)} cases, {len(rows)} grid points)")
    print(f"suggested: floor={best['floor']} temperature={best['temperature']} "
          f"top1={best['top1']:.2f}")
    return best


def _floats(raw: str) -> tuple[float, ...]:
    return tuple(float(part) for part in raw.split(",") if part.strip())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default="/var/lib/blue-team-mcp/calibration/labels.jsonl")
    parser.add_argument("--out", default="calibration_report.md")
    parser.add_argument("--floors", default=",".join(map(str, DEFAULT_FLOORS)))
    parser.add_argument("--temperatures", default=",".join(map(str, DEFAULT_TEMPERATURES)))
    args = parser.parse_args()
    asyncio.run(run(args.input, args.out, _floats(args.floors), _floats(args.temperatures)))


if __name__ == "__main__":
    main()
