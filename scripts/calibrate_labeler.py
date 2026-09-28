#!/usr/bin/env python3
"""Calibrate the labeler's confidence floor and score temperature.
Reads analyst labeled cases from a JSONL file, labels each one in-process over a
grid of (floor, temperature), and writes a markdown report with top-1 accuracy,
macro-F1 over the 16-tactic vocabulary, per-tactic precision/recall, coverage,
selective accuracy, ECE, a confusion matrix and suggested values.
``--gate`` turns the suggested point into an exit code: 2 when it misses the
provisional macro-F1 / selective-accuracy / coverage / ECE thresholds, so a
cron or CI run fails on a regression instead of writing a report nobody reads.
Works for both backends: onnx re-embeds per temperature, Laya re-runs inference per
temperature. Cases are embedded once per temperature and every floor is applied to
the returned vectors, so a 1,000-row set costs one pass per temperature, not one
call per grid point. The script never writes env files or code: suggestions are printed in the report
and the operator applies them with BLUETEAM_LAYA_CONFIDENCE_FLOOR /
BLUETEAM_LAYA_TEMPERATURE.

Row schema, one JSON object per line:
  {"id": "case-1", "text": "mass file encryption ...", "ground_truth_tactic": "Impact"}
  {"id": "case-2", "alert": {...}, "ground_truth_tactic": "Command and Control"}
Exactly one of ``text`` or ``alert`` per row. ``alert`` uses the same 11-field
allowlist as the tool, so an exported Wazuh alert can be pasted unchanged. Rows from
``scripts/build_label_corpus.py`` also carry ``split``; ``--split test`` evaluates
one of them.

Run it on the controlled stage, where the embedder cache exists: python3 scripts/calibrate_labeler.py --input /var/lib/blue-team-mcp/calibration/labels.jsonl
For the Laya backend, set BLUETEAM_LAYA_MODEL_PATH / BLUETEAM_LAYA_MODEL_SHA256 and pass --backend laya.
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
                      "state_text": state_text[:MAX_STATE_CHARS], "truth": truth,
                      "split": row.get("split")})
    if not cases:
        raise ValueError(f"{path}: no cases found")
    return cases


def _counts_and_f1(rows, vocabulary: tuple[str, ...]) -> tuple[dict[str, dict], float]:
    """Per-tactic precision/recall/F1 plus their unweighted mean over the whole
    vocabulary. A non-answer counts as a false negative, never as a prediction, and
    classes with no support still count: scoring only the covered classes is how a
    model that answers three tactics gets a perfect macro-F1."""
    stats = {tactic: {"tp": 0, "fp": 0, "fn": 0, "support": 0} for tactic in vocabulary}
    for truth, predicted in rows:
        if truth in stats:
            stats[truth]["support"] += 1
            if predicted != truth:
                stats[truth]["fn"] += 1
        if predicted in stats and predicted != truth:
            stats[predicted]["fp"] += 1
        if predicted == truth and truth in stats:
            stats[truth]["tp"] += 1
    per_tactic: dict[str, dict] = {}
    for tactic, counts in stats.items():
        tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        per_tactic[tactic] = {"support": counts["support"], "precision": precision,
                              "recall": recall, "f1": f1}
    macro = sum(entry["f1"] for entry in per_tactic.values()) / len(per_tactic)
    return per_tactic, macro


def _ece(confidences: list[float], correctness: list[bool], bins: int = 15) -> float | None:
    """Expected calibration error over the answered rows. None when no prediction
    carried a confidence: reporting 0.0 would read as perfect calibration."""
    if not confidences:
        return None
    total = len(confidences)
    error = 0.0
    for index in range(bins):
        low, high = index / bins, (index + 1) / bins
        members = [i for i, value in enumerate(confidences)
                   if low <= value < high or (index == bins - 1 and value == 1.0)]
        if not members:
            continue
        mean_confidence = sum(confidences[i] for i in members) / len(members)
        accuracy = sum(1 for i in members if correctness[i]) / len(members)
        error += len(members) / total * abs(accuracy - mean_confidence)
    return error


def score(cases: list[dict], predictions: list[dict],
          floor: float, temperature: float) -> dict:
    """One grid point. ``top1`` counts only verdicts that cleared the floor, and
    ``ece`` is measured only over those verdicts because an uncertain row has no
    confidence to calibrate."""
    from mcp_server.label.criteria import TACTICS

    n = len(cases)
    correct = answered = uncertain = unavailable = 0
    support: dict[str, dict] = {}
    confusion: dict[str, dict] = {}
    pairs_all: list[tuple[str, str | None]] = []
    pairs_answered: list[tuple[str, str | None]] = []
    confidences: list[float] = []
    correctness: list[bool] = []
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
        pairs_all.append((truth, label if status == "ok" else None))
        if status == "ok":
            correct += label == truth
            bucket["correct"] += 1
            pairs_answered.append((truth, label))
            confidence = pred.get("confidence")
            if isinstance(confidence, (int, float)):
                confidences.append(float(confidence))
                correctness.append(label == truth)
    per_tactic, macro_f1 = _counts_and_f1(pairs_all, tuple(TACTICS))
    _per_tactic_answered, macro_f1_answered = _counts_and_f1(pairs_answered, tuple(TACTICS))
    return {"floor": floor, "temperature": temperature, "cases": n, "correct": correct,
            "answered": answered, "uncertain": uncertain, "unavailable": unavailable,
            "top1": correct / n if n else 0.0,
            "top1_answered": correct / answered if answered else 0.0,
            "coverage": answered / n if n else 0.0,
            "macro_f1": macro_f1, "macro_f1_answered": macro_f1_answered,
            "ece": _ece(confidences, correctness),
            "support": support, "per_tactic": per_tactic, "confusion": confusion}


GATE_DEFAULTS = {"min_macro_f1": 0.80, "min_selective_accuracy": 0.90,
                 "min_coverage": 0.60, "max_ece": 0.10}


def evaluate_gate(best: dict, thresholds: dict) -> list[str]:
    """Provisional thresholds: macro F1 and selective accuracy floor the quality,
    coverage stops a high floor from answering nothing, and ECE stops an uncalibrated
    confidence from passing on accuracy alone."""
    checks = (("min_macro_f1", "macro_f1", "macro-F1", ">="),
              ("min_selective_accuracy", "top1_answered", "selective accuracy", ">="),
              ("min_coverage", "coverage", "coverage", ">="),
              ("max_ece", "ece", "ECE", "<="))
    failures: list[str] = []
    for key, metric, label, operator in checks:
        bound = thresholds.get(key)
        if bound is None:
            continue
        value = best.get(metric)
        if value is None:
            failures.append(f"{label} is unmeasured")
        elif operator == ">=" and value < bound:
            failures.append(f"{label} {value:.3f} < {bound}")
        elif operator == "<=" and value > bound:
            failures.append(f"{label} {value:.3f} > {bound}")
    return failures


def suggest(rows: list[dict], default_floor: float = 0.6,
            default_temperature: float = 0.05) -> dict:
    """Best macro-F1, then least uncertain, then nearest the current defaults.
    Raw correct would reward a threshold that only ever answers the majority tactic."""
    def rank(row: dict) -> tuple:
        quality = row.get("macro_f1")
        if quality is None:
            quality = row.get("top1", 0.0)
        return (-quality, row["uncertain"],
                abs(row["floor"] - default_floor) + abs(row["temperature"] - default_temperature))
    return min(rows, key=rank)


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
        return {"status": status, "label": label, "confidence": None}
    top = max(probabilities, key=probabilities.get)
    if probabilities[top] >= floor:
        return {"status": "ok", "label": top, "confidence": probabilities[top]}
    return {"status": "uncertain", "label": None, "confidence": None}


def _default_factory(backend: str):
    """Build the ``(floor, temperature) -> labeler`` factory for one backend.
    Selection mirrors ``labeler._build`` but keeps temperature injectable, which is
    the whole point of the sweep; importing and keeps the script importable without a configured Wazuh connection."""
    from mcp_server.core.config import config
    if backend == "laya":
        from mcp_server.label.backends import LayaLabeler
        label = config.label
        return lambda floor, temperature: LayaLabeler(
            floor, label.model_path, label.model_sha256, label.allow_download,
            temperature=temperature, max_len=label.max_len)
    from mcp_server.label.backends import ONNXPrototypeLabeler
    return lambda floor, temperature: ONNXPrototypeLabeler(floor, temperature=temperature)


def render_report(rows: list[dict], best: dict, source: str, criteria_version: str,
                  backend: str = "onnx", split: str | None = None) -> str:
    lines = [f"# Labeler calibration - {best['cases']} cases", "",
             f"- Source: `{source}`",
             f"- Backend: `{backend}`",
             (f"- Split: `{split}`" if split else "- Split: all rows"),
             f"- Criteria version: `{criteria_version}`",
             f"- Grid: {len(rows)} points "
             f"({len({r['floor'] for r in rows})} floors x "
             f"{len({r['temperature'] for r in rows})} temperatures)", "",
             "## Sweep", "",
             "| floor | temperature | top-1 | macro-F1 | selective acc | coverage | ECE | uncertain | unavailable |",
             "|---|---|---|---|---|---|---|---|---|"]
    for row in rows:
        ece = f"{row['ece']:.3f}" if row["ece"] is not None else "n/a"
        lines.append(f"| {row['floor']} | {row['temperature']} | {row['top1']:.2f} "
                     f"({row['correct']}/{row['cases']}) | {row['macro_f1']:.2f} | "
                     f"{row['top1_answered']:.2f} | {row['coverage']:.2f} | {ece} | "
                     f"{row['uncertain']} | {row['unavailable']} |")
    lines += ["", "## Suggested values", "",
              f"- **floor**: `{best['floor']}`",
              f"- **temperature**: `{best['temperature']}`",
              f"- top-1: {best['correct']}/{best['cases']} ({best['top1']:.0%}), "
              f"macro-F1 {best['macro_f1']:.3f}, coverage {best['coverage']:.2f}, "
              f"selective accuracy {best['top1_answered']:.3f}, "
              + (f"ECE {best['ece']:.3f}" if best["ece"] is not None else "ECE unmeasured"),
              "",
              "Apply manually, then restart the server:", "",
              "```bash",
              f"export BLUETEAM_LAYA_CONFIDENCE_FLOOR={best['floor']}",
              f"export BLUETEAM_LAYA_TEMPERATURE={best['temperature']}",
              "```", "", "## Per-tactic metrics (suggested row)", "",
              "| tactic | support | precision | recall | f1 |", "|---|---|---|---|---|"]
    for tactic, metrics in sorted(best["per_tactic"].items()):
        lines.append(f"| {tactic} | {metrics['support']} | {metrics['precision']:.2f} | "
                     f"{metrics['recall']:.2f} | {metrics['f1']:.2f} |")
    columns = sorted({key for row in best["confusion"].values() for key in row})
    lines += ["", "## Confusion matrix (suggested row)", "",
              "| truth \\ predicted | " + " | ".join(columns) + " |",
              "|---" * (len(columns) + 1) + "|"]
    for truth, row in sorted(best["confusion"].items()):
        lines.append(f"| {truth} | " + " | ".join(str(row.get(col, 0)) for col in columns) + " |")
    if "gate_failures" in best:
        lines += ["", "## Gate", ""]
        if best["gate_failures"]:
            lines += ["**FAIL**"] + [f"- {item}" for item in best["gate_failures"]]
        else:
            lines.append("**PASS** at the suggested point (provisional thresholds).")
    return "\n".join(lines) + "\n"


async def run(input_path: str | Path, out_path: str | Path,
              floors: tuple[float, ...] = DEFAULT_FLOORS,
              temperatures: tuple[float, ...] = DEFAULT_TEMPERATURES,
              factory=None, backend: str | None = None,
              split: str | None = None, gate: dict | None = None) -> dict:
    from mcp_server.label.criteria import version
    from mcp_server.core.config import config
    backend = backend or config.label.backend
    cases = load_cases(input_path)
    if split:
        cases = [case for case in cases if case["split"] == split]
        if not cases:
            raise ValueError(f"no cases carry split={split!r}; build the corpus with "
                             "scripts/build_label_corpus.py, which stamps the split")
    factory = factory or _default_factory(backend)
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
    best = suggest(rows, default_temperature=1.0 if backend == "laya" else 0.05)
    if gate is not None:
        best["gate_failures"] = evaluate_gate(best, gate)
    Path(out_path).write_text(
        render_report(rows, best, str(input_path), version(), backend, split),
        encoding="utf-8")
    where = f", split={split}" if split else ""
    print(f"wrote {out_path} ({len(cases)} cases, {len(rows)} grid points, backend={backend}{where})")
    print(f"suggested: floor={best['floor']} temperature={best['temperature']} "
          f"top1={best['top1']:.2f} macro_f1={best['macro_f1']:.2f} "
          f"coverage={best['coverage']:.2f}")
    if best.get("gate_failures"):
        print("gate FAILED: " + "; ".join(best["gate_failures"]))
    return best


def _floats(raw: str) -> tuple[float, ...]:
    return tuple(float(part) for part in raw.split(",") if part.strip())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default="/var/lib/blue-team-mcp/calibration/labels.jsonl")
    parser.add_argument("--out", default="calibration_report.md")
    parser.add_argument("--backend", choices=("onnx", "laya"), default=None,
                        help="Labeler backend to calibrate; defaults to "
                             "BLUETEAM_LAYA_BACKEND (onnx when unset).")
    parser.add_argument("--split", choices=("train", "val", "test"), default=None,
                        help="Evaluate one corpus split; rows from "
                             "scripts/build_label_corpus.py carry it.")
    parser.add_argument("--gate", action="store_true",
                        help="Exit 2 when the suggested point misses the thresholds.")
    parser.add_argument("--min-macro-f1", type=float, default=None)
    parser.add_argument("--min-selective-accuracy", type=float, default=None)
    parser.add_argument("--min-coverage", type=float, default=None)
    parser.add_argument("--max-ece", type=float, default=None)
    parser.add_argument("--floors", default=",".join(map(str, DEFAULT_FLOORS)))
    parser.add_argument("--temperatures", default=",".join(map(str, DEFAULT_TEMPERATURES)))
    args = parser.parse_args()
    overrides = {key: value for key, value in vars(args).items()
                 if key in GATE_DEFAULTS and value is not None}
    gate = {**GATE_DEFAULTS, **overrides} if (args.gate or overrides) else None
    best = asyncio.run(run(args.input, args.out, _floats(args.floors),
                           _floats(args.temperatures), backend=args.backend,
                           split=args.split, gate=gate))
    if best.get("gate_failures"):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
