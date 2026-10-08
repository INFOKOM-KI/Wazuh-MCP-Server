#!/usr/bin/env python3
"""Export candidate calibration rows from the false-positive KB and the
investigation history, and merge reviewer decisions into a frozen evaluation file.

Two modes:
  export (default)  store JSONL -> candidate rows with every review field empty.
                    Candidate text is synthesized from stored analyst fields and is
                    marked ``text_origin=synthesized_notes``; it is not a production
                    alert and must not be presented as one.
  review            --reviews applies a decision file to frozen candidates and
                    writes the evaluation file that ``calibrate_labeler.py`` reads,
                    plus an exclusions sidecar and an optional provenance manifest.

Neither mode invents ground truth. A row becomes evaluation data only when a named
reviewer supplies exactly one of the 16 tactics and an explicit ``split``; anything
else is dropped with an ``exclude_reason``. Projected/STIX-derived rows cannot enter
the evaluation file: only the two analyst sources are accepted.

python3 scripts/export_case_labels.py --false-positive-kb ~/fp.jsonl --history ~/hist.jsonl \\
    --out candidates.jsonl
python3 scripts/export_case_labels.py --candidates candidates.jsonl --reviews decisions.jsonl \\
    --out evaluation.jsonl --dataset analyst-eval-v1 --criteria-version v1:xxxxxxxx \\
    --manifest evaluation.manifest.json
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

ANALYST_SOURCES = ("false_positive_kb", "investigation_history")
TEXT_ORIGINS = ("synthesized_notes", "reviewer_text", "production_alert")
SPLITS = ("test", "tuning")
# Fields an alert must not carry in an evaluation row: rule.id and agent.name
# encode the source and rule.mitre states the answer, so the projected corpus
# strips them for the same reason. build_state_text() would otherwise score them.
LEAK_PATHS = (("rule", "id"), ("rule", "mitre"), ("agent", "name"))


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
    """Rows are the blueteam_mark_investigated entries:
    {"ts", "srcip", "verdict", "notes"}; a case id is kept when the store carries one.
    """
    rows = []
    for row in _iter_jsonl(path):
        srcip = str(row.get("srcip", "")).strip()
        if srcip:
            rows.append({"srcip": srcip, "ts": row.get("ts"),
                         "verdict": str(row.get("verdict", "")).strip(),
                         "notes": str(row.get("notes", "")).strip(),
                         "case_id": str(row.get("case_id", "")).strip()})
    return rows


def _observed_at(value) -> str:
    """ISO-8601 observation time, or "" when the store carried none/usable."""
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
        except (OSError, OverflowError, ValueError):
            return ""
    if isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return ""
        return parsed.isoformat() if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc).isoformat()
    return ""


def _candidate_row(row_id: str, source: str, source_ref: str, case_ref: str,
                   observed_at: str, text: str) -> dict:
    return {
        "id": row_id,
        "source": source,
        "source_ref": source_ref,
        "case_ref": case_ref,
        "observed_at": observed_at,
        "text": text,
        "text_origin": "synthesized_notes",
        "ground_truth_tactic": None,
        "review_state": "unreviewed",
        "reviewer": "",
        "adjudicator": "",
        "exclude_reason": "",
        "corpus_version": "",
        "split": None,
        "criteria_version": "",
    }


def _fp_row(entry: dict) -> dict:
    observed = _observed_at(entry.get("ts"))
    line = f"srcip={entry['ioc']} false-positive reason={entry['reason'] or 'not recorded'}"
    if observed:
        line += f" since={observed[:10]}"
    return _candidate_row(f"false_positive_kb:{entry['ioc']}", "false_positive_kb",
                          entry["ioc"], "", observed, line)


def _history_row(entry: dict) -> dict:
    observed = _observed_at(entry.get("ts"))
    text = (f"srcip={entry['srcip']} analyst verdict={entry['verdict'] or 'unknown'} "
            f"notes={entry['notes'] or 'none'}")
    return _candidate_row(f"investigation_history:{entry['srcip']}", "investigation_history",
                          entry["srcip"], entry.get("case_id") or "", observed, text)


def build_rows(fp_rows: list[dict], history_rows: list[dict],
               limit: int | None = None) -> list[dict]:
    """One row per indicator. A history entry replaces an FP entry for the same
    IP because it carries the analyst verdict and notes.
    """
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


def _tactics() -> tuple[str, ...]:
    from mcp_server.label.criteria import TACTICS
    return tuple(TACTICS)


def _code_criteria_version() -> str:
    from mcp_server.label.criteria import version
    return str(version())


def _leak_fields(alert: dict) -> list[str]:
    """Leakage fields present on a reviewer-supplied alert, as dotted paths."""
    found: list[str] = []
    for path in LEAK_PATHS:
        node: object = alert
        for key in path:
            node = node.get(key) if isinstance(node, dict) else None
            if node in (None, "", {}, []):
                break
        else:
            found.append(".".join(path))
    return found


def apply_reviews(candidates: list[dict], decisions: list[dict], corpus_version: str = "",
                  criteria_version: str = "") -> tuple[list[dict], list[dict], list[dict]]:
    """Merge reviewer decisions into frozen candidates.
    Returns ``(accepted, excluded, unreviewed)``, each sorted by id. Accepted rows
    carry exactly one of ``text``/``alert``; excluded and unreviewed rows are not
    calibration input. Every decision must name a reviewer; accepted rows must carry
    one of the 16 tactics and an explicit ``test``/``tuning`` split.
    """
    tactics = _tactics()
    by_id = {str(row.get("id") or ""): row for row in candidates}
    if len(by_id) != len(candidates) or "" in by_id:
        raise ValueError("candidate file has missing or duplicate ids")
    for row in candidates:
        if row.get("review_state") not in (None, "unreviewed"):
            raise ValueError(f"{row.get('id')}: candidate is already reviewed; "
                             "review the frozen candidate file, not an evaluation file")
        if str(row.get("source") or "") not in ANALYST_SOURCES:
            raise ValueError(f"{row.get('id')}: source {row.get('source')!r} is not an "
                             "analyst store; projected rows stay in their own corpus file")

    accepted: list[dict] = []
    excluded: list[dict] = []
    seen: set[str] = set()
    for decision in decisions:
        row_id = str(decision.get("id") or "")
        if row_id not in by_id:
            raise ValueError(f"review row {row_id!r} has no candidate")
        if row_id in seen:
            raise ValueError(f"duplicate review row for {row_id!r}")
        seen.add(row_id)
        row = dict(by_id[row_id])
        reviewer = str(decision.get("reviewer") or "").strip()
        if not reviewer:
            raise ValueError(f"{row_id}: reviewer is required")
        row["reviewer"] = reviewer
        row["adjudicator"] = str(decision.get("adjudicator") or "").strip()

        reason = str(decision.get("exclude_reason") or "").strip()
        if reason:
            row["review_state"] = "excluded"
            row["exclude_reason"] = reason
            row["ground_truth_tactic"] = None
            row["split"] = None
            excluded.append(row)
            continue

        tactic = decision.get("ground_truth_tactic")
        if tactic not in tactics:
            raise ValueError(f"{row_id}: ground_truth_tactic must be exactly one of the "
                             f"16 tactics, or set exclude_reason")
        split = str(decision.get("split") or "").strip()
        if split not in SPLITS:
            raise ValueError(f"{row_id}: split must be 'test' or 'tuning'")
        text, alert = decision.get("text"), decision.get("alert")
        if text and alert:
            raise ValueError(f"{row_id}: set at most one of 'text' or 'alert'")
        if alert is not None:
            if not isinstance(alert, dict) or not alert:
                raise ValueError(f"{row_id}: 'alert' must be a non-empty JSON object")
            leak = _leak_fields(alert)
            if leak:
                raise ValueError(f"{row_id}: alert carries leakage fields {leak}; strip "
                                 "rule.id, rule.mitre.* and agent.name, or supply the "
                                 "rule.description text instead")
            row.pop("text", None)
            row["alert"] = alert
            origin = "production_alert"
        elif text:
            row["text"] = str(text)
            origin = str(decision.get("text_origin") or "reviewer_text").strip()
        else:
            origin = str(decision.get("text_origin") or row.get("text_origin") or
                         "synthesized_notes").strip()
        if origin not in TEXT_ORIGINS:
            raise ValueError(f"{row_id}: text_origin must be one of {TEXT_ORIGINS}")
        row["text_origin"] = origin
        row["ground_truth_tactic"] = tactic
        row["review_state"] = "reviewed"
        row["exclude_reason"] = ""
        row["split"] = split
        row["corpus_version"] = corpus_version
        row["criteria_version"] = criteria_version
        accepted.append(row)

    unreviewed = [row for row in candidates if str(row.get("id") or "") not in seen]
    accepted.sort(key=lambda row: row["id"])
    excluded.sort(key=lambda row: row["id"])
    unreviewed.sort(key=lambda row: row["id"])
    return accepted, excluded, unreviewed


def build_manifest(dataset: str, evaluation_path: str, accepted: list[dict],
                   excluded: list[dict], unreviewed: list[dict],
                   exclusions_path: str, provenance: dict) -> dict:
    """Provenance sidecar for a frozen evaluation file. The ``sha256`` field hashes
    the evaluation file bytes, so re-running against the same rows reproduces it."""
    blob = Path(evaluation_path).read_bytes()
    by_tactic: dict[str, int] = {}
    split_counts: dict[str, int] = {}
    for row in accepted:
        by_tactic[row["ground_truth_tactic"]] = by_tactic.get(row["ground_truth_tactic"], 0) + 1
        split_counts[row["split"]] = split_counts.get(row["split"], 0) + 1
    manifest = {
        "dataset": dataset,
        "evaluation_file": str(evaluation_path),
        "evaluation_sha256": hashlib.sha256(blob).hexdigest(),
        "exclusions_file": str(exclusions_path) if exclusions_path else "",
        "rows": {"evaluation": len(accepted), "excluded": len(excluded),
                 "unreviewed": len(unreviewed)},
        "by_tactic": dict(sorted(by_tactic.items())),
        "split_counts": dict(sorted(split_counts.items())),
        "reviewers": sorted({row["reviewer"] for row in accepted if row.get("reviewer")}),
        "adjudicators": sorted({row["adjudicator"] for row in accepted if row.get("adjudicator")}),
        "corpus_version": provenance.get("corpus_version", ""),
        "criteria_version": provenance.get("criteria_version", ""),
        "backend": provenance.get("backend", ""),
        "model_path": provenance.get("model_path", ""),
        "model_sha256": provenance.get("model_sha256", ""),
        "confidence_floor": provenance.get("confidence_floor"),
        "temperature": provenance.get("temperature"),
        "host": provenance.get("host", ""),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    if exclusions_path and Path(exclusions_path).exists():
        manifest["exclusions_sha256"] = hashlib.sha256(
            Path(exclusions_path).read_bytes()).hexdigest()
    return manifest


def _provenance(args) -> dict:
    def env(name: str, fallback: str = "") -> str:
        return str(os.environ.get(name) or fallback).strip()

    def number(value, env_name: str):
        raw = value if value is not None else os.environ.get(env_name)
        if raw in (None, ""):
            return None
        return float(raw)

    return {
        "corpus_version": args.corpus_version,
        "criteria_version": args.criteria_version,
        "backend": args.backend or env("BLUETEAM_LAYA_BACKEND"),
        "model_path": args.model_path or env("BLUETEAM_LAYA_MODEL_PATH"),
        "model_sha256": args.model_sha256 or env("BLUETEAM_LAYA_MODEL_SHA256"),
        "confidence_floor": number(args.confidence_floor, "BLUETEAM_LAYA_CONFIDENCE_FLOOR"),
        "temperature": number(args.temperature, "BLUETEAM_LAYA_TEMPERATURE"),
        "host": args.host or socket.gethostname(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--false-positive-kb",
                        default=os.environ.get("BLUETEAM_FALSE_POSITIVE_KB", ""))
    parser.add_argument("--history", default=os.environ.get("BLUETEAM_INVESTIGATION_HISTORY", ""))
    parser.add_argument("--out", default="", help="default: stdout in export mode")
    parser.add_argument("--limit", type=int, default=None, help="optional cap; default: all")
    parser.add_argument("--reviews", default="",
                        help="reviewer decision JSONL; switches to review mode")
    parser.add_argument("--candidates", default="",
                        help="frozen candidate JSONL to review (required with --reviews)")
    parser.add_argument("--exclusions", default="",
                        help="default: <out>.exclusions.jsonl in review mode")
    parser.add_argument("--dataset", default="analyst-eval")
    parser.add_argument("--corpus-version", default="")
    parser.add_argument("--criteria-version", default="")
    parser.add_argument("--backend", default="")
    parser.add_argument("--model-path", default="")
    parser.add_argument("--model-sha256", default="")
    parser.add_argument("--confidence-floor", default=None)
    parser.add_argument("--temperature", default=None)
    parser.add_argument("--host", default="")
    parser.add_argument("--manifest", default="", help="write the provenance sidecar here")
    args = parser.parse_args()

    if args.reviews:
        if not args.candidates or not args.out:
            print("--reviews requires --candidates and --out", file=sys.stderr)
            return 2
        try:
            code_version = _code_criteria_version()
        except Exception as exc:
            print(f"cannot load the tactic vocabulary: {type(exc).__name__}: {exc}",
                  file=sys.stderr)
            return 2
        if args.criteria_version and args.criteria_version != code_version:
            print(f"criteria version mismatch: --criteria-version {args.criteria_version} "
                  f"but this host's code reports {code_version}", file=sys.stderr)
            return 2
        if args.manifest and not args.criteria_version:
            print("--manifest requires --criteria-version; a manifest without the vocabulary "
                  "binding is not auditable", file=sys.stderr)
            return 2
        try:
            candidates = [row for row in _iter_jsonl(args.candidates)]
            decisions = [row for row in _iter_jsonl(args.reviews)]
            accepted, excluded, unreviewed = apply_reviews(
                candidates, decisions, corpus_version=args.corpus_version,
                criteria_version=args.criteria_version)
        except ValueError as exc:
            print(f"review failed: {exc}", file=sys.stderr)
            return 2
        except Exception as exc:  # tactic vocabulary load
            print(f"cannot load the tactic vocabulary: {type(exc).__name__}: {exc}",
                  file=sys.stderr)
            return 2
        exclusions = args.exclusions or (args.out + ".exclusions.jsonl")
        write_rows(accepted, args.out)
        write_rows(excluded + unreviewed, exclusions)
        if args.manifest:
            manifest = build_manifest(args.dataset, args.out, accepted, excluded,
                                      unreviewed, exclusions, _provenance(args))
            Path(args.manifest).write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(f"wrote {args.manifest}", file=sys.stderr)
        if not args.criteria_version:
            print("[!] --criteria-version not given; the manifest will not bind the "
                  "evaluation to the deployed vocabulary.", file=sys.stderr)
        print(f"evaluation rows {len(accepted)} | excluded {len(excluded)} | "
              f"unreviewed {len(unreviewed)} -> {args.out}", file=sys.stderr)
        return 0

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
