#!/usr/bin/env python3
"""Project ATT&CK-labelled corpora into labeler training rows.
Sources are local checkouts, never fetched here:
CAR          mitre-attack/car              analytics/*.yaml
Atomic       redcanaryco/atomic-red-team   atomics/T*/T*.yaml
attack_data  splunk/attack_data            datasets/attack_techniques/T*/*/*.yml
STIX         enterprise-attack.json        the technique->tactic oracle
Each row is `{"id", "alert", "ground_truth_tactic", provenance...}`, the same
schema `scripts/calibrate_labeler.py` reads. The alert is rendered by the tool's own
`build_state_text`, so a corpus row is byte-identical to the model input a live alert
would produce.

Two rules make the numbers mean something:
Leakage. `rule.mitre.*` states the answer, and `rule.id`/`agent.name` encode the
source, so the default alert carries only `rule.description`. `--with-rule-mitre`
emits the leaky variant; the accuracy delta between the two runs is how much of a
score is metadata rather than detection.

Splits. A technique lands in exactly one of train/val/test, so a model cannot be
scored on a technique it trained on. Multi-tactic techniques are dropped: the tool
is single-label, and a technique under two tactics has no honest single answer.

Run from the repo root:
  python3 scripts/build_label_corpus.py --stix /var/log/blue-team-mcp/enterprise-attack.json \\
      --car ~/src/car --atomic ~/src/atomic-red-team --attack-data ~/src/attack_data \\
      --out calibration/corpus.jsonl
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional
import yaml

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bake_mitre_tactics import attack_version, extract_tactics  # noqa: E402
from mcp_server.core.constants import MITRE_TACTIC_TO_CATEGORY  # noqa: E402
from mcp_server.label.labeler import MAX_FIELD_CHARS  # noqa: E402

TRAIN_PCT, VAL_PCT = 70, 85
# attack_data logs are multi-MB event dumps; only the first command line is read.
MAX_LOG_BYTES = 2 * 1024 * 1024
COMMAND_PATTERNS = (
    re.compile(r'"CommandLine"\s*:\s*"(?P<cmd>(?:[^"\\]|\\.){4,400})"'),
    re.compile(r'<Data Name="CommandLine">(?P<cmd>.{4,400}?)</Data>', re.DOTALL),
    re.compile(r'CommandLine=|command_line=[:=]\s*(?P<cmd>.{4,400})'),
)


def load_technique_tactics(stix_path: Path) -> tuple[dict[str, set[str]], str, set[str]]:
    """STIX -> {technique_id: {tactic name}}. Deprecated and revoked techniques are
    skipped, and a phase with no matching x-mitre-tactic is ignored: an unknown
    shortname must not be guessed into the vocabulary."""
    bundle = json.loads(stix_path.read_text(encoding="utf-8"))
    shortname_to_name = {t["shortname"]: t["name"] for t in extract_tactics(bundle)}
    techniques: dict[str, set[str]] = {}
    unknown_ids: set[str] = set()
    for obj in bundle.get("objects", []):
        if not isinstance(obj, dict) or obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        technique = ""
        for ref in obj.get("external_references") or []:
            if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack":
                technique = str(ref.get("external_id") or "")
                break
        if not technique:
            continue
        tactics = {shortname_to_name[phase["phase_name"]]
                   for phase in obj.get("kill_chain_phases") or []
                   if isinstance(phase, dict) and phase.get("phase_name") in shortname_to_name}
        if not tactics:
            unknown_ids.add(technique)
            continue
        techniques.setdefault(technique, set()).update(tactics)
    return techniques, attack_version(bundle), unknown_ids


def assign_split(technique: str) -> str:
    bucket = int(hashlib.sha256(technique.encode("utf-8")).hexdigest()[:8], 16) % 100
    if bucket < TRAIN_PCT:
        return "train"
    return "val" if bucket < VAL_PCT else "test"


def render_alert(text: str, technique: str, with_rule_mitre: bool) -> dict:
    rule: dict[str, Any] = {"description": text}
    if with_rule_mitre:
        rule["mitre"] = {"id": technique}
    return {"rule": rule}


def iter_car(root: Path, techniques: dict[str, set[str]]) -> Iterator[tuple[str, str, str, str]]:
    for path in sorted((root / "analytics").glob("*.yaml")):
        try:
            analytic = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (yaml.YAMLError, OSError):
            continue
        if not isinstance(analytic, dict):
            continue
        title = str(analytic.get("title") or "").strip()
        body = " ".join(str(analytic.get("description") or "").split())
        text = f"{title}. {body}".strip(". ")
        for entry in analytic.get("coverage") or []:
            if not isinstance(entry, dict):
                continue
            technique = str(entry.get("technique") or "")
            if technique in techniques:
                yield "car", str(analytic.get("id") or path.stem), technique, text


def iter_atomic(root: Path, techniques: dict[str, set[str]]) -> Iterator[tuple[str, str, str, str]]:
    for path in sorted((root / "atomics").glob("T*/T*.yaml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (yaml.YAMLError, OSError):
            continue
        if not isinstance(doc, dict):
            continue
        technique = str(doc.get("attack_technique") or "")
        if technique not in techniques:
            continue
        for index, test in enumerate(doc.get("atomic_tests") or []):
            if not isinstance(test, dict):
                continue
            name = str(test.get("name") or "").strip()
            description = " ".join(str(test.get("description") or "").split())
            command = ""
            executor = test.get("executor") or {}
            if isinstance(executor, dict):
                command = " ".join(str(executor.get("command") or "").split())
            text = " | ".join(part for part in (name, description, command) if part)
            if text:
                yield "atomic", f"{technique}#{index}", technique, text


def _first_command(log_path: Path) -> str:
    try:
        with log_path.open("rb") as handle:
            blob = handle.read(MAX_LOG_BYTES).decode("utf-8", errors="replace")
    except OSError:
        return ""
    for pattern in COMMAND_PATTERNS:
        match = pattern.search(blob)
        if match:
            return " ".join(match.group("cmd").split())[:MAX_FIELD_CHARS]
    return ""


def iter_attack_data(root: Path, techniques: dict[str, set[str]]) -> Iterator[tuple[str, str, str, str]]:
    base = root / "datasets" / "attack_techniques"
    for meta_path in sorted(base.glob("T*/*/*.yml")):
        try:
            meta = yaml.safe_load(meta_path.read_text(encoding="utf-8")) or {}
        except (yaml.YAMLError, OSError):
            continue
        if not isinstance(meta, dict):
            continue
        declared = meta.get("mitre_technique") or []
        if isinstance(declared, str):
            declared = [declared]
        technique = next((str(item) for item in declared if str(item) in techniques), "")
        if not technique:
            continue
        description = " ".join(str(meta.get("description") or "").split())
        command = ""
        for dataset in meta.get("datasets") or []:
            if not isinstance(dataset, dict):
                continue
            relative = str(dataset.get("path") or "").lstrip("/")
            if not relative:
                continue
            command = _first_command(root / relative)
            if command:
                break
        text = " | ".join(part for part in (description, f"cmd: {command}" if command else "") if part)
        if text:
            yield "attack_data", meta_path.parent.name, technique, text


def _digest(alert: dict) -> str:
    return hashlib.sha256(json.dumps(alert, sort_keys=True).encode("utf-8")).hexdigest()


def build(sources: dict[str, Optional[Path]], stix_path: Path, cap: int,
          with_rule_mitre: bool = False) -> tuple[list[dict], dict]:
    techniques, version, unknown_ids = load_technique_tactics(stix_path)
    single = {tech: next(iter(tactics)) for tech, tactics in techniques.items()
              if len(tactics) == 1 and next(iter(tactics)) in MITRE_TACTIC_TO_CATEGORY}
    report: dict[str, Any] = {
        "attack_version": version,
        "techniques_total": len(techniques),
        "techniques_single_tactic": len(single),
        "techniques_multi_tactic": sum(1 for t in techniques.values() if len(t) > 1),
        "techniques_unknown_tactic": len(unknown_ids),
        "cap_per_tactic": cap,
        "with_rule_mitre": with_rule_mitre,
    }
    iterators: list[tuple[str, Iterable]] = []
    if sources.get("car"):
        iterators.append(("car", iter_car(sources["car"], single)))
    if sources.get("atomic"):
        iterators.append(("atomic", iter_atomic(sources["atomic"], single)))
    if sources.get("attack_data"):
        iterators.append(("attack_data", iter_attack_data(sources["attack_data"], single)))

    seen: set[str] = set()
    per_tactic: dict[str, list[dict]] = defaultdict(list)
    source_counts: Counter = Counter()
    for _source, rows in iterators:
        for source_name, source_id, technique, text in rows:
            tactic = single.get(technique)
            if not tactic:
                continue
            alert = render_alert(text[:MAX_FIELD_CHARS], technique, with_rule_mitre)
            digest = _digest(alert)
            if digest in seen:
                report["deduped"] = report.get("deduped", 0) + 1
                continue
            seen.add(digest)
            source_counts[source_name] += 1
            per_tactic[tactic].append({
                "id": f"{source_name}:{source_id}#{source_counts[source_name]}",
                "alert": alert,
                "ground_truth_tactic": tactic,
                "source": source_name,
                "source_id": source_id,
                "technique": technique,
                "tactic": tactic,
                "split": assign_split(technique),
                "sha256": digest,
            })

    rows: list[dict] = []
    for tactic in sorted(per_tactic):
        candidates = sorted(per_tactic[tactic], key=lambda row: row["sha256"])
        if len(candidates) > cap:
            report.setdefault("capped", {})[tactic] = len(candidates) - cap
        rows.extend(candidates[:cap])
    rows.sort(key=lambda row: (row["split"], row["tactic"], row["sha256"]))

    report["rows"] = len(rows)
    report["rows_per_source"] = dict(sorted(source_counts.items()))
    report["rows_per_tactic"] = dict(sorted(Counter(r["tactic"] for r in rows).items()))
    report["rows_per_split"] = dict(sorted(Counter(r["split"] for r in rows).items()))
    report["techniques_used"] = len({r["technique"] for r in rows})
    report["tactics_missing"] = sorted(set(MITRE_TACTIC_TO_CATEGORY) - set(report["rows_per_tactic"]))
    return rows, report


def write_jsonl(rows: list[dict], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--stix", required=True, help="enterprise-attack.json (the label oracle)")
    parser.add_argument("--car", help="checkout of mitre-attack/car")
    parser.add_argument("--atomic", help="checkout of redcanaryco/atomic-red-team")
    parser.add_argument("--attack-data", help="checkout of splunk/attack_data")
    parser.add_argument("--out", default="calibration/corpus.jsonl")
    parser.add_argument("--report", help="JSON summary path (default: <out>.report.json)")
    parser.add_argument("--cap", type=int, default=400, help="max rows per tactic")
    parser.add_argument("--with-rule-mitre", action="store_true",
                        help="emit rule.mitre.* (leaks the label; use for the ablation run only)")
    args = parser.parse_args()
    if not (args.car or args.atomic or args.attack_data):
        parser.error("give at least one of --car, --atomic, --attack-data")
    if args.cap < 1:
        parser.error("--cap must be >= 1")
    stix = Path(args.stix).expanduser()
    if not stix.is_file():
        parser.error(f"STIX bundle not found: {stix}")

    sources = {name: Path(value).expanduser() for name, value in
               (("car", args.car), ("atomic", args.atomic), ("attack_data", args.attack_data))
               if value}
    for name, path in sources.items():
        if not path.is_dir():
            parser.error(f"--{name.replace('_', '-')} is not a directory: {path}")

    rows, report = build(sources, stix, args.cap, args.with_rule_mitre)
    out = Path(args.out)
    write_jsonl(rows, out)
    report_path = Path(args.report) if args.report else out.with_suffix(out.suffix + ".report.json")
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {out} ({report['rows']} rows) and {report_path}")
    if report["tactics_missing"]:
        print(f"no rows for: {', '.join(report['tactics_missing'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
