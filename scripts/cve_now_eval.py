#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Evaluate technology identification and attack classification against labelled alerts.

Offline: reads the dataset, runs the pure identification functions, prints agreement.
No Indexer, no cve.now call, no network.

Usage:
    python scripts/cve_now_eval.py [--json]

Dataset: tests/fixtures/cve_now_eval_dataset.json. Its labels come from reading the
deployed ruleset, not from Wazuh telemetry; results describe agreement with a
ruleset-derived label set, not field accuracy against production.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from mcp_server.threat_intel.cve_now_assess import classify_attack, extract_alert_context
from mcp_server.threat_intel.cve_now_tech import identify_technologies

DATASET = pathlib.Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "cve_now_eval_dataset.json"


def evaluate(sample: dict) -> dict:
    alert = sample["alert"]
    expected = sample["expected"]
    identified = identify_technologies(alert)
    context = extract_alert_context(alert)
    attack = classify_attack(context)

    found = {entry["technology"]: entry for entry in identified["technologies"]}
    discoverable = {name for name, entry in found.items()
                    if entry["status"] in ("mapped", "identified_no_slug")}
    runtime_hints = {name for name, entry in found.items()
                     if entry["status"] == "runtime_hint_only"}
    wanted = {entry["technology"]: entry for entry in expected["technologies"]}

    hits = sorted(set(found) & set(wanted))
    missed = sorted(set(wanted) - set(found))
    extra = sorted(set(found) - set(wanted))
    target_wrong = [
        name for name in hits
        if found[name]["target"] is not wanted[name]["target"]
    ]
    role_wrong = [
        name for name in hits
        if found[name]["role"] != wanted[name]["role"]
    ]
    return {
        "id": sample["id"],
        "attack_expected": expected["attack_class"],
        "attack_actual": attack["attack_class"],
        "attack_ok": expected["attack_class"] == attack["attack_class"],
        "hits": hits,
        "missed": missed,
        "extra": extra,
        "runtime_hints": sorted(runtime_hints),
        "discoverable_extra": sorted(set(extra) & discoverable),
        "target_wrong": target_wrong,
        "role_wrong": role_wrong,
        "ambiguous": [entry["technology"] for entry in identified["ambiguous"]],
        "no_slug": [entry["technology"] for entry in identified["unmapped_mentions"]],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    data = json.loads(DATASET.read_text(encoding="utf-8"))
    rows = [evaluate(sample) for sample in data["samples"]]

    expected_tech = sum(len(row["hits"]) + len(row["missed"]) for row in rows)
    discoverable_extra = sum(len(row["discoverable_extra"]) for row in rows)
    runtime_hints = sum(len(row["runtime_hints"]) for row in rows)
    found_tech = sum(len(row["hits"]) + len(row["extra"]) for row in rows)
    hits = sum(len(row["hits"]) for row in rows)
    attack_ok = sum(1 for row in rows if row["attack_ok"])
    target_wrong = sum(len(row["target_wrong"]) for row in rows)
    role_wrong = sum(len(row["role_wrong"]) for row in rows)
    ambiguous = sum(len(row["ambiguous"]) for row in rows)
    no_slug = sum(len(row["no_slug"]) for row in rows)

    summary = {
        "samples": len(rows),
        "technology_precision": round(hits / found_tech, 3) if found_tech else None,
        "technology_recall": round(hits / expected_tech, 3) if expected_tech else None,
        "attack_class_accuracy": round(attack_ok / len(rows), 3),
        "target_disagreements": target_wrong,
        "role_disagreements": role_wrong,
        "ambiguous_entries": ambiguous,
        "identified_without_slug": no_slug,
        "discoverable_extra": discoverable_extra,
        "runtime_hint_entries": runtime_hints,
    }

    if args.json:
        print(json.dumps({"summary": summary, "rows": rows}, indent=2))
        return 0

    print(f"samples {summary['samples']} | tech P {summary['technology_precision']}"
          f" R {summary['technology_recall']} | attack acc {summary['attack_class_accuracy']}")
    print(f"target disagreements {target_wrong} | role disagreements {role_wrong}"
          f" | ambiguous {ambiguous} | no-slug {no_slug}")
    print(f"discoverable false positives {discoverable_extra}"
          f" | runtime hints (by design) {runtime_hints}")
    print()
    for row in rows:
        flags = []
        if not row["attack_ok"]:
            flags.append(f"attack {row['attack_expected']}!={row['attack_actual']}")
        if row["missed"]:
            flags.append(f"missed {row['missed']}")
        if row["extra"]:
            flags.append(f"extra {row['extra']}")
        if row["target_wrong"]:
            flags.append(f"target {row['target_wrong']}")
        if row["role_wrong"]:
            flags.append(f"role {row['role_wrong']}")
        print(f"{row['id']:<20} {'OK' if not flags else '; '.join(flags)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
