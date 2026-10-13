#!/usr/bin/env python3
"""Single source of truth for routing-benchmark dataset statistics.

The benchmark harness and the dataset tests both read this module, so a number in a
report cannot disagree with the file it came from. The first version of the Step 5
report was assembled by hand and carried a per-intent table taken before a split
rebalance plus a miscounted low-confidence total; generating both removes that class of
error rather than asking a reader to spot it.

Two versions are on disk. v1 is immutable and stays as the historical reference for its
own results. v2 differs from it only in four Indonesian prompt wordings, and every
reader can check that with `dataset_digest` and the change log in the file.

Imports nothing outside the standard library, so it is safe to use from a test, from the
harness, or from a one-off audit.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
from collections import Counter

DATASET_DIR = pathlib.Path(__file__).resolve().parent / "data"
DATASET_PATHS = {
    "v1": DATASET_DIR / "routing_benchmark_v1.json",
    "v2": DATASET_DIR / "routing_benchmark_v2.json",
}
VERSIONS = tuple(DATASET_PATHS)
CURRENT = "v2"

# The 17 areas of the discovery map in resource/your_prompthings. A new intent has to be
# added here deliberately, because the report is grouped by area.
AREAS = (
    "overview_timeline", "ip_triage", "threat_intel", "correlation_campaigns",
    "clustering_labeling", "forecasting", "cve_vulnerability", "email_breach_domain",
    "geo_host_forensics", "wazuh_manager_config", "investigation_case",
    "documents_evidence", "reporting_intelligence", "detection_engineering_yara",
    "detection_engineering_sigma", "local_case_rag", "resources",
)
RECORD_TYPES = ("operational", "paraphrase", "edge_case")
LANGS = ("en", "id")
SPLITS = ("dev", "held")


def path_for(version: str = CURRENT) -> pathlib.Path:
    if version not in DATASET_PATHS:
        raise KeyError(f"unknown dataset version {version!r}; have {VERSIONS}")
    return DATASET_PATHS[version]


def load(version: str = CURRENT) -> dict:
    """The parsed dataset document for `version`."""
    return json.loads(path_for(version).read_text(encoding="utf-8"))


def select(doc: dict, split: str) -> list[dict]:
    """Records for `dev`, `held`, or every record for `all`."""
    if split == "all":
        return list(doc["records"])
    return [record for record in doc["records"] if record["split"] == split]


def dataset_digest(doc: dict) -> str:
    """sha256 over the records alone, canonicalised.

    Covers ids, pairs, languages, intents, types, splits, prompts and labels, and
    nothing else, so reformatting a file's metadata does not move it while any record
    change does. Two versions can be compared without reading either one.
    """
    payload = json.dumps(doc["records"], sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode()).hexdigest()


def duplicate_prompts(records: list[dict]) -> int:
    """Repeated prompts after whitespace and case folding, across the whole file.

    A prompt repeated in both splits is how a held-out score stops meaning anything, so
    the count is reported rather than assumed to be zero.
    """
    seen = Counter(" ".join(record["prompt"].lower().split()) for record in records)
    return sum(count - 1 for count in seen.values() if count > 1)


def pair_leaks(records: list[dict]) -> list[str]:
    """Pair ids that appear in more than one split."""
    seen: dict[str, set[str]] = {}
    for record in records:
        seen.setdefault(record["pair"], set()).add(record["split"])
    return sorted(pair for pair, splits in seen.items() if len(splits) > 1)


def stats(doc: dict, version: str = "") -> dict:
    """Every dataset statistic a report needs, computed once.

    `low_confidence_areas` is derived here from `low_confidence_threshold` and the
    held-out counts, so a flag and the number behind it cannot drift apart.
    """
    records = doc["records"]
    threshold = doc["low_confidence_threshold"]

    by_intent: dict[str, dict] = {}
    for area in sorted({record["intent"] for record in records}):
        rows = [record for record in records if record["intent"] == area]
        dev = sum(1 for record in rows if record["split"] == "dev")
        held = len(rows) - dev
        by_intent[area] = {
            "records": len(rows),
            "dev": dev,
            "held": held,
            # Only the held-out half decides confidence; a large development half
            # cannot make a two-record held-out cell reportable.
            "low_confidence": held < threshold,
        }

    return {
        "version": doc["version"],
        "file": path_for(version or doc["version"]).name if not version
        else path_for(version).name,
        "created": doc["created"],
        "derived_from": doc.get("derived_from", {}),
        "digest": dataset_digest(doc),
        "records": len(records),
        "pairs": len({record["pair"] for record in records}),
        "splits": dict(Counter(record["split"] for record in records)),
        "languages": dict(Counter(record["lang"] for record in records)),
        "languages_by_split": {
            split: dict(Counter(record["lang"] for record in records
                                if record["split"] == split))
            for split in SPLITS
        },
        "types": dict(Counter(record["type"] for record in records)),
        # String keys, because JSON turns an int key into a string on the way out and
        # the harness writes this dict straight to disk. Two spellings of the same table
        # is how a printed report and a saved run end up disagreeing.
        "labels_per_record": {str(count): total for count, total in sorted(Counter(
            len(record["acceptable"]) for record in records).items())},
        "duplicate_prompts": duplicate_prompts(records),
        "pair_leaks": pair_leaks(records),
        "low_confidence_threshold": threshold,
        "low_confidence_areas": sorted(
            area for area, cell in by_intent.items() if cell["low_confidence"]),
        "by_intent": by_intent,
    }


def pair_outcomes(outcomes: list[dict]) -> dict:
    """Per-pair top-k outcome split by language, over pairs holding both languages.

    Two totals can say English routed better without saying whether the same request
    succeeded in one language and failed in the other, which is the question a
    bilingual dataset exists to answer.
    """
    by_pair: dict[str, dict[str, bool]] = {}
    for row in outcomes:
        by_pair.setdefault(row["pair"], {})[row["lang"]] = row["hit"]

    complete = {pair: langs for pair, langs in by_pair.items()
                if set(langs) == set(LANGS)}
    return {
        "pairs_compared": len(complete),
        "both": sorted(pair for pair, langs in complete.items() if all(langs.values())),
        "en_only": sorted(pair for pair, langs in complete.items()
                          if langs["en"] and not langs["id"]),
        "id_only": sorted(pair for pair, langs in complete.items()
                          if langs["id"] and not langs["en"]),
        "neither": sorted(pair for pair, langs in complete.items()
                          if not any(langs.values())),
    }


def format_stats(info: dict) -> str:
    """The canonical dataset tables, as printed by `bench_routing_benchmark --stats`."""
    lines = [
        f"dataset           : {info['file']} {info['version']} (created {info['created']})",
        f"digest            : {info['digest']}",
    ]
    if info["derived_from"]:
        parent = info["derived_from"]
        lines.append(f"derived from      : {parent.get('file')} "
                     f"{parent.get('version')} sha256 {parent.get('file_sha256', '')[:16]}...")
    lines += [
        f"records           : {info['records']}  pairs: {info['pairs']}  "
        f"split: {info['splits']}",
        f"languages         : {info['languages']}",
        f"languages/split   : {info['languages_by_split']}",
        f"record types      : {info['types']}",
        f"acceptable labels : {info['labels_per_record']}",
        f"duplicate prompts : {info['duplicate_prompts']}",
        f"pair split leaks  : {info['pair_leaks'] or 'none'}",
        f"low-conf threshold: fewer than {info['low_confidence_threshold']} held-out records",
        "",
        f"{'area':32} {'rec':>4} {'dev':>5} {'held':>5}  confidence",
        "-" * 66,
    ]
    for area, cell in info["by_intent"].items():
        note = "low-n" if cell["low_confidence"] else "ok"
        lines.append(f"{area:32} {cell['records']:>4} {cell['dev']:>5} "
                     f"{cell['held']:>5}  {note}")
    total = sum(cell["records"] for cell in info["by_intent"].values())
    dev = sum(cell["dev"] for cell in info["by_intent"].values())
    held = sum(cell["held"] for cell in info["by_intent"].values())
    lines.append("-" * 66)
    lines.append(f"{'TOTAL':32} {total:>4} {dev:>5} {held:>5}")
    lines.append("")
    lines.append(f"low-confidence areas: {len(info['low_confidence_areas'])} of "
                 f"{len(info['by_intent'])} (held-out records below "
                 f"{info['low_confidence_threshold']})")
    lines.append(f"  {info['low_confidence_areas']}")
    return "\n".join(lines)
