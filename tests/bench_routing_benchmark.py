#!/usr/bin/env python3
"""Labelled routing benchmark over tests/data/routing_benchmark_v1.json.

Not a pytest module (no `test_` prefix). It runs the production router unchanged and
scores it against hand labels, so a router change can be measured before it ships:

    python3 tests/bench_routing_benchmark.py --stats
    python3 tests/bench_routing_benchmark.py --split held --quiet
    python3 tests/bench_routing_benchmark.py --split held --json /tmp/held.json
    python3 tests/bench_routing_benchmark.py --split held --compare /tmp/held.json

Every dataset figure printed here comes from tests/routing_dataset.py, which the
dataset tests also read, so a number in a report cannot disagree with the file it came
from.

The 22-prompt suite in tests/bench_rerank_routing.py stays the fast regression guard
and is not replaced. This one is larger, balanced across the 17 discovery areas, and
split into development and held-out halves, which is what the small suite cannot be.

Read the split you are reporting. The development half exists to be tuned against. A
number from it is not evidence about unseen prompts, and tuning against the held-out
half repeatedly makes it a development set wearing a different name.

A cell with fewer than the configured held-out threshold records is marked [low-n]. Do
not read those numbers as estimates of that area's routing quality; the sample cannot
support one.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "bench")

from tests import routing_dataset as ds

from mcp_server.tools import register_all_tools
from mcp_server.tools.prompt_router import _get_router


def _pct(values: list[float], q: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(q * (len(ordered) - 1))))]


def main() -> int:
    parser = argparse.ArgumentParser(description="Labelled tool-routing benchmark.")
    parser.add_argument("--split", choices=("all", "dev", "held"), default="all")
    parser.add_argument("--dataset", choices=ds.VERSIONS, default=ds.CURRENT,
                        help="Dataset version. v1 is immutable and kept as the historical "
                             "reference for its own results.")
    parser.add_argument("--top-k", type=int, default=3,
                        help="Ranking depth for the top-k metric. The router is asked for this many.")
    parser.add_argument("--stats", action="store_true",
                        help="Print the dataset tables and exit. No router, no model, no network.")
    parser.add_argument("--json", default="", help="Write this run's results here.")
    parser.add_argument("--compare", default="",
                        help="A previous --json file to diff per-prompt outcomes against.")
    parser.add_argument("--quiet", action="store_true",
                        help="Skip the per-prompt table. The summary and JSON are unaffected.")
    args = parser.parse_args()

    doc = ds.load(args.dataset)
    info = ds.stats(doc, args.dataset)
    if args.stats:
        print(ds.format_stats(info))
        return 0

    threshold = info["low_confidence_threshold"]

    records = ds.select(doc, args.split)
    if not records:
        print(f"no records for split {args.split}", file=sys.stderr)
        return 2

    register_all_tools()
    router = _get_router()

    latencies: list[float] = []
    outcomes: list[dict] = []
    for record in records:
        start = time.perf_counter()
        ranked = router.route(record["prompt"], top_k=args.top_k)
        latencies.append((time.perf_counter() - start) * 1000)
        got = [r["tool"] for r in ranked]
        acceptable = set(record["acceptable"])
        outcomes.append({
            "id": record["id"],
            "pair": record["pair"],
            "lang": record["lang"],
            "intent": record["intent"],
            "type": record["type"],
            "split": record["split"],
            "prompt": record["prompt"],
            "acceptable": sorted(acceptable),
            "ranked": got,
            "top1": bool(got) and got[0] in acceptable,
            "hit": any(tool in acceptable for tool in got[:args.top_k]),
        })

    def _score(rows: list[dict]) -> dict:
        return {
            "n": len(rows),
            "top1": sum(row["top1"] for row in rows),
            "hit": sum(row["hit"] for row in rows),
            "top1_rate": round(sum(row["top1"] for row in rows) / len(rows), 4) if rows else 0.0,
            "hit_rate": round(sum(row["hit"] for row in rows) / len(rows), 4) if rows else 0.0,
        }

    summary = {"overall": _score(outcomes)}
    for lang in sorted({row["lang"] for row in records}):
        summary[f"lang:{lang}"] = _score([row for row in outcomes if row["lang"] == lang])

    by_intent = {}
    for area in sorted({row["intent"] for row in records}):
        rows = [row for row in outcomes if row["intent"] == area]
        cell = _score(rows)
        # Read both from the dataset stats rather than recomputing: one derivation of
        # the flag and the held-out count, so a report cannot disagree with the file.
        cell["held_out_records"] = info["by_intent"][area]["held"]
        cell["low_confidence"] = info["by_intent"][area]["low_confidence"]
        by_intent[area] = cell

    pairs = ds.pair_outcomes(outcomes)

    print(f"dataset           : {info['file']} {info['version']} "
          f"(created {info['created']})")
    print(f"digest            : {info['digest']}")
    print(f"contract          : {info['records']} records, {info['pairs']} pairs, "
          f"split {info['splits']}")
    print(f"language/split    : {info['languages_by_split']}")
    print(f"duplicate prompts : {info['duplicate_prompts']}   "
          f"pair split leaks: {info['pair_leaks'] or 'none'}")
    print(f"split evaluated   : {args.split}  ({len(records)} records)")
    print(f"low-conf threshold: fewer than {threshold} held-out records (dataset value)")
    print(f"tools indexed     : {len(router.tool_corpus)}")
    print()
    print(f"{'scope':22} {'n':>4} {'top-1':>11} {'top-3':>11}")
    print("-" * 52)
    for key, cell in summary.items():
        print(f"{key:22} {cell['n']:>4} {cell['top1']:>4}/{cell['n']:<4} "
              f"{cell['hit']:>4}/{cell['n']:<4}")
    print()
    print(f"{'area':32} {'n':>4} {'top-1':>8} {'top-3':>8} {'held':>5}")
    print("-" * 62)
    for area, cell in by_intent.items():
        flag = "  [low-n]" if cell["low_confidence"] else ""
        print(f"{area:32} {cell['n']:>4} {cell['top1_rate'] * 100:>7.0f}% "
              f"{cell['hit_rate'] * 100:>7.0f}% {cell['held_out_records']:>5}{flag}")
    print()
    print(f"latency BM25      : median {statistics.median(latencies):.0f} ms, "
          f"p95 {_pct(latencies, 0.95):.0f} ms (per prompt, router only, no rerank)")
    print()
    print(f"bilingual pairs   : {pairs['pairs_compared']} pairs hold both languages")
    print(f"  both correct    : {len(pairs['both'])} {pairs['both'] or ''}")
    print(f"  english only    : {len(pairs['en_only'])} {pairs['en_only'] or ''}")
    print(f"  indonesian only : {len(pairs['id_only'])} {pairs['id_only'] or ''}")
    print(f"  neither         : {len(pairs['neither'])} {pairs['neither'] or ''}")

    if not args.quiet:
        print()
        print(f"{'id':14} {'@1':>3} {'@3':>3}  expected / got")
        print("-" * 78)
        for row in outcomes:
            mark = "HIT" if row["hit"] else "-"
            first = "1" if row["top1"] else (" " if not row["hit"] else "*")
            print(f"{row['id']:14} {first:>3} {mark:>3}  "
                  f"{','.join(row['acceptable'])[:30]:30} -> {','.join(row['ranked'])[:28]}")

    if args.compare:
        previous = json.loads(pathlib.Path(args.compare).read_text())
        before = {row["id"]: row for row in previous["outcomes"]}
        gained = [row["id"] for row in outcomes
                  if row["hit"] and not before.get(row["id"], {}).get("hit")]
        lost = [row["id"] for row in outcomes
                if not row["hit"] and before.get(row["id"], {}).get("hit")]
        print()
        print(f"compared against  : {args.compare} (split {previous.get('split')})")
        print(f"gained top-3      : {len(gained)} {gained or 'none'}")
        print(f"lost top-3        : {len(lost)} {lost or 'none'}")
        print("A gain that only moves areas already scoring well still hides the losses; "
              "read the two lists, not the delta.")

    if args.json:
        payload = {
            "dataset": info["file"],
            "dataset_version": info["version"],
            "dataset_digest": info["digest"],
            "split": args.split,
            "top_k": args.top_k,
            "low_confidence_threshold": threshold,
            "dataset_stats": info,
            "tools_indexed": len(router.tool_corpus),
            "summary": summary,
            "by_intent": by_intent,
            "pairs": pairs,
            "latency_ms": {"median": round(statistics.median(latencies), 2),
                           "p95": round(_pct(latencies, 0.95), 2)},
            "outcomes": outcomes,
        }
        pathlib.Path(args.json).write_text(json.dumps(payload, indent=2) + "\n")
        print(f"written           : {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
