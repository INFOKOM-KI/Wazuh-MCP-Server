#!/usr/bin/env python3
"""Isolated routing candidates, measured on one dataset split.

Not a pytest module (no `test_` prefix). Production is untouched: each candidate patches
the alias map or the in-memory corpus for the duration of one run and restores it, so a
candidate that loses can be discarded without reverting anything.

    python3 tests/bench_routing_candidates.py --list
    python3 tests/bench_routing_candidates.py --split dev
    python3 tests/bench_routing_candidates.py --split dev --candidate B1_klaster_clusters
    python3 tests/bench_routing_candidates.py --split dev --candidate A_verb_forms --json /tmp/a.json

Every candidate is scored against the same frozen records and compared with the
`baseline` candidate in the same process, so a gain and its regressions come from one
measurement rather than two.

The `--split` default is `dev` on purpose. A candidate chosen on the held-out half is
not an experiment, and the harness will say so if you point it there.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import statistics
import sys
import time
from contextlib import contextmanager

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "bench")

from tests import routing_dataset as ds
from mcp_server.tools import register_all_tools
from mcp_server.tools import prompt_router as pr

# Experiment C text. Each line states what the tool does, taken from the tool source:
# the endpoint it calls or the docstring it already carries. Nothing here claims
# behaviour the code does not have.
THIN_DESCRIPTIONS = {
    "crowdsec_ip_reputation":
        "Look up one IP address reputation from CrowdSec for a single indicator.",
    "crowdsec_ip_reputation_bulk":
        "Look up several IP addresses against CrowdSec in one call.",
    "blueteam_wazuh_get_cluster_nodes":
        "List the Wazuh Manager cluster nodes and their status.",
    "blueteam_wazuh_get_groups":
        "List the rule groups defined on the Wazuh Manager.",
    "blueteam_wazuh_get_decoders":
        "List the decoders loaded on the Wazuh Manager.",
    "blueteam_wazuh_get_security_events":
        "Read Wazuh Manager security events with cursor pagination.",
    "blueteam_case_list":
        "List every investigation case, most recent first.",
    "blueteam_case_get":
        "Fetch one investigation case by id, with its IOCs and verdicts.",
}

CANDIDATES: dict[str, dict] = {
    "baseline": {},
    # Experiment B: the two expansions reported as wrong.
    # B0 restores the state production shipped before this experiment, so the three
    # states can be compared in one process rather than across sessions.
    "B0_klaster_cluster_nodes": {"aliases": {"klaster": "cluster nodes"}},
    "B1_klaster_clusters": {"aliases": {"klaster": "clusters"}},
    "B2_klaster_removed": {"drop_aliases": ["klaster"]},
    "B3_dokumen_document": {"aliases": {"dokumen": "document"}},
    "B4_dokumen_removed": {"drop_aliases": ["dokumen"]},
    "B5_klaster_and_dokumen": {"aliases": {"klaster": "clusters", "dokumen": "document"}},
    # B1 corrects the domain but keeps a plural, which matches "clusters" in the
    # campaign and attack-graph descriptions. The singular matches the name of the
    # alert-cluster family. Compared on dev only; B1's held-out effects were already
    # witnessed while verifying it, and looking at B6's would be choosing on held-out.
    "B6_klaster_cluster": {"aliases": {"klaster": "cluster"}},
    # B7 keeps the plural that separates alert clusters from the Manager tool and adds
    # the singular that the alert-cluster family carries in its own names. The risk is
    # the singular also matching "blueteam wazuh get cluster nodes".
    "B7_klaster_clusters_cluster": {"aliases": {"klaster": "clusters cluster"}},
    # Experiment A: verb forms missing from the alias map. Kept here to show what it
    # does on this split, which is nothing, because no development record uses them.
    "A_verb_forms": {"aliases": {
        "bandingkan": "compare",
        "petakan": "map geo",
        "eksploit": "exploit poc",
        "mengeksploitasi": "exploited exploit",
        "cepat": "velocity",
    }},
    # Experiment C: descriptions for the tools whose corpus document is name plus
    # parameter field names only.
    "C_thin_descriptions": {"corpus": THIN_DESCRIPTIONS},
    # Not one of the three authorized experiments. A diagnostic aimed at the largest
    # signal in the development failures: 'ip' survives tokenisation as a two-letter
    # term, is absent from _QUERY_STOPWORDS, and appears in 63 of 160 corpus documents.
    "D_ip_as_stopword": {"stopwords": ["ip"]},
}


@contextmanager
def _applied(name: str):
    """A fresh router with the candidate applied, restored on exit."""
    candidate = CANDIDATES[name]
    saved = dict(pr._ID_EN_ALIASES)
    saved_stop = pr._QUERY_STOPWORDS
    try:
        # A frozenset, so it is rebound rather than mutated.
        pr._QUERY_STOPWORDS = saved_stop | set(candidate.get("stopwords", ()))
        for key in candidate.get("drop_aliases", ()):
            pr._ID_EN_ALIASES.pop(key, None)
        pr._ID_EN_ALIASES.update(candidate.get("aliases", {}))
        router = pr.PromptRouter()
        additions = candidate.get("corpus", {})
        if additions:
            unknown = sorted(set(additions) - {t["name"] for t in router.tool_corpus})
            assert not unknown, f"corpus additions name unknown tools: {unknown}"
            for tool in router.tool_corpus:
                if tool["name"] in additions:
                    tool["text"] = f"{tool['text']} {additions[tool['name']]}"
            # The index has to be rebuilt from the edited documents, or the addition is
            # never scored.
            router.bm25 = pr._MiniBM25([t["text"] for t in router.tool_corpus])
        yield router
    finally:
        pr._ID_EN_ALIASES.clear()
        pr._ID_EN_ALIASES.update(saved)
        pr._QUERY_STOPWORDS = saved_stop


def _run(name: str, records: list[dict]) -> list[dict]:
    outcomes = []
    with _applied(name) as router:
        for record in records:
            start = time.perf_counter()
            ranked = [row["tool"] for row in router.route(record["prompt"], top_k=3)]
            latency = (time.perf_counter() - start) * 1000
            acceptable = set(record["acceptable"])
            outcomes.append({
                "id": record["id"], "intent": record["intent"], "lang": record["lang"],
                "ranked": ranked, "latency": latency,
                "top1": bool(ranked) and ranked[0] in acceptable,
                "hit": any(tool in acceptable for tool in ranked),
            })
    return outcomes


def _score(rows: list[dict]) -> dict:
    return {
        "n": len(rows),
        "top1": sum(r["top1"] for r in rows),
        "hit": sum(r["hit"] for r in rows),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Isolated routing candidates.")
    parser.add_argument("--dataset", choices=ds.VERSIONS, default=ds.CURRENT)
    parser.add_argument("--split", choices=("all", "dev", "held"), default="dev")
    parser.add_argument("--candidate", action="append", default=[],
                        help="Repeatable. Defaults to every candidate.")
    parser.add_argument("--json", default="", help="Write this run's results here.")
    parser.add_argument("--list", action="store_true", help="Print candidate names and exit.")
    args = parser.parse_args()

    if args.list:
        for name in CANDIDATES:
            print(name)
        return 0

    if args.split != "dev":
        print(f"warning: --split {args.split}. Candidates are meant to be chosen on "
              f"development records; a held-out score cannot do that.", file=sys.stderr)

    doc = ds.load(args.dataset)
    records = ds.select(doc, args.split)
    names = args.candidate or list(CANDIDATES)

    register_all_tools()
    baseline = _run("baseline", records)
    base = _score(baseline)
    base_by_id = {r["id"]: r for r in baseline}

    print(f"dataset           : {doc['version']}  split: {args.split}  records: {len(records)}")
    print(f"baseline          : top-1 {base['top1']}/{base['n']}  top-3 {base['hit']}/{base['n']}")
    print()
    header = (f"{'candidate':34} {'top-1':>11} {'top-3':>11} {'delta3':>7} "
              f"{'gained':>7} {'lost':>5} {'median ms':>10}")
    print(header)
    print("-" * len(header))

    results = {}
    for name in names:
        if name not in CANDIDATES:
            print(f"unknown candidate {name!r}", file=sys.stderr)
            return 2
        outcomes = baseline if name == "baseline" else _run(name, records)
        score = _score(outcomes)
        by_id = {r["id"]: r for r in outcomes}
        gained = [r["id"] for r in outcomes
                  if r["hit"] and not base_by_id[r["id"]]["hit"]]
        lost = [r["id"] for r in outcomes
                if not r["hit"] and base_by_id[r["id"]]["hit"]]
        top1_gained = [r["id"] for r in outcomes
                       if r["top1"] and not base_by_id[r["id"]]["top1"]]
        top1_lost = [r["id"] for r in outcomes
                     if not r["top1"] and base_by_id[r["id"]]["top1"]]
        median = statistics.median(r["latency"] for r in outcomes)
        print(f"{name:34} {score['top1']:>4}/{score['n']:<4} {score['hit']:>4}/{score['n']:<4} "
              f"{score['hit'] - base['hit']:>+7} {len(gained):>7} {len(lost):>5} {median:>10.2f}")
        results[name] = {"score": score, "gained": gained, "lost": lost,
                         "top1_gained": top1_gained, "top1_lost": top1_lost,
                         "outcomes": outcomes}

    for name, payload in results.items():
        if name == "baseline":
            continue
        if payload["gained"] or payload["lost"]:
            print()
            print(f"{name}, top-3 movement:")
            for rid in payload["gained"]:
                row = [r for r in payload["outcomes"] if r["id"] == rid][0]
                print(f"  gained {rid:14} -> {','.join(row['ranked'])[:60]}")
            for rid in payload["lost"]:
                row = [r for r in payload["outcomes"] if r["id"] == rid][0]
                print(f"  lost   {rid:14} -> {','.join(row['ranked'])[:60]}")
        if payload["top1_gained"] or payload["top1_lost"]:
            print()
            print(f"{name}, top-1 movement (a record that already hit top-3 may move here):")
            for rid in payload["top1_gained"]:
                row = [r for r in payload["outcomes"] if r["id"] == rid][0]
                print(f"  gained {rid:14} -> {','.join(row['ranked'])[:60]}")
            for rid in payload["top1_lost"]:
                row = [r for r in payload["outcomes"] if r["id"] == rid][0]
                print(f"  lost   {rid:14} -> {','.join(row['ranked'])[:60]}")

    # Per-intent movement, so a candidate that trades one area for another is visible.
    print()
    print("per-intent top-3 movement against baseline (non-zero rows only):")
    moved = False
    for name, payload in results.items():
        if name == "baseline":
            continue
        deltas = []
        for area in sorted({r["intent"] for r in records}):
            before = _score([r for r in baseline if r["intent"] == area])["hit"]
            after = _score([r for r in payload["outcomes"] if r["intent"] == area])["hit"]
            if before != after:
                deltas.append(f"{area} {before}->{after}")
        if deltas:
            moved = True
            print(f"  {name:34} {', '.join(deltas)}")
    if not moved:
        print("  none")

    if args.json:
        pathlib.Path(args.json).write_text(json.dumps(
            {"dataset": doc["version"], "split": args.split,
             "results": {k: {"score": v["score"], "gained": v["gained"],
                             "lost": v["lost"], "top1_gained": v["top1_gained"],
                             "top1_lost": v["top1_lost"]}
                         for k, v in results.items()}},
            indent=2) + "\n")
        print(f"written           : {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
