#!/usr/bin/env python3
"""Does core/term_sim.py route tools better than the BM25 router it would replace?

Not a pytest module (no `test_` prefix). Run with no arguments:

    python3 tests/bench_term_sim_routing.py

The 22 labelled prompts, the acceptable-tool sets and the `_hit` rule are imported
from tests/bench_rerank_routing.py rather than copied, so the two benchmarks cannot
drift apart.

Arms, all scored on the same tool corpus that `PromptRouter` indexes:

    A  BM25 + expanded query      the production baseline
    B  term_sim + expanded query  primary candidate, corpus tf/df
    C  term_sim + expanded query  no tf/df, so every token takes the OOV heuristic
    D  term_sim + raw query       isolates the Indonesian alias map from the scorer
    E  BM25 + raw query           isolates the alias map from BM25

A and E exist so a gap between B and A can be attributed: `_MiniBM25.score` runs
`_expand_query` internally, so BM25 never sees the raw prompt in production. Reading
B against A without E would credit the scorer for work the alias map did.

Two differences make the comparison inexact, and both are reported rather than
adjusted away. term_sim returns a coverage score in [0, 1], where any document
carrying all the query weight ties at the ceiling; BM25 returns an unbounded score
with length normalisation. And term_sim holds no index: it re-tokenises all 160
documents on every call, while BM25 tokenises once at construction.
"""
from __future__ import annotations
import argparse
import json
import os
import statistics
import sys
import time
from collections import Counter

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.dirname(_HERE))
os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "bench")

from bench_rerank_routing import PROMPTS, _hit
from mcp_server.core import term_sim
from mcp_server.tools import register_all_tools
from mcp_server.tools import prompt_router as pr


def _tf_df(documents: list[str]) -> tuple[Counter, Counter]:
    tokenised = [term_sim.tokenize(doc) for doc in documents]
    tf = Counter(tok for doc in tokenised for tok in doc)
    df = Counter(tok for doc in tokenised for tok in set(doc))
    return tf, df


def _term_sim_rank(documents: list[str], query: str, tf, df, top_k: int):
    scores = term_sim.score(query, documents, tf=tf, df=df)
    order = sorted(range(len(scores)), key=lambda i: -scores[i])
    return scores, order[:top_k]


def _tie_stats(scores: list[float]) -> tuple[int, int]:
    """(documents tied at the top score, documents sharing the third-place score)."""
    top = max(scores)
    tied_top = sum(1 for s in scores if s == top)
    third = sorted(scores, reverse=True)[2] if len(scores) >= 3 else 0.0
    return tied_top, sum(1 for s in scores if s == third)


def _pct(values: list[float], q: float) -> float:
    ordered = sorted(values)
    idx = min(len(ordered) - 1, int(round(q * (len(ordered) - 1))))
    return ordered[idx]


def main() -> int:
    parser = argparse.ArgumentParser(description="BM25 router vs core/term_sim.py on 22 prompts.")
    parser.add_argument("--json", default="", help="Write per-prompt results as JSON here.")
    args = parser.parse_args()

    register_all_tools()
    router = pr._get_router()
    corpus = [t["text"] for t in router.tool_corpus]
    names = [t["name"] for t in router.tool_corpus]
    tf, df = _tf_df(corpus)

    real_expand = pr._expand_query

    def _bm25_rank(query: str, top_k: int):
        return [names[i] for i, _ in router.bm25.score(query)[:top_k]]

    rows = []
    latencies = {key: [] for key in ("A", "B", "C", "D", "E")}

    for pid, lang, prompt, acceptable in PROMPTS:
        row = {"id": pid, "lang": lang, "prompt": prompt}

        start = time.perf_counter()
        row["A"] = _bm25_rank(prompt, 3)
        latencies["A"].append(time.perf_counter() - start)

        pr._expand_query = lambda text: text
        start = time.perf_counter()
        row["E"] = _bm25_rank(prompt, 3)
        latencies["E"].append(time.perf_counter() - start)
        pr._expand_query = real_expand

        for key, query, tables in (("B", router.expanded(prompt), (tf, df)),
                                   ("C", router.expanded(prompt), (None, None)),
                                   ("D", prompt, (tf, df))):
            start = time.perf_counter()
            scores, order = _term_sim_rank(corpus, query, tables[0], tables[1], 3)
            latencies[key].append(time.perf_counter() - start)
            row[key] = [names[i] for i in order]
            if key == "B":
                row["ties_top"], row["ties_third"] = _tie_stats(scores)

        for key in ("A", "B", "C", "D", "E"):
            row[f"{key}_hit"] = _hit([{"tool": t} for t in row[key]], acceptable, 3)
            row[f"{key}_top1"] = row[key][0] in acceptable
        rows.append(row)

    labels = {"A": "BM25+exp", "B": "ts+exp+tfdf", "C": "ts+exp", "D": "ts+raw+tfdf",
              "E": "BM25+raw"}
    print(f"tools indexed : {len(corpus)}")
    print(f"prompts       : {len(PROMPTS)} (12 report + 10 Indonesian ad-hoc)")
    print()
    header = " ".join([f"{'prompt':12}", f"{'lang':4}"] + [f"{labels[k]:>12}" for k in ("A", "B", "C", "D", "E")])
    print(header)
    print("-" * len(header))
    for row in rows:
        cells = " ".join(f"{'HIT' if row[f'{k}_hit'] else '-':>12}" for k in ("A", "B", "C", "D", "E"))
        print(f"{row['id']:12} {row['lang']:4} {cells}")

    print()
    print(f"{'arm':16} {'ALL@3':>8} {'ALL@1':>8} {'en@3':>7} {'id@3':>7} "
          f"{'median ms':>10} {'p95 ms':>8}")
    print("-" * 72)
    summary = {}
    for key in ("A", "B", "C", "D", "E"):
        hits3 = sum(row[f"{key}_hit"] for row in rows)
        hits1 = sum(row[f"{key}_top1"] for row in rows)
        en = [row for row in rows if row["lang"] == "en"]
        idn = [row for row in rows if row["lang"] == "id"]
        ms = [t * 1000 for t in latencies[key]]
        summary[key] = {"top3": hits3, "top1": hits1,
                        "en3": sum(r[f"{key}_hit"] for r in en),
                        "id3": sum(r[f"{key}_hit"] for r in idn),
                        "median_ms": round(statistics.median(ms), 2),
                        "p95_ms": round(_pct(ms, 0.95), 2)}
        print(f"{labels[key]:16} {hits3:>6}/22 {hits1:>6}/22 {summary[key]['en3']:>4}/6 "
              f"{summary[key]['id3']:>5}/16 {summary[key]['median_ms']:>10.2f} "
              f"{summary[key]['p95_ms']:>8.2f}")

    print()
    print("per-prompt movement, arm B against the production baseline A:")
    improved = [r["id"] for r in rows if r["B_hit"] and not r["A_hit"]]
    regressed = [r["id"] for r in rows if r["A_hit"] and not r["B_hit"]]
    print(f"  improved  ({len(improved)}): {', '.join(improved) or 'none'}")
    print(f"  regressed ({len(regressed)}): {', '.join(regressed) or 'none'}")
    print(f"  unchanged: {22 - len(improved) - len(regressed)}")

    print()
    print("arm B top-1 against arm A top-1 (where they disagree):")
    for row in rows:
        if row["B"][0] != row["A"][0]:
            mark = "hit " if row["B_top1"] else "miss"
            print(f"  {row['id']:12} A={row['A'][0]:38} B={row['B'][0]:38} {mark}")

    ties_top = [r["ties_top"] for r in rows]
    ties_third = [r["ties_third"] for r in rows]
    print()
    print(f"arm B ties at the top score : median {statistics.median(ties_top):.0f} of {len(corpus)} docs "
          f"(min {min(ties_top)}, max {max(ties_top)})")
    print(f"arm B ties at third place   : median {statistics.median(ties_third):.0f} "
          f"(min {min(ties_third)}, max {max(ties_third)})")

    if args.json:
        with open(args.json, "w") as handle:
            json.dump({"summary": summary, "rows": rows}, handle, indent=2, ensure_ascii=False)
        print(f"written: {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
