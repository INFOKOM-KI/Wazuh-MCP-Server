#!/usr/bin/env python3
"""M1 coverage geometry: how much of a parent the cross-encoder actually sees.

NOT the evaluation gate. This is the model-free half of plan section 5.3 item 6, runnable
before the model artifacts exist. It measures the shipped chunker and the shipped reranker
bound, both pure arithmetic, and it says nothing about retrieval or ranking quality. The
quality gates stay blocked until BAAI/bge-reranker-base and BAAI/bge-small-en-v1.5 are
cached and pypdf is installed.

What it answers: for a real long document, what fraction of its child positions land inside
the first `config.rag.chunk_chars` runes, which is the only text the cross-encoder receives
when BLUETEAM_RAG_PARENT_CHILD is on.

    python3 tests/bench_m1_coverage.py
    python3 tests/bench_m1_coverage.py --overlap 200
"""
from __future__ import annotations
import argparse
import os
import pathlib
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "bench")

from mcp_server.core.config import config
from mcp_server.tools import rag_kb

REPO = pathlib.Path(__file__).resolve().parent.parent

# Every document below lives at its canonical repository path. A fresh clone has all of
# them; no path outside this repository is consulted.
# Real repository documents. Stand-ins for the playbook layer, which needs pypdf.
# No repository file is 1200 runes or shorter, so the `short` band has no samples here:
# it is covered analytically instead, a document at or below the bound is one chunk and
# has no parent, so the reranker sees all of it.
DOCS = [
    ("README.md", REPO / "README.md"),
    ("SOC_3SUM_RUNBOOK.md", REPO / "SOC_3SUM_RUNBOOK.md"),
    ("SKILLS.md", REPO / "SKILLS.md"),
    ("SECURITY.md", REPO / "SECURITY.md"),
    ("PRD.md", REPO / "PRD.md"),
    ("MAESTRO.md", REPO / "MAESTRO.md"),
    ("PROMPT.md", REPO / "PROMPT.md"),
    ("AGENTS.md", REPO / "AGENTS.md"),
    ("CLAUDE.md", REPO / "CLAUDE.md"),
    # Medium band (1201 to 3600 runes). The audit records are the only prose files that
    # size, so they carry the band; both are versioned under anti-slop/.
    ("audit-002-...md", REPO / "anti-slop" / "audit-002-2026-10-04-copywriting.md"),
    ("audit-005-...md", REPO / "anti-slop" / "audit-005-2026-10-04-copywriting.md"),
]


def band(index: int, count: int) -> str:
    if count == 1:
        return "single"
    if index == 0:
        return "head"
    if index == count - 1:
        return "tail"
    return "middle"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--chunk-chars", type=int, default=1200,
                    help="the shipped BLUETEAM_RAG_CHUNK_CHARS default")
    ap.add_argument("--overlap", type=int, default=0,
                    help="0 gives the clean positional mapping the plan pins")
    args = ap.parse_args()

    config.rag.chunk_chars = args.chunk_chars
    config.rag.chunk_overlap = args.overlap
    config.rag.parent_child = True

    bound = config.rag.chunk_chars
    print("M1 coverage geometry: how much of a parent reaches the cross-encoder")
    print(f"  chunk_chars    : {bound} runes (frozen for the evaluation)")
    print(f"  chunk_overlap  : {args.overlap}")
    print(f"  parent_child   : on (so parents exist to be measured)")
    print(f"  documents      : {len(DOCS)} real repository documents")
    print()
    print(f"{'document':<22} {'runes':>7} {'kids':>5} {'parent':>7} {'cover':>7} "
          f"{'in view':>8} {'head':>6} {'mid':>6} {'tail':>6}")

    totals = {"kids": 0, "in_view": 0}
    by_band: dict[str, list[int]] = {"head": [0, 0], "middle": [0, 0], "tail": [0, 0],
                                     "single": [0, 0]}
    rows = []

    for name, path in DOCS:
        if not path.is_file():
            print(f"  {name:<22} MISSING {path}")
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        docs, _ = rag_kb._document_docs("pdf:eval", name, text, bound, args.overlap, {}, 0)
        children = [d for d in docs if not d.get("is_parent")]
        parent = next((d for d in docs if d.get("is_parent")), None)

        if parent is None:
            # A single-chunk document: no parent row, nothing to bound, the child IS the
            # document. This is the `short` band and it must behave identically either way.
            by_band["single"][1] += 1
            by_band["single"][0] += 1
            rows.append((name, len(text), len(children), len(text), 1.0, len(children),
                         "-", "-", "-"))
            continue

        # Cumulative chunk lengths approximate the child's span in the parent text. The
        # packer drops roughly 1% of the runes when it strips and rejoins sentences, so
        # the join is shorter than the parent and the computed offsets under-state the
        # true ones. The conclusion is unaffected: child 0 is under the bound either way,
        # and any later child starts after it, so past the bound. Measured deltas:
        # README 1011 of 105587 runes, CLAUDE.md 1194 of 38838, SOC_3SUM 102 of 6425.
        cumulative = 0
        in_view = 0
        per_band = {"head": [0, 0], "middle": [0, 0], "tail": [0, 0]}
        for i, child in enumerate(children):
            cumulative += len(child["text"])
            visible = cumulative <= bound
            in_view += visible
            b = band(i, len(children))
            per_band[b][1] += 1
            by_band[b][1] += 1
            if visible:
                per_band[b][0] += 1
                by_band[b][0] += 1
        coverage = min(len(parent["text"]), bound) / len(parent["text"])
        totals["kids"] += len(children)
        totals["in_view"] += in_view

        def rate(b: str) -> str:
            n, d = per_band[b]
            return f"{n}/{d}" if d else "-"

        rows.append((name, len(text), len(children), len(parent["text"]), coverage,
                     in_view, rate("head"), rate("middle"), rate("tail")))

    for name, runes, kids, plen, cov, iv, h, m, t in rows:
        print(f"{name:<22} {runes:>7} {kids:>5} {plen:>7} {cov:>6.1%} "
              f"{iv:>8} {h:>6} {m:>6} {t:>6}")

    print()
    print("aggregate by evidence position (any document):")
    for b in ("head", "middle", "tail", "single"):
        n, d = by_band[b]
        share = f"{n/d:.0%}" if d else "n/a"
        print(f"  {b:<8} {n}/{d} child positions in view   ({share})")
    share = totals["in_view"] / totals["kids"] if totals["kids"] else 0.0
    print(f"  overall  {totals['in_view']}/{totals['kids']} "
          f"({share:.1%} of child positions are visible to the cross-encoder)")
    print()
    print("reading this table:")
    print("  head  in view means the reranker scores the text that holds the evidence.")
    print("  middle and tail out of view means the reranker scores the document head")
    print("  and the labelled evidence is not part of what it scored.")
    print("  This is geometry, not a quality result. It bounds the M1 exposure; it does")
    print("  not measure it. The quality gate needs the cross-encoder.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
