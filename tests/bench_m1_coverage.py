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

Documentation input
-------------------
The documents measured here are project documentation, which is kept in the project
documentation directory and not in this repository. The directory is therefore an explicit
input: pass `--docs-dir` or set `BENCH_DOCS_DIR`. There is no default and no path inside this
repository is assumed.

The probe prints the directory it resolved, and exits 2 when that directory is missing, when
it holds no Markdown, or when nothing in it produces a parent. It does not report a ratio
computed over a thinner sample than the header claims.

    python3 tests/bench_m1_coverage.py --docs-dir /path/to/project-docs
    BENCH_DOCS_DIR=/path/to/project-docs python3 tests/bench_m1_coverage.py --overlap 200
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


def collect_docs(docs_dir: pathlib.Path) -> list[tuple[str, pathlib.Path]]:
    """Every Markdown file under ``docs_dir``, sorted, as ``(label, path)``.
    Sorting keeps the table stable between runs, so two invocations compare line by line.
    """
    return [(p.relative_to(docs_dir).as_posix(), p)
            for p in sorted(docs_dir.rglob("*.md")) if p.is_file()]


def band(index: int, count: int) -> str:
    if count == 1:
        return "single"
    if index == 0:
        return "head"
    if index == count - 1:
        return "tail"
    return "middle"


def size_band(child_count: int) -> str:
    """Which length band a document falls in, by the chunks it splits into."""
    if child_count == 0:
        return "empty"
    if child_count == 1:
        return "single"
    return "medium" if child_count <= 3 else "long"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--docs-dir", default=os.environ.get("BENCH_DOCS_DIR", ""),
                    help="project documentation directory to measure. No default; "
                         "BENCH_DOCS_DIR is the environment equivalent.")
    ap.add_argument("--chunk-chars", type=int, default=1200,
                    help="the shipped BLUETEAM_RAG_CHUNK_CHARS default")
    ap.add_argument("--overlap", type=int, default=0,
                    help="0 gives the clean positional mapping the plan pins")
    args = ap.parse_args()

    if not args.docs_dir:
        print("documentation input is required and none was supplied.\n"
              "  pass --docs-dir PATH, or set BENCH_DOCS_DIR.\n"
              "  the documents measured here are project documentation, which is kept in\n"
              "  the project documentation directory and is not part of this repository.",
              file=sys.stderr)
        return 2
    docs_dir = pathlib.Path(args.docs_dir).expanduser().resolve()
    if not docs_dir.is_dir():
        print(f"--docs-dir is not a directory: {docs_dir}", file=sys.stderr)
        return 2
    docs = collect_docs(docs_dir)
    if not docs:
        print(f"--docs-dir holds no Markdown: {docs_dir}", file=sys.stderr)
        return 2

    config.rag.chunk_chars = args.chunk_chars
    config.rag.chunk_overlap = args.overlap
    config.rag.parent_child = True

    bound = config.rag.chunk_chars
    print("M1 coverage geometry: how much of a parent reaches the cross-encoder")
    print(f"  docs dir       : {docs_dir}")
    print(f"  documents      : {len(docs)} Markdown files found")
    print(f"  chunk_chars    : {bound} runes (frozen for the evaluation)")
    print(f"  chunk_overlap  : {args.overlap}")
    print(f"  parent_child   : on (so parents exist to be measured)")
    print()
    print(f"{'document':<34} {'runes':>7} {'kids':>5} {'parent':>7} {'cover':>7} "
          f"{'in view':>8} {'head':>6} {'mid':>6} {'tail':>6}")

    totals = {"kids": 0, "in_view": 0}
    by_band: dict[str, list[int]] = {"head": [0, 0], "middle": [0, 0], "tail": [0, 0],
                                     "single": [0, 0]}
    band_docs = {"single": 0, "medium": 0, "long": 0, "empty": 0}
    rows = []

    for name, path in docs:
        text = path.read_text(encoding="utf-8", errors="replace")
        doc_rows, _ = rag_kb._document_docs("pdf:eval", name, text, bound, args.overlap, {}, 0)
        children = [d for d in doc_rows if not d.get("is_parent")]
        parent = next((d for d in doc_rows if d.get("is_parent")), None)
        band_docs[size_band(len(children))] += 1

        if parent is None:
            # A single-chunk document: no parent row, nothing to bound, the child IS the
            # document. Nothing to measure, so it is listed and skipped.
            by_band["single"][1] += 1
            by_band["single"][0] += 1
            rows.append((name, len(text), len(children), len(text), 1.0, len(children),
                         "-", "-", "-"))
            continue

        # Cumulative chunk lengths approximate the child's span in the parent text. The
        # packer drops roughly 1% of the runes when it strips and rejoins sentences, so
        # the join is shorter than the parent and the computed offsets under-state the
        # true ones. The conclusion is unaffected: child 0 is under the bound either way,
        # and any later child starts after it, so past the bound. Measured deltas on the
        # previous document set: README 1011 of 105587 runes, CLAUDE.md 1194 of 38838.
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

    if not totals["kids"]:
        print(f"\nno document in {docs_dir} produced a parent, so there is nothing to "
              f"measure. Point --docs-dir at a directory holding documents longer than "
              f"{bound} runes.", file=sys.stderr)
        return 2

    for name, runes, kids, plen, cov, iv, h, m, t in rows:
        print(f"{name:<34} {runes:>7} {kids:>5} {plen:>7} {cov:>6.1%} "
              f"{iv:>8} {h:>6} {m:>6} {t:>6}")

    print()
    print("documents measured, by length band:")
    print(f"  single chunk (no parent)   {band_docs['single']}")
    print(f"  2 to 3 chunks              {band_docs['medium']}")
    print(f"  4 or more chunks           {band_docs['long']}")
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
    print("  A document at or below chunk_chars is one chunk and gets no parent, so the")
    print("  cross-encoder sees all of it; that band is covered analytically, not sampled.")
    print("  This is geometry, not a quality result. It bounds the M1 exposure; it does")
    print("  not measure it. The quality gate needs the cross-encoder.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
