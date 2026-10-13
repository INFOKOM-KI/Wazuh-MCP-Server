#!/usr/bin/env python3
"""BM25 cost and event-loop impact, measured on the primitive both search paths share.

Not a pytest module (no `test_` prefix). Run it before and after any change that
moves BM25 work between threads:

    python3 tests/bench_bm25_latency.py

It answers three questions. How long does `_BM25` take to build and to score at the
50k-document size the alert path caps at? Does offloading the call to a worker thread
change the scores it returns? And how long does a 10 ms ticker starve while BM25 runs
inline on the event loop, against the same ticker with the call under
`asyncio.to_thread`?

The fingerprint is the sha256 of every `(doc index, score)` pair the query returned.
Two runs printing the same fingerprint computed the same result; a run whose
fingerprint moves changed the ranking.

Documents are synthetic and fixed-size, so the numbers are the cost of the algorithm
at that scale, not a measurement of any particular Wazuh index.
"""
from __future__ import annotations
import argparse
import asyncio
import functools
import hashlib
import json
import os
import random
import statistics
import string
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "bench")

from mcp_server.tools.semantic_search import _BM25

QUERY = "brute force ssh failed login webshell beacon"
TICK_SECONDS = 0.01
SCORE_REPS = 3


def _corpus(docs: int, tokens: int, seed: int) -> list[str]:
    """Random documents over a vocabulary that carries the query terms.

    Without the query terms planted, every document scores zero and the fingerprint
    becomes the hash of an empty list, which compares equal no matter what the ranker
    did. The planted terms are what make the equivalence check mean anything.
    """
    rng = random.Random(seed)
    vocab = QUERY.split() + ["".join(rng.choices(string.ascii_lowercase, k=rng.randint(4, 9)))
                             for _ in range(4000)]
    return [" ".join(rng.choices(vocab, k=tokens)) for _ in range(docs)]


def _fingerprint(scores: list[tuple[int, float]]) -> str:
    digest = hashlib.sha256()
    for idx, score in scores:
        digest.update(f"{idx}:{score!r}\n".encode())
    return digest.hexdigest()


async def _ticker(stop: asyncio.Event, gaps: list[float]) -> None:
    last = time.perf_counter()
    while not stop.is_set():
        await asyncio.sleep(TICK_SECONDS)
        now = time.perf_counter()
        gaps.append((now - last) * 1000)
        last = now


async def _worst_gap(call) -> float:
    """Worst ticker gap while `call` runs, so a blocked loop shows up as a late tick."""
    stop, gaps = asyncio.Event(), []
    ticker = asyncio.create_task(_ticker(stop, gaps))
    await asyncio.sleep(0.05)
    await call()
    await asyncio.sleep(0.05)
    stop.set()
    await ticker
    return max(gaps)


async def _sync_call(bm: _BM25, query: str) -> None:
    bm.score(query)


async def _threaded_call(bm: _BM25, query: str) -> None:
    await asyncio.to_thread(bm.score, query)


def main() -> int:
    parser = argparse.ArgumentParser(description="BM25 build/score cost and loop impact.")
    parser.add_argument("--docs", type=int, default=50000,
                        help="Corpus size. 50000 is the semantic-search alert scan cap.")
    parser.add_argument("--tokens", type=int, default=300,
                        help="Tokens per document.")
    parser.add_argument("--seed", type=int, default=7,
                        help="Corpus seed. Fixed so two runs compare equal.")
    parser.add_argument("--json", default="",
                        help="Write the results as JSON to this path.")
    parser.add_argument("--skip-sync", action="store_true",
                        help="Measure only the offloaded arm. The sync arm stalls the "
                             "loop for the whole score, which is the point of the test.")
    args = parser.parse_args()

    corpus = _corpus(args.docs, args.tokens, args.seed)

    start = time.perf_counter()
    bm = _BM25(corpus)
    build_s = time.perf_counter() - start

    reps = []
    for _ in range(SCORE_REPS):
        start = time.perf_counter()
        scores = bm.score(QUERY)
        reps.append((time.perf_counter() - start) * 1000)
    score_ms = statistics.median(reps)

    result = {
        "docs": args.docs,
        "tokens_per_doc": args.tokens,
        "seed": args.seed,
        "build_s": round(build_s, 4),
        "score_ms_median": round(score_ms, 2),
        "score_ms_reps": [round(r, 2) for r in reps],
        "matches": len(scores),
        "fingerprint": _fingerprint(scores),
        "ticker_nominal_ms": TICK_SECONDS * 1000,
    }

    if not args.skip_sync:
        result["ticker_worst_gap_sync_ms"] = round(
            asyncio.run(_worst_gap(functools.partial(_sync_call, bm, QUERY))), 1)
    result["ticker_worst_gap_to_thread_ms"] = round(
        asyncio.run(_worst_gap(functools.partial(_threaded_call, bm, QUERY))), 1)

    print(f"corpus            : {args.docs:,} docs x {args.tokens} tokens (seed {args.seed})")
    print(f"build             : {build_s:.3f} s")
    print(f"score             : {score_ms:.1f} ms (median of {SCORE_REPS})")
    print(f"matching docs     : {len(scores):,}")
    print(f"fingerprint       : {result['fingerprint'][:16]}")
    print(f"ticker nom./worst : {TICK_SECONDS * 1000:.0f} ms nominal, "
          f"{result['ticker_worst_gap_to_thread_ms']:.1f} ms worst under to_thread")
    if not args.skip_sync:
        print(f"                    {result['ticker_worst_gap_sync_ms']:.1f} ms worst inline "
              f"on the event loop")

    if args.json:
        with open(args.json, "w") as handle:
            json.dump(result, handle, indent=2)
        print(f"written           : {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
