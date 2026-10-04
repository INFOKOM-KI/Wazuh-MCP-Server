#!/usr/bin/env python3
"""Retrieval flag benchmark: BLUETEAM_RERANK_NORMALIZE, BLUETEAM_RAG_PARENT_CHILD,
BLUETEAM_RAG_QUERY_NORMALIZE, measured against the all-off baseline.

Implements the design in EVAL_PLAN_RAG_PHASE1_3.md. Read that first: the acceptance gates,
the control matrix and the invariants live there, and this file is only the instrument.

    python3 tests/bench_rag_flags.py --preflight
    python3 tests/bench_rag_flags.py --combo false,false,false --json /tmp/base.json
    python3 tests/bench_rag_flags.py --matrix --json /tmp/matrix.json

Environment scope: this measures the checkout it runs in. A staging run says nothing about
a production deployment, and a missing model or dependency here is an environment blocker
for this run only.

Integrity rules enforced in code, from the plan:
  1. The raw-score invariants are checked before any metric is computed. A violation aborts
     that configuration and reports the violation instead of printing numbers.
  2. The all-off row is the baseline. The all-on row is a ceiling for context and is never
     used as a control by the gate evaluation in the report.
  3. A query with no label resolves to a recorded skip, never to an invented one.
"""
from __future__ import annotations
import argparse
import asyncio
import json
import os
import pathlib
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "bench")

from mcp_server.core import rag_store, rerank as rerank_mod
from mcp_server.core.config import config
from mcp_server.agents import fp_validator_graph as fpv  # noqa: F401  (invariant 4, via pytest)
from mcp_server.tools import rag_kb

REPO = pathlib.Path(__file__).resolve().parent.parent

# Repository fixtures, resolved from this checkout only. A fresh clone has everything the
# benchmark needs, and no path outside the repository is consulted.
QUERY_FILE = REPO / "tests" / "fixtures" / "rag_eval_queries.jsonl"
CASE_FILE = REPO / "tests" / "fixtures" / "rag_eval_cases.jsonl"

# Pinned. A run whose header differs from the baseline is not comparable.
PINNED = {
    "chunk_chars": 1200,
    "chunk_overlap": 0,
    "rag_max_candidates": 100,
    "rerank_max_candidates": 100,
    "rag_model": "BAAI/bge-small-en-v1.5",
    "rerank_model": "BAAI/bge-reranker-base",
}

# ASCII to vendor-width. The inverse of normalize_query, used to derive the paired variant
# so the two members differ only in encoding.
_WIDE = {i: chr(i + 0xFEE0) for i in range(0x21, 0x7F)}
_WIDE[0x20] = "\u3000"


def to_full_width(text: str) -> str:
    return text.translate(_WIDE)


# Preflight
def preflight() -> dict:
    """What this environment can actually measure. No conclusions about any other one."""
    status = {"rag_embedder": None, "reranker": None, "pypdf": None, "queries": None}
    cfg = (config.rag.enabled, config.rag.db_path, config.rag.allow_download,
           config.rerank.enabled, config.rerank.allow_download)
    config.rag.enabled = True
    config.rag.db_path = config.rag.db_path or "/tmp/bench-preflight/rag.db"
    config.rag.allow_download = False
    config.rerank.enabled = True
    config.rerank.allow_download = False
    try:
        _, status["rag_embedder"] = asyncio.run(rag_store.embed_texts(["probe"]))
        _, status["reranker"] = asyncio.run(rerank_mod.rerank("q", ["probe"]))
    finally:
        (config.rag.enabled, config.rag.db_path, config.rag.allow_download,
         config.rerank.enabled, config.rerank.allow_download) = cfg
    try:
        import pypdf  # noqa: F401
        status["pypdf"] = None
    except ImportError:
        status["pypdf"] = "pypdf is not installed"
    # Distinguish absent from present-but-unpopulated: a fixture with no labels and a
    # fixture that is not there are different problems for whoever is setting up the run.
    if not QUERY_FILE.is_file():
        status["queries"] = "not found"
        status["query_rows"] = 0
    else:
        status["query_rows"] = sum(
            1 for line in QUERY_FILE.read_text().splitlines()
            if line.strip() and not line.startswith("#"))
        status["queries"] = "present" if status["query_rows"] else "empty"
    return status


def print_preflight(status: dict) -> None:
    print("preflight, this environment only")
    print(f"  query fixture      : {QUERY_FILE.name} {status['queries']} "
          f"({status['query_rows']} labels)")
    print(f"  resolved from      : {QUERY_FILE.relative_to(REPO)}")
    print(f"  case fixture       : {CASE_FILE.name} "
          f"{'present' if CASE_FILE.is_file() else 'absent'}")
    print(f"  rag embedder       : {status['rag_embedder'] or 'ready'}")
    print(f"  reranker           : {status['reranker'] or 'ready'}")
    print(f"  pypdf              : {status['pypdf'] or 'installed'}")
    blocked = [k for k in ("rag_embedder", "reranker") if status[k]]
    if blocked:
        print()
        print("  QUALITY METRICS ARE NOT MEASURABLE IN THIS ENVIRONMENT.")
        print(f"  {', '.join(blocked)} did not load from cache and downloads are disabled.")
        print("  This is a blocker for this run. It is not a finding about any other")
        print("  deployment, and no flag conclusion follows from it.")
        print("  To make them measurable here: run setup.sh to bootstrap the model cache,")
        print("  or set the allow-download flags in a controlled bootstrap.")
        print("  The model-free coverage constraint is measurable now, in this environment:")
        print("    python3 tests/bench_m1_coverage.py --overlap 0")


# Labels
def load_queries(path: pathlib.Path) -> list[dict]:
    """One JSON object per line. Blank lines and lines starting with # are ignored."""
    out = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"{path.name}:{n} is not valid JSON: {exc}") from exc
        for field in ("query_id", "query", "variant", "relevant"):
            if field not in rec:
                raise SystemExit(f"{path.name}:{n} is missing {field!r}")
        out.append(rec)
    return out


def resolve_doc_id(entry: dict) -> str:
    """doc_key to id, using the shipped deterministic derivation.

    A parent id is _parent_id(source, doc_key). A document that fits in one chunk has no
    parent, so its id is the chunk id, which the caller supplies as `chunk_id`.
    """
    if entry.get("chunk_id"):
        return entry["chunk_id"]
    return rag_store._parent_id(entry["source"], entry["doc_key"])


# Corpus
def build_corpus(queries: list[dict], db_path: pathlib.Path, corpus: str) -> dict:
    """Ingest the documents the labels reference. Returns a per-source report."""
    report: dict = {}
    sources = sorted({e["source"] for q in queries for e in q["relevant"]})

    case_text = None
    if CASE_FILE.is_file():
        case_text = CASE_FILE.read_text(encoding="utf-8")
    if not case_text:
        for q in queries:
            if any(e["source"] == "cases" for e in q["relevant"]):
                raise SystemExit(
                    f"{CASE_FILE.name} is absent, so the case-layer labels cannot be "
                    "resolved. This is pending the redacted production export. Run with "
                    "--corpus geometry, or provide the fixture.")

    for source in sources:
        if source.startswith("pdf:"):
            import pypdf  # noqa: F401
            path = source.split("pdf:", 1)[1]
            out = asyncio.run(rag_kb.blueteam_rag_ingest.__wrapped__(
                rag_kb.RagIngestInput(source="pdf", path=path, response_format="json")))
            report[source] = json.loads(out)
        elif source == "cases":
            out = asyncio.run(rag_kb.blueteam_rag_ingest.__wrapped__(
                rag_kb.RagIngestInput(source="cases", response_format="json")))
            report[source] = json.loads(out)
        else:
            report[source] = {"skipped": "unsupported source"}
    report["_store"] = rag_store.stats()
    return report


# Invariants, checked before any metric
def check_invariants(record: dict) -> list[str]:
    """Plan section 5.6, items 1, 2, 3 and 5, read off the response."""
    bad: list[str] = []
    for match in record.get("matches", []):
        fused = record.get("blend_stage") == "post-rerank"
        where = f"{record['query_id']} rank {match.get('rank')}"
        if fused:
            if match.get("rerank_raw") is None:
                bad.append(f"1: {where} fused but rerank_raw absent")
            score = match.get("rerank_score")
            if score is None or not (0.0 <= score <= 1.0):
                bad.append(f"5: {where} fused rerank_score out of [0,1]: {score!r}")
            if match.get("hybrid_score") is None:
                bad.append(f"3: {where} fused but hybrid_score absent")
        else:
            if "rerank_raw" in match:
                bad.append(f"2: {where} not fused but rerank_raw present")
            if "hybrid_score" in match:
                bad.append(f"3: {where} not fused but hybrid_score present")
    return bad


# One query
def _run(coro):
    return asyncio.run(coro)


def measure(query: str, label: dict) -> dict:
    """Run one labelled query through the shipped tool and capture the plan's 3.1 fields."""
    rec: dict = {"query_id": label["query_id"], "variant": label.get("variant", "ascii"),
                 "band": label.get("band"), "position": label.get("position"),
                 "target_text": label.get("target_text", "ascii")}
    target_ids = [resolve_doc_id(e) for e in label["relevant"]]
    target_seqs = {s for e in label["relevant"] for s in e.get("child_seqs", [])}

    recall = min(label.get("recall_k", config.rag.max_candidates), config.rag.max_candidates)
    t0 = time.perf_counter()
    hits, status = _run(rag_store.query(query, top_k=recall))
    rec["recall_latency_ms"] = (time.perf_counter() - t0) * 1000
    rec["candidates"] = len(hits)
    rec["retrieval_status"] = status

    t0 = time.perf_counter()
    ranked, reranked, rstatus = _run(rerank_mod.rerank_hits(
        query, hits, label.get("top_k", config.rag.top_k)))
    rec["rerank_latency_ms"] = (time.perf_counter() - t0) * 1000
    rec["rerank_status"] = rstatus
    rec["reranked"] = reranked

    t0 = time.perf_counter()
    out = _run(rag_kb.blueteam_rag_query.__wrapped__(rag_kb.RagQueryInput(
        query=query, top_k=label.get("top_k", config.rag.top_k),
        recall_k=recall, rerank=True, response_format="json")))
    rec["total_latency_ms"] = (time.perf_counter() - t0) * 1000

    payload = json.loads(out)
    rec["query"] = payload.get("query")
    rec["query_normalized"] = payload.get("query_normalized")
    rec["blend_stage"] = payload.get("blend_stage")
    rec["returned"] = payload.get("returned")
    rec["store"] = payload.get("store")

    matches = []
    for i, hit in enumerate(payload.get("matches", []), 1):
        match = {
            "rank": i, "id": hit.get("id"), "vector_score": hit.get("vector_score"),
            "child_count": hit.get("child_count"), "matched_seq": hit.get("matched_seq"),
            "text_len": len(hit.get("text") or ""),
        }
        for field in ("rerank_score", "rerank_raw", "term_score", "hybrid_score"):
            if field in hit:
                match[field] = hit[field]
        parent = next((e for e in label["relevant"]
                       if resolve_doc_id(e) == hit.get("id")), None)
        if parent is not None:
            match["is_target"] = True
            match["child_attributed"] = bool(
                set(parent.get("child_seqs", [])) & set(hit.get("matched_seq") or []))
        matches.append(match)
    rec["matches"] = matches

    rec["rank_of_target"] = next((m["rank"] for m in matches if m.get("is_target")), None)
    rec["target_retrieved"] = rec["rank_of_target"] is not None
    rec["parent_retrieved"] = any(
        m.get("is_target") and m.get("child_count") is not None for m in matches)
    rec["child_attributed"] = any(m.get("child_attributed") for m in matches)
    coverage = [min(m["text_len"], config.rag.chunk_chars) / m["text_len"]
                for m in matches if m["text_len"]]
    rec["rerank_coverage_min"] = min(coverage) if coverage else None
    rec["rerank_coverage_mean"] = (statistics.fmean(coverage) if coverage else None)
    rec["distinct_documents"] = len({m["id"] for m in matches})
    rec["children_consumed"] = sum(m["child_count"] or 0 for m in matches)
    rec["invariant_violations"] = check_invariants(rec)
    return rec


# Metrics
def _recall(records: list[dict], k: int) -> float:
    hit = sum(1 for r in records
              if r["rank_of_target"] is not None and r["rank_of_target"] <= k)
    return hit / len(records) if records else 0.0


def _mrr(records: list[dict], cap: int = 10) -> float:
    vals = [1.0 / r["rank_of_target"]
            for r in records
            if r["rank_of_target"] is not None and r["rank_of_target"] <= cap]
    return statistics.fmean(vals) if records else 0.0


def _pct(vals: list[float], p: float) -> float:
    return sorted(vals)[min(len(vals) - 1, int(len(vals) * p))] if vals else 0.0


def summarize(records: list[dict]) -> dict:
    """Plan section 3.2, and the seven Phase 2 items kept separate."""
    live = [r for r in records if r.get("retrieval_status") in (None, "no_corpus")]
    lat_r = [r["rerank_latency_ms"] for r in live]
    lat_t = [r["total_latency_ms"] for r in live]
    out = {
        "n": len(records), "n_scored": len(live),
        "recall@1": _recall(live, 1), "recall@3": _recall(live, 3),
        "recall@10": _recall(live, 10), "mrr@10": _mrr(live),
        "parent_recall": (sum(1 for r in live if r["parent_retrieved"]) / len(live)
                          if live else 0.0),
        "child_attribution_rate": (sum(1 for r in live if r["child_attributed"]) / len(live)
                                   if live else 0.0),
        "candidates_mean": (statistics.fmean([r["candidates"] for r in live]) if live else 0.0),
        "coverage_mean": (statistics.fmean([r["rerank_coverage_mean"] for r in live
                                            if r["rerank_coverage_mean"] is not None])
                          if live else 0.0),
        "coverage_min": (min((r["rerank_coverage_min"] for r in live
                              if r["rerank_coverage_min"] is not None), default=0.0)),
        "rerank_p50_ms": statistics.median(lat_r) if lat_r else 0.0,
        "rerank_p95_ms": _pct(lat_r, 0.95),
        "total_p50_ms": statistics.median(lat_t) if lat_t else 0.0,
        "total_p95_ms": _pct(lat_t, 0.95),
        "diversity_mean": (statistics.fmean([r["distinct_documents"] for r in live])
                           if live else 0.0),
        "single_document_share": (sum(1 for r in live if r["distinct_documents"] == 1)
                                  / len(live) if live else 0.0),
        "children_consumed_mean": (statistics.fmean([r["children_consumed"] for r in live])
                                   if live else 0.0),
        "invariant_violations": [v for r in records for v in r.get("invariant_violations", [])],
    }
    for b in ("head", "middle", "tail"):
        sub = [r for r in live if r.get("position") == b]
        out[f"mrr@10_{b}"] = _mrr(sub)
        out[f"recall@10_{b}"] = _recall(sub, 10)
        out[f"n_{b}"] = len(sub)
    return out


def paired(control: list[dict], treatment: list[dict]) -> dict:
    """Win, loss, tie per query. More trustworthy than an aggregate at these sample sizes."""
    by_id = {r["query_id"]: r for r in treatment}
    win = loss = tie = 0
    for c in control:
        t = by_id.get(c["query_id"])
        if t is None:
            continue
        cr, tr = c["rank_of_target"], t["rank_of_target"]
        if cr == tr:
            tie += 1
        elif tr is not None and (cr is None or tr < cr):
            win += 1
        else:
            loss += 1
    return {"win": win, "loss": loss, "tie": tie}


def phase3_counts(records: list[dict]) -> dict:
    """Plan section 5.4: six counts per pair. Count 1 is a mechanism check, not a win."""
    ascii_rows = {r["query_id"]: r for r in records if r["variant"] == "ascii"}
    wide_rows = {r["query_id"]: r for r in records if r["variant"] == "fullwidth"}
    counts = {"pairs": 0, "query_string_changed": 0, "target_in_corpus": 0,
              "target_retrieved": 0, "target_rank_changed": 0,
              "useful_hit_gained": 0, "useful_hit_lost": 0,
              "case_a": 0, "case_b": 0}
    for qid, a in ascii_rows.items():
        w = wide_rows.get(qid)
        if w is None:
            continue
        counts["pairs"] += 1
        if w.get("query_normalized"):
            counts["query_string_changed"] += 1
        if a.get("target_text") == "ascii":
            counts["case_a"] += 1
        else:
            counts["case_b"] += 1
        ar, wr = a["rank_of_target"], w["rank_of_target"]
        if wr is not None:
            counts["target_retrieved"] += 1
        if ar != wr:
            counts["target_rank_changed"] += 1
        if wr is not None and (ar is None or wr < ar):
            counts["useful_hit_gained"] += 1
        if ar is not None and (wr is None or wr > ar):
            counts["useful_hit_lost"] += 1
    return counts


# Driver
def apply_combo(pc: bool, rn: bool, qn: bool) -> None:
    config.rag.parent_child = pc
    config.rerank.normalize = rn
    config.rag.query_normalize = qn


def run_combo(pc: bool, rn: bool, qn: bool, queries: list[dict],
              db_path: pathlib.Path, keep: bool) -> dict:
    label = f"PC={pc} RN={rn} QN={qn}"
    if not keep:
        db_path.unlink(missing_ok=True)
        for suffix in ("-wal", "-shm"):
            pathlib.Path(str(db_path) + suffix).unlink(missing_ok=True)
    config.rag.enabled = True
    config.rag.db_path = str(db_path)
    rag_store._cache_key = None
    rag_store._cache_rows = None
    rag_store._cache_matrix = None
    rag_store._cache_stats = None
    apply_combo(pc, rn, qn)
    corpus = build_corpus(queries, db_path, "full")
    records = [measure(q["query"], q) for q in queries]
    violations = [v for r in records for v in r["invariant_violations"]]
    if violations:
        print(f"\n!! {label}: RAW-SCORE INVARIANT VIOLATED, aborting this configuration")
        for v in violations[:10]:
            print(f"   {v}")
        return {"label": label, "combo": [pc, rn, qn], "aborted": True,
                "violations": violations, "records": records}
    return {"label": label, "combo": [pc, rn, qn], "aborted": False,
            "corpus": corpus, "summary": summarize(records), "records": records}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--preflight", action="store_true")
    ap.add_argument("--combo", help="false,false,false")
    ap.add_argument("--matrix", action="store_true", help="all 8 combinations")
    ap.add_argument("--json", help="write the full record set here")
    ap.add_argument("--db", default="/tmp/bench-rag-flags/rag.db")
    ap.add_argument("--keep-db", action="store_true")
    args = ap.parse_args()

    status = preflight()
    print_preflight(status)
    if args.preflight:
        return 0
    if status["rag_embedder"] or status["reranker"]:
        print("\nstopping: quality metrics are not measurable in this environment.")
        return 2
    if status["queries"] != "present":
        print(f"\nstopping: {QUERY_FILE.name} {status['queries']}.")
        return 2

    config.rag.chunk_chars = PINNED["chunk_chars"]
    config.rag.chunk_overlap = PINNED["chunk_overlap"]
    config.rag.max_candidates = PINNED["rag_max_candidates"]
    config.rerank.max_candidates = PINNED["rerank_max_candidates"]

    queries = load_queries(QUERY_FILE)
    print(f"\nqueries: {len(queries)}")
    print(f"config : {PINNED}")
    db = pathlib.Path(args.db)
    db.parent.mkdir(parents=True, exist_ok=True)

    if args.combo:
        pc, rn, qn = (p.strip().lower() == "true" for p in args.combo.split(","))
        runs = [run_combo(pc, rn, qn, queries, db, args.keep_db)]
    else:
        runs = [run_combo(pc, rn, qn, queries, db, args.keep_db)
                for pc in (False, True) for rn in (False, True) for qn in (False, True)]

    for run in runs:
        if run["aborted"]:
            continue
        s = run["summary"]
        print(f"\n{run['label']}")
        print(f"  recall@1/3/10  : {s['recall@1']:.3f} / {s['recall@3']:.3f} / {s['recall@10']:.3f}")
        print(f"  mrr@10         : {s['mrr@10']:.3f}   parent recall: {s['parent_recall']:.3f}")
        print(f"  child attrib.  : {s['child_attribution_rate']:.3f}")
        print(f"  positions      : head n={s['n_head']} mrr={s['mrr@10_head']:.3f} | "
              f"middle n={s['n_middle']} mrr={s['mrr@10_middle']:.3f} | "
              f"tail n={s['n_tail']} mrr={s['mrr@10_tail']:.3f}")
        print(f"  coverage       : mean {s['coverage_mean']:.3f} min {s['coverage_min']:.3f}")
        print(f"  latency        : rerank p50 {s['rerank_p50_ms']:.0f} p95 "
              f"{s['rerank_p95_ms']:.0f} ms | total p50 {s['total_p50_ms']:.0f} p95 "
              f"{s['total_p95_ms']:.0f} ms")
        print(f"  diversity      : mean {s['diversity_mean']:.2f} distinct docs in top k, "
              f"single-doc share {s['single_document_share']:.2f}")
        print(f"  folding        : {s['children_consumed_mean']:.1f} children per query")
        print(f"  invariants     : {'clean' if not s['invariant_violations'] else 'VIOLATED'}")

    by = {tuple(r["combo"]): r for r in runs if not r["aborted"]}
    base = by.get((False, False, False))
    if base and args.matrix:
        print("\npaired against the all-off baseline (plan 6.2 controls)")
        for combo in ((False, True, False), (True, False, False), (False, False, True)):
            treat = by.get(combo)
            if treat:
                p = paired(base["records"], treat["records"])
                print(f"  {treat['label']:<22} win {p['win']} loss {p['loss']} tie {p['tie']}")

    if args.json:
        pathlib.Path(args.json).write_text(json.dumps({
            "pinned": PINNED, "preflight": status,
            "runs": [{k: v for k, v in r.items() if k != "records"} for r in runs],
            "records": {r["label"]: r.get("records", []) for r in runs},
        }, indent=1, ensure_ascii=False))
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
