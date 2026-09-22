#!/usr/bin/env python3
"""Routing benchmark: BM25-only vs BM25 + bge-reranker-base, on prompt_route.

Not a pytest module (no `test_` prefix, so pytest does not collect it). Run it
against a live model cache:

    BLUETEAM_RERANK_MODEL_... python3 tests/bench_rerank_routing.py

The question it answers: does the cross-encoder put the right tool in the top 3
more often than BM25 alone, and what does each call cost in wall time?

Ground truth is hand-labelled below (and therefore mine, not an oracle). Read
deltas under ~10 points as noise at n=22. Every prompt is scored twice: BM25
top-3, then cross-encoder top-3 over the same 20 BM25 candidates (the Q5 cap).
"""
from __future__ import annotations

import asyncio
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "bench")

CACHE = os.environ.get("BENCH_RERANK_CACHE", "/tmp/rerank-bench-cache")
CANDIDATES = 20

# (id, lang, prompt, acceptable tools)
PROMPTS: list[tuple[str, str, str, set[str]]] = [
    # --- 12 report prompts, one per saving-prompt file (6 windows x en/id) ---
    ("24h-en", "en", "Write the 24 hour SOC report for TangerangKota-CSIRT",
     {"wazuh_alert_aggregate_analysis", "wazuh_alert_timeline", "blueteam_curated_threat_report"}),
    ("24h-id", "id", "Buat laporan SOC harian untuk 24 jam terakhir",
     {"wazuh_alert_aggregate_analysis", "wazuh_alert_timeline", "blueteam_curated_threat_report"}),
    ("3d-en", "en", "Write the 3 day SOC report: what happened in the last 72 hours",
     {"wazuh_alert_aggregate_analysis", "wazuh_alert_timeline", "blueteam_curated_threat_report"}),
    ("3d-id", "id", "Buat laporan SOC untuk 3 hari terakhir",
     {"wazuh_alert_aggregate_analysis", "wazuh_alert_timeline", "blueteam_curated_threat_report"}),
    ("7d-en", "en", "Weekly SOC report covering the last 7 days",
     {"wazuh_alert_aggregate_analysis", "wazuh_alert_timeline", "blueteam_curated_threat_report"}),
    ("7d-id", "id", "Susun laporan mingguan SOC untuk 7 hari terakhir",
     {"wazuh_alert_aggregate_analysis", "wazuh_alert_timeline", "blueteam_curated_threat_report"}),
    ("30d-en", "en", "Monthly SOC report for the last 30 days",
     {"wazuh_alert_aggregate_analysis", "wazuh_alert_timeline", "blueteam_curated_threat_report"}),
    ("30d-id", "id", "Buat laporan bulanan SOC periode 30 hari terakhir",
     {"wazuh_alert_aggregate_analysis", "wazuh_alert_timeline", "blueteam_curated_threat_report"}),
    ("90d-en", "en", "Quarterly SOC report covering the last 90 days",
     {"wazuh_alert_aggregate_analysis", "wazuh_alert_timeline", "blueteam_curated_threat_report"}),
    ("90d-id", "id", "Buat laporan kuartalan SOC untuk 90 hari terakhir",
     {"wazuh_alert_aggregate_analysis", "wazuh_alert_timeline", "blueteam_curated_threat_report"}),
    ("1yr-en", "en", "Annual SOC report for the past year",
     {"wazuh_alert_aggregate_analysis", "wazuh_alert_timeline", "blueteam_curated_threat_report"}),
    ("1yr-id", "id", "Buat laporan tahunan SOC untuk satu tahun terakhir",
     {"wazuh_alert_aggregate_analysis", "wazuh_alert_timeline", "blueteam_curated_threat_report"}),
    # --- 10 Indonesian ad-hoc analyst questions, tight labels ---
    ("id-adhoc-1", "id", "IP ini pernah menyerang kita atau tidak?",
     {"blueteam_threat_card", "blueteam_threat_intel_aggregate", "blueteam_unified_threat_score"}),
    ("id-adhoc-2", "id", "cek apakah IP ini ada di blocklist sangfor",
     {"sangfor_blocklist_check", "sangfor_blocklist_list"}),
    ("id-adhoc-3", "id", "email siapa saja yang bocor kredensialnya",
     {"wazuh_compromised_emails_analysis", "stealer_log_check", "blueteam_breach_check"}),
    ("id-adhoc-4", "id", "ada serangan webshell di server nginx tidak?",
     {"blueteam_check_webshell", "blueteam_read_web_log"}),
    ("id-adhoc-5", "id", "alert brute force ssh naik drastis dibanding hari biasanya",
     {"blueteam_baseline_drift", "blueteam_failed_logins", "wazuh_attack_velocity"}),
    ("id-adhoc-6", "id", "apakah alert ini false positive?",
     {"blueteam_rag_fp_validate", "blueteam_false_positive_tracker", "blueteam_false_positive_kb"}),
    ("id-adhoc-7", "id", "agent wazuh mana saja yang offline",
     {"blueteam_wazuh_agents_summary", "blueteam_wazuh_agents"}),
    ("id-adhoc-8", "id", "ada trafik beaconing periodik ke C2 dari host ini",
     {"blueteam_beacon_detect"}),
    ("id-adhoc-9", "id", "buatkan case investigasi untuk insiden ini",
     {"blueteam_case_create", "blueteam_investigation_workflow"}),
    ("id-adhoc-10", "id", "port apa saja yang terbuka di server ini",
     {"blueteam_list_listening_ports", "blueteam_check_open_firewall"}),
]


def _hit(results: list[dict], acceptable: set[str], k: int) -> bool:
    return any(r["tool"] in acceptable for r in results[:k])


async def main() -> int:
    from mcp_server.core.config import config
    from mcp_server.core.rerank import reason
    from mcp_server.tools import register_all_tools
    from mcp_server.tools.prompt_router import _get_router

    register_all_tools()
    config.rerank.enabled = True
    config.rerank.cache_path = CACHE
    config.rerank.model = "BAAI/bge-reranker-base"
    config.rerank.max_candidates = 100

    router = _get_router()
    print(f"tools indexed      : {len(router.tool_corpus)}")
    print(f"prompts            : {len(PROMPTS)} (12 report + 10 Indonesian ad-hoc)")
    print(f"rerank candidates  : {CANDIDATES}\n")

    rows = []
    lat_bm25, lat_rerank = [], []
    stats = {"en": {"bm25_3": 0, "re_3": 0, "bm25_1": 0, "re_1": 0, "n": 0},
             "id": {"bm25_3": 0, "re_3": 0, "bm25_1": 0, "re_1": 0, "n": 0}}
    fallbacks = []

    for pid, lang, prompt, acceptable in PROMPTS:
        t0 = time.perf_counter()
        bm25 = router.route(prompt, top_k=3)
        lat_bm25.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        ranked, status = await router.route_reranked(prompt, top_k=3, candidates=CANDIDATES)
        lat_rerank.append(time.perf_counter() - t0)
        if status is not None:
            fallbacks.append((pid, status))

        b3 = _hit(bm25, acceptable, 3)
        r3 = _hit(ranked, acceptable, 3)
        b1 = _hit(bm25, acceptable, 1)
        r1 = _hit(ranked, acceptable, 1)
        s = stats[lang]
        s["n"] += 1
        s["bm25_3"] += b3
        s["re_3"] += r3
        s["bm25_1"] += b1
        s["re_1"] += r1
        rows.append((pid, lang, b3, r3, b1, r1, bm25[:3], ranked[:3], accepted_tools(bm25, ranked, acceptable)))

    print(f"{'prompt':<12} {'lang':<4} {'BM25@3':<7} {'RERANK@3':<9} "
          f"{'BM25@1':<7} {'RERANK@1':<9} top-3 BM25 -> top-3 reranked")
    for pid, lang, b3, r3, b1, r1, bt, rt, _ in rows:
        print(f"{pid:<12} {lang:<4} {str(b3):<7} {str(r3):<9} {str(b1):<7} {str(r1):<9} "
              f"{','.join(t for _, t in [(0, r['tool']) for r in bt])} -> "
              f"{','.join(r['tool'] for r in rt)}")

    print("\n=== summary ===")
    tot = {"bm25_3": 0, "re_3": 0, "bm25_1": 0, "re_1": 0, "n": 0}
    for lang, s in stats.items():
        print(f"{lang}: BM25@3 {s['bm25_3']}/{s['n']} ({100*s['bm25_3']/s['n']:.0f}%) | "
              f"rerank@3 {s['re_3']}/{s['n']} ({100*s['re_3']/s['n']:.0f}%) | "
              f"BM25@1 {s['bm25_1']}/{s['n']} ({100*s['bm25_1']/s['n']:.0f}%) | "
              f"rerank@1 {s['re_1']}/{s['n']} ({100*s['re_1']/s['n']:.0f}%)")
        for k in tot:
            tot[k] += s[k]
    print(f"ALL: BM25@3 {tot['bm25_3']}/{tot['n']} ({100*tot['bm25_3']/tot['n']:.0f}%) | "
          f"rerank@3 {tot['re_3']}/{tot['n']} ({100*tot['re_3']/tot['n']:.0f}%) | "
          f"BM25@1 {tot['bm25_1']}/{tot['n']} ({100*tot['bm25_1']/tot['n']:.0f}%) | "
          f"rerank@1 {tot['re_1']}/{tot['n']} ({100*tot['re_1']/tot['n']:.0f}%)")

    def pct(v: list[float], p: float) -> float:
        return sorted(v)[min(len(v) - 1, int(len(v) * p))]

    print(f"\nlatency BM25   : median {statistics.median(lat_bm25)*1000:.0f} ms, "
          f"p95 {pct(lat_bm25, 0.95)*1000:.0f} ms")
    print(f"latency rerank : median {statistics.median(lat_rerank)*1000:.0f} ms, "
          f"p95 {pct(lat_rerank, 0.95)*1000:.0f} ms  (stage-2 inference only, model warm)")
    print(f"rerank model   : {reason()}")
    if fallbacks:
        print(f"!! fallbacks (rerank did NOT run): {fallbacks}")
    else:
        print("rerank ran on every prompt (no fallbacks)")
    return 0


def accepted_tools(bm25: list[dict], ranked: list[dict], acceptable: set[str]) -> list[str]:
    """Names of acceptable tools present in either top-3, for eyeballing."""
    seen = [r["tool"] for r in bm25 + ranked if r["tool"] in acceptable]
    return list(dict.fromkeys(seen))


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
