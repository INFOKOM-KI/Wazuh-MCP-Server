#!/usr/bin/env python3
"""Phase 2 measurement harness for subject memory.

Replays tests/fixtures/repeat_subjects.jsonl through the real store and answers five
separate questions, because "it produced hits" is not evidence of value:

  1. did recall return the expected historical facts?
  2. did it avoid returning unrelated ones?
  3. did repeated runs avoid duplicate storage?
  4. how many context characters does recall add per call?
  5. does the recalled history actually contain the decision and its reason?
  6. does the retention sweep leave a fresh corpus alone?

It makes no claim about tool-call reduction: recall never skips a graph node, so
that number can only come from production telemetry.

Run: python3 tests/bench_memory_recall.py
"""
from __future__ import annotations
import json
import os
import pathlib
import sys
import tempfile

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "bench")

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from mcp_server.core import memory_store  # noqa: E402
from mcp_server.core.config import config  # noqa: E402

FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "repeat_subjects.jsonl"


def load_rows() -> list[dict]:
    rows = []
    for line in FIXTURE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            rows.append(json.loads(line))
    return rows


def main() -> int:
    config.memory.enabled = True
    config.memory.db_path = os.path.join(tempfile.mkdtemp(), "bench.db")
    rows = load_rows()

    expected_hits = [row for row in rows if row["expect_prior"]]
    hits, wrong_verdict, false_hits = [], [], []
    context_chars: list[int] = []
    reasons_by_subject: dict[str, set[str]] = {}
    cross_subject_leaks = 0
    tallies: dict[str, dict[str, int]] = {"decision": {}, "reason": {}}

    for row in rows:
        subject = memory_store.subject_for_srcip(row["srcip"])
        envelope = memory_store.recall_subject(subject)
        context_chars.append(len(json.dumps(envelope)))
        if bool(envelope["decisions"]) != bool(row["expect_prior"]):
            (false_hits if not row["expect_prior"] else wrong_verdict).append(row)
        elif row["expect_prior"]:
            verdicts = {decision["verdict"] for decision in envelope["decisions"]}
            (hits if row["expect_verdict"] in verdicts else wrong_verdict).append(row)

        # Question 2, the hard half: nothing from another subject may appear here.
        seen_here = {reason["text"] for reason in envelope["recent_reasons"]}
        for other_subject, texts in reasons_by_subject.items():
            if other_subject != subject and seen_here & texts:
                cross_subject_leaks += 1

        outcome = memory_store.record_decision(srcip=row["srcip"], verdict=row["verdict"],
                                               notes=row["notes"])
        for slot in ("decision", "reason"):
            value = str(outcome.get(slot))
            tallies[slot][value] = tallies[slot].get(value, 0) + 1
        reasons_by_subject[subject] = seen_here | {
            row["notes"]} if row["notes"] else seen_here

    stats = memory_store.memory_stats()
    units, _ = _all_units()
    decisions = sum(1 for unit in units if unit["kind"] == "decision")
    reasons = sum(1 for unit in units if unit["kind"] == "reason")
    other = len(units) - decisions - reasons
    reconciled = (sum(tallies["decision"].values()) == len(rows)
                  and sum(tallies["reason"].values()) == len(rows)
                  and len(units) == decisions + reasons)
    analyst_repeats = [row for row in rows
                       if row["label"] == "repeat-analyst-note" and row["expect_prior"]]
    auto_repeats = [row for row in rows
                    if row["label"] == "repeat-auto-note" and row["expect_prior"]]
    analyst_with_reason = sum(
        1 for row in analyst_repeats
        if memory_store.recall_subject(memory_store.subject_for_srcip(row["srcip"]))["recent_reasons"])
    auto_with_reason = sum(
        1 for row in auto_repeats
        if memory_store.recall_subject(memory_store.subject_for_srcip(row["srcip"]))["recent_reasons"])

    print(f"fixture rows            : {len(rows)} ({len(expected_hits)} with a prior decision)")
    print(f"1. expected facts found : {len(hits)}/{len(expected_hits)}"
          f"  wrong verdict: {len(wrong_verdict)}")
    print(f"2. unrelated retrievals : {len(false_hits) + cross_subject_leaks}"
          f"  (unexpected hits: {len(false_hits)}, cross-subject: {cross_subject_leaks})")
    print(f"3. accounting           : {len(rows)} retain events -> {len(units)} rows")
    print(f"   decision outcomes    : {tallies['decision']}")
    print(f"   reason outcomes      : {tallies['reason']}")
    print(f"   rows                 : {decisions} decisions + {reasons} reasons"
          f" + {other} other")
    print(f"4. context added        : mean {sum(context_chars) / len(context_chars):.0f} chars,"
          f" max {max(context_chars)} chars")
    print(f"5. reason available     : analyst-note repeats {analyst_with_reason}/{len(analyst_repeats)},"
          f" auto-note repeats {auto_with_reason}/{len(auto_repeats)}")
    retention = memory_store.prune_memory()
    print(f"6. retention sweep      : {retention['status']}, pruned {retention['pruned']},"
          f" merged {retention['merged']}")

    failures = len(wrong_verdict) + len(false_hits) + cross_subject_leaks
    if retention["pruned"] or retention["merged"]:
        print("FAIL: a fresh fixture should need no retention work")
        return 1
    if not reconciled:
        print("FAIL: retained units do not reconcile with the retain events")
        return 1
    if failures:
        print("FAIL: retrieval contract violated")
        return 1
    print("ok: every expected decision was retrievable, nothing unrelated was, and the"
          " accounting reconciles")
    return 0


def _all_units() -> tuple[list[dict], None]:
    units: list[dict] = []
    with memory_store._store() as conn:
        for row in conn.execute("SELECT * FROM units"):
            units.append(memory_store._row_to_unit(row))
    return units, None


if __name__ == "__main__":
    raise SystemExit(main())
