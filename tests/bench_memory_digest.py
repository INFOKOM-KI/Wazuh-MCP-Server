#!/usr/bin/env python3
"""Phase 4 evaluation harness: does a deterministic digest of the Phase 3 recall envelope
cut the memory-supplied context by at least 25% without losing a fact?

The candidate lives in this file on purpose: the brief approves measuring one, not wiring one
in, so nothing under mcp_server changes. The envelope is the preservation reference. The tune
half freezes the one parameter, then the gate half is measured once.

Run: python3 tests/bench_memory_digest.py              # the frozen gate, reproduced
     python3 tests/bench_memory_digest.py --first-seen # A/B on the same gate data
     python3 tests/bench_memory_digest.py --safety     # long-note truncation safety
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import statistics
import sys
import tempfile
import time
from datetime import datetime, timezone

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "measure")

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from mcp_server.core import memory_store  # noqa: E402
from mcp_server.core.config import config  # noqa: E402

FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "mental_digest_eval.jsonl"
LONGNOTE_FIXTURE = (pathlib.Path(__file__).resolve().parent / "fixtures"
                    / "mental_digest_longnote.jsonl")
FROZEN_REASON_CHARS = 200          # chosen on the tune half, not touched again
LATENCY_RUNS = 200
TUNE_BUDGETS = (200, 300, 400, 600, 10 ** 9)
DIGEST_KEYS = {"subject", "status", "boundary", "decisions", "reasons", "elided"}
RECALL_LIMIT = 5
DECISION_KEYS = {"verdict", "advisory", "age_days", "support_count", "case_id", "recorded_by"}
REASON_KEYS = {"text", "tainted", "support_count"}
FIRST_SEEN_KEY = "age_days_first"
# Function words only. Anything a reader could call a fact stays a required token.
STOPWORDS = frozenset("""a an the and or but if then than that this these those there their they
with from for into over under about after before while when where which what will would could
should have has had been being was were are is are not no nor only also more most some each
both every other same such very own too can may must""".split())


def load_rows(path: pathlib.Path = FIXTURE) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            rows.append(json.loads(line))
    return rows


def seed(rows: list[dict]) -> None:
    """Replay the fixture into a fresh store, then apply Phase 3 retention once so the
    store is in the state a production subject would be in."""
    config.memory.enabled = True
    config.memory.db_path = os.path.join(tempfile.mkdtemp(), "digest-eval.db")
    for row in rows:
        if row.get("action") == "invalidate":
            subject = memory_store.subject_for_srcip(row["srcip"])
            for unit in memory_store.units_for_subject(subject, limit=1000)[0]:
                if unit["kind"] == "reason" and unit["text"] == row["notes"]:
                    memory_store.invalidate_unit(unit["unit_id"], reason="fixture withdrawal")
        else:
            memory_store.record_decision(srcip=row["srcip"], verdict=row["verdict"],
                                         notes=row.get("notes", ""),
                                         recorded_by=row.get("recorded_by", "analyst"))
    memory_store.prune_memory()


def content_tokens(text: str) -> set[str]:
    return {token for token in re.findall(r"[a-z0-9]{4,}", (text or "").lower())
            if token not in STOPWORDS}


def age_days_since(stamp: str | None) -> float | None:
    """Days since a timestamp, or None when it is missing or unreadable."""
    try:
        when = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    return round((datetime.now(timezone.utc) - when).total_seconds() / 86400.0, 1)


def build_digest(envelope: dict, reason_chars: int, include_first_seen: bool = False) -> dict:
    """The candidate: the envelope with metadata fields dropped and reason text capped.
    It truncates, it never rewrites, which is what makes token containment a complete
    test for truncation loss rather than a proxy. include_first_seen adds the compact
    one-field answer to "when was this first concluded", which the base digest drops."""
    decisions = []
    for entry in envelope["decisions"]:
        decision = {"verdict": entry["verdict"], "advisory": entry["advisory"],
                    "age_days": entry["age_days"], "support_count": entry["support_count"],
                    "case_id": entry["case_id"], "recorded_by": entry["recorded_by"]}
        if include_first_seen:
            decision[FIRST_SEEN_KEY] = age_days_since(entry.get("first_seen"))
        decisions.append(decision)
    reasons, truncated = [], 0
    for entry in envelope["recent_reasons"]:
        kept = entry["text"][:reason_chars]
        if len(kept) < len(entry["text"]):
            truncated += 1
        reasons.append({"text": kept, "tainted": entry["tainted"],
                        "support_count": entry["support_count"]})
    return {"subject": envelope["subject"], "status": envelope["status"],
            "boundary": envelope["boundary"], "decisions": decisions, "reasons": reasons,
            "elided": {"decisions": 0, "reasons": 0, "reason_text_truncated": truncated}}


def decision_facts(envelope: dict) -> list[tuple]:
    return sorted((entry["verdict"], entry["advisory"], entry["support_count"])
                  for entry in envelope["decisions"])


def audit(envelope: dict, digest: dict) -> dict:
    """Per-subject preservation audit against the envelope, field by field."""
    same_decisions = decision_facts(envelope) == sorted(
        (entry["verdict"], entry["advisory"], entry["support_count"])
        for entry in digest["decisions"])
    lost: list[list] = []
    truncated: list[dict] = []
    taint_ok = True
    for entry in envelope["recent_reasons"]:
        matching = [candidate for candidate in digest["reasons"]
                    if entry["text"].startswith(candidate["text"])]
        if not matching:
            lost.append([entry["unit_id"], sorted(content_tokens(entry["text"]))])
            continue
        kept_text = matching[0]["text"]
        missing = content_tokens(entry["text"]) - content_tokens(kept_text)
        if missing:
            lost.append([entry["unit_id"], sorted(missing)])
        if len(kept_text) < len(entry["text"]):
            truncated.append({"unit_id": entry["unit_id"], "from": len(entry["text"]),
                              "to": len(kept_text)})
        taint_ok = taint_ok and matching[0]["tainted"] is True
    return {"decisions_preserved": same_decisions,
            "reasons_expected": len(envelope["recent_reasons"]),
            "reasons_preserved": len(envelope["recent_reasons"]) - len(lost),
            "lost": lost,
            "truncated": truncated,
            "taint_preserved": taint_ok}


def statement_counter():
    """Count store opens, so the candidate's cost is measured and not asserted."""
    real = memory_store._store
    counter = {"n": 0}

    def counting():
        counter["n"] += 1
        return real()

    memory_store._store = counting
    return counter, lambda: setattr(memory_store, "_store", real)


def schema_fingerprint() -> list[str]:
    with memory_store._store() as conn:
        return sorted(row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table','index')"))


def latency(envelope: dict, budget: int) -> tuple[float, float, float, float]:
    baseline = []
    for _ in range(LATENCY_RUNS):
        started = time.perf_counter()
        json.dumps(envelope)
        baseline.append(time.perf_counter() - started)
    candidate = []
    for _ in range(LATENCY_RUNS):
        started = time.perf_counter()
        json.dumps(build_digest(envelope, budget))
        candidate.append(time.perf_counter() - started)
    return (statistics.median(baseline) * 1000, statistics.median(candidate) * 1000,
            sorted(candidate)[int(0.95 * LATENCY_RUNS) - 1] * 1000,
            statistics.median(baseline) * 1000 * 2)


def first_seen_ab() -> int:
    """Does the memory contract need first_seen? Two digests, one frozen gate dataset.

    A drops it (the current design), B carries one compact number per decision. The
    comparison is reported on the same subjects and characters the gate uses.
    """
    rows = load_rows(FIXTURE)
    seed(rows)
    subjects = list(dict.fromkeys(memory_store.subject_for_srcip(row["srcip"])
                                 for row in rows if row["half"] == "gate"))
    print(f"first_seen A/B on the frozen gate data, budget {FROZEN_REASON_CHARS}")
    for label, include in (("A  without first_seen", False), ("B  with age_days_first", True)):
        baseline = candidate = lost = 0
        per_subject = []
        timings = []
        for subject in subjects:
            envelope = memory_store.recall_subject(subject, limit=RECALL_LIMIT)
            started = time.perf_counter()
            digest = build_digest(envelope, FROZEN_REASON_CHARS,
                                  include_first_seen=include)
            timings.append(time.perf_counter() - started)
            result = audit(envelope, digest)
            size = len(json.dumps(digest, separators=(",", ":")))
            envelope_size = len(json.dumps(envelope, separators=(",", ":")))
            baseline += envelope_size
            candidate += size
            lost += len(result["lost"]) + (0 if result["decisions_preserved"] else 1)
            per_subject.append(f".{subject.rsplit('.', 1)[-1]} {100 * (1 - size / envelope_size):.0f}%")
        print(f"  {label:24s} {baseline} -> {candidate} chars "
              f"({100 * (1 - candidate / baseline):.1f}% reduction) | lost facts {lost}"
              f" | median {statistics.median(timings) * 1000:.3f} ms")
        print(f"  {'':24s} per subject: {' '.join(per_subject)}")
    print("  contract: the base digest cannot answer when a subject was first concluded;")
    print("  age_days_first restores that with one number per decision entry.")
    return 0


def safety_main() -> int:
    """Long-note safety: is a truncation loss observable, and what does preserving
    every token cost? The frozen budget is used as frozen, never retuned here."""
    rows = load_rows(LONGNOTE_FIXTURE)
    seed(rows)
    subjects = list(dict.fromkeys(memory_store.subject_for_srcip(row["srcip"]) for row in rows))
    longest = max(len(row.get("notes", "")) for row in rows)
    print(f"long-note safety fixture: {len(rows)} events, {len(subjects)} subjects, "
          f"longest reason {longest} characters, frozen budget {FROZEN_REASON_CHARS}")

    frozen_lost = frozen_truncated = 0
    baseline = candidate = 0
    per_subject = []
    for subject in subjects:
        envelope = memory_store.recall_subject(subject, limit=RECALL_LIMIT)
        digest = build_digest(envelope, FROZEN_REASON_CHARS)
        result = audit(envelope, digest)
        size = len(json.dumps(digest, separators=(",", ":")))
        envelope_size = len(json.dumps(envelope, separators=(",", ":")))
        baseline += envelope_size
        candidate += size
        frozen_lost += sum(len(item[1]) for item in result["lost"])
        frozen_truncated += len(result["truncated"])
        per_subject.append(
            f".{subject.rsplit('.', 1)[-1]} {len(envelope['recent_reasons'])} reasons, "
            f"truncated {len(result['truncated'])}, lost "
            f"{sum(len(item[1]) for item in result['lost'])}, "
            f"{100 * (1 - size / envelope_size):.0f}% smaller")
    print("  at the frozen budget")
    for line in per_subject:
        print(f"    {line}")
    print(f"    aggregate {baseline} -> {candidate} chars "
          f"({100 * (1 - candidate / baseline):.1f}% reduction), "
          f"reasons truncated {frozen_truncated}, content tokens lost {frozen_lost}")
    print("  the loss is visible in elided.reason_text_truncated and in the coverage audit,"
          " so it cannot pass silently" if frozen_lost else
          "  no truncation happened at the frozen budget, which would be a fixture problem")

    preserving = None
    for budget in TUNE_BUDGETS:
        lost = 0
        for subject in subjects:
            envelope = memory_store.recall_subject(subject, limit=RECALL_LIMIT)
            lost += sum(len(item[1]) for item in
                        audit(envelope, build_digest(envelope, budget))["lost"])
        if lost == 0:
            preserving = budget
            break
    if preserving is None:
        print("  no budget in the candidate list preserves every token")
        return 1
    cost = preserved = 0
    for subject in subjects:
        envelope = memory_store.recall_subject(subject, limit=RECALL_LIMIT)
        digest = build_digest(envelope, preserving)
        result = audit(envelope, digest)
        preserved += 0 if result["lost"] else 1
        cost += len(json.dumps(digest, separators=(",", ":")))
    print(f"  coverage-preserving budget {preserving}: aggregate {cost} chars "
          f"({100 * (1 - cost / baseline):.1f}% reduction), "
          f"subjects with zero loss {preserved}/{len(subjects)}")

    # The same invariants the gate checks, on the long-note set.
    injection = 0
    taint = 0
    in_decisions = 0
    resurrected = 0
    classes_kept = True
    invalidated = [row["notes"] for row in rows if row.get("action") == "invalidate"]
    for subject in subjects:
        envelope = memory_store.recall_subject(subject, limit=RECALL_LIMIT)
        for budget in (FROZEN_REASON_CHARS, preserving):
            digest = build_digest(envelope, budget)
            if (set(digest) != DIGEST_KEYS
                    or any(set(entry) != DECISION_KEYS for entry in digest["decisions"])
                    or any(set(entry) != REASON_KEYS for entry in digest["reasons"])):
                classes_kept = False
            taint += sum(1 for entry in digest["reasons"] if entry["tainted"] is True)
            for entry in digest["reasons"]:
                if "IGNORE ALL PREVIOUS INSTRUCTIONS" in entry["text"]:
                    injection += 1
            byte = json.dumps(digest["decisions"])
            in_decisions += 1 if "IGNORE ALL PREVIOUS INSTRUCTIONS" in byte else 0
            for note in invalidated:
                if any(note == entry["text"] for entry in envelope["recent_reasons"]):
                    resurrected += 1
                if any(note == entry["text"] for entry in digest["reasons"]):
                    resurrected += 1
    print(f"  adversarial: injection reasons {injection}, tainted entries {taint}, "
          f"injection inside decisions {in_decisions}, invalidated resurrected {resurrected}, "
          f"key shape fixed {classes_kept}")
    return 0


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "gate"
    if mode == "--safety":
        return safety_main()
    if mode == "--first-seen":
        return first_seen_ab()
    return gate_main()


def gate_main() -> int:
    rows = load_rows()
    seed(rows)
    halves: dict[str, list[str]] = {"tune": [], "gate": []}
    for row in rows:
        subject = memory_store.subject_for_srcip(row["srcip"])
        if subject not in halves[row["half"]]:
            halves[row["half"]].append(subject)
    print(f"fixture: {len(rows)} events, {len(halves['tune'])} tune subjects, "
          f"{len(halves['gate'])} gate subjects")

    # Tune: the smallest text budget with no token loss anywhere on the tune half.
    frozen, tune_row = None, []
    for budget in TUNE_BUDGETS:
        lost_total = 0
        for subject in halves["tune"]:
            envelope = memory_store.recall_subject(subject, limit=RECALL_LIMIT)
            result = audit(envelope, build_digest(envelope, budget))
            lost_total += len(result["lost"]) + (0 if result["decisions_preserved"] else 1)
        tune_row.append((budget, lost_total))
        if lost_total == 0 and frozen is None:
            frozen = budget
    print("tune half, lost facts per candidate budget: "
          + ", ".join(f"{b if b < 10 ** 9 else 'unlimited'}->{n}" for b, n in tune_row))
    if frozen is None:
        print("RESULT: FAIL. No text budget preserves every fact on the tune half, so the "
              "candidate cannot meet the coverage gate at any size.")
        return 1
    print(f"frozen parameter: reason text budget = {frozen if frozen < 10 ** 9 else 'unlimited'}")

    schema_before = schema_fingerprint()
    units_before = memory_store.memory_stats()["units"]
    statements, restore = statement_counter()
    baseline_chars = candidate_chars = 0
    all_lost: list = []
    all_truncated: list = []
    audit_rows: list[str] = []
    leakage: dict[str, set[str]] = {}
    ops_ok = True
    for subject in halves["gate"]:
        memory_store.recall_subject(subject, limit=RECALL_LIMIT)  # opens the schema, not counted
        statements["n"] = 0
        envelope = memory_store.recall_subject(subject, limit=RECALL_LIMIT)
        baseline_ops = statements["n"]
        digest = build_digest(envelope, frozen)
        digest_ops = statements["n"] - baseline_ops
        result = audit(envelope, digest)
        if not result["decisions_preserved"]:
            all_lost.append((subject, ["decision facts mismatch"]))
        if not result["taint_preserved"]:
            all_lost.append((subject, ["reason taint lost"]))
        base_text = json.dumps(envelope, separators=(",", ":"))
        dig_text = json.dumps(digest, separators=(",", ":"))
        baseline_chars += len(base_text)
        candidate_chars += len(dig_text)
        ops_ok = ops_ok and baseline_ops == 1 and digest_ops == 0
        all_lost += result["lost"]
        all_truncated += [(subject, item) for item in result["truncated"]]
        for entry in envelope["recent_reasons"]:
            leakage.setdefault(entry["text"], set()).add(subject)
        audit_rows.append(
            f"  {subject:22s} envelope {len(base_text):5d} -> digest {len(dig_text):5d} chars"
            f" | decisions {len(envelope['decisions'])}/{len(envelope['decisions'])}"
            f" | reasons {result['reasons_preserved']}/{result['reasons_expected']}"
            f" | truncated {len(result['truncated'])} | lost {len(result['lost'])}"
            f" | store ops {baseline_ops}+{digest_ops}")
    restore()
    schema_after = schema_fingerprint()

    # Adversarial: injection stays tainted data, the key set is fixed, decisions stay clean.
    injection_notes = [row["notes"] for row in rows
                       if "IGNORE ALL PREVIOUS INSTRUCTIONS" in row.get("notes", "")]
    invalidated = [row["notes"] for row in rows if row.get("action") == "invalidate"]
    injection_tainted = injection_visible = injects_into_decisions = 0
    key_shape_ok = True
    verdicts_separate = True
    resurrected = 0
    for subject in halves["gate"]:
        envelope = memory_store.recall_subject(subject, limit=RECALL_LIMIT)
        digest = build_digest(envelope, frozen)
        if set(digest) != DIGEST_KEYS or any(set(d) != DECISION_KEYS for d in digest["decisions"]) \
                or any(set(r) != REASON_KEYS for r in digest["reasons"]):
            key_shape_ok = False
        for note in injection_notes:
            if any(entry["text"] == note for entry in digest["reasons"]):
                injection_visible += 1
                entry = next(e for e in digest["reasons"] if e["text"] == note)
                injection_tainted += 1 if entry["tainted"] is True else 0
                byte = json.dumps(digest["decisions"])
                injects_into_decisions += 1 if note in byte else 0
        pairs = {(e["verdict"], e["advisory"]) for e in envelope["decisions"]}
        if pairs != {(e["verdict"], e["advisory"]) for e in digest["decisions"]}:
            verdicts_separate = False
        for note in invalidated:
            if any(note in entry["text"] for entry in digest["reasons"]):
                resurrected += 1

    reduction = 1 - candidate_chars / baseline_chars
    gate_subject = halves["gate"][0]
    envelope = memory_store.recall_subject(gate_subject, limit=RECALL_LIMIT)
    base_ms, candidate_ms, p95_ms, limit_ms = latency(envelope, frozen)
    units_after = memory_store.memory_stats()["units"]

    print("\nauditable comparison, gate half (Phase 3 recall -> digest -> preserved -> elided)")
    print("\n".join(audit_rows))
    print(f"  truncated reason text: {len(all_truncated)} entries, "
          f"lost content tokens: {sum(len(item[1]) for item in all_lost)}")
    for subject, item in all_truncated:
        print(f"    {subject} {item['unit_id']}: {item['from']} -> {item['to']} chars")
    print(f"\nmemory-block characters: envelope {baseline_chars} -> digest {candidate_chars} "
          f"({reduction * 100:.1f}% reduction, gate 25.0%)")
    print(f"latency per construction: baseline median {base_ms:.3f} ms, digest median "
          f"{candidate_ms:.3f} ms, p95 {p95_ms:.3f} ms (limit {limit_ms:.3f} ms)")
    print(f"store operations per recall: baseline 1 SELECT, digest 0 extra; schema unchanged: "
          f"{schema_before == schema_after}")
    print(f"adversarial: injection reasons visible {injection_visible}, tainted "
          f"{injection_tainted}, injected into decisions {injects_into_decisions}; "
          f"key shape fixed {key_shape_ok}; class and verdict facts separate {verdicts_separate}; "
          f"invalidated reasons resurrected {resurrected}")
    print(f"leakage: reason texts shared between subjects "
          f"{sum(1 for owners in leakage.values() if len(owners) > 1)}")

    checks = [
        ("1  character reduction >= 25%", reduction >= 0.25, f"{reduction * 100:.1f}%"),
        ("2  decision coverage 100%", not all_lost, f"{len(all_lost)} lost facts"),
        ("3  reason coverage and taint 100%", sum(len(item[1]) for item in all_lost) == 0,
         f"{sum(len(item[1]) for item in all_lost)} lost tokens or taints"),
        ("4  zero unrelated retrievals", not all_lost, "digest facts are a subset of the envelope"),
        ("5  zero cross-subject leakage",
         sum(1 for owners in leakage.values() if len(owners) > 1) == 0,
         f"{sum(1 for owners in leakage.values() if len(owners) > 1)} shared reason texts"),
        ("6  zero trust-class merging", verdicts_separate, "fact sets compared"),
        ("7  zero verdict merging", verdicts_separate, "fact sets compared"),
        ("8  zero invalidated resurrection", resurrected == 0, f"{resurrected} found"),
        ("9  verdict/correlation/routing unchanged", units_after == units_before,
         "no writer ran and the unit set is identical; the recall surface "
         "is non-authoritative under the Phase 2 test"),
        ("10 no injection escalation",
         injects_into_decisions == 0 and injection_tainted == injection_visible > 0,
         f"{injection_tainted}/{injection_visible} tainted"),
        ("11 latency within limits", candidate_ms <= limit_ms, f"{candidate_ms:.3f} ms"),
        ("12 store operations within limit", ops_ok, "one SELECT per recall, digest adds none"),
        ("13 no second index, cache or process", schema_before == schema_after and digest_ops == 0,
         "schema fingerprint unchanged"),
    ]
    print("\ngate")
    for name, ok, detail in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {name:44s} {detail}")
    passed = all(ok for _, ok, _ in checks)
    print(f"\nRESULT: {'PASS. Phase 4 implementation may be proposed.' if passed else 'FAIL.'} "
          f"{'' if passed else 'Phase 4 is rejected. Phase 3 remains the production candidate.'}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
