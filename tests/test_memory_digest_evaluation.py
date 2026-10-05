#!/usr/bin/env python3
"""Regression guard for the rejected Phase 4 evaluation.

Phase 4 was measured and rejected: no reason-text budget satisfies both the 25% reduction
and full semantic coverage once realistic long notes are in the data. These tests keep
that evidence alive, so a later proposal has to beat the measurement rather than weaken
the check. They exercise the evaluation harness, and no production module is involved.

Run: python3 -m pytest tests/test_memory_digest_evaluation.py -q
"""
from __future__ import annotations
import os

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import asyncio  # noqa: F401  (kept alongside the sibling memory tests for fixture parity)
import json
import pytest
from mcp_server.core import memory_store
from mcp_server.core.config import config
from tests import bench_memory_digest as bench

FROZEN = bench.FROZEN_REASON_CHARS


@pytest.fixture(autouse=True)
def _isolated():
    config.memory.enabled = False
    config.memory.db_path = ""
    config.memory.ttl_seconds = 7776000
    config.memory.max_units_per_subject = 50
    yield
    config.memory.enabled = False
    config.memory.db_path = ""
    config.memory.ttl_seconds = 7776000
    config.memory.max_units_per_subject = 50


def _subjects(fixture, half: str | None = None) -> list[str]:
    rows = bench.load_rows(fixture)
    bench.seed(rows)
    return list(dict.fromkeys(memory_store.subject_for_srcip(row["srcip"]) for row in rows
                              if half is None or row["half"] == half))


def _loss(subjects: list[str], budget: int) -> int:
    lost = 0
    for subject in subjects:
        envelope = memory_store.recall_subject(subject, limit=bench.RECALL_LIMIT)
        result = bench.audit(envelope, bench.build_digest(envelope, budget))
        lost += sum(len(item[1]) for item in result["lost"])
    return lost


def _chars(subjects: list[str], budget: int) -> tuple[int, int]:
    baseline = candidate = 0
    for subject in subjects:
        envelope = memory_store.recall_subject(subject, limit=bench.RECALL_LIMIT)
        baseline += len(json.dumps(envelope, separators=(",", ":")))
        candidate += len(json.dumps(bench.build_digest(envelope, budget), separators=(",", ":")))
    return baseline, candidate


def test_longnote_fixture_stays_representative():
    """A pass may not come from short notes alone, which is what the first gate run did."""
    rows = bench.load_rows(bench.LONGNOTE_FIXTURE)
    longest = max(len(row.get("notes", "")) for row in rows)
    assert FROZEN == 200
    assert longest > FROZEN, f"longest long-note reason is {longest} characters"


def test_frozen_budget_loses_semantic_content_on_long_notes():
    """The measured failure: at the frozen budget every long reason loses content tokens."""
    subjects = _subjects(bench.LONGNOTE_FIXTURE)
    truncated = lost_reasons = 0
    for subject in subjects:
        envelope = memory_store.recall_subject(subject, limit=bench.RECALL_LIMIT)
        result = bench.audit(envelope, bench.build_digest(envelope, FROZEN))
        truncated += len(result["truncated"])
        lost_reasons += len(result["lost"])
    assert truncated == 6 and lost_reasons >= 5
    assert _loss(subjects, FROZEN) >= 60


def test_no_budget_satisfies_both_requirements_on_long_notes():
    """The structural finding: the smallest coverage-preserving budget drops below 25%."""
    subjects = _subjects(bench.LONGNOTE_FIXTURE)
    preserving = next(budget for budget in bench.TUNE_BUDGETS if _loss(subjects, budget) == 0)
    assert preserving == 400, f"coverage first holds at {preserving}"
    baseline, candidate = _chars(subjects, preserving)
    reduction = 1 - candidate / baseline
    assert reduction < 0.25, f"reduction at the preserving budget is {reduction:.3f}"


def test_frozen_gate_fixture_result_stands_at_31_8_percent():
    """The gate result that remains valid on short notes, with zero coverage loss."""
    subjects = _subjects(bench.FIXTURE, half="gate")
    assert _loss(subjects, FROZEN) == 0
    baseline, candidate = _chars(subjects, FROZEN)
    reduction = 1 - candidate / baseline
    assert reduction == pytest.approx(0.318, abs=0.005)
    assert reduction >= 0.25
