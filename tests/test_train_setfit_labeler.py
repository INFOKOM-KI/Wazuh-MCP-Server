#!/usr/bin/env python3
"""Tests for scripts/train_setfit_labeler.py.
Only the corpus-shaping logic runs here; the training body needs torch, datasets
and a network download, so it stays untested in this staging tree.
"""
from __future__ import annotations
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from train_setfit_labeler import select_train_rows


def _cases() -> list[dict]:
    return ([{"truth": "Impact"} for _ in range(10)]
            + [{"truth": "Execution"} for _ in range(10)])


def test_select_train_rows_is_stratified_and_deterministic():
    picked = select_train_rows(_cases(), per_class=3, seed=7)
    assert len(picked) == 6
    assert Counter(case["truth"] for case in picked) == Counter({"Impact": 3,
                                                                "Execution": 3})
    assert picked == select_train_rows(_cases(), per_class=3, seed=7)


def test_select_train_rows_keeps_everything_when_uncapped():
    cases = _cases()
    assert select_train_rows(cases, per_class=0, seed=7) == cases


def test_select_train_rows_returns_fewer_when_a_class_is_small():
    cases = _cases() + [{"truth": "Collection"}]
    picked = select_train_rows(cases, per_class=5, seed=1)
    assert Counter(case["truth"] for case in picked) == Counter(
        {"Impact": 5, "Execution": 5, "Collection": 1})
