#!/usr/bin/env python3
"""Tests for core/query_norm.py: deterministic NFKC query normalization.
The load-bearing claim is that NFKC cannot rewrite an indicator. NFKC leaves every code
point at or below U+007E alone, so the golden table below asserts identity on the shapes
this repository retrieves on, not only on the full-width inputs the rewrite repairs.
"""

from __future__ import annotations
import os
import unicodedata

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import pytest

from mcp_server.core import term_sim
from mcp_server.core.config import config
from mcp_server.core.query_norm import normalize_query, query_for_retrieval

# Every shape the retrieval paths must be able to match. None of these may be rewritten.
INDICATORS = [
    "203.0.113.9",
    "2001:db8::1",
    "evil.example.com",
    "xn--bcher-kva.example",
    "mail.example.com:587",
    "http://evil.example.com/a?b=1&c=2",
    "https://evil.example.com:8443/p?q=1#f",
    "/var/www/html/upload.php",
    "C:\\Windows\\Temp\\x.exe",
    "d41d8cd98f00b204e9800998ecf8427e",
    "cve-2024-3400",
    "T1059.001",
    "10.0.0.0/8",
    "analyst@example.com",
    "00:1A:2B:3C:4D:5E",
]

FULL_WIDTH = [
    ("２０３．０．１１３．９", "203.0.113.9"),
    ("ｈｔｔｐ：／／ｅｖｉｌ．ｅｘａｍｐｌｅ．ｃｏｍ／ａ？ｂ＝１",
     "http://evil.example.com/a?b=1"),
    ("ＣＶＥ－２０２４－３４００", "CVE-2024-3400"),
    ("／ｖａｒ／ｗｗｗ／ｈｔｍｌ／ｕｐｌｏａｄ．ｐｈｐ", "/var/www/html/upload.php"),
]


@pytest.fixture(autouse=True)
def _flag():
    saved = config.rag.query_normalize
    config.rag.query_normalize = False
    yield
    config.rag.query_normalize = saved


def test_full_width_ipv4_folds_to_ascii():
    assert normalize_query("２０３．０．１１３．９") == "203.0.113.9"


@pytest.mark.parametrize("full,ascii_form", FULL_WIDTH)
def test_full_width_forms_fold_to_ascii(full, ascii_form):
    assert normalize_query(full) == ascii_form


@pytest.mark.parametrize("indicator", INDICATORS)
def test_no_indicator_shape_is_rewritten(indicator):
    assert normalize_query(indicator) == indicator


@pytest.mark.parametrize("indicator", INDICATORS)
def test_indicators_still_tokenize_after_normalization(indicator):
    """The normalizer runs before the tokenizer. A shape the tokenizer keeps whole must
    still be whole after both; one it already splits is not a normalization fault."""
    tokens = term_sim.tokenize(normalize_query(indicator))
    assert tokens, indicator
    if indicator == "203.0.113.9":
        assert tokens == ["203.0.113.9"]
        assert term_sim.ner_weight(tokens[0]) == term_sim.NUMERIC_WEIGHT


def test_ipv4_keeps_its_numeric_weight_not_the_indicator_weight():
    """Phase 1 orders the numeric check before the indicator check, so an IPv4 literal
    scores 2.0 rather than 3.0. Normalization must not disturb that."""
    assert term_sim.ner_weight(normalize_query("203.0.113.9")) == 2.0


def test_collapses_whitespace_runs():
    assert normalize_query("  a\t b\n\nc  ") == "a b c"


def test_full_width_space_becomes_a_single_half_width_space():
    assert normalize_query("a\u3000b") == "a b"


@pytest.mark.parametrize("text", ["203.0.113.9", "a  b\tc", "２０３．０．１１３．９", "   "])
def test_idempotent(text):
    once = normalize_query(text)
    assert normalize_query(once) == once


@pytest.mark.parametrize("text", ["", "   ", "\t\n ", "\u3000"])
def test_empty_and_whitespace_only_return_empty(text):
    """Empty is not an error: callers hand it to the existing empty-query path."""
    assert normalize_query(text) == ""


def test_none_returns_empty():
    assert normalize_query(None) == ""


def test_normalization_never_deletes_a_character():
    """NFKC has no ignore mappings, unlike NFKC_Casefold. A caller can therefore never
    receive an empty string from a query that was not already blank."""
    for text in ["\u00ad", "\u200b", "\ufeff", "\u2060", "a\u200bb", "\u00ad\u200b"]:
        result = normalize_query(text)
        assert result != ""
        assert result == unicodedata.normalize("NFKC", text)


def test_flag_off_returns_the_input_unchanged():
    config.rag.query_normalize = False
    for text in ["２０３．０．１１３．９", "a  b", "203.0.113.9"]:
        assert query_for_retrieval(text) is text


def test_flag_on_normalizes():
    config.rag.query_normalize = True
    assert query_for_retrieval("２０３．０．１１３．９") == "203.0.113.9"


def test_flag_on_leaves_ascii_alone():
    config.rag.query_normalize = True
    for indicator in INDICATORS:
        assert query_for_retrieval(indicator) == indicator


if __name__ == "__main__":
    import inspect
    import sys
    import traceback

    tests = [f for f in dir() if f.startswith("test_")
             and not inspect.signature(globals()[f]).parameters]
    passed = 0
    for name in tests:
        try:
            globals()[name]()
            print(f"PASS {name}")
            passed += 1
        except Exception:
            print(f"FAIL {name}")
            traceback.print_exc()
    print(f"\n{passed}/{len(tests)} passed")
    sys.exit(0 if passed == len(tests) else 1)
