#!/usr/bin/env python3
"""Tests for Sangfor blocklist markdown table rendering"""
from __future__ import annotations
import os

# Minimal env so importing mcp_server.tools.alert_enrichment passes config
# validation (WAZUH_INDEXER_URL/PASSWORD are required at import time).
os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")


def _render(raw):
    from mcp_server.tools.alert_enrichment import _format_sangfor_blocklist_markdown
    return _format_sangfor_blocklist_markdown(raw)


def test_markdown_from_raw_list():
    out = _render([{
        "ip_address": "149.102.230.133",
        "isp": "Datacamp Limited",
        "location": "Germany - Frankfurt am Main",
        "blockmode": "permanent",
        "created_at": "2026-09-01 00:03:45",
        "updated_at": None,
        "wazuh_score": 69,
        "tip_score": 73.13,
        "overall_score": 70.65,
    }])
    assert "Sangfor Blocklist (1 IPs)" in out
    assert "149.102.230.133" in out
    assert "Datacamp Limited" in out
    assert "Germany - Frankfurt am Main" in out
    assert "permanent" in out
    assert "69" in out
    assert "73.13" in out
    assert "70.65" in out


def test_markdown_from_normalized_entries_dict():
    out = _render({"entries": [{"ip_address": "1.2.3.4", "wazuh_score": 10}]})
    assert "Sangfor Blocklist (1 IPs)" in out
    assert "1.2.3.4" in out
    assert "10" in out


def test_markdown_from_data_key_dict():
    out = _render({"data": [{"ip_address": "5.6.7.8"}]})
    assert "5.6.7.8" in out


def test_markdown_empty():
    out = _render([])
    assert "Sangfor Blocklist (0 IPs)" in out
    assert "No entries in this window." in out


def test_markdown_empty_dict():
    out = _render({"entries": []})
    assert "Sangfor Blocklist (0 IPs)" in out


def test_markdown_truncates_to_50_rows():
    out = _render([{"ip_address": f"10.0.{i}.1"} for i in range(60)])
    assert "Sangfor Blocklist (60 IPs)" in out   # header reports full count
    assert "10.0.49.1" in out                     # 50th row rendered
    assert "10.0.50.1" not in out                 # 51st row dropped


if __name__ == "__main__":
    import sys, traceback
    tests = [f for f in dir() if f.startswith("test_")]
    passed = 0
    for t in tests:
        try:
            globals()[t]()
            print(f"PASS {t}")
            passed += 1
        except Exception:
            print(f"FAIL {t}")
            traceback.print_exc()
    print(f"\n{passed}/{len(tests)} passed")
    sys.exit(0 if passed == len(tests) else 1)
