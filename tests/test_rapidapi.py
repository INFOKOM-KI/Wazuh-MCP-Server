#!/usr/bin/env python3
"""
Tests for RapidAPI capability lookups - pure helpers + input validation.
No network calls: the request helper and tools are exercised indirectly.
"""
from __future__ import annotations
import os
os.environ.setdefault("WAZUH_INDEXER_URL", "https://idx:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "pw")
import json
import pytest
from mcp_server.threat_intel import rapidapi as r


def test_headers_require_key():
    os.environ.pop("RAPIDAPI_KEY", None)
    with pytest.raises(RuntimeError):
        r._rapidapi_headers("example.p.rapidapi.com")


def test_headers_include_key():
    os.environ["RAPIDAPI_KEY"] = "test-key"
    h = r._rapidapi_headers("example.p.rapidapi.com")
    assert h["x-rapidapi-key"] == "test-key"
    assert h["x-rapidapi-host"] == "example.p.rapidapi.com"
    assert h["Accept"] == "application/json"


def test_dynamic_markdown_recognizes_keys():
    out = r._dynamic_markdown("T", {"status": "blacklisted", "total": 3})
    assert "blacklisted" in out
    assert "total" in out


def test_dynamic_markdown_falls_back_to_json():
    out = r._dynamic_markdown("T", {"unrecognized_shape": {"nested": [1, 2, 3]}})
    assert "```json" in out  # unknown schema -> dump full body rather than crash


def test_envelope_wraps_raw():
    d = json.loads(r._envelope("1.2.3.4", "apiverve_ip_blacklist", {"a": 1}))
    assert d == {"query": "1.2.3.4", "source": "apiverve_ip_blacklist", "result": {"a": 1}}


def test_breach_email_validation():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        r.BreachCheckInput(email="not-an-email")
    assert r.BreachCheckInput(email="csirt@tangerangkota.go.id").email == "csirt@tangerangkota.go.id"


def test_ip_input_rejects_private():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        r._IpInput(ip="192.168.1.1")  # RFC1918 -> public-IP validator rejects
