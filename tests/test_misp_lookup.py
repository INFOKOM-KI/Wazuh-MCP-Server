#!/usr/bin/env python3
"""
Tests for mcp_server/tools/misp.py the adaptive MISP response normalizer,
the HTTP-200 error detector, and the PII allowlist reducer.
The normalizer is the part that has to survive MISP 2.4.x - 2.5+ shape drift,
so every wrapper shape MISP has emitted gets an explicit case.
"""
from __future__ import annotations
import os

# mcp_server/__init__.py calls init_config() at import and hard-fails without
# WAZUH_INDEXER_* (ConfigurationError). Seed them at module level so this file
# passes in isolation, not only when a peer module happens to import first.
os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import pytest
from mcp_server.core.exceptions import ThreatIntelError
from mcp_server.tools.misp import (
    _check_misp_error,
    _extract_attributes,
    _strip_event,
    _strip_misp_attributes,
)

ATTR = {
    "id": "1",
    "event_id": "7",
    "type": "domain",
    "category": "Network activity",
    "value": "evil.example",
    "to_ids": True,
    "first_seen": "2026-09-01",
}


# Adaptive normalizer test
def test_extracts_nested_response_attribute():
    assert _extract_attributes({"response": {"Attribute": [ATTR]}}) == [ATTR]


def test_extracts_response_list_of_attributes():
    assert _extract_attributes({"response": [ATTR]}) == [ATTR]


def test_extracts_root_attribute_key():
    assert _extract_attributes({"Attribute": [ATTR]}) == [ATTR]


def test_extracts_bare_root_list():
    assert _extract_attributes([ATTR, {**ATTR, "id": "2"}]) == [ATTR, {**ATTR, "id": "2"}]


def test_flattens_attributes_nested_inside_events():
    payload = {"response": {"Event": [{"id": "7", "info": "campaign", "Attribute": [ATTR]}]}}
    assert _extract_attributes(payload) == [ATTR]


def test_attribute_less_event_degrades_to_metadata_record():
    payload = {"response": {"Event": [{"id": "7", "info": "campaign", "date": "2026-09-01"}]}}
    assert _extract_attributes(payload) == [{"id": "7", "date": "2026-09-01"}]


def test_unknown_wrapper_is_traversed():
    assert _extract_attributes({"result": {"data": {"Attribute": [ATTR]}}}) == [ATTR]


@pytest.mark.parametrize("payload", [None, "text", 42, {}, {"message": "no results"}])
def test_non_attribute_payloads_return_empty(payload):
    assert _extract_attributes(payload) == []


def test_scalar_children_are_not_mistaken_for_attributes():
    # A Tag object has no 'value'; it must not be returned as a record.
    assert _extract_attributes({"Tag": [{"name": "tlp:white"}]}) == []


# HTTP 200 logic errors
def test_message_only_body_raises():
    with pytest.raises(ThreatIntelError):
        _check_misp_error(
            {"name": "Forbidden", "message": "Insufficient privileges",
             "url": "/attributes/restSearch"},
            "attributes/restSearch",
        )


def test_errors_body_raises():
    with pytest.raises(ThreatIntelError):
        _check_misp_error({"errors": ["Invalid value for limit"]}, "attributes/restSearch")


def test_normal_result_body_does_not_raise():
    _check_misp_error({"response": {"Attribute": []}}, "attributes/restSearch")
    _check_misp_error([ATTR], "attributes/restSearch")
    _check_misp_error(None, "attributes/restSearch")


# PII allowlist reducer
def test_strip_drops_free_text_and_keeps_technical_fields():
    stripped = _strip_misp_attributes([{
        **ATTR,
        "comment": "contact Marco Maske +49 228 92934876",
        "Tag": [{"name": "tlp:white"}],
        "Event": {"id": "7", "Orgc": {"name": "CIRCL"}},
    }])
    assert len(stripped) == 1
    record = stripped[0]
    assert record["value"] == "evil.example"
    assert record["type"] == "domain"
    assert record["tags"] == ["tlp:white"]
    assert record["event"]["org"] == "CIRCL"
    assert "comment" not in record


def test_event_info_is_gated_by_policy_flag():
    event = {"id": "7", "info": "victim: Acme GmbH"}
    assert _strip_event(event, keep_info=False) == {"id": "7"}
    assert _strip_event(event, keep_info=True)["info"] == "victim: Acme GmbH"


def test_strip_bounds_long_values_and_drops_non_dicts():
    long_value = "A" * 5000
    stripped = _strip_misp_attributes([{**ATTR, "value": long_value}, "not-a-dict"])
    assert len(stripped) == 1
    assert len(stripped[0]["value"]) == 512


# Request path
def test_tool_posts_restsearch_and_renders_markdown(monkeypatch):
    import asyncio
    import mcp_server.tools.misp as mod
    from mcp_server.tools.misp import MispIocLookupInput, blueteam_misp_ioc_lookup

    cfg = type("FakeMispConfig", (), {
        "url": "https://misp.local", "api_key": "k", "verify_ssl": True,
        "cache_ttl": 900, "min_interval": 0.0, "max_concurrent": 1,
        "timeout": 5.0, "enabled": True,
    })()
    monkeypatch.setattr(mod, "_misp_config", lambda: cfg)
    monkeypatch.setattr(mod, "_misp_headers", lambda: {"Authorization": "k"})

    captured = {}

    class _Resp:
        status_code = 200
        text = ""

        def json(self):
            return {"response": {"Attribute": [dict(ATTR, comment="Marco Maske")]}}

    async def _fake_api_call(method, url, **kw):
        captured.update(method=method, url=url, kw=kw)
        return _Resp()

    async def _fake_probe():
        return {"probed": True, "version": "2.4.150", "note": ""}

    monkeypatch.setattr(mod, "_api_call", _fake_api_call)
    monkeypatch.setattr(mod, "_ensure_capabilities", _fake_probe)

    out = asyncio.run(blueteam_misp_ioc_lookup(MispIocLookupInput(value="evil.example")))

    assert captured["method"] == "post"
    assert captured["url"] == "https://misp.local/attributes/restSearch"
    assert captured["kw"]["json"]["returnFormat"] == "json"
    assert captured["kw"]["json"]["value"] == "evil.example"
    assert captured["kw"]["json"]["limit"] == 50
    assert "metadata" not in captured["kw"]["json"]
    assert "evil.example" in out
    assert "Marco Maske" not in out
    assert "2.4.150" in out
