#!/usr/bin/env python3
"""Opt-in live validation harness behavior; no live API call is made."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")

import pytest

from mcp_server.threat_intel import virustotal as vt
from mcp_server.threat_intel import virustotal_live as live


def _data(cached=False, retrieved_at=None, **extra):
    return {
        "indicator": "1.1.1.1",
        "kind": "ip_addresses",
        "http_status": 200,
        "analysis_stats": {"malicious": 1, "suspicious": 0, "harmless": 90,
                           "undetected": 1, "timeout": 0},
        "stats_complete": True,
        "missing_stats": [],
        "malicious": 1,
        "suspicious": 0,
        "harmless": 90,
        "undetected": 1,
        "timeout": 0,
        "total_engines": 92,
        "detection_percent": 1,
        "community_reputation": 117,
        "as_owner": "Cloudflare, Inc.",
        "asn": 13335,
        "network": "1.1.1.0/24",
        "country": "AU",
        "total_votes": {"harmless": 1, "malicious": 0},
        "tags": ["cdn"],
        "last_analysis_date": 1794095894,
        "retrieved_at": retrieved_at or datetime.now(timezone.utc).isoformat(),
        "cached": cached,
        **extra,
    }


def test_live_validation_requires_confirmation(monkeypatch):
    monkeypatch.setattr(vt, "lookup", lambda *a, **k: pytest.fail("lookup called"))
    output = live.run("1.1.1.1", confirm=False, api_key_configured=True)
    assert output["validation"] == "not_performed"
    assert output["reason"] == "confirmation_required"


def test_live_validation_requires_a_key(monkeypatch):
    monkeypatch.setattr(vt, "lookup", lambda *a, **k: pytest.fail("lookup called"))
    output = live.run("1.1.1.1", confirm=True, api_key_configured=False)
    assert output["validation"] == "not_performed"
    assert output["reason"] == "api_key_not_configured"


def test_live_validation_requires_ioc_sharing_acknowledgement(monkeypatch):
    monkeypatch.setattr(vt, "lookup", lambda *a, **k: pytest.fail("lookup called"))
    output = live.run("1.1.1.1", confirm=True, api_key_configured=True)
    assert output["validation"] == "not_performed"
    assert output["reason"] == "ioc_sharing_acknowledgement_required"


def test_live_validation_rejects_private_ip(monkeypatch):
    monkeypatch.setattr(vt, "lookup", lambda *a, **k: pytest.fail("lookup called"))
    output = live.run("10.0.0.1", confirm=True, acknowledge_sharing=True,
                      api_key_configured=True)
    assert output["validation"] == "not_performed"
    assert output["reason"] == "invalid_or_non_public_ip"


def test_live_validation_reports_quota_and_cache(monkeypatch):
    now = datetime.now(timezone.utc).isoformat()
    monkeypatch.setattr(vt, "VIRUSTOTAL_CACHE_TTL", 3600)
    monkeypatch.setattr(vt, "lookup", lambda *a, **k: _data(cached=True, retrieved_at=now))
    monkeypatch.setattr(live, "_quota_snapshot", lambda: {
        "budget": 50, "spent": 7, "remaining": 43, "daily_spent": 7,
        "daily_limit": 500, "rate_spent": 1, "rate_limit": 4, "window_open": True})
    output = live.run("1.1.1.1", confirm=True, acknowledge_sharing=True,
                      api_key_configured=True)
    result = output["results"][0]
    assert output["validation"] == "performed"
    assert result["outcome"] == "success"
    assert result["http_status"] == 200
    assert result["malicious"] == 1
    assert result["cached"] is True
    assert result["source"] == "cache"
    assert output["live_api_observed"] is False
    assert result["cache_age_seconds"] >= 0
    assert result["cache_expired"] is False
    assert result["quota_before"]["spent"] == 7
    assert result["quota_after"]["spent"] == 7
    assert "test-key" not in json.dumps(output)


def test_live_validation_reports_optional_ipv6(monkeypatch):
    calls = []

    def fake_lookup(kind, value, **kwargs):
        calls.append(value)
        return _data(cached=False)

    monkeypatch.setattr(vt, "lookup", fake_lookup)
    monkeypatch.setattr(live, "_quota_snapshot", lambda: {"spent": 1})
    output = live.run("1.1.1.1", "2606:4700:4700::1111", confirm=True,
                      acknowledge_sharing=True, api_key_configured=True)
    assert output["validation"] == "performed"
    assert output["live_api_observed"] is True
    assert [item["input"] for item in output["results"]] == ["ipv4", "ipv6"]
    assert calls == ["1.1.1.1", "2606:4700:4700::1111"]


def test_live_validation_reports_http_error(monkeypatch):
    def fake_lookup(*args, **kwargs):
        raise vt.VirusTotalError("auth", "auth_error", http_status=403)

    monkeypatch.setattr(vt, "lookup", fake_lookup)
    monkeypatch.setattr(live, "_quota_snapshot", lambda: {"spent": 1})
    output = live.run("1.1.1.1", confirm=True, acknowledge_sharing=True,
                      api_key_configured=True)
    result = output["results"][0]
    assert result["outcome"] == "error"
    assert result["error_kind"] == "auth_error"
    assert result["http_status"] == 403


def test_cli_without_confirmation_does_not_call_lookup(monkeypatch, capsys):
    monkeypatch.setattr(vt, "lookup", lambda *a, **k: pytest.fail("lookup called"))
    assert live.main(["--ip", "1.1.1.1"]) == 2
    assert "not_performed" in capsys.readouterr().out


def test_cli_confirm_without_sharing_ack_does_not_call_lookup(monkeypatch, capsys):
    monkeypatch.setattr(live, "VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(vt, "lookup", lambda *a, **k: pytest.fail("lookup called"))
    assert live.main(["--ip", "1.1.1.1", "--confirm-live"]) == 2
    output = capsys.readouterr().out
    assert "ioc_sharing_acknowledgement_required" in output
