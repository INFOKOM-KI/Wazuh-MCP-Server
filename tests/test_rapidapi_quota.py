#!/usr/bin/env python3
"""
Tests for the account-wide RapidAPI budget guard, its persistent state, and the
bulk-lookup path. No network calls.
The guard is the only thing standing between a scheduled report pass and the whole
month's allowance, so the cases that matter here are the negative ones: a closed
budget must refuse before any request, a spent budget must stay spent across a
restart, and a failed request must not silently hand the allowance back.
"""
from __future__ import annotations
import os
os.environ.setdefault("WAZUH_INDEXER_URL", "https://idx:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "pw")
os.environ.setdefault("RAPIDAPI_KEY", "test-key")
import json
import time
import httpx
import pytest
from pydantic import ValidationError
from mcp_server.core.exceptions import ThreatIntelError
from mcp_server.core.http_client import CircuitOpenError, _rate_limit_text
from mcp_server.threat_intel import rapidapi as r
from mcp_server.threat_intel._cache import PersistentJsonlCache
from mcp_server.threat_intel.rapidapi_quota import RapidApiBudget

# Every request test arms the budget explicitly: the guard is account-wide, so a
# module-level default of 0 would otherwise refuse inside _rapidapi_request and mask
# the behaviour each test is actually asserting.
def _armed(n: int = 5) -> RapidApiBudget:
    return RapidApiBudget(budget=n, hours=1)


def test_closed_by_default():
    """The default deployment must not be able to spend: a report run armed by
    omission is how 100 requests disappear in five days."""
    with pytest.raises(ThreatIntelError, match="Budget closed"):
        RapidApiBudget().check()


def test_armed_budget_allows_then_exhausts():
    budget = RapidApiBudget(budget=2, hours=1)
    budget.check()
    budget.charge()
    assert budget.remaining == 1
    budget.check()
    budget.charge()
    with pytest.raises(ThreatIntelError, match="exhausted"):
        budget.check()


def test_exhausted_message_names_the_reset_date():
    budget = RapidApiBudget(budget=1, hours=1)
    budget.check()
    budget.charge()
    with pytest.raises(ThreatIntelError) as err:
        budget.check()
    assert budget.state()["resets"] in str(err.value)

def test_allowance_is_capped_by_the_account_limit():
    """A typo in the arm amount cannot buy more than the account will serve."""
    assert RapidApiBudget(budget=100, monthly_cap=3).allowance == 3
    assert RapidApiBudget(budget=4, monthly_cap=100).allowance == 4


def test_expired_window_refuses_without_resetting_the_month():
    budget = RapidApiBudget(budget=5, hours=4)
    budget.check()
    budget.charge()
    budget._armed_at = time.time() - 5 * 3600

    with pytest.raises(ThreatIntelError, match="Arm window closed"):
        budget.check()
    assert budget.state()["spent"] == 1
    assert budget.state()["window_open"] is False


def test_state_survives_a_restart(tmp_path):
    """Bouncing the process must not restore a budget the account was billed for."""
    path = str(tmp_path / "state.jsonl")
    first = RapidApiBudget(budget=2, hours=4, store=PersistentJsonlCache(path))
    for _ in range(2):
        first.check()
        first.charge()

    restarted = RapidApiBudget(budget=2, hours=4, store=PersistentJsonlCache(path))
    assert restarted.state()["spent"] == 2
    with pytest.raises(ThreatIntelError, match="exhausted"):
        restarted.check()


def test_arm_window_survives_a_restart(tmp_path):
    """The window is an incident window, not a process lifetime, so a restart three
    hours in leaves one hour and not a fresh four."""
    path = str(tmp_path / "state.jsonl")
    first = RapidApiBudget(budget=5, hours=4, store=PersistentJsonlCache(path))
    first.check()
    first._armed_at = time.time() - 3 * 3600
    first._persist()

    restarted = RapidApiBudget(budget=5, hours=4, store=PersistentJsonlCache(path))
    assert restarted.state()["window_open"] is True
    restarted.check()

    expired = RapidApiBudget(budget=5, hours=4, store=PersistentJsonlCache(path))
    expired._armed_at = time.time() - 5 * 3600
    with pytest.raises(ThreatIntelError, match="Arm window closed"):
        expired.check()


def test_new_month_refills_the_counter(tmp_path):
    path = str(tmp_path / "state.jsonl")
    store = PersistentJsonlCache(path)
    store.set_quota({"m": "2000-01", "s": 99, "a": time.time()})
    assert RapidApiBudget(budget=5, hours=4, store=store).state()["spent"] == 0


def test_persistent_cache_round_trips(tmp_path):
    path = str(tmp_path / "state.jsonl")
    PersistentJsonlCache(path).set("k", {"a": 1}, ttl=60)
    assert PersistentJsonlCache(path).get("k") == {"a": 1}


def test_persistent_cache_drops_expired_entries(tmp_path):
    path = str(tmp_path / "state.jsonl")
    PersistentJsonlCache(path).set("k", {"a": 1}, ttl=-1)
    assert PersistentJsonlCache(path).get("k") is None


def test_empty_path_stays_in_memory():
    cache = PersistentJsonlCache("")
    assert cache.enabled is False
    cache.set("k", 1, ttl=60)
    cache.set_quota({"m": "2026-09"})
    assert cache.get("k") == 1
    assert cache.get_quota() == {"m": "2026-09"}


def test_torn_final_line_does_not_lose_the_state(tmp_path):
    """A process killed mid-append leaves half a line; the next start must still
    read the quota record rather than resetting to a full allowance."""
    path = str(tmp_path / "state.jsonl")
    PersistentJsonlCache(path).set_quota({"m": time.strftime("%Y-%m", time.gmtime()),
                                          "s": 7, "a": time.time()})
    with open(path, "a", encoding="utf-8") as fh:
        fh.write('{"t": "c", "k": "tru')

    assert PersistentJsonlCache(path).get_quota()["s"] == 7


def _ok(method, url, **kw):
    return httpx.Response(200, json={"ok": True}, request=httpx.Request(method, url))


@pytest.mark.asyncio
async def test_request_disables_retries_and_charges_once(monkeypatch):
    seen = {}

    async def fake(method, url, **kw):
        seen.update(kw)
        seen["method"] = method
        return _ok(method, url)

    monkeypatch.setattr(r, "_api_call", fake)
    monkeypatch.setattr(r, "_QUOTA", _armed(3))

    assert await r._rapidapi_request("get", "h.example", "/p") == {"ok": True}
    assert seen["max_retries"] == 0
    assert r._QUOTA.state()["spent"] == 1


@pytest.mark.asyncio
async def test_closed_budget_refuses_before_the_request(monkeypatch):
    called = False

    async def fake(method, url, **kw):
        nonlocal called
        called = True
        return _ok(method, url)

    monkeypatch.setattr(r, "_api_call", fake)
    monkeypatch.setattr(r, "_QUOTA", RapidApiBudget())

    with pytest.raises(ThreatIntelError, match="Budget closed"):
        await r._rapidapi_request("get", "h.example", "/p")
    assert called is False


@pytest.mark.asyncio
async def test_circuit_open_does_not_spend_the_budget(monkeypatch):
    async def boom(method, url, **kw):
        raise CircuitOpenError("circuit breaker open for 'rapidapi'")

    monkeypatch.setattr(r, "_api_call", boom)
    monkeypatch.setattr(r, "_QUOTA", _armed(1))

    with pytest.raises(CircuitOpenError):
        await r._rapidapi_request("get", "h.example", "/p")
    assert r._QUOTA.state()["spent"] == 0


@pytest.mark.asyncio
async def test_upstream_error_still_charges(monkeypatch):
    """The gateway counted the request even though it answered 500, so handing the
    allowance back would overspend the account."""
    async def boom(method, url, **kw):
        raise httpx.HTTPStatusError(
            "boom", request=httpx.Request(method, url), response=httpx.Response(500))

    monkeypatch.setattr(r, "_api_call", boom)
    monkeypatch.setattr(r, "_QUOTA", _armed(1))

    with pytest.raises(httpx.HTTPStatusError):
        await r._rapidapi_request("get", "h.example", "/p")
    assert r._QUOTA.state()["spent"] == 1


@pytest.mark.asyncio
async def test_cache_hit_costs_no_budget(monkeypatch):
    monkeypatch.setattr(r, "_QUOTA", _armed(1))

    async def fake(method, url, **kw):
        return _ok(method, url)

    monkeypatch.setattr(r, "_api_call", fake)
    monkeypatch.setattr(r, "_STORE", PersistentJsonlCache(""))
    await r._rapidapi_get("host.example", "/cached")
    await r._rapidapi_get("host.example", "/cached")
    assert r._QUOTA.state()["spent"] == 1


@pytest.mark.asyncio
async def test_empty_persistent_store_is_still_used(monkeypatch, tmp_path):
    """PersistentJsonlCache defines __len__, so an empty instance is falsy. Testing
    truthiness sent every cached response to the shared in-memory cache instead, which
    silently undid the point of BLUETEAM_RAPIDAPI_CACHE and spent the budget again
    after every restart."""
    monkeypatch.setattr(r, "_QUOTA", _armed(5))
    store = PersistentJsonlCache(str(tmp_path / "state.jsonl"))
    monkeypatch.setattr(r, "_STORE", store)
    calls = 0

    async def fake(method, url, **kw):
        nonlocal calls
        calls += 1
        return _ok(method, url)

    monkeypatch.setattr(r, "_api_call", fake)
    await r._rapidapi_get("h.example", "/cached-twice")
    await r._rapidapi_get("h.example", "/cached-twice")

    assert calls == 1
    assert len(store) == 1, "the response must land in the persistent store"
    assert '"t": "c"' in (tmp_path / "state.jsonl").read_text(encoding="utf-8")


def test_bulk_cache_key_ignores_order():
    a = r._bulk_cache_key("h", "/p", ["185.220.101.1", "103.46.186.148"])
    b = r._bulk_cache_key("h", "/p", ["103.46.186.148", "185.220.101.1"])
    assert a == b
    assert a != r._bulk_cache_key("h", "/p", ["185.220.101.1"])


def test_bulk_input_rejects_private_ips():
    with pytest.raises(ValidationError):
        r.BulkIpIntelInput(ips=["10.0.0.1"])


def test_bulk_input_caps_the_list():
    over = [f"9.9.9.{i}" for i in range(1, r._BULK_MAX_IPS + 2)]
    with pytest.raises(ValidationError):
        r.BulkIpIntelInput(ips=over)
    assert len(r.BulkIpIntelInput(ips=over[:-1]).ips) == r._BULK_MAX_IPS


def test_bulk_input_rejects_an_empty_list():
    with pytest.raises(ValidationError):
        r.BulkIpIntelInput(ips=[])


@pytest.mark.asyncio
async def test_bulk_sends_one_request_for_many_ips(monkeypatch):
    seen = {}

    async def fake(method, url, **kw):
        seen.update(kw)
        seen["method"] = method
        return _ok(method, url)

    monkeypatch.setattr(r, "_api_call", fake)
    monkeypatch.setattr(r, "_QUOTA", _armed(5))
    monkeypatch.setattr(r, "_STORE", PersistentJsonlCache(""))

    await r._rapidapi_post("h.example", "/v1/ip-intel/bulk",
                           {"ips": ["185.220.101.1", "103.46.186.148"]})
    assert seen["method"] == "post"
    assert seen["json"] == {"ips": ["185.220.101.1", "103.46.186.148"]}
    assert seen["max_retries"] == 0
    assert r._QUOTA.state()["spent"] == 1


def _resp(headers: dict[str, str]) -> httpx.Response:
    return httpx.Response(429, headers=headers,
                          request=httpx.Request("GET", "https://x.example/"))


def test_429_with_empty_quota_is_terminal():
    text = _rate_limit_text(_resp({"x-ratelimit-requests-remaining": "0"}))
    assert "exhausted" in text and "unlikely to help" in text


def test_429_with_empty_quota_still_shows_retry_after():
    """The terminal branch must not swallow Retry-After: a plan reset window is the
    one case where the same call could work again."""
    text = _rate_limit_text(_resp({"x-ratelimit-requests-remaining": "0",
                                   "Retry-After": "900"}))
    assert "Retry after 900 seconds." in text


def test_429_with_quota_left_keeps_the_retry_hint():
    text = _rate_limit_text(_resp({"x-ratelimit-requests-remaining": "7",
                                   "Retry-After": "12"}))
    assert "7 request(s) left" in text and "12 seconds" in text


def test_429_without_the_header_is_unchanged():
    """RapidAPI's remaining-requests header is a convention, not a contract, so an
    absent or malformed one must fall back to the old wording instead of guessing."""
    assert _rate_limit_text(_resp({})) == "Rate limit reached (429)."
    assert _rate_limit_text(_resp({"x-ratelimit-requests-remaining": "abc"})) == \
        "Rate limit reached (429)."


# WHOIS posture for blueteam_ip_intel_bulk (SECURITY.md 4.1d).

def test_raw_whois_exemption_is_the_shipped_default():
    """The exemption is a policy decision, so it is the default rather than something an
    operator discovers is off mid-incident. Changing either value here silently changes
    the PII posture the docs describe."""
    from mcp_server.core.config import ThreatIntelConfig
    cfg = ThreatIntelConfig()
    assert cfg.rapidapi_raw_whois is True
    assert cfg.rapidapi_budget_hours == 8.0, "one shift, not a 4h window that needs a restart"


def test_scrub_whois_deep_drops_person_fields_at_any_depth():
    body = {
        "data": {"whois": "netname: TOR-EXIT\nperson: Jane Doe\naddress: 1 Main St\n"
                         "route: 1.2.3.0/24"},
        "results": [{"whois": "org-name: ExampleHost\nphone: +3312345"}],
    }
    out = r._scrub_whois_deep(body)
    blob = json.dumps(out)
    for dropped in ("Jane Doe", "1 Main St", "+3312345", "phone", "address"):
        assert dropped not in blob, f"{dropped} survived the allowlist"
    assert out["data"]["whois"]["netname"] == ["TOR-EXIT"]
    assert out["data"]["whois"]["route"] == ["1.2.3.0/24"]
    assert out["results"][0]["whois"]["org-name"] == ["ExampleHost"]


def test_scrub_whois_deep_targets_whois_keys_not_every_person_field():
    """It has to fire on the field holding a registry record, or it would strip unrelated
    keys out of an unmapped schema."""
    body = {"network": {"asn": 1, "person": "analyst note"}}
    assert r._scrub_whois_deep(body) == body


@pytest.mark.asyncio
async def test_bulk_marks_the_unredacted_whois(monkeypatch):
    async def fake_post(host, path, payload, ttl=None):
        return {"data": {"whois": "netname: TOR-EXIT\nperson: Jane Doe"}}

    monkeypatch.setattr(r, "_rapidapi_post", fake_post)
    monkeypatch.setattr(r, "RAPIDAPI_RAW_WHOIS", True)

    out = await r.blueteam_ip_intel_bulk(r.BulkIpIntelInput(ips=["185.220.101.1"]))
    assert r._WHOIS_RAW_NOTE.strip() in out, "an unredacted block must say so in the output"
    assert "Jane Doe" in out, "the exemption retains the registrant field"


@pytest.mark.asyncio
async def test_bulk_allowlists_when_the_exemption_is_off(monkeypatch):
    async def fake_post(host, path, payload, ttl=None):
        return {"data": {"whois": "netname: TOR-EXIT\nperson: Jane Doe\naddress: 1 Main St"}}

    monkeypatch.setattr(r, "_rapidapi_post", fake_post)
    monkeypatch.setattr(r, "RAPIDAPI_RAW_WHOIS", False)

    out = await r.blueteam_ip_intel_bulk(r.BulkIpIntelInput(ips=["185.220.101.1"]))
    assert "Jane Doe" not in out and "1 Main St" not in out
    assert "TOR-EXIT" in out, "the technical registry fields must survive"
    assert r._WHOIS_RAW_NOTE.strip() not in out, "no exemption, no warning banner"
