#!/usr/bin/env python3
"""Tests for shared threat intel cache + rate limiter"""
from __future__ import annotations
import os

# mcp_server/__init__.py calls init_config() at import and hard-fails without
# WAZUH_INDEXER_* (ConfigurationError). Seed them at module level so this file
# passes in isolation, not only when a peer module happens to import first.
os.environ.setdefault("WAZUH_INDEXER_URL", "https://indexer:9200")
os.environ.setdefault("WAZUH_INDEXER_PASSWORD", "test-indexer-pass")


def test_ttl_cache_get_set():
    from mcp_server.threat_intel._cache import TTLCache
    c = TTLCache(maxsize=10)
    c.set("a", {"v": 1}, ttl=60)
    assert c.get("a") == {"v": 1}
    assert c.get("missing") is None


def test_ttl_cache_expiry():
    from mcp_server.threat_intel._cache import TTLCache
    import time
    c = TTLCache(maxsize=10)
    c.set("a", "value", ttl=0.01)
    time.sleep(0.02)
    assert c.get("a") is None  # expired


def test_ttl_cache_lru_eviction():
    from mcp_server.threat_intel._cache import TTLCache
    c = TTLCache(maxsize=2)
    c.set("a", 1, ttl=60)
    c.set("b", 2, ttl=60)
    c.set("c", 3, ttl=60)  # evicts "a" (oldest)
    assert c.get("a") is None
    assert c.get("b") == 2
    assert c.get("c") == 3
    assert len(c) == 2


def test_rate_limiter_context_manager():
    import asyncio
    from mcp_server.threat_intel._cache import AsyncRateLimiter

    async def _run():
        limiter = AsyncRateLimiter(max_concurrent=2, min_interval=0.01)
        async with limiter:
            assert True  # acquires + releases cleanly

    asyncio.run(_run())


def test_rate_limiter_enforces_concurrency():
    import asyncio
    from mcp_server.threat_intel._cache import AsyncRateLimiter

    async def _run():
        limiter = AsyncRateLimiter(max_concurrent=1, min_interval=0.01)
        active = 0
        max_active = 0

        async def _worker():
            nonlocal active, max_active
            async with limiter:
                active += 1
                max_active = max(max_active, active)
                await asyncio.sleep(0.01)
                active -= 1

        await asyncio.gather(*[_worker() for _ in range(5)])
        assert max_active == 1  # never exceeded concurrency limit

    asyncio.run(_run())


def test_netra_argus_sangfor_lookup_spacing():
    """Netra/Argus lookups spaced 30s, Sangfor 5s, all serialized (max_concurrent=1)."""
    import mcp_server.tools.alert_enrichment  # noqa: F401
    import mcp_server.tools.wazuh_compromised  # noqa: F401
    import mcp_server.tools.alert_curated_report  # noqa: F401
    from mcp_server.threat_intel._cache import _limiters

    assert _limiters["netra"].min_interval == 30.0
    assert _limiters["argus"].min_interval == 30.0
    assert _limiters["sangfor"].min_interval == 5.0
    assert _limiters["netra"]._semaphore._value == 1
    assert _limiters["argus"]._semaphore._value == 1
    assert _limiters["sangfor"]._semaphore._value == 1


def test_netra_fanout_gets_a_90s_per_request_timeout():
    """Netra analysis fans out to ~6 sources and took 34s in production. It must
    override the global HTTP_TIMEOUT, or a slow-but-healthy lookup counts as a failure
    and trips the circuit breaker for the whole upstream."""
    import asyncio
    import mcp_server.tools.alert_enrichment as ae

    captured = {}

    class _Resp:
        def json(self):
            return {"data": {"results": {}}}

    async def _run():
        async def fake_api_call(method, url, **kw):
            captured.update(kw, url=url)
            return _Resp()

        real_call, real_limiter = ae._api_call, ae._netra_limiter
        ae._api_call, ae._netra_limiter = fake_api_call, asyncio.Semaphore(1)
        os.environ["NETRA_API_KEY"] = "test-key"
        try:
            await ae.netra_ip_analysis(ae.NetraIpAnalysisInput(ip="180.93.3.100"))
        finally:
            ae._api_call, ae._netra_limiter = real_call, real_limiter
            os.environ.pop("NETRA_API_KEY", None)

    asyncio.run(_run())
    assert captured["timeout"] == 90.0
    assert captured["url"].endswith("/analysis/180.93.3.100")


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
