#!/usr/bin/env python3
"""Tests for shared threat intel cache + rate limiter"""
from __future__ import annotations


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
