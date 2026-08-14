#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Shared TTL cache + async rate limiter for threat-intel providers.
Replaces the per-provider `_cache` dict + `_semaphore` + `_last_request`
triplet with two small reusable classes. Each provider configures its own
TTL, max concurrency, and min interval between requests.
"""
from __future__ import annotations
import asyncio, time
from typing import Any


class TTLCache:
    """In-memory TTL cache with LRU eviction.
    Thread-safety note: threat-intel lookups run on a single asyncio event
    loop, so no locking is needed. If the MCP server ever runs multiple
    workers (multi-process), switch to a shared store (Redis/memcached).
    """

    def __init__(self, maxsize: int = 1000):
        self.maxsize = maxsize
        self._data: dict[str, tuple[float, Any]] = {}

    def get(self, key: str) -> Any | None:
        """Return the cached value if present and unexpired, else None."""
        entry = self._data.get(key)
        if entry is None:
            return None
        expiry, value = entry
        if time.monotonic() < expiry:
            return value
        del self._data[key]
        return None

    def set(self, key: str, value: Any, ttl: float) -> None:
        """Store a value with a TTL. Evicts oldest (LRU) when over maxsize."""
        if len(self._data) >= self.maxsize:
            # Evict the first-inserted key (dict preserves insertion order)
            self._data.pop(next(iter(self._data)))
        self._data[key] = (time.monotonic() + ttl, value)

    def __len__(self) -> int:
        return len(self._data)


class AsyncRateLimiter:
    """Async semaphore + min-interval rate limiter (token-bucket-lite).

    Usage::

        limiter = AsyncRateLimiter(max_concurrent=3, min_interval=0.1)
        async with limiter:
            resp = await _api_call(...)

    The ``async with`` block acquires a concurrency slot, waits until at least
    ``min_interval`` seconds have passed since the previous request, and
    records the completion time on exit.
    """

    def __init__(self, max_concurrent: int = 3, min_interval: float = 0.1):
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self.min_interval = min_interval
        self._last_request = 0.0

    async def __aenter__(self) -> "AsyncRateLimiter":
        await self._semaphore.acquire()
        elapsed = time.monotonic() - self._last_request
        if elapsed < self.min_interval:
            await asyncio.sleep(self.min_interval - elapsed)
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        self._last_request = time.monotonic()
        self._semaphore.release()
