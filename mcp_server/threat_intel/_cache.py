#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
Shared TTL cache + async rate limiter for threat-intel providers.
Replaces the per-provider `_cache` dict + `_semaphore` + `_last_request`
triplet with two small reusable classes. Each provider configures its own
TTL, max concurrency, and min interval between requests.
"""
from __future__ import annotations
import asyncio, json, logging, time
from pathlib import Path
from typing import Any

logger = logging.getLogger("blue_team_mcp.threat_intel.cache")


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


class PersistentJsonlCache:
    """TTL cache that survives a restart, so quota already spent is not spent again.
    Opt-in: an empty path keeps everything in memory. Entries are appended as JSONL
    (``{"t":"c"}`` per entry, ``{"t":"q"}`` for the quota record) and the file is
    rewritten on load and every ``maxsize`` appends. Expiry is stored as wall-clock
    epoch, never ``time.monotonic()``, because a monotonic clock means nothing to the
    next process.
    """
    def __init__(self, path: str, maxsize: int = 500):
        self._path = Path(path)
        self._maxsize = maxsize
        self._entries: dict[str, tuple[float, Any]] = {}
        self._quota: dict[str, Any] = {}
        self._appends = 0
        if str(path):
            self._load()

    @property
    def enabled(self) -> bool:
        return bool(str(self._path)) and str(self._path) != "."

    def get(self, key: str) -> Any | None:
        entry = self._entries.get(key)
        if entry is None:
            return None
        expiry, value = entry
        if time.time() < expiry:
            return value
        del self._entries[key]
        return None

    def set(self, key: str, value: Any, ttl: float) -> None:
        if len(self._entries) >= self._maxsize:
            self._entries.pop(next(iter(self._entries)))
        self._entries[key] = (time.time() + ttl, value)
        self._append({"t": "c", "k": key, "e": time.time() + ttl, "v": value})

    def get_quota(self) -> dict[str, Any]:
        """Arm window + month-to-date spend. Survives a restart for the same reason
        the cache does: bouncing the process must not restore a spent budget."""
        return dict(self._quota)

    def set_quota(self, state: dict[str, Any]) -> None:
        self._quota = dict(state)
        self._append({"t": "q", **state})

    def _append(self, record: dict[str, Any]) -> None:
        if not self.enabled:
            return
        try:
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        except (OSError, TypeError, ValueError) as e:
            logger.warning("RapidAPI state file %s not writable (%s); this run is memory-only.",
                           self._path, e)
            return
        self._appends += 1
        if self._appends >= self._maxsize:
            self._rewrite()

    def _load(self) -> None:
        if not self._path.is_file():
            return
        now = time.time()
        try:
            raw_lines = self._path.read_text(encoding="utf-8").splitlines()
        except OSError as e:
            logger.warning("RapidAPI state file %s unreadable (%s); starting cold.", self._path, e)
            return
        for line in raw_lines:
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if not isinstance(rec, dict):
                continue
            if rec.get("t") == "c" and isinstance(rec.get("e"), (int, float)):
                if rec["e"] > now:
                    self._entries[rec.get("k", "")] = (rec["e"], rec.get("v"))
            elif rec.get("t") == "q":
                self._quota = {k: v for k, v in rec.items() if k != "t"}
        while len(self._entries) > self._maxsize:
            self._entries.pop(next(iter(self._entries)))
        self._rewrite()

    def _rewrite(self) -> None:
        """Atomic rewrite: temp file + rename, so a crash mid-write cannot leave a
        half-line that the next load reads as a truncated entry."""
        if not self.enabled:
            return
        records = [{"t": "q", **self._quota}] if self._quota else []
        records += [{"t": "c", "k": k, "e": e, "v": v} for k, (e, v) in self._entries.items()]
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(self._path.suffix + ".tmp")
            tmp.write_text("".join(
                json.dumps(r, ensure_ascii=False, default=str) + "\n" for r in records),
                encoding="utf-8")
            tmp.replace(self._path)
        except (OSError, TypeError, ValueError) as e:
            logger.warning("RapidAPI state file %s not compactable (%s).", self._path, e)
            return
        self._appends = 0

    def __len__(self) -> int:
        return len(self._entries)

    def stats(self) -> dict[str, Any]:
        return {"persistent": self.enabled, "entries": len(self._entries),
                "maxsize": self._maxsize, "path": str(self._path) if self.enabled else ""}


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


# Shared namespaced cache + limiter registry
# One backing TTLCache shared across all threat-intel providers; keys are
# namespaced ("provider:key") so each provider keeps its own TTL (passed to
# cache_set) while memory is consolidated in a single store. Rate limiters stay
# per-provider via a registry because different APIs have different
# concurrency / min-interval limits.

_SHARED_CACHE = TTLCache(maxsize=10_000)


def cache_get(namespace: str, key: str) -> Any | None:
    """Return the cached value for a namespaced key, or None if absent/expired."""
    return _SHARED_CACHE.get(f"{namespace}:{key}")


def cache_set(namespace: str, key: str, value: Any, ttl: float) -> None:
    """Store a value under a namespaced key with the provider's TTL."""
    _SHARED_CACHE.set(f"{namespace}:{key}", value, ttl)


_limiters: dict[str, AsyncRateLimiter] = {}


def get_limiter(namespace: str, max_concurrent: int = 3,
                min_interval: float = 0.1) -> AsyncRateLimiter:
    """Return (or lazily create) the rate limiter for a provider namespace."""
    if namespace not in _limiters:
        _limiters[namespace] = AsyncRateLimiter(max_concurrent=max_concurrent,
                                                min_interval=min_interval)
    return _limiters[namespace]


def cache_stats() -> dict:
    """Operational stats for the shared cache + limiter registry."""
    return {
        "cache_entries": len(_SHARED_CACHE),
        "cache_maxsize": _SHARED_CACHE.maxsize,
        "limiter_namespaces": sorted(_limiters.keys()),
    }
