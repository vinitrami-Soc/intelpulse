"""Two-tier cache for external threat-intel lookups.

Free API tiers are the binding constraint in this design: AbuseIPDB gives
1 000 checks/day, GreyNoise community 100/day. Re-triaging the same IP three
times in a shift must not cost three quota units, so every provider response —
including failures, with a shorter TTL — is cached by (provider, ioc).

Redis is used when REDIS_URL is set; otherwise an in-process TTL dict keeps the
app fully functional for a single-container demo run.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any

from .config import settings

logger = logging.getLogger(__name__)

try:  # pragma: no cover - import guard
    from redis import asyncio as aioredis
except ImportError:  # pragma: no cover
    aioredis = None  # type: ignore[assignment]


class _MemoryCache:
    """Minimal TTL map used when Redis is not configured or not reachable."""

    def __init__(self, max_entries: int = 5_000) -> None:
        self._store: dict[str, tuple[float, str]] = {}
        self._max_entries = max_entries

    def get(self, key: str) -> str | None:
        entry = self._store.get(key)
        if not entry:
            return None
        expires_at, payload = entry
        if expires_at < time.time():
            self._store.pop(key, None)
            return None
        return payload

    def set(self, key: str, value: str, ttl: int) -> None:
        if len(self._store) >= self._max_entries:
            for stale in [k for k, (exp, _) in self._store.items() if exp < time.time()]:
                self._store.pop(stale, None)
            if len(self._store) >= self._max_entries:
                self._store.pop(next(iter(self._store)), None)
        self._store[key] = (time.time() + ttl, value)

    def delete_prefix(self, prefix: str) -> int:
        keys = [k for k in self._store if k.startswith(prefix)]
        for key in keys:
            self._store.pop(key, None)
        return len(keys)

    def stats(self) -> dict[str, Any]:
        live = sum(1 for exp, _ in self._store.values() if exp >= time.time())
        return {"entries": live}


class IntelCache:
    NAMESPACE = "intelpulse:v1"

    def __init__(self) -> None:
        self._memory = _MemoryCache()
        self._redis: Any | None = None
        self._redis_healthy = False
        self.hits = 0
        self.misses = 0

    async def connect(self) -> None:
        if not settings.redis_url or aioredis is None:
            logger.info("cache: Redis not configured, using in-process TTL cache")
            return
        try:
            self._redis = aioredis.from_url(
                settings.redis_url, encoding="utf-8", decode_responses=True
            )
            await self._redis.ping()
            self._redis_healthy = True
            logger.info("cache: connected to Redis at %s", settings.redis_url)
        except Exception as exc:  # pragma: no cover - depends on environment
            logger.warning("cache: Redis unavailable (%s); falling back to memory", exc)
            self._redis = None
            self._redis_healthy = False

    async def close(self) -> None:
        if self._redis is not None:  # pragma: no cover
            await self._redis.aclose()

    def key(self, provider: str, ioc: str) -> str:
        return f"{self.NAMESPACE}:{provider}:{ioc.lower()}"

    async def get(self, provider: str, ioc: str) -> dict | None:
        key = self.key(provider, ioc)
        raw: str | None = None
        if self._redis is not None and self._redis_healthy:
            try:
                raw = await self._redis.get(key)
            except Exception as exc:  # pragma: no cover
                logger.warning("cache: Redis read failed (%s)", exc)
                self._redis_healthy = False
        if raw is None:
            raw = self._memory.get(key)
        if raw is None:
            self.misses += 1
            return None
        self.hits += 1
        try:
            return json.loads(raw)
        except ValueError:
            return None

    async def set(self, provider: str, ioc: str, value: dict, *, ttl: int | None = None) -> None:
        key = self.key(provider, ioc)
        payload = json.dumps(value, default=str)
        ttl = ttl or settings.cache_ttl_seconds
        if self._redis is not None and self._redis_healthy:
            try:
                await self._redis.set(key, payload, ex=ttl)
            except Exception as exc:  # pragma: no cover
                logger.warning("cache: Redis write failed (%s)", exc)
                self._redis_healthy = False
        self._memory.set(key, payload, ttl)

    async def invalidate(self, ioc: str) -> int:
        removed = self._memory.delete_prefix(self.NAMESPACE)
        if self._redis is not None and self._redis_healthy:  # pragma: no cover
            try:
                async for key in self._redis.scan_iter(f"{self.NAMESPACE}:*:{ioc.lower()}"):
                    await self._redis.delete(key)
                    removed += 1
            except Exception as exc:
                logger.warning("cache: Redis invalidate failed (%s)", exc)
        return removed

    def status(self) -> dict[str, Any]:
        total = self.hits + self.misses
        return {
            "backend": "redis" if self._redis_healthy else "memory",
            "redis_configured": bool(settings.redis_url),
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": round(self.hits / total, 3) if total else 0.0,
            "ttl_seconds": settings.cache_ttl_seconds,
            **self._memory.stats(),
        }


cache = IntelCache()
