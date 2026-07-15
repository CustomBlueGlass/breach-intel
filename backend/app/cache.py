"""
Redis caching layer.

Strategy:
  * List/search/analytics endpoints are cached under deterministic keys
    derived from their query params (cache_key_for_list, etc).
  * Single-breach detail views cache under `breach:{id}`.
  * After every successful collector batch (see scheduler.py), we (a) refresh
    the materialized views, then (b) flush every cache key under the
    `breach_intel:*` namespace so the next request rebuilds from fresh data.
    This trades a slightly-cold cache right after ingestion for guaranteed
    freshness — acceptable since ingestion runs only every 6 hours.
"""
import hashlib
import json
from typing import Any

import redis.asyncio as redis

from app.config import settings

_pool = None


def get_redis() -> redis.Redis:
    global _pool
    if not settings.redis_url:
        raise RuntimeError("REDIS_URL is not configured — caching is disabled.")
    if _pool is None:
        _pool = redis.ConnectionPool.from_url(settings.redis_url, decode_responses=True)
    return redis.Redis(connection_pool=_pool)


NAMESPACE = "breach_intel"
DEFAULT_TTL_SECONDS = 21600  # 6h — matches collector cadence; invalidated sooner on ingestion


def _key(*parts: str) -> str:
    return ":".join([NAMESPACE, *parts])


def cache_key_for_list(filters: dict[str, Any], sort: str, page: int, page_size: int) -> str:
    digest_src = json.dumps(filters, sort_keys=True, default=str) + f"|{sort}|{page}|{page_size}"
    digest = hashlib.sha256(digest_src.encode()).hexdigest()[:16]
    return _key("list", digest)


def cache_key_for_breach(breach_id: str) -> str:
    return _key("breach", breach_id)


def cache_key_for_analytics(name: str, params: dict[str, Any] | None = None) -> str:
    suffix = hashlib.sha256(json.dumps(params or {}, sort_keys=True).encode()).hexdigest()[:12]
    return _key("analytics", name, suffix)


async def cache_get_json(key: str) -> Any | None:
    r = get_redis()
    raw = await r.get(key)
    return json.loads(raw) if raw else None


async def cache_set_json(key: str, value: Any, ttl: int = DEFAULT_TTL_SECONDS) -> None:
    r = get_redis()
    await r.set(key, json.dumps(value, default=str), ex=ttl)


async def invalidate_all() -> int:
    """Called once per collector batch after materialized views refresh."""
    r = get_redis()
    deleted = 0
    async for key in r.scan_iter(match=f"{NAMESPACE}:*"):
        await r.delete(key)
        deleted += 1
    return deleted
