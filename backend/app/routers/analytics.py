from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.cache import cache_get_json, cache_key_for_analytics, cache_set_json
from app.db import get_db

router = APIRouter(prefix="/api/analytics", tags=["analytics"])


@router.get("/trends")
async def breach_trends(db: AsyncSession = Depends(get_db)):
    cache_key = cache_key_for_analytics("trends")
    if cached := await cache_get_json(cache_key):
        return cached
    rows = await db.execute(
        text("SELECT week_start, industry, breach_count, records_affected_sum "
             "FROM mv_breach_trends ORDER BY week_start")
    )
    result = {"items": [dict(r._mapping) for r in rows]}
    await cache_set_json(cache_key, result)
    return result


@router.get("/top-ransomware-groups")
async def top_groups(db: AsyncSession = Depends(get_db), limit: int = 10):
    cache_key = cache_key_for_analytics("top_groups", {"limit": limit})
    if cached := await cache_get_json(cache_key):
        return cached
    rows = await db.execute(
        text("SELECT * FROM mv_top_ransomware_groups LIMIT :limit"), {"limit": limit}
    )
    result = {"items": [dict(r._mapping) for r in rows]}
    await cache_set_json(cache_key, result)
    return result


@router.get("/source-health")
async def source_health(db: AsyncSession = Depends(get_db)):
    """Powers the footer 'collector status' strip — last run per source."""
    cache_key = cache_key_for_analytics("source_health")
    if cached := await cache_get_json(cache_key):
        return cached
    rows = await db.execute(text("SELECT * FROM mv_source_health ORDER BY name"))
    result = {"items": [dict(r._mapping) for r in rows]}
    await cache_set_json(cache_key, result, ttl=300)  # short TTL — operational data
    return result
