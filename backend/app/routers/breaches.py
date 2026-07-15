"""
Breach list + detail endpoints.

Hard constraints from the spec, enforced here:
  * page_size is clamped to [1, 50] — the client can never request the
    full dataset.
  * The list endpoint reads from mv_breach_ledger (materialized view),
    never from breach_source_records directly, so listing stays fast
    regardless of how many raw source records have accumulated.
  * Every response is cached in Redis under a key derived from the exact
    filter/sort/page combination and invalidated wholesale after each
    ingestion batch (see scheduler.run_all_collectors).
"""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.cache import cache_get_json, cache_key_for_breach, cache_key_for_list, cache_set_json
from app.config import settings
from app.db import get_db

router = APIRouter(prefix="/api/breaches", tags=["breaches"])

SORTABLE_COLUMNS = {
    "incident_date": "incident_date",
    "disclosed_date": "disclosed_date",
    "records_affected": "records_affected_est",
    "source_count": "source_count",
    "confidence": "confidence_avg",
    "company": "canonical_name",
}


@router.get("")
async def list_breaches(
    db: AsyncSession = Depends(get_db),
    q: str | None = Query(None, description="full text search"),
    industry: str | None = None,
    country: str | None = None,
    region_state: str | None = None,
    ransomware_group: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    min_records_affected: int | None = None,
    sort_by: Literal[
        "incident_date", "disclosed_date", "records_affected", "source_count", "confidence", "company"
    ] = "incident_date",
    sort_dir: Literal["asc", "desc"] = "desc",
    page: int = Query(1, ge=1),
    page_size: int = Query(settings.pagination_default_page_size, ge=1),
):
    page_size = min(page_size, settings.pagination_max_page_size)  # never exceed 50
    filters = {
        "q": q, "industry": industry, "country": country, "region_state": region_state,
        "ransomware_group": ransomware_group, "date_from": date_from, "date_to": date_to,
        "min_records_affected": min_records_affected,
    }
    cache_key = cache_key_for_list(filters, f"{sort_by}:{sort_dir}", page, page_size)
    cached = await cache_get_json(cache_key)
    if cached:
        return cached

    where = ["1=1"]
    params: dict = {}
    if q:
        where.append("(canonical_name ILIKE :q OR ransomware_group ILIKE :q)")
        params["q"] = f"%{q}%"
    if industry:
        where.append("industry = :industry"); params["industry"] = industry
    if country:
        where.append("country = :country"); params["country"] = country
    if region_state:
        where.append("region_state = :region_state"); params["region_state"] = region_state
    if ransomware_group:
        where.append("ransomware_group = :ransomware_group"); params["ransomware_group"] = ransomware_group
    if date_from:
        where.append("incident_date >= :date_from"); params["date_from"] = date_from
    if date_to:
        where.append("incident_date <= :date_to"); params["date_to"] = date_to
    if min_records_affected:
        where.append("records_affected_est >= :min_records")
        params["min_records"] = min_records_affected

    sort_col = SORTABLE_COLUMNS[sort_by]
    offset = (page - 1) * page_size

    count_row = await db.execute(
        text(f"SELECT count(*) FROM mv_breach_ledger WHERE {' AND '.join(where)}"), params
    )
    total = count_row.scalar_one()

    rows = await db.execute(
        text(
            f"""
            SELECT id, canonical_name, domain, industry, country, region_state,
                   ransomware_group, incident_date, disclosed_date, records_affected_est,
                   severity, status, source_count, confidence_avg, last_updated_at
            FROM mv_breach_ledger
            WHERE {' AND '.join(where)}
            ORDER BY {sort_col} {sort_dir.upper()} NULLS LAST
            LIMIT :limit OFFSET :offset
            """
        ),
        {**params, "limit": page_size, "offset": offset},
    )

    result = {
        "items": [dict(r._mapping) for r in rows],
        "page": page,
        "page_size": page_size,
        "total": total,
        "total_pages": (total + page_size - 1) // page_size,
    }
    await cache_set_json(cache_key, result)
    return result


@router.get("/{breach_id}")
async def get_breach_detail(breach_id: str, db: AsyncSession = Depends(get_db)):
    """Single clickable breach view: the master record plus every linked
    source record (disclosures, notices, filings, advisories, articles)."""
    cache_key = cache_key_for_breach(breach_id)
    cached = await cache_get_json(cache_key)
    if cached:
        return cached

    breach_row = await db.execute(
        text("SELECT * FROM breaches WHERE id = :id"), {"id": breach_id}
    )
    breach = breach_row.first()
    if not breach:
        raise HTTPException(404, "Breach not found")

    sources = await db.execute(
        text(
            """
            SELECT r.id, r.source_record_url, r.document_type, r.summary,
                   r.source_published_at, r.match_confidence,
                   s.name AS source_name, s.category AS source_category
            FROM breach_source_records r
            JOIN breach_data_sources s ON s.id = r.source_id
            WHERE r.matched_breach_id = :id
            ORDER BY r.source_published_at DESC NULLS LAST
            """
        ),
        {"id": breach_id},
    )

    result = {
        "breach": dict(breach._mapping),
        "linked_sources": [dict(r._mapping) for r in sources],
    }
    await cache_set_json(cache_key, result)
    return result
