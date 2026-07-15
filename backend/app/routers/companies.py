from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.cache import cache_get_json, cache_key_for_list, cache_set_json
from app.config import settings
from app.db import get_db

router = APIRouter(prefix="/api/companies", tags=["companies"])


@router.get("")
async def list_companies(
    db: AsyncSession = Depends(get_db),
    q: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(settings.pagination_default_page_size, ge=1),
):
    page_size = min(page_size, settings.pagination_max_page_size)
    cache_key = cache_key_for_list({"q": q, "scope": "companies"}, "name", page, page_size)
    cached = await cache_get_json(cache_key)
    if cached:
        return cached

    where = "canonical_name ILIKE :q" if q else "1=1"
    params = {"q": f"%{q}%"} if q else {}
    total = (
        await db.execute(text(f"SELECT count(*) FROM breach_companies WHERE {where}"), params)
    ).scalar_one()
    rows = await db.execute(
        text(
            f"""
            SELECT id, canonical_name, domain, industry, country, region_state,
                   breach_count, first_breach_at, last_breach_at
            FROM breach_companies WHERE {where}
            ORDER BY last_breach_at DESC NULLS LAST
            LIMIT :limit OFFSET :offset
            """
        ),
        {**params, "limit": page_size, "offset": (page - 1) * page_size},
    )
    result = {
        "items": [dict(r._mapping) for r in rows],
        "page": page, "page_size": page_size, "total": total,
        "total_pages": (total + page_size - 1) // page_size,
    }
    await cache_set_json(cache_key, result)
    return result


@router.get("/{company_id}")
async def get_company(company_id: str, db: AsyncSession = Depends(get_db)):
    row = await db.execute(text("SELECT * FROM breach_companies WHERE id = :id"), {"id": company_id})
    company = row.first()
    if not company:
        raise HTTPException(404, "Company not found")
    breaches = await db.execute(
        text("SELECT id, canonical_name, incident_date, source_count FROM breaches "
             "WHERE company_id = :id ORDER BY incident_date DESC"),
        {"id": company_id},
    )
    return {"company": dict(company._mapping), "breaches": [dict(b._mapping) for b in breaches]}
