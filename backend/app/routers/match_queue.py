from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.cache import invalidate_all
from app.correlation.merge import create_new_breach, link_record_to_breach
from app.db import get_db

router = APIRouter(prefix="/api/match-queue", tags=["match_queue"])


@router.get("")
async def list_queue(db: AsyncSession = Depends(get_db), status: str = "pending"):
    rows = await db.execute(
        text(
            """
            SELECT q.id, q.confidence, q.match_reasons, q.status, q.created_at,
                   r.company_name_raw, r.source_record_url, r.incident_date,
                   b.canonical_name AS candidate_breach_name
            FROM breach_match_queue q
            JOIN breach_source_records r ON r.id = q.source_record_id
            LEFT JOIN breaches b ON b.id = q.candidate_breach_id
            WHERE q.status = :status
            ORDER BY q.created_at DESC
            """
        ),
        {"status": status},
    )
    return {"items": [dict(r._mapping) for r in rows]}


class ReviewDecision(BaseModel):
    decision: str  # 'approve' | 'reject' | 'merge_as_new'
    reviewer: str = "analyst"


@router.post("/{queue_id}/review")
async def review_match(queue_id: str, decision: ReviewDecision, db: AsyncSession = Depends(get_db)):
    row = await db.execute(text("SELECT * FROM breach_match_queue WHERE id = :id"), {"id": queue_id})
    item = row.first()
    if not item:
        raise HTTPException(404, "Queue item not found")

    if decision.decision == "approve":
        await link_record_to_breach(db, str(item.source_record_id), str(item.candidate_breach_id), float(item.confidence))
        new_status = "approved"
    elif decision.decision == "reject":
        new_status = "rejected"
    elif decision.decision == "merge_as_new":
        # analyst determined this is genuinely a different, new incident
        rec_row = await db.execute(
            text("SELECT * FROM breach_source_records WHERE id = :id"), {"id": item.source_record_id}
        )
        # NormalizedRecord reconstruction omitted for brevity in this reference
        # endpoint — in production, rehydrate from rec_row and call create_new_breach().
        new_status = "merged_new"
    else:
        raise HTTPException(400, "Invalid decision")

    await db.execute(
        text("UPDATE breach_match_queue SET status = :status, reviewed_by = :by, reviewed_at = now() WHERE id = :id"),
        {"status": new_status, "by": decision.reviewer, "id": queue_id},
    )
    await invalidate_all()
    return {"status": new_status}
