"""
One-off backfill: recompute org_guess / org_norm on existing UNMATCHED
news_watch rows using the improved headline extractor (app.normalize.
headline_org via news_watch._org_from_title), then re-run correlation.

Rows were stored with whatever extractor was current at insert time, and
news_watch.match() reads the stored org_norm, so headlines pulled before the
extractor improvement never benefit from it. This job re-derives the org for
the still-unmatched backlog and re-correlates, so the gain shows immediately
instead of only accruing on newly-pulled headlines.

Metadata only (it rewrites a name guess, never touches breach data). Idempotent
and safe to run any number of times: it only ever recomputes org fields on rows
that are still unmatched, then matches. Matched rows are left untouched.

Run via the "Backfill news-watch org names" workflow (workflow_dispatch), or
locally with `python -m app.backfill_news_org` and DATABASE_URL set.
"""
from __future__ import annotations

import asyncio
import logging

from sqlalchemy import text

from app.db import get_session, run_resiliently
from app.news_watch import _org_from_title, match
from app.normalize.company_name import normalize_company_name

logger = logging.getLogger("breach_intel.backfill_news_org")


async def backfill(session) -> tuple[int, int]:
    """Recompute org_guess/org_norm for unmatched headlines. Returns
    (rows_seen, rows_changed)."""
    rows = (
        await session.execute(
            text("SELECT id, title, org_norm FROM news_watch WHERE matched_breach_id IS NULL")
        )
    ).fetchall()

    changed = 0
    for r in rows:
        org = _org_from_title(r.title)
        org_norm = normalize_company_name(org) if org else None
        if org_norm == r.org_norm:
            continue  # extractor produced the same guess; nothing to write
        await session.execute(
            text(
                "UPDATE news_watch SET org_guess = :og, org_norm = :on "
                "WHERE id = :id AND matched_breach_id IS NULL"
            ),
            {"og": org, "on": org_norm, "id": str(r.id)},
        )
        changed += 1
    logger.info(
        "backfill: %d unmatched headlines scanned, %d org guesses updated",
        len(rows), changed,
    )
    return len(rows), changed


async def run() -> None:
    async with get_session() as session:
        seen, changed = await backfill(session)
    async with get_session() as session:
        matched = await match(session)
    logger.info(
        "backfill complete: %d scanned, %d re-guessed, %d newly matched",
        seen, changed, matched,
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run_resiliently(run))
