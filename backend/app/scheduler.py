"""
Runs every collector on a 6-hour cadence via APScheduler, logging each run
to breach_collector_log per the spec. After a batch completes successfully,
refreshes the materialized views and flushes the Redis cache so the API
serves fresh data immediately rather than waiting out the TTL.

Run this as its own long-lived process (see deployment/docker-compose.yml
'scheduler' service) — separate from the FastAPI web process, so a slow
collector run never blocks API requests.
"""
from __future__ import annotations

import asyncio
import logging

import httpx
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy import text

from app.cache import invalidate_all
from app.collectors.registry import build_collector, collector_available
from app.config import settings
from app.correlation.merge import IngestOutcome, ingest_record
from app.db import get_session

logger = logging.getLogger("breach_intel.scheduler")


async def _active_sources(session):
    rows = await session.execute(
        text("SELECT * FROM breach_data_sources WHERE enabled = TRUE AND collection_mode = 'scheduled'")
    )
    return rows.fetchall()


async def run_one_collector(source_row) -> None:
    # Decide whether a collector exists BEFORE inserting a log row — a row
    # inserted first and then abandoned on `return` stays 'running' forever,
    # which used to litter breach_collector_log with stuck rows every run.
    if not collector_available(source_row):
        return  # on-demand-only / unimplemented / untuned source, nothing to schedule

    async with get_session() as session:
        log_id = (
            await session.execute(
                text(
                    "INSERT INTO breach_collector_log (source_id, status, feed_type_used) "
                    "VALUES (:sid, 'running', :ft) RETURNING id"
                ),
                {"sid": source_row.id, "ft": source_row.feed_type},
            )
        ).first().id

    stats = {"fetched": 0, "new": 0, "deduped": 0, "auto_merge": 0, "queued": 0}
    error_message = None
    try:
        async with httpx.AsyncClient(
            timeout=30.0, headers={"User-Agent": settings.scraper_user_agent}, follow_redirects=True
        ) as client:
            collector = build_collector(source_row, client)
            records = await collector.collect()
            stats["fetched"] = len(records)

            async with get_session() as session:
                for i, record in enumerate(records, 1):
                    outcome: IngestOutcome = await ingest_record(session, str(source_row.id), record)
                    if outcome.deduped:
                        stats["deduped"] += 1
                    elif outcome.action == "auto_merge":
                        stats["new"] += 1
                        stats["auto_merge"] += 1
                    elif outcome.action == "queue_for_review":
                        stats["new"] += 1
                        stats["queued"] += 1
                    elif outcome.action in ("new_breach", "stored_unlinked"):
                        stats["new"] += 1
                    # Commit in batches so a long first pull from a bulk source
                    # keeps its progress if the job is killed partway — the
                    # next run dedups what already landed and continues.
                    if i % 100 == 0:
                        await session.commit()

        status = "success"
    except Exception as exc:  # noqa: BLE001 — collector failures must not crash the scheduler
        logger.exception("Collector failed: %s", source_row.slug)
        status = "failed"
        error_message = str(exc)[:2000]

    async with get_session() as session:
        await session.execute(
            text(
                """
                UPDATE breach_collector_log
                SET finished_at = now(), status = :status, records_fetched = :fetched,
                    records_new = :new, records_deduped = :deduped,
                    records_matched_auto = :auto_merge, records_queued = :queued,
                    error_message = :err
                WHERE id = :id
                """
            ),
            {
                "status": status,
                "fetched": stats["fetched"],
                "new": stats["new"],
                "deduped": stats["deduped"],
                "auto_merge": stats["auto_merge"],
                "queued": stats["queued"],
                "err": error_message,
                "id": log_id,
            },
        )


async def run_all_collectors() -> None:
    async with get_session() as session:
        sources = await _active_sources(session)

    # Run collectors concurrently but capped, so we don't open 35 connections
    # to 35 different sites simultaneously (politeness + avoids self-DoS-ing
    # the event loop on slow scrapers).
    semaphore = asyncio.Semaphore(6)

    async def _bounded(source_row):
        async with semaphore:
            await run_one_collector(source_row)

    await asyncio.gather(*[_bounded(s) for s in sources], return_exceptions=True)

    async with get_session() as session:
        await session.execute(text("SELECT refresh_breach_views()"))

    # Redis is optional — the free deployment path (GitHub Actions + Supabase +
    # Vercel) has no Redis and reads straight from the materialized views via
    # Supabase's auto-API, so skip cache invalidation cleanly if it's not configured.
    if settings.redis_url:
        try:
            flushed = await invalidate_all()
            logger.info("Ingestion batch complete. Flushed %d cache keys.", flushed)
        except Exception:
            logger.warning("Redis configured but unreachable — skipping cache flush.")
    else:
        logger.info("Ingestion batch complete. (No Redis configured — skipped cache flush.)")


def start_scheduler() -> AsyncIOScheduler:
    scheduler = AsyncIOScheduler()
    scheduler.add_job(
        run_all_collectors,
        "interval",
        minutes=settings.collector_interval_minutes,  # 360 = every 6 hours
        id="run_all_collectors",
        next_run_time=None,  # set by caller; avoids double-run on deploy
    )
    scheduler.start()
    return scheduler


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run_all_collectors())
