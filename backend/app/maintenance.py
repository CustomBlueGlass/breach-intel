"""
Idempotent database maintenance, run before each ingestion batch
(see .github/workflows/ingest.yml). Heals a live database that was
populated by earlier versions of the pipeline:

  * purges "breaches" that were minted from news headlines, government
    advisories, or placeholder-selector HTML scrapes — the ledger lists
    breached companies, not news;
  * unlinks (but keeps) the underlying news source records so they can
    re-attach to real breaches during future correlation;
  * merges duplicate company rows created by the old upsert bug and
    recomputes denormalized counts;
  * disables sources that cannot run (no collector / broken feed) so they
    stop erroring in the collector logs every 6 hours, and fixes source
    URLs that have moved;
  * creates mv_platform_stats if missing (the original grants script
    referenced it before creating it, so it never got created) and
    updates refresh_breach_views() to include it.

Safe to run on every batch: each step is a no-op once the database is clean.
"""
from __future__ import annotations

import asyncio
import logging

from sqlalchemy import text

from app.collectors.registry import NOT_YET_IMPLEMENTED_SLUGS, PLACEHOLDER_HTML_SLUGS
from app.correlation.merge import BREACH_CREATING_DOC_TYPES
from app.db import get_session

logger = logging.getLogger("breach_intel.maintenance")

# Sources disabled until they have a working collector or their feed is
# reachable again. slug -> reason (stored in breach_data_sources.notes).
DISABLE_SOURCES = {
    **{slug: "Disabled: no hand-tuned ScrapeConfig yet — generic selectors scrape garbage"
       for slug in PLACEHOLDER_HTML_SLUGS},
    **{slug: "Disabled: collector not yet implemented"
       for slug in NOT_YET_IMPLEMENTED_SLUGS},
    "bleepingcomputer": "Disabled: feed returns 403 to datacenter IPs (CDN bot protection)",
    "cisa_kev": "Disabled: vulnerability catalog, not breach data — re-enable only as dossier enrichment",
}

# Feed locations that moved since the seed was written (kept current even for
# disabled sources so re-enabling them starts from the right URL).
URL_FIXES = {
    "oregon_doj": "https://justice.oregon.gov/consumer/DataBreach/",
    "indiana_ag": "https://www.in.gov/attorneygeneral/consumer-protection-division/id-theft-prevention/data-breach-notifications",
    "north_dakota_ag": "https://attorneygeneral.nd.gov/consumer-resources/data-breach-notices",
    "sec_cyber_disclosures": "https://www.sec.gov/securities-topics/cybersecurity",
}

PLATFORM_STATS_VIEW = """
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_platform_stats AS
SELECT
    (SELECT count(*) FROM breaches) AS total_breaches,
    (SELECT count(*) FROM breach_data_sources WHERE enabled) AS total_sources,
    (SELECT round(avg(confidence_avg), 3) FROM breaches) AS avg_confidence,
    (SELECT count(*) FROM breach_match_queue WHERE status = 'pending') AS pending_review,
    now() AS computed_at
"""

REFRESH_FUNCTION = """
CREATE OR REPLACE FUNCTION refresh_breach_views() RETURNS void AS $$
BEGIN
    -- plain REFRESH (not CONCURRENTLY): CONCURRENTLY is disallowed inside a
    -- function's transaction context, and at this data volume the brief
    -- lock during refresh is a non-issue.
    REFRESH MATERIALIZED VIEW mv_breach_ledger;
    REFRESH MATERIALIZED VIEW mv_breach_trends;
    REFRESH MATERIALIZED VIEW mv_top_ransomware_groups;
    REFRESH MATERIALIZED VIEW mv_source_health;
    REFRESH MATERIALIZED VIEW mv_platform_stats;
END
$$ LANGUAGE plpgsql
"""

GRANT_STATS_VIEW = """
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
        GRANT SELECT ON mv_platform_stats TO anon;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        GRANT SELECT ON mv_platform_stats TO authenticated;
    END IF;
END $$
"""

# Tables the public site reads directly (breach detail panel, match queue).
# The original supabase_grants.sql aborted partway on some databases (grant
# before create), which left RLS policies and grants missing — the ledger
# views still worked but the detail panel's base-table queries returned
# nothing. Re-assert the full read-only setup idempotently on every run.
PUBLIC_READ_TABLES = [
    "breaches", "breach_companies", "breach_source_records",
    "breach_match_queue", "breach_data_sources", "breach_collector_log",
    "threat_actors",
]
PUBLIC_READ_VIEWS = [
    "mv_breach_ledger", "mv_breach_trends", "mv_top_ransomware_groups",
    "mv_source_health", "mv_platform_stats",
]

ENSURE_PUBLIC_READ = """
DO $$
DECLARE
    tbl text;
    rel text;
BEGIN
    FOREACH tbl IN ARRAY ARRAY[{tables}]
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tbl);
        IF NOT EXISTS (
            SELECT 1 FROM pg_policies
            WHERE schemaname = 'public' AND tablename = tbl AND policyname = 'public read'
        ) THEN
            EXECUTE format('CREATE POLICY "public read" ON %I FOR SELECT USING (true)', tbl);
        END IF;
    END LOOP;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
        FOREACH rel IN ARRAY ARRAY[{relations}]
        LOOP
            EXECUTE format('GRANT SELECT ON %I TO anon', rel);
        END LOOP;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        FOREACH rel IN ARRAY ARRAY[{relations}]
        LOOP
            EXECUTE format('GRANT SELECT ON %I TO authenticated', rel);
        END LOOP;
    END IF;
END $$
""".format(
    tables=", ".join(f"'{t}'" for t in PUBLIC_READ_TABLES),
    relations=", ".join(f"'{r}'" for r in PUBLIC_READ_TABLES + PUBLIC_READ_VIEWS),
)


async def fix_sources(session) -> None:
    for slug, url in URL_FIXES.items():
        await session.execute(
            text("UPDATE breach_data_sources SET base_url = :url WHERE slug = :slug AND base_url <> :url"),
            {"url": url, "slug": slug},
        )
    for slug, reason in DISABLE_SOURCES.items():
        res = await session.execute(
            text(
                "UPDATE breach_data_sources SET enabled = FALSE, notes = :reason "
                "WHERE slug = :slug AND enabled"
            ),
            {"slug": slug, "reason": reason},
        )
        if res.rowcount:
            logger.info("Disabled source '%s' (%s)", slug, reason)


async def purge_non_breach_entries(session) -> None:
    """
    Delete breach rows with no authoritative source behind them. A breach is
    kept only if at least one linked source record is an authoritative
    document type from a non-placeholder source.
    """
    doc_types = sorted(BREACH_CREATING_DOC_TYPES)
    placeholder = sorted(PLACEHOLDER_HTML_SLUGS)

    junk_ids = [
        str(r.id) for r in (await session.execute(
            text(
                """
                SELECT b.id FROM breaches b
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM breach_source_records r
                    JOIN breach_data_sources s ON s.id = r.source_id
                    WHERE r.matched_breach_id = b.id
                      AND r.document_type = ANY(:doc_types)
                      AND NOT (s.slug = ANY(:placeholder))
                )
                """
            ),
            {"doc_types": doc_types, "placeholder": placeholder},
        )).fetchall()
    ]
    if junk_ids:
        await session.execute(
            text("DELETE FROM breach_match_queue WHERE candidate_breach_id = ANY(:ids)"),
            {"ids": junk_ids},
        )
        await session.execute(
            text(
                "UPDATE breach_source_records SET matched_breach_id = NULL, match_confidence = NULL "
                "WHERE matched_breach_id = ANY(:ids)"
            ),
            {"ids": junk_ids},
        )
        await session.execute(text("DELETE FROM breaches WHERE id = ANY(:ids)"), {"ids": junk_ids})
        logger.info("Purged %d non-breach ledger entries (news/advisory/scrape-garbage)", len(junk_ids))

    # Placeholder-selector scrapes stored nav/headline garbage as source
    # records — those have no evidentiary value, delete them outright.
    res = await session.execute(
        text(
            """
            DELETE FROM breach_match_queue WHERE source_record_id IN (
                SELECT r.id FROM breach_source_records r
                JOIN breach_data_sources s ON s.id = r.source_id
                WHERE s.slug = ANY(:placeholder)
            )
            """
        ),
        {"placeholder": placeholder},
    )
    res = await session.execute(
        text(
            """
            DELETE FROM breach_source_records WHERE source_id IN (
                SELECT id FROM breach_data_sources WHERE slug = ANY(:placeholder)
            )
            """
        ),
        {"placeholder": placeholder},
    )
    if res.rowcount:
        logger.info("Deleted %d garbage source records from placeholder scrapers", res.rowcount)

    # CVE advisories are vulnerability metadata, not company breach reports.
    await session.execute(
        text(
            """
            DELETE FROM breach_match_queue WHERE source_record_id IN (
                SELECT id FROM breach_source_records WHERE company_name_raw LIKE '[CVE advisory]%'
            )
            """
        )
    )
    res = await session.execute(
        text("DELETE FROM breach_source_records WHERE company_name_raw LIKE '[CVE advisory]%'")
    )
    if res.rowcount:
        logger.info("Deleted %d CVE-advisory pseudo-records", res.rowcount)


async def dedupe_companies(session) -> None:
    """
    The old upsert never conflicted (no unique constraint on canonical_name),
    so every breach minted its own company row. Keep the oldest row per
    canonical_name, repoint breaches at it, drop the rest.
    """
    await session.execute(
        text(
            """
            WITH keepers AS (
                SELECT DISTINCT ON (canonical_name) id, canonical_name
                FROM breach_companies
                ORDER BY canonical_name, created_at
            )
            UPDATE breaches b
            SET company_id = k.id
            FROM breach_companies c
            JOIN keepers k ON k.canonical_name = c.canonical_name
            WHERE b.company_id = c.id AND c.id <> k.id
            """
        )
    )
    res = await session.execute(
        text(
            """
            DELETE FROM breach_companies c
            WHERE NOT EXISTS (SELECT 1 FROM breaches b WHERE b.company_id = c.id)
            """
        )
    )
    if res.rowcount:
        logger.info("Removed %d orphaned/duplicate company rows", res.rowcount)


async def recompute_denormalized(session) -> None:
    await session.execute(
        text(
            """
            UPDATE breaches b SET source_count = sub.n
            FROM (
                SELECT matched_breach_id, count(*) AS n
                FROM breach_source_records
                WHERE matched_breach_id IS NOT NULL
                GROUP BY matched_breach_id
            ) sub
            WHERE sub.matched_breach_id = b.id AND b.source_count <> sub.n
            """
        )
    )
    await session.execute(
        text(
            """
            UPDATE breach_companies c
            SET breach_count = sub.n,
                first_breach_at = sub.first_d,
                last_breach_at = sub.last_d
            FROM (
                SELECT company_id, count(*) AS n,
                       min(incident_date) AS first_d, max(incident_date) AS last_d
                FROM breaches
                WHERE company_id IS NOT NULL
                GROUP BY company_id
            ) sub
            WHERE sub.company_id = c.id
              AND (c.breach_count <> sub.n
                   OR c.first_breach_at IS DISTINCT FROM sub.first_d
                   OR c.last_breach_at IS DISTINCT FROM sub.last_d)
            """
        )
    )


async def ensure_views(session) -> None:
    await session.execute(text(PLATFORM_STATS_VIEW))
    await session.execute(text(REFRESH_FUNCTION))
    await session.execute(text(GRANT_STATS_VIEW))
    await session.execute(text(ENSURE_PUBLIC_READ))


async def run_maintenance() -> None:
    async with get_session() as session:
        await fix_sources(session)
    async with get_session() as session:
        await purge_non_breach_entries(session)
    async with get_session() as session:
        await dedupe_companies(session)
    async with get_session() as session:
        await recompute_denormalized(session)
    async with get_session() as session:
        await ensure_views(session)
    async with get_session() as session:
        await session.execute(text("SELECT refresh_breach_views()"))
    logger.info("Maintenance pass complete.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run_maintenance())
