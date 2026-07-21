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
from app.correlation.merge import BREACH_CREATING_DOC_TYPES, recompute_severity
from app.db import get_session
from app.normalize.company_name import normalize_company_name
from app.normalize.ransomware_group_aliases import normalize_ransomware_group

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

# Sources that now have a working collector: re-enable them (they were
# disabled by an earlier maintenance pass), pin their verified feed_url, and
# correct the feed_type where discovery got it wrong in the original seed.
RE_ENABLE_SOURCES = {
    "sec_edgar_search": {
        "feed_url": "https://efts.sec.gov/LATEST/search-index?q=%22material+cybersecurity+incident%22&forms=8-K",
        "feed_type": "json_api",
        "note": "8-K Item 1.05 filings via the EDGAR full-text search JSON API",
    },
    "washington_atg": {
        "feed_url": "https://data.wa.gov/resource/sb4j-ca4h.json",
        "feed_type": "json_api",
        "note": "WA AG breach notifications via the state's Socrata open-data API (no key, updated daily)",
    },
    "oregon_doj": {
        "feed_url": None,
        "feed_type": "html_scrape",
        "note": "Oregon DOJ breach notification table at justice.oregon.gov (positional HTML parse)",
    },
    "haveibeenpwned": {
        "feed_url": "https://haveibeenpwned.com/api/v3/breaches",
        "feed_type": "json_api",
        "note": "The /breaches metadata endpoint requires NO API key (verified) — a key only raises rate limits",
    },
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

    for slug, cfg in RE_ENABLE_SOURCES.items():
        res = await session.execute(
            text(
                "UPDATE breach_data_sources "
                "SET enabled = TRUE, feed_url = :fu, feed_type = :ft, notes = :note, requires_api_key = FALSE "
                "WHERE slug = :slug AND (NOT enabled OR feed_url IS DISTINCT FROM :fu "
                "                        OR feed_type IS DISTINCT FROM :ft OR requires_api_key)"
            ),
            {"slug": slug, "fu": cfg["feed_url"], "ft": cfg["feed_type"], "note": cfg["note"]},
        )
        if res.rowcount:
            logger.info("Re-enabled source '%s' (%s)", slug, cfg["note"])


async def close_stale_collector_runs(session) -> None:
    """
    A killed/cancelled job (e.g. workflow timeout) leaves its collector-log
    rows stuck in 'running' forever. Anything still 'running' after 2 hours
    did not survive its run — mark it failed so the source-health view tells
    the truth.
    """
    res = await session.execute(
        text(
            """
            UPDATE breach_collector_log
            SET status = 'failed', finished_at = now(),
                error_message = 'run did not complete (job cancelled or timed out)'
            WHERE status = 'running' AND started_at < now() - INTERVAL '2 hours'
            """
        )
    )
    if res.rowcount:
        logger.info("Closed %d stale 'running' collector-log rows as failed", res.rowcount)


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


async def merge_duplicate_breaches(session) -> None:
    """
    Collapse breaches that are the same incident but were stored separately
    because a second source's blended score fell short of auto-merge (missing
    industry/location) and got stranded — leaving each company at one source.
    Two breaches merge when their normalized names are identical AND their
    incident dates are within 45 days (or either is NULL); a company breached
    years apart keeps distinct rows. Source records repoint to the oldest
    breach; the duplicates are deleted.
    """
    # Group by the SAME suffix-stripped normalization the correlator uses, so
    # "Contoso Ltd" and "Contoso Limited" collapse (a plain regex would not
    # strip the legal suffix and would miss them).
    rows = (await session.execute(
        text("SELECT id, canonical_name, incident_date, first_seen_at FROM breaches ORDER BY first_seen_at")
    )).fetchall()
    buckets: dict[str, list] = {}
    for r in rows:
        key = normalize_company_name(r.canonical_name or "")
        if not key:
            continue
        buckets.setdefault(key, []).append(r)

    merged = 0
    for key, brs in buckets.items():
        if len(brs) < 2:
            continue
        keep = str(brs[0].id)
        keep_date = brs[0].incident_date
        drop = []
        for b in brs[1:]:
            d = b.incident_date
            close = (keep_date is None or d is None or abs((d - keep_date).days) <= 45)
            if close:
                drop.append(str(b.id))
        if not drop:
            continue
        await session.execute(
            text("UPDATE breach_source_records SET matched_breach_id = :keep WHERE matched_breach_id = ANY(:drop)"),
            {"keep": keep, "drop": drop},
        )
        await session.execute(
            text("UPDATE breach_match_queue SET candidate_breach_id = :keep WHERE candidate_breach_id = ANY(:drop)"),
            {"keep": keep, "drop": drop},
        )
        await session.execute(text("DELETE FROM breaches WHERE id = ANY(:drop)"), {"drop": drop})
        merged += len(drop)
    if merged:
        logger.info("Merged %d duplicate breach rows into their canonical incident", merged)


async def drain_strong_review_queue(session) -> None:
    """
    On a public read-only site nothing drains the human review queue, so a
    second source whose blended score landed in the review band (exact name,
    but missing industry/location) stays unlinked forever and the breach shows
    one source. Auto-approve queue items that are clearly the same incident —
    exact normalized name (name_score >= 0.90) within a 45-day window — by
    linking the record to its candidate breach.
    """
    rows = (await session.execute(
        text(
            """
            SELECT q.id AS qid, q.source_record_id, q.candidate_breach_id, q.confidence,
                   (q.match_reasons->>'name_score')::float AS name_score,
                   NULLIF(q.match_reasons->>'date_delta_days','')::int AS delta
            FROM breach_match_queue q
            WHERE q.status = 'pending' AND q.candidate_breach_id IS NOT NULL
            """
        )
    )).fetchall()
    drained = 0
    for r in rows:
        strong = (r.name_score is not None and r.name_score >= 0.90
                  and ((r.delta is not None and r.delta <= 45) or r.name_score >= 0.97))
        if not strong:
            continue
        await session.execute(
            text("UPDATE breach_source_records SET matched_breach_id = :b, match_confidence = :c WHERE id = :r AND matched_breach_id IS NULL"),
            {"b": str(r.candidate_breach_id), "c": r.confidence, "r": str(r.source_record_id)},
        )
        await session.execute(
            text("UPDATE breach_match_queue SET status = 'approved', reviewed_at = now(), reviewed_by = 'auto-maintenance' WHERE id = :q"),
            {"q": str(r.qid)},
        )
        drained += 1
    if drained:
        logger.info("Auto-approved %d strong review-queue matches into their breach", drained)


async def renormalize_groups(session) -> None:
    """
    Collapse threat-actor name fragmentation (e.g. 'lockbit' / 'LockBit 3.0'
    stored alongside canonical 'LockBit') so the actor filter and analytics
    don't split one group across several values.
    """
    rows = (await session.execute(
        text("SELECT DISTINCT ransomware_group FROM breaches WHERE ransomware_group IS NOT NULL")
    )).fetchall()
    changed = 0
    for (raw,) in rows:
        canon = normalize_ransomware_group(raw)
        if canon and canon != raw:
            await session.execute(
                text("UPDATE breaches SET ransomware_group = :c WHERE ransomware_group = :r"),
                {"c": canon, "r": raw},
            )
            changed += 1
    if changed:
        logger.info("Re-normalized %d fragmented threat-actor names", changed)


async def backfill_breach_fields(session) -> None:
    """
    Fill breach fields that are still NULL from facts carried by the breach's
    already-linked source records (group from leak posts, record counts from
    HHS/HIBP, earliest published date as the disclosure date), then derive
    severity. Keeps the ledger's threat-actor/disclosed/records columns
    populated for rows ingested before merge-time enrichment existed.
    """
    res = await session.execute(
        text(
            """
            UPDATE breaches b SET
                ransomware_group = COALESCE(b.ransomware_group, sub.group_norm),
                records_affected_est = COALESCE(b.records_affected_est, sub.max_records),
                incident_date = COALESCE(b.incident_date, sub.min_incident),
                disclosed_date = COALESCE(b.disclosed_date, sub.min_published, b.incident_date, sub.min_incident),
                summary = COALESCE(b.summary, sub.any_summary),
                data_types_exposed = CASE
                    WHEN b.data_types_exposed IS NULL OR b.data_types_exposed = '{}'::text[]
                        THEN sub.all_data_types
                    ELSE b.data_types_exposed
                END
            FROM (
                SELECT r.matched_breach_id AS bid,
                       (array_agg(r.ransomware_group_norm) FILTER (WHERE r.ransomware_group_norm IS NOT NULL))[1] AS group_norm,
                       max(r.records_affected_est) AS max_records,
                       min(r.incident_date) AS min_incident,
                       CAST(min(r.source_published_at) AS date) AS min_published,
                       (array_agg(r.summary) FILTER (WHERE r.summary IS NOT NULL))[1] AS any_summary,
                       array_agg(DISTINCT dt_elem) FILTER (WHERE dt_elem IS NOT NULL) AS all_data_types
                FROM breach_source_records r
                LEFT JOIN LATERAL unnest(COALESCE(r.data_types_exposed, '{}'::text[])) AS dt_elem ON TRUE
                WHERE r.matched_breach_id IS NOT NULL
                GROUP BY r.matched_breach_id
            ) sub
            WHERE b.id = sub.bid
              AND (
                   (b.ransomware_group IS NULL AND sub.group_norm IS NOT NULL)
                OR (b.records_affected_est IS NULL AND sub.max_records IS NOT NULL)
                OR (b.incident_date IS NULL AND sub.min_incident IS NOT NULL)
                OR (b.disclosed_date IS NULL
                    AND COALESCE(sub.min_published, b.incident_date, sub.min_incident) IS NOT NULL)
                OR (b.summary IS NULL AND sub.any_summary IS NOT NULL)
                OR ((b.data_types_exposed IS NULL OR b.data_types_exposed = '{}'::text[])
                    AND sub.all_data_types IS NOT NULL)
              )
            """
        )
    )
    if res.rowcount:
        logger.info("Backfilled missing fields on %d breaches from linked sources", res.rowcount)
    await recompute_severity(session)


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
        await close_stale_collector_runs(session)
    async with get_session() as session:
        await purge_non_breach_entries(session)
    async with get_session() as session:
        await dedupe_companies(session)
    async with get_session() as session:
        await drain_strong_review_queue(session)
    async with get_session() as session:
        await merge_duplicate_breaches(session)
    async with get_session() as session:
        await renormalize_groups(session)
    async with get_session() as session:
        await backfill_breach_fields(session)
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
