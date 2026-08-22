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
from app.db import get_session, run_resiliently
from app.normalize.attack_cve import extract_cves, map_techniques
from app.normalize.developments import classify_development
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
    "california_oag": {
        "feed_url": None,
        "feed_type": "html_scrape",
        "note": "CA OAG SB24 breach list: hand-tuned ScrapeConfig (views-table row parse), capped to recent rows",
    },
    "haveibeenpwned": {
        "feed_url": "https://haveibeenpwned.com/api/v3/breaches",
        "feed_type": "json_api",
        "note": "The /breaches metadata endpoint requires NO API key (verified) — a key only raises rate limits",
    },
}

# Sources added after the initial seed_sources.sql. On an already-seeded
# production database that INSERT never re-runs, so ensure they exist here
# (idempotent via the unique slug). ransomlook runs on the schedule;
# breachdirectory is an on-demand lookup (never scheduled — see registry
# ON_DEMAND_ONLY_SLUGS) and stays dormant until a RapidAPI key is set.
NEW_SOURCES = [
    {
        "slug": "ransomlook", "name": "RansomLook", "base_url": "https://www.ransomlook.io",
        "category": "ransomware_leak_tracker", "feed_type": "json_api",
        "feed_url": "https://www.ransomlook.io/api/recent", "requires_api_key": False,
        "collection_mode": "scheduled",
        "notes": "Keyless JSON API of recent leak-site victims; corroborates ransomware.live",
    },
    {
        "slug": "breachdirectory", "name": "BreachDirectory", "base_url": "https://breachdirectory.org",
        "category": "breach_lookup_service", "feed_type": "json_api",
        "feed_url": "https://breachdirectory.p.rapidapi.com/", "requires_api_key": True,
        "collection_mode": "on_demand_lookup",
        "notes": "Per-query lookup via RapidAPI. Metadata-only; never store credential fields.",
    },
]


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
SET search_path = pg_catalog, public
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

# Public-data contract (WP-002). Default private; deliberately public only where
# the unauthenticated product needs it. See docs/security/public-data-contract.md.
# Anonymous reads are limited to these genuinely-public product objects; internal
# and operational tables are made private by ENSURE_PRIVATE below, and the dossier
# reads source/news data through the curated v_public_* views instead of the raw
# base tables. This is re-asserted idempotently on every run so the state cannot
# silently drift back to "everything public".
PUBLIC_READ_TABLES = [
    "breaches", "threat_radar", "breach_developments", "breach_enrichment_log",
    # WP-003 curated public projection tables (sanitised copies; the app-facing
    # v_public_* views are security_invoker views over these).
    "public_breach_sources", "public_breach_news",
]
PUBLIC_READ_VIEWS = [
    "mv_breach_ledger", "mv_breach_trends", "mv_top_ransomware_groups",
    "mv_platform_stats", "v_public_breach_sources", "v_public_news",
]

# Internal / operational tables that must NOT be anonymously readable. Source and
# news data reach the site through curated views; the rest are operational or
# join-only. Enforced every run (RLS on, public-read policy dropped, grants
# revoked) so hardening is durable.
PRIVATE_TABLES = [
    "breach_source_records", "news_watch", "breach_data_sources",
    "breach_companies", "breach_collector_log", "breach_match_queue",
    "threat_actors",
]

ENSURE_PUBLIC_READ = """
DO $$
DECLARE
    tbl text;
    rel text;
BEGIN
    FOREACH tbl IN ARRAY ARRAY[{tables}]
    LOOP
        -- news_watch is created by the news-watch job, which may not have run
        -- yet on a given database. Skip any table that doesn't exist rather
        -- than aborting the whole heal.
        CONTINUE WHEN to_regclass('public.' || tbl) IS NULL;
        -- ENABLE RLS takes an AccessExclusiveLock even when RLS is already on,
        -- so only run it when actually needed — otherwise every 6h pass grabs
        -- exclusive locks on every table for nothing (and can deadlock against
        -- a concurrent schema-creating job).
        IF NOT (SELECT relrowsecurity FROM pg_class WHERE oid = to_regclass('public.' || tbl)) THEN
            EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tbl);
        END IF;
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
            CONTINUE WHEN to_regclass('public.' || rel) IS NULL;
            EXECUTE format('GRANT SELECT ON %I TO anon', rel);
        END LOOP;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        FOREACH rel IN ARRAY ARRAY[{relations}]
        LOOP
            CONTINUE WHEN to_regclass('public.' || rel) IS NULL;
            EXECUTE format('GRANT SELECT ON %I TO authenticated', rel);
        END LOOP;
    END IF;
END $$
""".format(
    tables=", ".join(f"'{t}'" for t in PUBLIC_READ_TABLES),
    relations=", ".join(f"'{r}'" for r in PUBLIC_READ_TABLES + PUBLIC_READ_VIEWS),
)


# WP-003 public projection tables. The trust boundary is a deliberately-public,
# sanitised COPY of the source/news data, populated by this owner-side code. The
# application-facing names (v_public_breach_sources, v_public_news) stay, but as
# security_invoker views over the public projection tables, so they never bypass
# RLS on a private table and clear the "Security Definer View" adviser finding.
# Schema + views only here (idempotent); data is loaded by refresh_public_projections.
ENSURE_PROJECTIONS = """
DO $$
BEGIN
    CREATE TABLE IF NOT EXISTS public.public_breach_sources (
        id                   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        matched_breach_id    uuid NOT NULL,
        source_record_url    text,
        document_type        text,
        summary              text,
        source_published_at  timestamptz,
        match_confidence     numeric(4,3),
        records_affected_est bigint,
        data_types_exposed   text[],
        ransomware_group_norm text,
        ransomware_group_raw  text,
        incident_date        date,
        industry             text,
        region_state         text,
        country              text,
        source_name          text,
        source_category      text,
        disclosure_url       text,
        screenshot_url       text
    );
    CREATE INDEX IF NOT EXISTS idx_public_sources_breach ON public.public_breach_sources (matched_breach_id);
    CREATE TABLE IF NOT EXISTS public.public_breach_news (
        id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        matched_breach_id uuid NOT NULL,
        title             text,
        url               text,
        source_name       text,
        published_at      timestamptz,
        similarity        numeric(4,3)
    );
    CREATE INDEX IF NOT EXISTS idx_public_news_breach ON public.public_breach_news (matched_breach_id);

    ALTER TABLE public.public_breach_sources ENABLE ROW LEVEL SECURITY;
    ALTER TABLE public.public_breach_news    ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS "public read" ON public.public_breach_sources;
    CREATE POLICY "public read" ON public.public_breach_sources FOR SELECT USING (true);
    DROP POLICY IF EXISTS "public read" ON public.public_breach_news;
    CREATE POLICY "public read" ON public.public_breach_news FOR SELECT USING (true);

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='anon') THEN
        REVOKE INSERT, UPDATE, DELETE ON public.public_breach_sources FROM anon;
        REVOKE INSERT, UPDATE, DELETE ON public.public_breach_news FROM anon;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='authenticated') THEN
        REVOKE INSERT, UPDATE, DELETE ON public.public_breach_sources FROM authenticated;
        REVOKE INSERT, UPDATE, DELETE ON public.public_breach_news FROM authenticated;
    END IF;

    DROP VIEW IF EXISTS public.v_public_breach_sources;
    CREATE VIEW public.v_public_breach_sources WITH (security_invoker = true) AS
        SELECT matched_breach_id, source_record_url, document_type, summary, source_published_at,
               match_confidence, records_affected_est, data_types_exposed, ransomware_group_norm,
               ransomware_group_raw, incident_date, industry, region_state, country,
               source_name, source_category, disclosure_url, screenshot_url
        FROM public.public_breach_sources;
    DROP VIEW IF EXISTS public.v_public_news;
    CREATE VIEW public.v_public_news WITH (security_invoker = true) AS
        SELECT matched_breach_id, title, url, source_name, published_at, similarity
        FROM public.public_breach_news;
END $$
"""


# Owner-side refresh of the public projections: a full transactional replace from
# the private source/news tables, so it is deterministic, idempotent and prunes
# rows that no longer exist upstream. The two evidence URLs are distilled from
# raw_payload here (never exposed to the public layer). Run in its own session
# (transaction) so external readers see an atomic swap, never an empty table.
REFRESH_SOURCES_INSERT = """
INSERT INTO public.public_breach_sources
    (matched_breach_id, source_record_url, document_type, summary, source_published_at,
     match_confidence, records_affected_est, data_types_exposed, ransomware_group_norm,
     ransomware_group_raw, incident_date, industry, region_state, country,
     source_name, source_category, disclosure_url, screenshot_url)
SELECT r.matched_breach_id, r.source_record_url, r.document_type, r.summary, r.source_published_at,
       r.match_confidence, r.records_affected_est, r.data_types_exposed, r.ransomware_group_norm,
       r.ransomware_group_raw, r.incident_date, r.industry, r.region_state, r.country,
       s.name, s.category,
       COALESCE(r.raw_payload->>'DisclosureUrl', r.raw_payload->>'disclosure_url'),
       COALESCE(r.raw_payload->>'screenshot', r.raw_payload->>'screen', r.raw_payload->>'image')
FROM public.breach_source_records r
LEFT JOIN public.breach_data_sources s ON s.id = r.source_id
WHERE r.matched_breach_id IS NOT NULL
"""

REFRESH_NEWS_INSERT = """
INSERT INTO public.public_breach_news
    (matched_breach_id, title, url, source_name, published_at, similarity)
SELECT matched_breach_id, title, url, source_name, published_at, similarity
FROM public.news_watch
WHERE matched_breach_id IS NOT NULL
"""


async def refresh_public_projections(session) -> None:
    """Reload the public projection tables from the private source/news tables.
    Full replace inside one transaction = atomic swap for readers. Removed/edited
    upstream rows are reflected because the projection is rebuilt from scratch."""
    if (await session.execute(
        text("SELECT to_regclass('public.public_breach_sources') IS NOT NULL")
    )).scalar() and (await session.execute(
        text("SELECT to_regclass('public.breach_source_records') IS NOT NULL")
    )).scalar():
        await session.execute(text("DELETE FROM public.public_breach_sources"))
        await session.execute(text(REFRESH_SOURCES_INSERT))
        n = (await session.execute(text("SELECT count(*) FROM public.public_breach_sources"))).scalar()
        logger.info("Refreshed public_breach_sources projection: %s row(s)", n)

    has_news = (await session.execute(
        text("SELECT to_regclass('public.news_watch') IS NOT NULL")
    )).scalar()
    if has_news and (await session.execute(
        text("SELECT to_regclass('public.public_breach_news') IS NOT NULL")
    )).scalar():
        await session.execute(text("DELETE FROM public.public_breach_news"))
        await session.execute(text(REFRESH_NEWS_INSERT))
        n = (await session.execute(text("SELECT count(*) FROM public.public_breach_news"))).scalar()
        logger.info("Refreshed public_breach_news projection: %s row(s)", n)


# Make internal/operational tables private and keep them private: RLS on, the
# blanket public-read policy dropped, grants revoked from the API roles. Also
# removes the operational mv_source_health from the Data API. Idempotent.
ENSURE_PRIVATE = """
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY[{privtables}]
    LOOP
        CONTINUE WHEN to_regclass('public.' || t) IS NULL;
        IF NOT (SELECT relrowsecurity FROM pg_class WHERE oid = to_regclass('public.' || t)) THEN
            EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        END IF;
        EXECUTE format('DROP POLICY IF EXISTS "public read" ON %I', t);
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
            EXECUTE format('REVOKE ALL ON %I FROM anon', t);
        END IF;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
            EXECUTE format('REVOKE ALL ON %I FROM authenticated', t);
        END IF;
    END LOOP;
    IF to_regclass('public.mv_source_health') IS NOT NULL THEN
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
            REVOKE ALL ON mv_source_health FROM anon;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
            REVOKE ALL ON mv_source_health FROM authenticated;
        END IF;
    END IF;
END $$
""".format(privtables=", ".join(f"'{t}'" for t in PRIVATE_TABLES))


# Keep administrative functions off the Data API and pin safe search paths.
# refresh_breach_views is expensive (5x REFRESH) and must not be RPC-callable;
# rls_auto_enable (dashboard-created, SECURITY DEFINER) must not be anon-callable.
# The trigger functions get a fixed search_path to clear the adviser warning.
HARDEN_FUNCTIONS = """
DO $$
BEGIN
    IF to_regprocedure('public.refresh_breach_views()') IS NOT NULL THEN
        REVOKE ALL ON FUNCTION public.refresh_breach_views() FROM PUBLIC;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
            REVOKE ALL ON FUNCTION public.refresh_breach_views() FROM anon;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
            REVOKE ALL ON FUNCTION public.refresh_breach_views() FROM authenticated;
        END IF;
        ALTER FUNCTION public.refresh_breach_views() SET search_path = pg_catalog, public;
    END IF;
    IF to_regprocedure('public.rls_auto_enable()') IS NOT NULL THEN
        REVOKE ALL ON FUNCTION public.rls_auto_enable() FROM PUBLIC;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
            REVOKE ALL ON FUNCTION public.rls_auto_enable() FROM anon;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
            REVOKE ALL ON FUNCTION public.rls_auto_enable() FROM authenticated;
        END IF;
        ALTER FUNCTION public.rls_auto_enable() SET search_path = pg_catalog, public;
    END IF;
    IF to_regprocedure('public.set_updated_at()') IS NOT NULL THEN
        ALTER FUNCTION public.set_updated_at() SET search_path = pg_catalog, public;
    END IF;
    IF to_regprocedure('public.breaches_search_vector_trigger()') IS NOT NULL THEN
        ALTER FUNCTION public.breaches_search_vector_trigger() SET search_path = pg_catalog, public;
    END IF;
END $$
"""


async def fix_sources(session) -> None:
    # Register sources added after the original seed (idempotent on slug).
    for s in NEW_SOURCES:
        res = await session.execute(
            text(
                "INSERT INTO breach_data_sources "
                "(slug, name, base_url, category, feed_type, feed_url, requires_api_key, collection_mode, notes) "
                "VALUES (:slug, :name, :base_url, :category, :feed_type, :feed_url, :requires_api_key, :collection_mode, :notes) "
                "ON CONFLICT (slug) DO NOTHING"
            ),
            s,
        )
        if res.rowcount:
            logger.info("Registered new source '%s'", s["slug"])

    # Source names show on breach pages; normalize em/en dashes in them to a
    # plain hyphen so the UI stays dash-free (0x2014 = em dash, 0x2013 = en).
    em, en = chr(0x2014), chr(0x2013)
    await session.execute(
        text(
            "UPDATE breach_data_sources SET name = replace(replace(name, :em, '-'), :en, '-') "
            "WHERE name LIKE :emlike OR name LIKE :enlike"
        ),
        {"em": em, "en": en, "emlike": f"%{em}%", "enlike": f"%{en}%"},
    )
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


# A single transaction-level advisory lock shared by every code path that
# runs grant/RLS/schema DDL (maintenance here, plus news_watch and
# threat_radar ensure_schema). Acquired BEFORE any table lock, it serializes
# concurrent DDL runs so an overlapping ingest + news-watch (or a
# double-dispatch) waits instead of deadlocking on table locks. Value is
# arbitrary but must match across those modules.
DDL_ADVISORY_LOCK = 918273645


# Columns added after the original schema. Guarded so the ALTER (and its
# exclusive lock) only runs the first time, then is a catalog no-op.
ENSURE_BREACH_COLUMNS = """
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='breaches' AND column_name='cves') THEN
        ALTER TABLE breaches ADD COLUMN cves TEXT[] NOT NULL DEFAULT '{}';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='breaches' AND column_name='attack_techniques') THEN
        ALTER TABLE breaches ADD COLUMN attack_techniques TEXT[] NOT NULL DEFAULT '{}';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='breaches' AND column_name='data_flags') THEN
        ALTER TABLE breaches ADD COLUMN data_flags TEXT[] NOT NULL DEFAULT '{}';
    END IF;
END $$
"""

# mv_breach_ledger predates the data_flags column, so a live database has the
# view without it. It has no dependent objects (the other MVs read base tables),
# so recreate it once to expose data_flags to the site. Guarded on the view's
# columns so this drop/create runs only the first time; grants are re-asserted
# by ENSURE_PUBLIC_READ immediately after.
ENSURE_LEDGER_HAS_FLAGS = """
DO $$
BEGIN
    -- information_schema.columns does NOT list materialized-view columns, so the
    -- presence of data_flags must be checked via pg_attribute on the matview.
    IF EXISTS (SELECT 1 FROM pg_matviews WHERE matviewname='mv_breach_ledger')
       AND NOT EXISTS (
           SELECT 1 FROM pg_attribute a
           JOIN pg_class c ON c.oid = a.attrelid
           WHERE c.relname='mv_breach_ledger' AND c.relkind='m'
             AND a.attname='data_flags' AND a.attnum > 0 AND NOT a.attisdropped) THEN
        DROP MATERIALIZED VIEW mv_breach_ledger CASCADE;
        CREATE MATERIALIZED VIEW mv_breach_ledger AS
        SELECT b.id, b.canonical_name, c.domain, b.industry, b.country, b.region_state,
               b.ransomware_group, b.incident_date, b.disclosed_date, b.records_affected_est,
               b.severity, b.status, b.source_count, b.confidence_avg, b.data_flags, b.last_updated_at
        FROM breaches b LEFT JOIN breach_companies c ON c.id = b.company_id;
        CREATE UNIQUE INDEX idx_mv_ledger_id ON mv_breach_ledger (id);
        CREATE INDEX idx_mv_ledger_date ON mv_breach_ledger (incident_date DESC);
        CREATE INDEX idx_mv_ledger_industry ON mv_breach_ledger (industry);
        CREATE INDEX idx_mv_ledger_group ON mv_breach_ledger (ransomware_group);
    END IF;
END $$
"""


# Append-only audit trail of what the re-enrichment loop changed on each
# breach and when, so the dossier can show "this record improved as more was
# disclosed." Created here (IF NOT EXISTS) so existing databases pick it up.
# asyncpg refuses multiple commands in one prepared statement, so the table
# plus its indexes are wrapped in a single DO block (one command to the driver).
ENSURE_ENRICHMENT_LOG = """
DO $$
BEGIN
    CREATE TABLE IF NOT EXISTS breach_enrichment_log (
        id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        breach_id   UUID NOT NULL REFERENCES breaches(id) ON DELETE CASCADE,
        changed     JSONB NOT NULL,
        enriched_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS idx_enrichment_log_breach ON breach_enrichment_log (breach_id);
    CREATE INDEX IF NOT EXISTS idx_enrichment_log_time ON breach_enrichment_log (enriched_at DESC);
END $$
"""


# Post-incident developments attached to an existing breach: regulatory fines,
# litigation and settlements that surface after disclosure. One row per detected
# development, deduped per breach by a stable key. Wrapped in a DO block so the
# table plus its index reach asyncpg as a single command.
ENSURE_DEVELOPMENTS = """
DO $$
BEGIN
    CREATE TABLE IF NOT EXISTS breach_developments (
        id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        breach_id   UUID NOT NULL REFERENCES breaches(id) ON DELETE CASCADE,
        kind        TEXT NOT NULL,
        title       TEXT NOT NULL,
        detail      JSONB NOT NULL DEFAULT '{}',
        url         TEXT,
        source_name TEXT,
        occurred_at DATE,
        dedupe_key  TEXT NOT NULL,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (breach_id, dedupe_key)
    );
    CREATE INDEX IF NOT EXISTS idx_developments_breach ON breach_developments (breach_id);
    CREATE INDEX IF NOT EXISTS idx_developments_kind ON breach_developments (kind);
END $$
"""


async def ensure_views(session) -> None:
    # Take the DDL lock first, before ALTER / CREATE MATERIALIZED VIEW / GRANT
    # below acquire any table locks.
    await session.execute(text("SELECT pg_advisory_xact_lock(CAST(:k AS bigint))"), {"k": DDL_ADVISORY_LOCK})
    await session.execute(text(ENSURE_BREACH_COLUMNS))
    await session.execute(text(ENSURE_LEDGER_HAS_FLAGS))
    await session.execute(text(ENSURE_ENRICHMENT_LOG))
    await session.execute(text(ENSURE_DEVELOPMENTS))
    await session.execute(text(PLATFORM_STATS_VIEW))
    await session.execute(text(REFRESH_FUNCTION))
    # Create the public projection tables + security_invoker views before
    # granting them, then apply the least-privilege contract: grant the public
    # allowlist, revoke everything else from the API roles, and keep admin
    # functions off the Data API.
    await session.execute(text(ENSURE_PROJECTIONS))
    await session.execute(text(GRANT_STATS_VIEW))
    await session.execute(text(ENSURE_PUBLIC_READ))
    await session.execute(text(ENSURE_PRIVATE))
    await session.execute(text(HARDEN_FUNCTIONS))


async def backfill_attack_cve(session) -> None:
    """
    Tag each breach with the CVEs and MITRE ATT&CK techniques derivable from
    its linked sources' text (titles/summaries/AG-letter payloads). CVEs are
    matched by identifier; techniques are inferred from breach-reporting
    language (see normalize/attack_cve.py). Idempotent — only writes on change.
    """
    from collections import defaultdict

    rows = (await session.execute(
        text(
            "SELECT matched_breach_id AS bid, summary, company_name_raw, raw_payload::text AS rp "
            "FROM breach_source_records WHERE matched_breach_id IS NOT NULL"
        )
    )).fetchall()

    texts: dict[str, list[str]] = defaultdict(list)
    for r in rows:
        texts[str(r.bid)].append(" ".join(x for x in (r.summary, r.company_name_raw, r.rp) if x))

    updated = 0
    for bid, parts in texts.items():
        blob = " ".join(parts)
        cves = extract_cves(blob)
        techs = map_techniques(blob)
        res = await session.execute(
            text(
                "UPDATE breaches SET cves = CAST(:cves AS text[]), attack_techniques = CAST(:techs AS text[]) "
                "WHERE id = :bid AND (cves IS DISTINCT FROM CAST(:cves AS text[]) "
                "OR attack_techniques IS DISTINCT FROM CAST(:techs AS text[]))"
            ),
            {"cves": cves, "techs": techs, "bid": bid},
        )
        if res.rowcount:
            updated += 1
    if updated:
        logger.info("Tagged %d breaches with CVEs / ATT&CK techniques from source text", updated)


# The re-enrichment loop. Unlike backfill_breach_fields (which only fills a
# breach field that is still NULL), this revisits every breach and lets its
# facts IMPROVE from the full set of currently-linked source records as more is
# disclosed over time: a higher/confirmed record count (GREATEST), additional
# exposed-data categories (set union), and a threat actor named by a source
# that arrived later (COALESCE). Dates are fill-only, never moved, so a curated
# or earlier date is never regressed. Every change is written to
# breach_enrichment_log so the dossier can show that the record got better, and
# the whole thing is idempotent: once a breach reflects the best of its sources,
# later passes compute the same values and log nothing.
REENRICH_SQL = """
WITH src AS (
    SELECT r.matched_breach_id AS bid,
        min(r.incident_date) FILTER (
            WHERE r.incident_date >= DATE '2000-01-01' AND r.incident_date <= CURRENT_DATE + 2) AS min_inc,
        min(CAST(r.source_published_at AS date)) FILTER (
            WHERE CAST(r.source_published_at AS date) >= DATE '2000-01-01'
              AND CAST(r.source_published_at AS date) <= CURRENT_DATE + 2) AS min_disc,
        max(r.records_affected_est) AS max_records,
        (array_agg(r.ransomware_group_norm) FILTER (WHERE r.ransomware_group_norm IS NOT NULL))[1] AS any_group
    FROM breach_source_records r
    WHERE r.matched_breach_id IS NOT NULL
    GROUP BY r.matched_breach_id
),
dts AS (
    SELECT r.matched_breach_id AS bid, array_agg(DISTINCT d) AS dtypes
    FROM breach_source_records r
    CROSS JOIN LATERAL unnest(COALESCE(r.data_types_exposed, '{}'::text[])) AS d
    WHERE r.matched_breach_id IS NOT NULL
    GROUP BY r.matched_breach_id
),
d AS (
    SELECT b.id,
        COALESCE(b.incident_date, s.min_inc) AS inc_date,
        COALESCE(b.disclosed_date, s.min_disc, b.incident_date, s.min_inc) AS disc_date,
        GREATEST(b.records_affected_est, s.max_records) AS records,
        COALESCE(
            (SELECT array_agg(DISTINCT x)
             FROM unnest(COALESCE(b.data_types_exposed, '{}'::text[]) || COALESCE(dts.dtypes, '{}'::text[])) AS x),
            b.data_types_exposed) AS data_types,
        COALESCE(b.ransomware_group, s.any_group) AS grp,
        b.incident_date AS old_inc, b.disclosed_date AS old_disc,
        b.records_affected_est AS old_records, b.data_types_exposed AS old_dt,
        b.ransomware_group AS old_grp
    FROM breaches b
    JOIN src s ON s.bid = b.id
    LEFT JOIN dts ON dts.bid = b.id
),
diffed AS (
    SELECT d.*,
        jsonb_strip_nulls(jsonb_build_object(
            'records_affected_est', CASE WHEN d.records IS DISTINCT FROM d.old_records
                THEN jsonb_build_object('from', d.old_records, 'to', d.records) END,
            'data_types_exposed', CASE WHEN NOT (
                    COALESCE(d.data_types, '{}'::text[]) @> COALESCE(d.old_dt, '{}'::text[])
                AND COALESCE(d.data_types, '{}'::text[]) <@ COALESCE(d.old_dt, '{}'::text[]))
                THEN jsonb_build_object('from', to_jsonb(d.old_dt), 'to', to_jsonb(d.data_types)) END,
            'ransomware_group', CASE WHEN d.grp IS DISTINCT FROM d.old_grp
                THEN jsonb_build_object('from', d.old_grp, 'to', d.grp) END,
            'incident_date', CASE WHEN d.inc_date IS DISTINCT FROM d.old_inc
                THEN jsonb_build_object('from', d.old_inc, 'to', d.inc_date) END,
            'disclosed_date', CASE WHEN d.disc_date IS DISTINCT FROM d.old_disc
                THEN jsonb_build_object('from', d.old_disc, 'to', d.disc_date) END
        )) AS changed
    FROM d
),
ins AS (
    INSERT INTO breach_enrichment_log (breach_id, changed)
    SELECT id, changed FROM diffed WHERE changed <> '{}'::jsonb
    RETURNING 1
)
UPDATE breaches b SET
    incident_date = df.inc_date,
    disclosed_date = df.disc_date,
    records_affected_est = df.records,
    data_types_exposed = df.data_types,
    ransomware_group = df.grp,
    last_updated_at = now()
FROM diffed df
WHERE b.id = df.id AND df.changed <> '{}'::jsonb
"""


async def reenrich_breaches(session) -> None:
    res = await session.execute(text(REENRICH_SQL))
    if res.rowcount:
        logger.info("Re-enriched %d breach(es) from newer/richer source data", res.rowcount)
        await recompute_severity(session)


# Insert any classified developments in one statement (asyncpg-safe): the
# per-row values arrive as parallel arrays and are unnested server-side.
# text[]::jsonb[] casts the JSON strings to jsonb. ON CONFLICT keeps it
# idempotent per (breach_id, dedupe_key).
INSERT_DEVELOPMENTS_SQL = """
INSERT INTO breach_developments (breach_id, kind, title, detail, url, source_name, occurred_at, dedupe_key)
SELECT * FROM unnest(
    CAST(:bids AS uuid[]), CAST(:kinds AS text[]), CAST(:titles AS text[]),
    CAST(:details AS jsonb[]), CAST(:urls AS text[]), CAST(:sources AS text[]),
    CAST(:occurred AS date[]), CAST(:keys AS text[]))
ON CONFLICT (breach_id, dedupe_key) DO NOTHING
"""


async def detect_developments(session) -> None:
    """
    Scan every breach-matched text (news-watch headlines + source-record
    summaries) for post-incident developments — regulatory fines, litigation
    and settlements — and attach them to the breach as breach_developments
    rows. Then set/clear the 'has_developments' data flag so the ledger can
    badge a breach whose story continued. Idempotent: rows are deduped per
    breach and re-runs insert nothing new.
    """
    import hashlib
    import json

    candidates: list = []
    # news_watch is created by the news-watch job and may be absent on a fresh
    # database; include it only when present.
    has_news = (await session.execute(
        text("SELECT to_regclass('public.news_watch') IS NOT NULL")
    )).scalar()
    if has_news:
        candidates += (await session.execute(text(
            "SELECT matched_breach_id AS bid, title AS txt, url, source_name, "
            "CAST(published_at AS date) AS occurred "
            "FROM news_watch WHERE matched_breach_id IS NOT NULL"
        ))).fetchall()
    candidates += (await session.execute(text(
        "SELECT r.matched_breach_id AS bid, r.summary AS txt, r.source_record_url AS url, "
        "s.name AS source_name, CAST(r.source_published_at AS date) AS occurred "
        "FROM breach_source_records r LEFT JOIN breach_data_sources s ON s.id = r.source_id "
        "WHERE r.matched_breach_id IS NOT NULL AND r.summary IS NOT NULL"
    ))).fetchall()

    cols = {"bids": [], "kinds": [], "titles": [], "details": [], "urls": [], "sources": [], "occurred": [], "keys": []}
    seen: set = set()
    for row in candidates:
        cls = classify_development(row.txt)
        if not cls:
            continue
        bid = str(row.bid)
        url = row.url or ""
        # Stable per-breach key: kind + the source link (or the text when there
        # is no link), so the same story is not attached twice.
        key = hashlib.sha1(f"{cls['kind']}|{url or row.txt}".encode("utf-8")).hexdigest()[:16]
        if (bid, key) in seen:
            continue
        seen.add((bid, key))
        cols["bids"].append(bid)
        cols["kinds"].append(cls["kind"])
        cols["titles"].append((row.txt or "")[:400])
        cols["details"].append(json.dumps(cls["detail"]))
        cols["urls"].append(row.url)
        cols["sources"].append(row.source_name)
        cols["occurred"].append(row.occurred)
        cols["keys"].append(key)

    if cols["bids"]:
        before = (await session.execute(text("SELECT count(*) FROM breach_developments"))).scalar()
        await session.execute(text(INSERT_DEVELOPMENTS_SQL), cols)
        after = (await session.execute(text("SELECT count(*) FROM breach_developments"))).scalar()
        if after > before:
            logger.info("Detected %d new post-incident development(s) (fines / litigation / settlements)", after - before)

    # Self-heal: drop stored developments whose text no longer classifies as the
    # same kind under the current rules, so tightening the classifier (e.g. the
    # breach-nexus guard) retroactively cleans out earlier false positives. Only
    # ever removes rows that fail the current check; genuine developments stay.
    stored = (await session.execute(
        text("SELECT id, kind, title FROM breach_developments")
    )).fetchall()
    stale = []
    for r in stored:
        cc = classify_development(r.title)
        if not cc or cc["kind"] != r.kind:
            stale.append(str(r.id))
    if stale:
        await session.execute(
            text("DELETE FROM breach_developments WHERE id = ANY(CAST(:ids AS uuid[]))"),
            {"ids": stale},
        )
        logger.info("Removed %d stale development(s) no longer matching the classifier", len(stale))

    # Flag breaches that now carry a development, and clear the flag from any
    # that no longer do, so the ledger badge stays accurate.
    await session.execute(text(
        "UPDATE breaches SET data_flags = "
        "(SELECT array_agg(DISTINCT f) FROM unnest(data_flags || ARRAY['has_developments']) AS f) "
        "WHERE id IN (SELECT DISTINCT breach_id FROM breach_developments) "
        "AND NOT ('has_developments' = ANY(data_flags))"
    ))
    await session.execute(text(
        "UPDATE breaches SET data_flags = array_remove(data_flags, 'has_developments') "
        "WHERE 'has_developments' = ANY(data_flags) "
        "AND id NOT IN (SELECT DISTINCT breach_id FROM breach_developments)"
    ))


# Hand-verified corrections to individual breaches. The ledger is machine-built,
# so a mis-parsed source occasionally needs an override. Corrections live here
# (reviewed in git, never edited into the database by hand) and run near the end
# of a maintenance pass, right before the views refresh. Each is idempotent:
# backfill only fills NULL date fields and merge keeps the earliest date, so once
# a correct non-NULL value is written nothing overwrites it, and the guarded
# WHERE clause matches zero rows on later passes.
async def apply_curated_fixes(session) -> None:
    # DaVita Inc.: dateutil fuzzy parsing produced an impossible future date
    # (2027-11-20) for both incident and disclosure, which sorted the row to the
    # top of the ledger. Authoritative dates: incident 2024-06-17, disclosed
    # 2024-07-02. Keyed on "DaVita with a future date" so it targets only the
    # one broken row and leaves the other DaVita incidents' dates untouched.
    res = await session.execute(
        text(
            """
            UPDATE breaches
            SET incident_date = DATE '2024-06-17',
                disclosed_date = DATE '2024-07-02',
                last_updated_at = now()
            WHERE canonical_name ILIKE 'davita%'
              AND (disclosed_date > CURRENT_DATE OR incident_date > CURRENT_DATE)
            """
        )
    )
    if res.rowcount:
        logger.info("Applied curated date correction to %d DaVita breach row(s)", res.rowcount)


# A date in the future, or before 2000, is implausible for a breach and is
# almost always a source-side typo (e.g. DaVita's CA OAG notice listing 2027).
# Rather than silently drop it at parse time or show a wrong date, blank it to
# UNKNOWN on the breach and tag the breach 'date_needs_review' so the site
# surfaces it for a manual fix. Also blank the implausible date on the source
# records so backfill can't reintroduce it. Idempotent, and runs after the
# curated fixes so a corrected breach is never flagged.
IMPLAUSIBLE_DATE_PRED = "{col} > CURRENT_DATE + 2 OR {col} < DATE '2000-01-01'"


async def flag_implausible_dates(session) -> None:
    await session.execute(
        text(
            "UPDATE breach_source_records SET incident_date = NULL "
            f"WHERE {IMPLAUSIBLE_DATE_PRED.format(col='incident_date')}"
        )
    )
    inc = IMPLAUSIBLE_DATE_PRED.format(col="incident_date")
    disc = IMPLAUSIBLE_DATE_PRED.format(col="disclosed_date")
    res = await session.execute(
        text(
            f"""
            UPDATE breaches SET
                data_flags = (SELECT array_agg(DISTINCT f)
                              FROM unnest(data_flags || ARRAY['date_needs_review']) AS f),
                incident_date = CASE WHEN {inc} THEN NULL ELSE incident_date END,
                disclosed_date = CASE WHEN {disc} THEN NULL ELSE disclosed_date END
            WHERE {inc} OR {disc}
            """
        )
    )
    if res.rowcount:
        logger.info("Flagged %d breach(es) with implausible source dates for manual date review", res.rowcount)
    # Clear the tag once a breach has a real date again (e.g. after a curated fix).
    await session.execute(
        text(
            "UPDATE breaches SET data_flags = array_remove(data_flags, 'date_needs_review') "
            "WHERE 'date_needs_review' = ANY(data_flags) "
            "AND (incident_date IS NOT NULL OR disclosed_date IS NOT NULL)"
        )
    )


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
        await backfill_attack_cve(session)
    async with get_session() as session:
        await reenrich_breaches(session)
    async with get_session() as session:
        await detect_developments(session)
    async with get_session() as session:
        await apply_curated_fixes(session)
    async with get_session() as session:
        await flag_implausible_dates(session)
    # Rebuild the public projection tables from the (now settled) private source
    # and news data, in their own transaction for an atomic swap.
    async with get_session() as session:
        await refresh_public_projections(session)
    async with get_session() as session:
        await session.execute(text("SELECT refresh_breach_views()"))
    logger.info("Maintenance pass complete.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run_resiliently(run_maintenance))
