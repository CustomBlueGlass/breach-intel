-- ============================================================================
-- Migration 0002: public projection tables (WP-003)
--
-- Follow-up to 0001. Removes the two Security Definer views the Supabase adviser
-- flags as ERROR by moving the trust boundary to deliberately-public, curated
-- projection TABLES populated by owner-side maintenance. The application-facing
-- names remain as ordinary security_invoker views over those public tables, so
-- no frontend change is needed and the private operational tables are never
-- queried by the anon role.
--
-- Apply AFTER 0001:  psql "$DATABASE_URL" -f db/migrations/0002_public_projection_tables.sql
-- Idempotent and non-destructive: creates two public tables, (re)creates two
-- views, backfills the tables from the private sources. Drops ONLY the two
-- v_public_* views (allowed by spec); never drops source tables or data.
--
-- maintenance.py applies the same objects and refreshes the projections every
-- run, so this state is self-healing and does not depend on re-applying this file.
-- ============================================================================

BEGIN;

SELECT pg_catalog.pg_advisory_xact_lock(918273645);

-- ---- curated public projection tables -------------------------------------
-- public_breach_sources: sanitised, publishable copy of the dossier source data.
-- Contains ONLY the columns the UI renders plus the two evidence URLs distilled
-- from raw_payload during this trusted refresh. It never holds raw_payload,
-- fingerprints, source ids or raw company names.
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

-- public_breach_news: sanitised copy of correlated news headlines.
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

-- ---- RLS + grants: public SELECT only, no client writes -------------------
ALTER TABLE public.public_breach_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.public_breach_news    ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "public read" ON public.public_breach_sources;
CREATE POLICY "public read" ON public.public_breach_sources FOR SELECT USING (true);
DROP POLICY IF EXISTS "public read" ON public.public_breach_news;
CREATE POLICY "public read" ON public.public_breach_news FOR SELECT USING (true);

DO $$
DECLARE rl text;
BEGIN
  FOREACH rl IN ARRAY ARRAY['anon','authenticated'] LOOP
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=rl) THEN
      EXECUTE format('GRANT SELECT ON public.public_breach_sources TO %I', rl);
      EXECUTE format('GRANT SELECT ON public.public_breach_news TO %I', rl);
      EXECUTE format('REVOKE INSERT, UPDATE, DELETE ON public.public_breach_sources FROM %I', rl);
      EXECUTE format('REVOKE INSERT, UPDATE, DELETE ON public.public_breach_news FROM %I', rl);
    END IF;
  END LOOP;
END $$;

-- ---- backfill from the private source tables (owner-side) ------------------
-- Full transactional replace: deterministic, idempotent, removes rows that no
-- longer exist upstream. Readers see the previous contents until COMMIT.
DO $$
BEGIN
  IF pg_catalog.to_regclass('public.breach_source_records') IS NOT NULL
     AND pg_catalog.to_regclass('public.breach_data_sources') IS NOT NULL THEN
    DELETE FROM public.public_breach_sources;
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
    WHERE r.matched_breach_id IS NOT NULL;
  END IF;

  IF pg_catalog.to_regclass('public.news_watch') IS NOT NULL THEN
    DELETE FROM public.public_breach_news;
    INSERT INTO public.public_breach_news
      (matched_breach_id, title, url, source_name, published_at, similarity)
    SELECT matched_breach_id, title, url, source_name, published_at, similarity
    FROM public.news_watch
    WHERE matched_breach_id IS NOT NULL;
  END IF;
END $$;

-- ---- replace the Security Definer views with security_invoker views --------
-- These now read ONLY the public projection tables, so they never bypass RLS on
-- a private table and the "Security Definer View" adviser finding is cleared.
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

DO $$
DECLARE rl text;
BEGIN
  FOREACH rl IN ARRAY ARRAY['anon','authenticated'] LOOP
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=rl) THEN
      EXECUTE format('GRANT SELECT ON public.v_public_breach_sources TO %I', rl);
      EXECUTE format('GRANT SELECT ON public.v_public_news TO %I', rl);
    END IF;
  END LOOP;
END $$;

COMMIT;
