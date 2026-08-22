-- ============================================================================
-- Migration 0001: security data hardening (WP-002)
--
-- Moves the Data API from "everything public unless proven otherwise" to
-- "default private; deliberately public where required". See
-- docs/security/public-data-contract.md for the per-object rationale.
--
-- Apply:   psql "$DATABASE_URL" -f db/migrations/0001_security_hardening.sql
-- Safe to re-run: every statement is idempotent and guarded by existence checks.
-- Non-destructive: no table/column/data is dropped. Only grants, the blanket
-- "public read" policies on internal tables, and admin-function EXECUTE are
-- changed, plus two curated read-only views are (re)created.
--
-- The GitHub Actions ingestion job connects as the owner/service role, which
-- bypasses RLS and retains ownership privileges, so ingestion is unaffected.
-- backend/app/maintenance.py enforces this same contract on every run, so the
-- state is self-healing and does not depend on this file being re-applied.
-- ============================================================================

BEGIN;

-- Serialize against the application's DDL self-heal (same advisory lock).
SELECT pg_catalog.pg_advisory_xact_lock(918273645);

-- ---------------------------------------------------------------------------
-- Task 2 — remove dangerous / expensive admin RPC exposure
-- ---------------------------------------------------------------------------
-- rls_auto_enable(): reported SECURITY DEFINER and executable by anon. It is
-- NOT referenced anywhere in this repository (created ad hoc in the dashboard),
-- so no client needs it. Neutralise the anon-callable-RPC risk by revoking
-- EXECUTE from every API role. Not dropped here because its body is unknown to
-- version control; the owner may DROP it after confirming it is unused. If it
-- is retained, pin a safe search_path.
DO $$
BEGIN
  IF pg_catalog.to_regprocedure('public.rls_auto_enable()') IS NOT NULL THEN
    REVOKE ALL ON FUNCTION public.rls_auto_enable() FROM PUBLIC;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='anon') THEN
      REVOKE ALL ON FUNCTION public.rls_auto_enable() FROM anon;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='authenticated') THEN
      REVOKE ALL ON FUNCTION public.rls_auto_enable() FROM authenticated;
    END IF;
    ALTER FUNCTION public.rls_auto_enable() SET search_path = pg_catalog, public;
  END IF;
END $$;

-- refresh_breach_views(): expensive (REFRESH MATERIALIZED VIEW x5). Only the
-- ingestion job (owner) should ever call it; revoke from the API roles so it is
-- not reachable as a PostgREST RPC (denial-of-service vector).
DO $$
BEGIN
  IF pg_catalog.to_regprocedure('public.refresh_breach_views()') IS NOT NULL THEN
    REVOKE ALL ON FUNCTION public.refresh_breach_views() FROM PUBLIC;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='anon') THEN
      REVOKE ALL ON FUNCTION public.refresh_breach_views() FROM anon;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='authenticated') THEN
      REVOKE ALL ON FUNCTION public.refresh_breach_views() FROM authenticated;
    END IF;
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- Task 3 — fix mutable search_path on the flagged functions
-- ---------------------------------------------------------------------------
-- A fixed search_path (pg_catalog first) prevents object-resolution hijacking
-- and clears the adviser warning. Bodies are unchanged: all referenced objects
-- resolve under pg_catalog + public, so behaviour is identical.
DO $$
BEGIN
  IF pg_catalog.to_regprocedure('public.refresh_breach_views()') IS NOT NULL THEN
    ALTER FUNCTION public.refresh_breach_views() SET search_path = pg_catalog, public;
  END IF;
  IF pg_catalog.to_regprocedure('public.set_updated_at()') IS NOT NULL THEN
    ALTER FUNCTION public.set_updated_at() SET search_path = pg_catalog, public;
  END IF;
  IF pg_catalog.to_regprocedure('public.breaches_search_vector_trigger()') IS NOT NULL THEN
    ALTER FUNCTION public.breaches_search_vector_trigger() SET search_path = pg_catalog, public;
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- Task 4/5 — curated public views + reduce table-level exposure
-- ---------------------------------------------------------------------------
-- Curated, read-only projection of source records for the public dossier.
-- Exposes ONLY the fields the site needs plus two distilled evidence URLs.
-- Deliberately omits: raw_payload, content_fingerprint, source_id, external_id,
-- company_name_raw/norm, fetched_at, created_at. Owner-owned view so anon can
-- read the curated columns without any access to the base table. This is an
-- intentional column-curation view (documented adviser exception).
DO $$
BEGIN
  IF pg_catalog.to_regclass('public.breach_source_records') IS NOT NULL
     AND pg_catalog.to_regclass('public.breach_data_sources') IS NOT NULL THEN
    CREATE OR REPLACE VIEW public.v_public_breach_sources AS
    SELECT
        r.matched_breach_id,
        r.source_record_url,
        r.document_type,
        r.summary,
        r.source_published_at,
        r.match_confidence,
        r.records_affected_est,
        r.data_types_exposed,
        r.ransomware_group_norm,
        r.ransomware_group_raw,
        r.incident_date,
        r.industry,
        r.region_state,
        r.country,
        s.name     AS source_name,
        s.category AS source_category,
        COALESCE(r.raw_payload->>'DisclosureUrl', r.raw_payload->>'disclosure_url') AS disclosure_url,
        COALESCE(r.raw_payload->>'screenshot', r.raw_payload->>'screen', r.raw_payload->>'image') AS screenshot_url
    FROM public.breach_source_records r
    LEFT JOIN public.breach_data_sources s ON s.id = r.source_id
    WHERE r.matched_breach_id IS NOT NULL;
  END IF;
END $$;

-- Curated, read-only projection of correlated news headlines (title + link
-- only; omits internal org_guess/org_norm/title_hash/first_seen).
DO $$
BEGIN
  IF pg_catalog.to_regclass('public.news_watch') IS NOT NULL THEN
    CREATE OR REPLACE VIEW public.v_public_news AS
    SELECT matched_breach_id, title, url, source_name, published_at, similarity
    FROM public.news_watch
    WHERE matched_breach_id IS NOT NULL;
  END IF;
END $$;

-- Grant the curated views to the API roles.
DO $$
DECLARE rl text;
BEGIN
  FOREACH rl IN ARRAY ARRAY['anon','authenticated'] LOOP
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=rl) THEN
      IF pg_catalog.to_regclass('public.v_public_breach_sources') IS NOT NULL THEN
        EXECUTE format('GRANT SELECT ON public.v_public_breach_sources TO %I', rl);
      END IF;
      IF pg_catalog.to_regclass('public.v_public_news') IS NOT NULL THEN
        EXECUTE format('GRANT SELECT ON public.v_public_news TO %I', rl);
      END IF;
    END IF;
  END LOOP;
END $$;

-- Make the internal + operational tables private: keep RLS on, drop the blanket
-- "public read" policy, and revoke all grants from the API roles. Access is then
-- denied by BOTH missing grant and missing policy (defence in depth). The base
-- tables fronted by curated views are included here.
DO $$
DECLARE
  t text;
  internal text[] := ARRAY[
    'breach_source_records',  -- fronted by v_public_breach_sources
    'news_watch',             -- fronted by v_public_news
    'breach_data_sources',    -- operational config (feed urls, keys flag, notes)
    'breach_companies',       -- only needed via the mv_breach_ledger join
    'breach_collector_log',   -- operational run log (status, error_message)
    'breach_match_queue',     -- internal review state (reviewed_by, reasons)
    'threat_actors'           -- not read by the public UI
  ];
BEGIN
  FOREACH t IN ARRAY internal LOOP
    IF pg_catalog.to_regclass('public.'||t) IS NOT NULL THEN
      EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
      EXECUTE format('DROP POLICY IF EXISTS "public read" ON public.%I', t);
      IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='anon') THEN
        EXECUTE format('REVOKE ALL ON public.%I FROM anon', t);
      END IF;
      IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='authenticated') THEN
        EXECUTE format('REVOKE ALL ON public.%I FROM authenticated', t);
      END IF;
    END IF;
  END LOOP;
END $$;

-- mv_source_health is operational (last-run status per collector) and unused by
-- the UI. Remove it from the Data API.
DO $$
BEGIN
  IF pg_catalog.to_regclass('public.mv_source_health') IS NOT NULL THEN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='anon') THEN
      REVOKE ALL ON public.mv_source_health FROM anon;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='authenticated') THEN
      REVOKE ALL ON public.mv_source_health FROM authenticated;
    END IF;
  END IF;
END $$;

COMMIT;

-- ============================================================================
-- Reverse (only if you must restore the previous, less-safe state):
--   GRANT SELECT ON <table> TO anon, authenticated;
--   CREATE POLICY "public read" ON <table> FOR SELECT USING (true);
--   GRANT EXECUTE ON FUNCTION public.refresh_breach_views() TO anon, authenticated;
-- Not recommended; re-exposes internal/operational data.
-- ============================================================================
