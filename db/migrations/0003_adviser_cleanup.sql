-- ============================================================================
-- Migration 0003: remove direct materialized-view Data API exposure (WP-004)
--
-- Supabase flags the four product materialized views as exposed through the Data
-- API (RLS cannot apply to a matview). A security_invoker view over a matview
-- does NOT help: with the matview grant revoked, anon gets "permission denied"
-- through the view (verified). So, as in WP-003, the public surface becomes
-- deliberately-public projection TABLES populated by owner-side maintenance; the
-- matviews stay internal as the compute layer.
--
-- Apply AFTER 0001 and 0002:
--   psql "$DATABASE_URL" -f db/migrations/0003_adviser_cleanup.sql
-- Idempotent, non-destructive (no source data deleted). maintenance.py applies
-- the same objects and refreshes them every run, so the state is self-healing.
--
-- Extensions pg_trgm / btree_gin are intentionally NOT relocated here; see the
-- PR "Extensions" section for the assessment (unqualified similarity()/% and
-- gin_trgm_ops usage in correlation makes relocation a breaking, out-of-scope
-- change). Those remain justified residual adviser warnings.
-- ============================================================================

BEGIN;

SELECT pg_catalog.pg_advisory_xact_lock(918273645);

-- ---- public projection tables (sanitised public copies of the matviews) ----
CREATE TABLE IF NOT EXISTS public.public_breach_ledger (
    id                   uuid PRIMARY KEY,
    canonical_name       text,
    domain               text,
    industry             text,
    country              text,
    region_state         text,
    ransomware_group     text,
    incident_date        date,
    disclosed_date       date,
    records_affected_est bigint,
    severity             text,
    status               text,
    source_count         integer,
    confidence_avg       numeric(4,3),
    data_flags           text[],
    last_updated_at      timestamptz
);
CREATE INDEX IF NOT EXISTS idx_pub_ledger_incident   ON public.public_breach_ledger (incident_date DESC);
CREATE INDEX IF NOT EXISTS idx_pub_ledger_disclosed  ON public.public_breach_ledger (disclosed_date DESC);
CREATE INDEX IF NOT EXISTS idx_pub_ledger_industry   ON public.public_breach_ledger (industry);
CREATE INDEX IF NOT EXISTS idx_pub_ledger_group      ON public.public_breach_ledger (ransomware_group);

CREATE TABLE IF NOT EXISTS public.public_breach_trends (
    week_start           date,
    industry             text,
    breach_count         bigint,
    records_affected_sum numeric
);
CREATE INDEX IF NOT EXISTS idx_pub_trends_week ON public.public_breach_trends (week_start);

CREATE TABLE IF NOT EXISTS public.public_top_ransomware_groups (
    ransomware_group     text,
    victim_count         bigint,
    most_recent_incident date
);

CREATE TABLE IF NOT EXISTS public.public_platform_stats (
    total_breaches bigint,
    total_sources  bigint,
    avg_confidence numeric,
    pending_review bigint,
    computed_at    timestamptz
);

-- ---- RLS + grants: public SELECT only, no client writes --------------------
DO $$
DECLARE t text; rl text;
BEGIN
  FOREACH t IN ARRAY ARRAY['public_breach_ledger','public_breach_trends',
                           'public_top_ransomware_groups','public_platform_stats'] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS "public read" ON public.%I', t);
    EXECUTE format('CREATE POLICY "public read" ON public.%I FOR SELECT USING (true)', t);
    FOREACH rl IN ARRAY ARRAY['anon','authenticated'] LOOP
      IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=rl) THEN
        EXECUTE format('GRANT SELECT ON public.%I TO %I', t, rl);
        EXECUTE format('REVOKE INSERT, UPDATE, DELETE ON public.%I FROM %I', t, rl);
      END IF;
    END LOOP;
  END LOOP;
END $$;

-- ---- backfill from the matviews (owner-side, full transactional replace) ----
DO $$
BEGIN
  IF pg_catalog.to_regclass('public.mv_breach_ledger') IS NOT NULL THEN
    DELETE FROM public.public_breach_ledger;
    INSERT INTO public.public_breach_ledger
      SELECT id, canonical_name, domain, industry, country, region_state, ransomware_group,
             incident_date, disclosed_date, records_affected_est, severity, status,
             source_count, confidence_avg, data_flags, last_updated_at
      FROM public.mv_breach_ledger;
  END IF;
  IF pg_catalog.to_regclass('public.mv_breach_trends') IS NOT NULL THEN
    DELETE FROM public.public_breach_trends;
    INSERT INTO public.public_breach_trends
      SELECT week_start, industry, breach_count, records_affected_sum FROM public.mv_breach_trends;
  END IF;
  IF pg_catalog.to_regclass('public.mv_top_ransomware_groups') IS NOT NULL THEN
    DELETE FROM public.public_top_ransomware_groups;
    INSERT INTO public.public_top_ransomware_groups
      SELECT ransomware_group, victim_count, most_recent_incident FROM public.mv_top_ransomware_groups;
  END IF;
  IF pg_catalog.to_regclass('public.mv_platform_stats') IS NOT NULL THEN
    DELETE FROM public.public_platform_stats;
    INSERT INTO public.public_platform_stats
      SELECT total_breaches, total_sources, avg_confidence, pending_review, computed_at
      FROM public.mv_platform_stats;
  END IF;
END $$;

-- ---- take the matviews off the Data API -------------------------------------
-- They remain as the internal compute layer (refreshed by refresh_breach_views);
-- only the projection tables above are anonymously readable.
DO $$
DECLARE m text; rl text;
BEGIN
  FOREACH m IN ARRAY ARRAY['mv_breach_ledger','mv_breach_trends',
                           'mv_top_ransomware_groups','mv_platform_stats','mv_source_health'] LOOP
    IF pg_catalog.to_regclass('public.'||m) IS NOT NULL THEN
      FOREACH rl IN ARRAY ARRAY['anon','authenticated'] LOOP
        IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=rl) THEN
          EXECUTE format('REVOKE ALL ON public.%I FROM %I', m, rl);
        END IF;
      END LOOP;
    END IF;
  END LOOP;
END $$;

COMMIT;

-- ============================================================================
-- Rollback (restores the flagged direct exposure; not recommended):
--   GRANT SELECT ON public.mv_breach_ledger, public.mv_breach_trends,
--                   public.mv_top_ransomware_groups, public.mv_platform_stats
--     TO anon, authenticated;
--   -- and repoint the frontend/STIX back to the mv_* names.
-- The projection tables can be left in place or dropped:
--   DROP TABLE IF EXISTS public.public_breach_ledger, public.public_breach_trends,
--                        public.public_top_ransomware_groups, public.public_platform_stats;
-- ============================================================================
