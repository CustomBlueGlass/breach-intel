-- ============================================================================
-- Security regression assertions (WP-002).
--
-- Proves the least-privilege contract holds after migration 0001. Run as the
-- database owner against a database that has: schema.sql + materialized_views.sql
-- applied, a minimal news_watch table, the anon/authenticated roles, and
-- migration 0001 applied. db/tests/run_security_assertions.sh sets all of this
-- up against a throwaway local Postgres.
--
-- Any failed assertion RAISES and aborts with a non-zero exit, so this is a
-- deterministic pass/fail gate. It uses SET ROLE to execute as the anon API role.
-- ============================================================================

\set ON_ERROR_STOP on

-- Helper: assert that a SELECT as the current role is DENIED.
CREATE OR REPLACE FUNCTION _assert_denied(rel text) RETURNS void AS $$
BEGIN
  BEGIN
    EXECUTE format('SELECT 1 FROM public.%I LIMIT 1', rel);
    RAISE EXCEPTION 'SECURITY FAIL: role % can read public.%', current_user, rel;
  EXCEPTION
    WHEN insufficient_privilege THEN RETURN;         -- expected
    WHEN undefined_table THEN RETURN;                -- also acceptable (not exposed)
  END;
END $$ LANGUAGE plpgsql;

-- Helper: assert that a SELECT as the current role is ALLOWED.
CREATE OR REPLACE FUNCTION _assert_allowed(rel text) RETURNS void AS $$
BEGIN
  EXECUTE format('SELECT 1 FROM public.%I LIMIT 1', rel);  -- raises if denied
END $$ LANGUAGE plpgsql;

-- Helper: assert that INSERT as the current role is DENIED.
CREATE OR REPLACE FUNCTION _assert_write_denied(rel text) RETURNS void AS $$
BEGIN
  BEGIN
    EXECUTE format('INSERT INTO public.%I (matched_breach_id) VALUES (gen_random_uuid())', rel);
    RAISE EXCEPTION 'SECURITY FAIL: role % can INSERT into public.%', current_user, rel;
  EXCEPTION
    WHEN insufficient_privilege THEN RETURN;         -- expected
  END;
END $$ LANGUAGE plpgsql;

-- ---- as the anonymous API role -------------------------------------------
SET ROLE anon;

-- Internal / operational objects must be denied.
SELECT _assert_denied('breach_source_records');
SELECT _assert_denied('breach_match_queue');
SELECT _assert_denied('breach_collector_log');
SELECT _assert_denied('breach_data_sources');
SELECT _assert_denied('breach_companies');
SELECT _assert_denied('threat_actors');
SELECT _assert_denied('news_watch');
SELECT _assert_denied('mv_source_health');

-- Public product objects must remain readable.
SELECT _assert_allowed('breaches');
SELECT _assert_allowed('breach_developments');
SELECT _assert_allowed('breach_enrichment_log');
SELECT _assert_allowed('threat_radar');
SELECT _assert_allowed('mv_breach_ledger');
SELECT _assert_allowed('mv_breach_trends');
SELECT _assert_allowed('mv_top_ransomware_groups');
SELECT _assert_allowed('mv_platform_stats');

-- Curated public views must be readable (dossier sources + related news).
SELECT _assert_allowed('v_public_breach_sources');
SELECT _assert_allowed('v_public_news');

-- WP-003: the public projection TABLES are readable but not writable by anon.
SELECT _assert_allowed('public_breach_sources');
SELECT _assert_allowed('public_breach_news');
SELECT _assert_write_denied('public_breach_sources');
SELECT _assert_write_denied('public_breach_news');

-- The exact dossier source query shape (columns the frontend selects) still works.
SELECT source_record_url, document_type, summary, source_published_at, match_confidence,
       records_affected_est, data_types_exposed, ransomware_group_norm, ransomware_group_raw,
       incident_date, industry, region_state, country, source_name, source_category,
       disclosure_url, screenshot_url
FROM public.v_public_breach_sources WHERE matched_breach_id = gen_random_uuid() LIMIT 1;
SELECT title, url, source_name, published_at, similarity
FROM public.v_public_news WHERE matched_breach_id = gen_random_uuid() LIMIT 1;

-- Neither the curated source view nor the projection table may leak the
-- sensitive base columns (WP-002 + WP-003).
DO $$
DECLARE rel text;
BEGIN
  FOREACH rel IN ARRAY ARRAY['v_public_breach_sources','public_breach_sources'] LOOP
    IF EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema='public' AND table_name=rel
        AND column_name IN ('raw_payload','content_fingerprint','source_id','external_id',
                            'company_name_raw','company_name_norm','fetched_at')
    ) THEN
      RAISE EXCEPTION 'SECURITY FAIL: % exposes a sensitive column', rel;
    END IF;
  END LOOP;
END $$;

-- WP-003: the application-facing views must be security_invoker (not definer),
-- so they do not bypass RLS and clear the "Security Definer View" adviser finding.
DO $$
DECLARE rel text;
BEGIN
  FOREACH rel IN ARRAY ARRAY['v_public_breach_sources','v_public_news'] LOOP
    IF NOT EXISTS (
      SELECT 1 FROM pg_class
      WHERE relname = rel AND relnamespace = 'public'::regnamespace
        AND reloptions @> ARRAY['security_invoker=true']
    ) THEN
      RAISE EXCEPTION 'SECURITY FAIL: % is not a security_invoker view', rel;
    END IF;
  END LOOP;
END $$;

-- Administrative functions must not be executable by anon.
DO $$
BEGIN
  BEGIN
    PERFORM public.refresh_breach_views();
    RAISE EXCEPTION 'SECURITY FAIL: anon can execute refresh_breach_views()';
  EXCEPTION WHEN insufficient_privilege THEN NULL;   -- expected
  END;
END $$;

DO $$
BEGIN
  IF to_regprocedure('public.rls_auto_enable()') IS NOT NULL THEN
    BEGIN
      PERFORM public.rls_auto_enable();
      RAISE EXCEPTION 'SECURITY FAIL: anon can execute rls_auto_enable()';
    EXCEPTION WHEN insufficient_privilege THEN NULL; -- expected
    END;
  END IF;
END $$;

RESET ROLE;

DROP FUNCTION _assert_denied(text);
DROP FUNCTION _assert_allowed(text);

SELECT 'ALL SECURITY ASSERTIONS PASSED' AS result;
