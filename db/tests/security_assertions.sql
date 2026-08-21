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

-- The curated source view must NOT leak the sensitive base columns.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema='public' AND table_name='v_public_breach_sources'
      AND column_name IN ('raw_payload','content_fingerprint','source_id','external_id',
                          'company_name_raw','company_name_norm')
  ) THEN
    RAISE EXCEPTION 'SECURITY FAIL: v_public_breach_sources exposes a sensitive column';
  END IF;
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
