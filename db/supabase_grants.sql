-- ============================================================================
-- Supabase setup: run this AFTER schema.sql + materialized_views.sql + seed_sources.sql
-- (paste into Supabase Dashboard → SQL Editor → New query → Run)
--
-- What this does:
--   * Enables Row-Level Security on every base table (deny-by-default).
--   * Adds a single "anyone can SELECT" policy per table — this is a public
--     breach-intelligence ledger, so read access is meant to be public.
--   * Does NOT add any INSERT/UPDATE/DELETE policy for the anon/public role,
--     so the website can read but never write. Only the GitHub Actions
--     ingestion job can write, because it connects with the database's
--     service-role/owner credentials (set as a GitHub secret), which bypass
--     RLS entirely — never put that connection string in frontend code.
--   * Grants SELECT on the materialized views too, since materialized views
--     don't support RLS policies directly — they inherit from the
--     permissions of the role querying them.
-- ============================================================================

ALTER TABLE breaches ENABLE ROW LEVEL SECURITY;
ALTER TABLE breach_companies ENABLE ROW LEVEL SECURITY;
ALTER TABLE breach_source_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE breach_match_queue ENABLE ROW LEVEL SECURITY;
ALTER TABLE breach_data_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE breach_collector_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_actors ENABLE ROW LEVEL SECURITY;

CREATE POLICY "public read" ON breaches FOR SELECT USING (true);
CREATE POLICY "public read" ON breach_companies FOR SELECT USING (true);
CREATE POLICY "public read" ON breach_source_records FOR SELECT USING (true);
CREATE POLICY "public read" ON breach_match_queue FOR SELECT USING (true);
CREATE POLICY "public read" ON breach_data_sources FOR SELECT USING (true);
CREATE POLICY "public read" ON breach_collector_log FOR SELECT USING (true);
CREATE POLICY "public read" ON threat_actors FOR SELECT USING (true);

-- A tiny single-row view powering the hero stats strip (total breaches,
-- total sources, avg. correlation confidence) without pulling full tables
-- into the browser to compute an average client-side.
-- NOTE: created BEFORE it is granted below — the previous version of this
-- script granted first and aborted with "relation does not exist", which
-- left mv_platform_stats missing and the hero stats erroring in the console.
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_platform_stats AS
SELECT
    (SELECT count(*) FROM breaches) AS total_breaches,
    (SELECT count(*) FROM breach_data_sources WHERE enabled) AS total_sources,
    (SELECT round(avg(confidence_avg), 3) FROM breaches) AS avg_confidence,
    (SELECT count(*) FROM breach_match_queue WHERE status = 'pending') AS pending_review,
    now() AS computed_at;

GRANT SELECT ON mv_breach_ledger TO anon, authenticated;
GRANT SELECT ON mv_breach_trends TO anon, authenticated;
GRANT SELECT ON mv_top_ransomware_groups TO anon, authenticated;
GRANT SELECT ON mv_source_health TO anon, authenticated;
GRANT SELECT ON mv_platform_stats TO anon, authenticated;

-- Re-run after adding mv_platform_stats above so it's included going forward.
-- Plain REFRESH (not CONCURRENTLY): CONCURRENTLY is disallowed inside a
-- function's transaction context.
CREATE OR REPLACE FUNCTION refresh_breach_views() RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW mv_breach_ledger;
    REFRESH MATERIALIZED VIEW mv_breach_trends;
    REFRESH MATERIALIZED VIEW mv_top_ransomware_groups;
    REFRESH MATERIALIZED VIEW mv_source_health;
    REFRESH MATERIALIZED VIEW mv_platform_stats;
END
$$ LANGUAGE plpgsql;
