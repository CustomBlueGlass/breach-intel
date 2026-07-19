-- ============================================================================
-- Materialized views — refreshed after each successful ingestion batch
-- (see backend/app/cache.py :: invalidate_and_refresh())
-- ============================================================================

-- Fast listing view: everything the ledger table page needs, pre-joined,
-- so the paginated list endpoint never touches breach_source_records directly.
CREATE MATERIALIZED VIEW mv_breach_ledger AS
SELECT
    b.id,
    b.canonical_name,
    c.domain,
    b.industry,
    b.country,
    b.region_state,
    b.ransomware_group,
    b.incident_date,
    b.disclosed_date,
    b.records_affected_est,
    b.severity,
    b.status,
    b.source_count,
    b.confidence_avg,
    b.last_updated_at
FROM breaches b
LEFT JOIN breach_companies c ON c.id = b.company_id;

CREATE UNIQUE INDEX idx_mv_ledger_id ON mv_breach_ledger (id);
CREATE INDEX idx_mv_ledger_date ON mv_breach_ledger (incident_date DESC);
CREATE INDEX idx_mv_ledger_industry ON mv_breach_ledger (industry);
CREATE INDEX idx_mv_ledger_group ON mv_breach_ledger (ransomware_group);

-- Analytics: breach counts per week per industry (powers the trend chart)
CREATE MATERIALIZED VIEW mv_breach_trends AS
SELECT
    date_trunc('week', incident_date)::date AS week_start,
    industry,
    count(*) AS breach_count,
    sum(coalesce(records_affected_est, 0)) AS records_affected_sum
FROM breaches
WHERE incident_date IS NOT NULL
GROUP BY 1, 2;

CREATE INDEX idx_mv_trends_week ON mv_breach_trends (week_start);

-- Analytics: top ransomware groups by victim count (rolling)
CREATE MATERIALIZED VIEW mv_top_ransomware_groups AS
SELECT
    ransomware_group,
    count(*) AS victim_count,
    max(incident_date) AS most_recent_incident
FROM breaches
WHERE ransomware_group IS NOT NULL
GROUP BY ransomware_group
ORDER BY victim_count DESC;

-- Source coverage / health, shown in the footer "collector status" strip
CREATE MATERIALIZED VIEW mv_source_health AS
SELECT
    s.id AS source_id,
    s.name,
    s.category,
    s.feed_type,
    s.enabled,
    l.status AS last_run_status,
    l.finished_at AS last_run_finished_at,
    l.records_new AS last_run_records_new
FROM breach_data_sources s
LEFT JOIN LATERAL (
    SELECT * FROM breach_collector_log
    WHERE source_id = s.id
    ORDER BY started_at DESC
    LIMIT 1
) l ON TRUE;

-- Refresh helper (called by the app after each ingestion batch completes).
-- Plain REFRESH (not CONCURRENTLY): CONCURRENTLY is disallowed inside a
-- function's transaction context.
CREATE OR REPLACE FUNCTION refresh_breach_views() RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW mv_breach_ledger;
    REFRESH MATERIALIZED VIEW mv_breach_trends;
    REFRESH MATERIALIZED VIEW mv_top_ransomware_groups;
    REFRESH MATERIALIZED VIEW mv_source_health;
END
$$ LANGUAGE plpgsql;
