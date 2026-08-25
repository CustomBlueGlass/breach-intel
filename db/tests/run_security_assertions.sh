#!/usr/bin/env bash
# Deterministic local/integration runner for the security assertions.
#
# Spins up a throwaway PostgreSQL cluster, loads the schema + materialized views
# + a minimal news_watch, simulates the OLD "everything public" grant state,
# applies migration 0001, then runs db/tests/security_assertions.sql.
#
# This does NOT touch production and needs no secrets. GitHub CI cannot reach
# the production Supabase database (no service credentials in CI), so this is the
# authoritative reproducible check for the database-permission contract; run it
# locally or in an integration job with a local Postgres service.
#
# Usage:  bash db/tests/run_security_assertions.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PGBIN="$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1 || true)"
export PATH="${PGBIN:-/usr/bin}:$PATH"

WORK="$(mktemp -d)"
DATA="$WORK/data"
SOCK="$WORK/sock"
mkdir -p "$SOCK"
cleanup() { pg_ctl -D "$DATA" -m immediate stop >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT

# Run initdb/postgres as a non-root user if we are root (postgres refuses root).
RUN=""
if [ "$(id -u)" = "0" ]; then
  chown -R postgres "$WORK" 2>/dev/null || true
  RUN="runuser -u postgres --"
fi

$RUN initdb -D "$DATA" -A trust >/dev/null
$RUN pg_ctl -D "$DATA" -o "-k $SOCK -p 5433 -c listen_addresses=''" -w start >/dev/null

PSQL="$RUN psql -h $SOCK -p 5433 -d postgres -v ON_ERROR_STOP=1 -q"

# Roles that the Supabase Data API uses.
$PSQL -c "CREATE ROLE anon NOLOGIN;" -c "CREATE ROLE authenticated NOLOGIN;"
$PSQL -c "GRANT USAGE ON SCHEMA public TO anon, authenticated;"

# Real schema + views.
$PSQL -f "$ROOT/db/schema.sql" >/dev/null
$PSQL -f "$ROOT/db/materialized_views.sql" >/dev/null

# mv_platform_stats lives in supabase_grants.sql (created at deploy time); build
# it here so the public-read assertion has the object.
$PSQL -c "CREATE MATERIALIZED VIEW IF NOT EXISTS mv_platform_stats AS
  SELECT (SELECT count(*) FROM breaches) AS total_breaches,
         (SELECT count(*) FROM breach_data_sources WHERE enabled) AS total_sources,
         (SELECT round(avg(confidence_avg),3) FROM breaches) AS avg_confidence,
         (SELECT count(*) FROM breach_match_queue WHERE status='pending') AS pending_review,
         now() AS computed_at;" >/dev/null

# Minimal news_watch (created by the news-watch job in production).
$PSQL -c "CREATE TABLE IF NOT EXISTS news_watch (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source_name text NOT NULL, title text NOT NULL, url text NOT NULL UNIQUE,
  published_at timestamptz, title_hash text NOT NULL, org_guess text, org_norm text,
  first_seen timestamptz DEFAULT now(), similarity numeric(4,3),
  matched_breach_id uuid REFERENCES breaches(id) ON DELETE SET NULL);"

# Simulate the OLD, over-permissive state so the migration has something to undo.
$PSQL <<'SQL'
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['breaches','breach_companies','breach_source_records',
      'breach_match_queue','breach_data_sources','breach_collector_log','threat_actors',
      'news_watch','threat_radar','breach_enrichment_log','breach_developments'] LOOP
    IF to_regclass('public.'||t) IS NOT NULL THEN
      EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
      EXECUTE format('DROP POLICY IF EXISTS "public read" ON public.%I', t);
      EXECUTE format('CREATE POLICY "public read" ON public.%I FOR SELECT USING (true)', t);
      EXECUTE format('GRANT SELECT ON public.%I TO anon, authenticated', t);
    END IF;
  END LOOP;
END $$;
GRANT SELECT ON mv_breach_ledger, mv_breach_trends, mv_top_ransomware_groups,
               mv_source_health, mv_platform_stats TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.refresh_breach_views() TO anon, authenticated;
SQL

# threat_radar + enrichment_log + developments are created at runtime by the app;
# create minimal versions so the public-read assertions have objects to hit.
$PSQL <<'SQL'
CREATE TABLE IF NOT EXISTS threat_radar (id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind text, source_name text, title text, subtitle text, url text, published_at timestamptz);
CREATE TABLE IF NOT EXISTS breach_enrichment_log (id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  breach_id uuid, changed jsonb NOT NULL, enriched_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS breach_developments (id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  breach_id uuid, kind text NOT NULL, title text NOT NULL, detail jsonb NOT NULL DEFAULT '{}',
  url text, source_name text, occurred_at date, dedupe_key text NOT NULL);
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['threat_radar','breach_enrichment_log','breach_developments'] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS "public read" ON public.%I', t);
    EXECUTE format('CREATE POLICY "public read" ON public.%I FOR SELECT USING (true)', t);
    EXECUTE format('GRANT SELECT ON public.%I TO anon, authenticated', t);
  END LOOP;
END $$;
SQL

# Apply the migrations under test, in order.
$PSQL -f "$ROOT/db/migrations/0001_security_hardening.sql" >/dev/null
$PSQL -f "$ROOT/db/migrations/0002_public_projection_tables.sql" >/dev/null
$PSQL -f "$ROOT/db/migrations/0003_adviser_cleanup.sql" >/dev/null
$PSQL -f "$ROOT/db/migrations/0004_demand_capture.sql" >/dev/null

# Run the assertions.
$RUN psql -h "$SOCK" -p 5433 -d postgres -v ON_ERROR_STOP=1 -f "$ROOT/db/tests/security_assertions.sql"
