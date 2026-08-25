-- ============================================================================
-- Migration 0004: demand capture (monetisation Phase 1)
--
-- A fully-private table for plan waitlist / access-request / sales enquiries.
-- It is NOT exposed through the anonymous or authenticated Data API: RLS is on
-- with no policy, and no grants are given to anon/authenticated, so PostgREST
-- returns nothing for either role. Rows are written only by the trusted
-- serverless function (frontend/api/enquiry.js) using the server-side
-- service-role key, after it has verified the caller's Supabase session,
-- validated the input and rate-limited. The owner reads submissions out of band.
--
-- Durable, cross-instance rate limiting lives in the database too: rate_limits +
-- rl_hit(). Vercel functions are stateless and horizontally scaled, so an
-- in-process counter cannot bound abuse; the shared table can. rl_hit() is a
-- SECURITY DEFINER counter callable only by the service role.
--
-- Apply after 0001-0003:  psql "$DATABASE_URL" -f db/migrations/0004_demand_capture.sql
-- Idempotent and non-destructive. maintenance.py self-heals the same objects.
-- ============================================================================

BEGIN;

SELECT pg_catalog.pg_advisory_xact_lock(918273645);

-- ---- demand capture -------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.plan_enquiries (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at    timestamptz NOT NULL DEFAULT now(),
    user_id       uuid,                       -- verified Supabase auth user id
    email         text NOT NULL,              -- verified email from the session
    plan          text NOT NULL CHECK (plan IN ('pro','business','enterprise')),
    organisation  text,
    role_use_case text,
    message       text,
    source        text,                       -- where the enquiry came from
    status        text NOT NULL DEFAULT 'new'
);
CREATE INDEX IF NOT EXISTS idx_plan_enquiries_created ON public.plan_enquiries (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_plan_enquiries_plan    ON public.plan_enquiries (plan);

-- Private: RLS on, no policy, no API-role grants. Only the service role writes.
ALTER TABLE public.plan_enquiries ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "public read" ON public.plan_enquiries;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='anon') THEN
    REVOKE ALL ON public.plan_enquiries FROM anon;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='authenticated') THEN
    REVOKE ALL ON public.plan_enquiries FROM authenticated;
  END IF;
END $$;

-- ---- durable rate limiting -----------------------------------------------
-- Shared counter buckets. Private: RLS on, no policy, no API-role grants, so
-- the Data API cannot read or tamper with them. Written only via rl_hit().
CREATE TABLE IF NOT EXISTS public.rate_limits (
    bucket       text PRIMARY KEY,
    window_start timestamptz NOT NULL DEFAULT now(),
    hits         integer NOT NULL DEFAULT 0
);
ALTER TABLE public.rate_limits ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "public read" ON public.rate_limits;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='anon') THEN
    REVOKE ALL ON public.rate_limits FROM anon;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='authenticated') THEN
    REVOKE ALL ON public.rate_limits FROM authenticated;
  END IF;
END $$;

-- Atomic fixed-window counter. Returns true while the bucket is within p_limit
-- for the current window, false once it is exceeded. SECURITY DEFINER so the
-- caller needs only EXECUTE (granted to the service role) and never direct table
-- rights. NULL args never block (fail-open on misconfiguration).
CREATE OR REPLACE FUNCTION public.rl_hit(p_bucket text, p_limit integer, p_window_secs integer)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
DECLARE
    v_hits integer;
BEGIN
    IF p_bucket IS NULL OR p_limit IS NULL OR p_window_secs IS NULL THEN
        RETURN true;
    END IF;
    INSERT INTO public.rate_limits AS rl (bucket, window_start, hits)
    VALUES (p_bucket, now(), 1)
    ON CONFLICT (bucket) DO UPDATE
        SET hits = CASE WHEN rl.window_start < now() - make_interval(secs => p_window_secs)
                        THEN 1 ELSE rl.hits + 1 END,
            window_start = CASE WHEN rl.window_start < now() - make_interval(secs => p_window_secs)
                                THEN now() ELSE rl.window_start END
        RETURNING rl.hits INTO v_hits;
    RETURN v_hits <= p_limit;
END
$fn$;

-- Lock the RPC down: nobody by default, service role only.
REVOKE ALL ON FUNCTION public.rl_hit(text, integer, integer) FROM PUBLIC;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='anon') THEN
    REVOKE ALL ON FUNCTION public.rl_hit(text, integer, integer) FROM anon;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='authenticated') THEN
    REVOKE ALL ON FUNCTION public.rl_hit(text, integer, integer) FROM authenticated;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='service_role') THEN
    GRANT EXECUTE ON FUNCTION public.rl_hit(text, integer, integer) TO service_role;
  END IF;
END $$;

COMMIT;

-- Rollback:
--   DROP FUNCTION IF EXISTS public.rl_hit(text, integer, integer);
--   DROP TABLE IF EXISTS public.rate_limits;
--   DROP TABLE IF EXISTS public.plan_enquiries;   (destroys captured enquiries)
