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
-- Apply after 0001-0003:  psql "$DATABASE_URL" -f db/migrations/0004_demand_capture.sql
-- Idempotent and non-destructive. maintenance.py self-heals the same object.
-- ============================================================================

BEGIN;

SELECT pg_catalog.pg_advisory_xact_lock(918273645);

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

COMMIT;

-- Rollback: DROP TABLE IF EXISTS public.plan_enquiries;  (destroys captured enquiries)
