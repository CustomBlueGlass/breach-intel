# Monetisation Phase 1: conversion and demand capture

What shipped, how it is secured, and the exact steps to make it live. Phase 1 adds
conversion prompts, a secure demand-capture flow, a clearer pricing page, and a
privacy-respecting analytics abstraction. It does not add billing, does not gate any
public ledger data, and adds no third-party trackers.

## Components

- `frontend/src/pricing.jsx`: Free / Analyst Pro (GBP 19/mo) / Business (GBP 149/mo) /
  Enterprise, an entitlement comparison matrix, and CTAs that open the enquiry modal.
  Annual billing is shown as unavailable (placeholder), not purchasable.
- `frontend/src/demand.jsx`: the enquiry modal. Sign-in is required so the email is
  verified server-side. It collects organisation, role/use case and an optional
  message only. It shows success only when the server confirms the row was saved.
- `frontend/api/enquiry.js`: the serverless capture endpoint (details below).
- `frontend/src/lib/analytics.js`: allowlist-only event abstraction. Honours Do Not
  Track. Forwards only `plan, source, tier, cadence, prompt`. The default sink is a
  no-op. No form contents, email, org or message ever reach analytics.
- Contextual prompts in `account.jsx` (dashboard) and `workspace.jsx` (watchlist),
  kept neutral and away from dossier evidence and source links.

## Database changes (migration 0004)

`db/migrations/0004_demand_capture.sql` is idempotent and non-destructive. It creates:

- `public.plan_enquiries`: the demand-capture store. RLS on, no policy, no
  anon/authenticated grants, so PostgREST returns nothing for either API role. Rows
  are written only by `api/enquiry` using the service role.
- `public.rate_limits` + `public.rl_hit(text, integer, integer)`: durable,
  cross-instance rate limiting (see below). `rate_limits` is private; `rl_hit` is
  SECURITY DEFINER, revoked from PUBLIC/anon/authenticated, granted EXECUTE to
  `service_role` only.

`backend/app/maintenance.py` self-heals all three objects on every ingest
(`ensure_views`), so a fresh or drifted database converges to the same private state
without a manual migration. `plan_enquiries` and `rate_limits` are in
`PRIVATE_TABLES`; `rl_hit` is locked down in `HARDEN_FUNCTIONS`; stale rate-limit
buckets are pruned each pass.

Apply manually (optional, since maintenance self-heals):

```
psql "$DATABASE_URL" -f db/migrations/0004_demand_capture.sql
```

Rollback is documented at the foot of the migration file. Dropping `plan_enquiries`
destroys captured enquiries.

## Rate limiting is durable, not in-memory

Vercel functions are stateless and horizontally scaled, so an in-process counter
cannot bound abuse across instances. The limiter lives in Postgres:

- Per client IP: 30 requests / 60s, checked before any auth call.
- Per verified user: 10 enquiries / 3600s, checked after sign-in.
- A request with no bearer token is rejected with 401 before any upstream call, so the
  endpoint cannot be used as an unauthenticated amplifier.
- `rl_hit` fails open on a transport error: a transient database blip must not block a
  genuine, authenticated enquiry. The auth gate, validation and the private table
  still bound abuse.

## Environment variables

Set in Vercel, Project Settings, Environment Variables (Production and Preview).

| Variable | Where | Notes |
| --- | --- | --- |
| `VITE_SUPABASE_URL` | build + functions | existing; public project URL |
| `VITE_SUPABASE_ANON_KEY` | build + functions | existing; publishable anon key |
| `SUPABASE_SERVICE_ROLE_KEY` | **functions only, server-side** | **new.** Never use a `VITE_` prefix. Used only by `api/enquiry` to write the private table and call `rl_hit`. If unset, the endpoint returns `503 configured:false` and captures nothing (it never fakes success). |

The service-role key must never enter the client bundle. This is enforced by tests
(`test/api-security.test.js`) and a build-time scan of `dist/`.

## Deployment steps

1. Merge the Phase 1 PR to `main`. Vercel builds and deploys the frontend and the
   `api/enquiry` function.
2. Add `SUPABASE_SERVICE_ROLE_KEY` to Vercel (Production), server-side only. Redeploy
   so functions pick it up.
3. Apply migration 0004, or let the next scheduled maintenance run self-heal the
   objects. Confirm with:
   `select to_regclass('public.plan_enquiries'), to_regclass('public.rate_limits'), to_regprocedure('public.rl_hit(text,integer,integer)');`
4. Smoke test: signed-out, an enquiry CTA shows the sign-in gate. Signed-in, a
   submission returns 201 and the row appears in `plan_enquiries`. Reading
   `plan_enquiries` with the anon key returns nothing.

## Vercel Deployment Protection

The production site currently redirects anonymous visitors to Vercel authentication.
That is project-level Deployment Protection, not anything in this repo. For a public
launch:

- Vercel, Project, Settings, Deployment Protection.
- Set Production to public (Vercel Authentication off for Production).
- Keep Preview protected (Vercel Authentication on for Preview only), or use a
  protection bypass for the smoke-test workflow. Do not disable protection for
  Preview.

This is a dashboard setting. It is documented here, not changed by the code. Confirm
the Production/Preview split before announcing the site.

## Reading captured enquiries

Out of band, with the service role or a direct owner connection, for example:

```
select created_at, plan, email, organisation, role_use_case, source
from public.plan_enquiries order by created_at desc;
```

Never expose this table through the Data API or a public view.
