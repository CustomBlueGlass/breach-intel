# Secret and environment-variable inventory

Sanitised. **No secret values appear here or anywhere in the repository** (verified
by tree + git-history scan and by the gitleaks CI job). This lists variable names,
the component that uses each, whether it is publishable or secret, where it must be
set, and the impact of rotating it.

## Supabase

| Variable | Component | Class | Environments | Rotation impact |
| --- | --- | --- | --- | --- |
| `VITE_SUPABASE_URL` | frontend build + serverless (`api/stix`, `api/exposure`) | public | Vercel (build + functions) | project URL; changes only on project move |
| `VITE_SUPABASE_ANON_KEY` | frontend + serverless | publishable | Vercel | SELECT-only under RLS; safe in the client bundle; rotate if abused, then redeploy |
| `SUPABASE_URL` / `SUPABASE_ANON_KEY` | serverless fallback names | same as above | Vercel (optional) | as above |
| `DATABASE_URL` | GitHub Actions ingestion + maintenance | **secret (high impact)** | GitHub Actions secret | owner/service DB connection; bypasses RLS. Rotating breaks all workflows until updated. Never place in frontend or Vercel. |

There is **no Supabase service-role key in the repository or the frontend/serverless
code** (asserted by a test). Privileged database access is only the Actions-only
`DATABASE_URL`.

## Third-party provider keys (server-side only)

| Variable | Component | Class | Paid? | Environments | Rotation impact |
| --- | --- | --- | --- | --- | --- |
| `ABUSEIPDB_API_KEY` | `api/enrich` | secret | free tier | Vercel (optional) | enrichment loses AbuseIPDB; keyless checks still work |
| `BREACHDIRECTORY_API_KEY` | `api/exposure` | secret | **paid** | Vercel (optional) | exposure loses BreachDirectory |
| `DEHASHED_API_KEY` | `api/exposure` | secret | **paid** | Vercel (optional) | exposure loses DeHashed |
| `OTX_API_KEY` | `app.threat_radar` | secret | free | GitHub Actions (optional) | radar loses OTX pulses |
| `URLHAUS_AUTH_KEY` | `app.threat_radar` | secret | free | GitHub Actions (optional) | radar loses URLhaus |
| `HIBP_API_KEY` | collectors | secret | paid | GitHub Actions (optional) | HIBP collector disabled |
| `LEAKIX_API_KEY` | collectors | secret | free/paid | GitHub Actions (optional) | LeakIX rate-limited/disabled |
| `INTELX_API_KEY` | collectors (`dehashed_intelx`) | secret | paid | GitHub Actions (optional) | on-demand lookup disabled |

The paid keys (`BREACHDIRECTORY_API_KEY`, `DEHASHED_API_KEY`) are the ones an
attacker would want to burn. `/api/exposure` now requires a valid Supabase session
before any paid provider is called (see the API changes), plus a per-instance rate
limit.

## CI / deployment automation

| Variable | Component | Class | Environments | Rotation impact |
| --- | --- | --- | --- | --- |
| `VERCEL_AUTOMATION_BYPASS_SECRET` | smoke-test workflow | secret | GitHub Actions secret (optional) | only enables Preview smoke tests; if unset, protected Previews are skipped, not failed |
| `GITHUB_TOKEN` | Actions (built-in) | secret | provided by GitHub | scoped per run |

## Handling rules

- Secrets live only in GitHub Actions secrets (ingestion/CI) or Vercel Environment
  Variables (serverless). Never commit them; never echo them in logs (the gitleaks
  step redacts; the smoke-test bypass secret is sent as a header, never printed).
- `VITE_`-prefixed values are exposed to the browser by design and must only ever
  be the public URL and the publishable anon key.
