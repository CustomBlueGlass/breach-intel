# Deploying for $0 — exact steps

Stack: **GitHub** (code + free scheduler) + **Supabase** (free Postgres, no card) +
**Vercel** (free frontend hosting, no card). No Redis, no separate backend server —
Supabase's auto-generated REST API replaces the custom FastAPI service for reads.

Total cost: $0/month, indefinitely, as long as usage stays within each free tier
(very likely for a personal/demo project — see the limits noted at each step).

---

## 1. Create the GitHub repo

1. Go to github.com → New repository → name it (e.g. `breach-intel`) → **Public**
   (public repos get unlimited free GitHub Actions minutes; private repos get
   2,000 free minutes/month, also plenty for this, but public is simplest).
2. Upload this entire `breach-intel/` folder to it (drag-and-drop on the GitHub
   web UI works fine for a one-time upload, or `git init && git add . && git commit -m "init" && git push`).

## 2. Create the Supabase project (free, no card)

1. Go to supabase.com → New project → pick any name/region, set a database password
   (save it somewhere).
2. Open the **SQL Editor** in the Supabase dashboard and run these files **in order**,
   pasting each one's contents and clicking Run:
   - `db/schema.sql`
   - `db/materialized_views.sql`
   - `db/seed_sources.sql`
   - `db/supabase_grants.sql`
3. Go to Project Settings → API. Copy:
   - **Project URL** → you'll use this as `VITE_SUPABASE_URL`
   - **anon public key** → you'll use this as `VITE_SUPABASE_ANON_KEY`
4. Go to Project Settings → Database → Connection string → choose **URI** (the
   *direct* connection, not the pooler) → copy it, then change `postgresql://`
   to `postgresql+asyncpg://` at the start. This becomes your `DATABASE_URL` secret
   in step 3.

   Supabase free projects pause after 7 days with zero database activity — the
   ingestion job in step 3 hits the database every 6 hours, which counts as
   activity, so this should never happen in practice.

## 3. Wire up the free scheduler (GitHub Actions)

1. In your GitHub repo: Settings → Secrets and variables → Actions → **New repository secret**.
2. Add `DATABASE_URL` with the connection string from step 2.4.
3. (Optional) Add `HIBP_API_KEY` / `LEAKIX_API_KEY` / `DEHASHED_API_KEY` / `INTELX_API_KEY`
   if you have accounts with those services — every collector works without
   a key by simply skipping that source.
4. That's it — `.github/workflows/ingest.yml` is already in the repo. Go to the
   **Actions** tab → "Ingest breach sources" → **Run workflow** to trigger the
   first run manually and confirm it succeeds. After that it runs automatically
   every 6 hours, forever, for free.

## 4. Deploy the frontend (Vercel, free, no card)

1. Go to vercel.com → sign in with GitHub → **Add New → Project** → select your repo.
2. Set **Root Directory** to `frontend`.
3. Framework preset: Vite (auto-detected).
4. Add Environment Variables:
   - `VITE_SUPABASE_URL` = (from step 2.3)
   - `VITE_SUPABASE_ANON_KEY` = (from step 2.3)
5. Click **Deploy**. ~1 minute later you get a live `https://your-project.vercel.app` URL.

That URL is the real thing: it queries live Postgres through Supabase, paginated
server-side, refreshed every 6 hours by the GitHub Action — not the mock-data
artifact from chat.

---

## What's intentionally left out of the free path

- **Redis caching** — skipped. At personal-project traffic, Postgres + the
  materialized views in `materialized_views.sql` are already fast; Redis only
  starts to matter at real concurrent load.
- **Custom FastAPI backend** — skipped for reads. Supabase's auto-generated
  REST API (PostgREST) serves `frontend/src/lib/api.js` directly. The FastAPI
  code in `backend/app/routers/` still exists in the repo if you outgrow this
  later and want a real custom API layer (e.g. to add write endpoints, auth,
  or business logic beyond what PostgREST can express).
- **Match-queue approve/reject** — read-only on the public site, since the
  anon key can only `SELECT` (see `db/supabase_grants.sql`). To actually
  approve/reject matches, run `backend/app/routers/match_queue.py`'s logic
  locally or behind Supabase Auth — letting anonymous visitors approve merges
  into your breach data isn't something you want on a public deployment.

## If you outgrow the free tier

- Supabase: 500MB DB / 2 active projects free. Upgrade path is Pro at $25/mo.
- Vercel Hobby: personal/non-commercial use only, 100GB bandwidth/month.
  If this becomes a commercial product, Vercel's terms require Pro ($20/mo).
- GitHub Actions: unlimited free on public repos regardless of scale.
