# Breach Intelligence Platform

A unified ingestion, correlation, and presentation layer for breach
intelligence across ransomware leak-site trackers, state AG notification
portals, federal regulators (HHS OCR, SEC), security journalism, breach
lookup services, nonprofit trackers and government/EU/UK advisories.

## What's in this repo

```
db/                      Postgres schema, materialized views, source seed data
backend/app/
  collectors/            Pluggable collector framework (RSS, JSON API, CSV/XLSX, HTML fallback)
  collectors/sources/    Source-specific implementations + the full 40-source registry
  normalize/             Company name / date / industry / location / threat-actor normalization
  correlation/           Cross-source entity matching, auto-merge and review-queue logic
  routers/                FastAPI endpoints: breaches, companies, analytics, match queue
  scheduler.py            Runs every collector on a 6h cadence, logs every run
  cache.py                Redis caching + post-ingestion invalidation
deployment/              docker-compose.yml, Dockerfile, .env.example
```

The frontend (search/filter/sort/paginated breach ledger + single breach
dossier view + analytics) was delivered separately as an interactive
artifact - lift its components directly into a Next.js app - point
`lib/api.js` at these endpoints.

## Why DeHashed and Intelligence X are handled differently

Every other source in this list publishes (or can be made to publish, via
RSS/CSV/JSON) a *bulk feed* of breach metadata - "Company X disclosed an
incident on date Y." DeHashed and Intelx are different: they're per-query
lookup APIs over actual leaked credential data (emails, password hashes,
sometimes plaintext). Two consequences, both implemented in
`collectors/sources/dehashed_intelx.py`:

1. **They aren't scheduled.** There's no "list everything new" call to
   make every 6 hours - you query a specific domain/company. Call
   `enrich_company()` on demand from the breach dossier UI ("check dark-web
   exposure"), or batch it nightly against your `breach_companies` table.
2. **Only metadata is ever persisted.** `_strip_to_metadata()` discards
   every credential field and keeps only breach name, date and a record
   count. This isn't just caution - it's also the right call for your own
   risk posture: a database holding other people's live passwords is a
   massive liability and a high-value attacker target and the `breaches`
   schema is incident-level, not individual-level, so there's no legitimate
   use for those fields here anyway.

Have I Been Pwned is the exception among the three: its `/breaches`
endpoint returns only aggregate metadata (no credentials), so it's wired
as a normal scheduled collector.

## Scraping etiquette

For the ~16 sources with no discovered CSV/JSON/RSS feed, the HTML fallback
collector checks `robots.txt` before scraping, identifies itself with a
real, contactable User-Agent (set `SCRAPER_USER_AGENT` in `.env`) and rate
-limits itself between pages. It does not attempt to evade anti-bot
measures. Review each target site's terms of service before enabling
scraping in production - a few (state AG sites in particular) may prefer
or require manual/CSV-request access instead.

## Running it

```bash
cd deployment
cp .env.example .env        # fill in any API keys you have
docker compose up -d        # postgres + redis + api + scheduler
```

The Postgres container auto-runs `db/schema.sql`, `db/materialized_views.sql`
and `db/seed_sources.sql` on first boot. The API comes up at
`http://localhost:8000` (`/health` to check, `/docs` for interactive
OpenAPI docs). The scheduler container starts ingesting immediately and
then every 6 hours; watch `breach_collector_log` to confirm sources are
returning records - `records_fetched = 0` on a source usually means its
HTML selectors need updating (see `collectors/sources/ca_ag.py` for the
pattern and `collectors/registry.py::PLACEHOLDER_HTML_SLUGS` for which
sources still need this).

## Extending to a new source

1. Add a row to `db/seed_sources.sql` (or insert into `breach_data_sources`
   directly) with the discovered `feed_type` and `feed_url`.
2. If it's RSS or a JSON/CSV shape the generic collectors already handle,
   no code needed - `registry.py` wires it automatically.
3. If the field names are source-specific, add a small file under
   `collectors/sources/` (see `hhs_ocr.py` for a CSV example, `ca_ag.py`
   for HTML) and register it in `EXPLICIT_COLLECTORS`.

## Known reference-implementation simplifications

* The RSS collector guesses a company name from the headline using simple
  string heuristics. Swap in a proper NER model (spaCy or similar) for
  materially better precision on news-source attribution.
* `PLACEHOLDER_HTML_SLUGS` sources use a generic CSS-selector config -
  inspect each live page and fill in real selectors before enabling.
* The correlation engine's candidate query and weights are a solid
  starting point; tune `auto_merge_confidence_threshold` and
  `queue_confidence_threshold` in `config.py` against your own labeled
  data before trusting auto-merge at scale.
