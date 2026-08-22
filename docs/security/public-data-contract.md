# Public data contract

Model: **default private; deliberately public only where the unauthenticated
product needs it.** Enforced by migration `db/migrations/0001_security_hardening.sql`
and re-asserted every ingest run by `backend/app/maintenance.py`
(`PUBLIC_READ_TABLES`, `PUBLIC_READ_VIEWS`, `PRIVATE_TABLES`, `ENSURE_PRIVATE`,
`HARDEN_FUNCTIONS`). The anonymous Supabase Data API role (`anon`) may read only
the objects marked public below. The GitHub Actions ingestion job connects as the
owner/service role, bypasses RLS and is unaffected.

Traced from the only two anonymous consumers: the frontend queries in
`frontend/src/lib/api.js` and the serverless feed in `frontend/api/stix.js`.

## Public (anon SELECT)

| Object | Kind | anon | why public | columns exposed |
| --- | --- | --- | --- | --- |
| `mv_breach_ledger` | matview | yes | the customer-facing ledger + STIX feed | all (already curated product columns) |
| `mv_breach_trends` | matview | yes | analytics trend chart | week, industry, counts |
| `mv_top_ransomware_groups` | matview | yes | analytics + group filter | group, victim_count, most_recent |
| `mv_platform_stats` | matview | yes | hero stat strip | four aggregate counts |
| `breaches` | table | yes | core public ledger record (dossier) | product columns only; no PII |
| `breach_developments` | table | yes | dossier "developments" (fines, suits) | product columns; `dedupe_key` is a non-sensitive hash |
| `breach_enrichment_log` | table | yes | dossier "enhancement history" | `changed` (diff of public fields), `enriched_at` |
| `threat_radar` | table | yes | live ticker | product columns |
| `public_breach_sources` | table | yes | curated public projection (dossier sources) | curated allowlist (see below) |
| `public_breach_news` | table | yes | curated public projection (related news) | matched_breach_id, title, url, source_name, published_at, similarity |
| `v_public_breach_sources` | view | yes | app-facing name; `security_invoker` view over `public_breach_sources` | same columns as the projection |
| `v_public_news` | view | yes | app-facing name; `security_invoker` view over `public_breach_news` | same columns as the projection |

**WP-003 architecture.** The trust boundary is a pair of deliberately-public
projection TABLES (`public_breach_sources`, `public_breach_news`) that hold a
sanitised copy of the publishable state, populated only by owner-side maintenance
(`refresh_public_projections`). The application-facing names remain as
`security_invoker` views over those tables, so no view ever queries a private
table and the "Security Definer View" adviser findings are cleared. anon has
SELECT only on the projection tables (RLS SELECT policy, INSERT/UPDATE/DELETE
revoked).

`public_breach_sources` deliberately omits `raw_payload`, `content_fingerprint`,
`source_id`, `external_id`, `company_name_raw`, `company_name_norm`, `fetched_at`,
`created_at`. It exposes only the reported fields the dossier renders plus two
distilled evidence URLs (`disclosure_url`, `screenshot_url`) extracted from
`raw_payload` **during the trusted refresh**, so the raw source payload is never
granted to the public layer. Stale/deleted upstream rows drop out because each
refresh is a full transactional replace (DELETE + INSERT in one transaction).

## Private (no anon access)

| Object | Kind | why private | how the UI still works |
| --- | --- | --- | --- |
| `breach_source_records` | table | raw_payload, fingerprints, source ids, raw org names | read via `v_public_breach_sources` |
| `news_watch` | table | internal org_guess/org_norm/title_hash | read via `v_public_news` |
| `breach_data_sources` | table | operational config (feed urls, key flags, notes) | name + category surfaced via the curated source view; health via internal matview |
| `breach_companies` | table | not read directly by the UI | `domain` already joined into `mv_breach_ledger` |
| `breach_collector_log` | table | operational run log (status, error_message) | not surfaced publicly |
| `breach_match_queue` | table | internal review state (reviewed_by, reasons) | `fetchMatchQueue()` now returns empty for the public site |
| `threat_actors` | table | not read by the public UI | actor pages derive from `mv_breach_ledger` + the source view |
| `mv_source_health` | matview | operational collector status | not read by the UI |

## Functions

| Function | State |
| --- | --- |
| `refresh_breach_views()` | EXECUTE revoked from PUBLIC/anon/authenticated (ingestion job only); fixed `search_path` |
| `rls_auto_enable()` | not in version control (dashboard-created); EXECUTE revoked from PUBLIC/anon/authenticated; fixed `search_path` if retained; owner may DROP once confirmed unused |
| `set_updated_at()` | trigger only; fixed `search_path` |
| `breaches_search_vector_trigger()` | trigger only; fixed `search_path` |

## Documented adviser exceptions

- **Materialized views on the Data API** (`mv_breach_ledger`, `mv_breach_trends`,
  `mv_top_ransomware_groups`, `mv_platform_stats`): intentionally public. They
  contain only already-public, aggregate product data and are the customer-facing
  ledger/analytics. `mv_source_health` (operational) was removed from the API.
- **Curated public projection** (`public_breach_sources`, `public_breach_news` +
  their `security_invoker` views): replaces the earlier owner-privileged
  ("security definer") views. No view queries a private table; the projection
  tables are a sanitised public copy refreshed by owner-side maintenance. This
  clears the two "Security Definer View" adviser ERRORs (WP-003).
- **Extensions in `public`** (`pg_trgm`, `btree_gin`): left in place. Moving them
  risks breaking the trigram GIN indexes the correlation/search paths depend on.
  Low severity; tracked as deferred in the PR "Remaining risks".
