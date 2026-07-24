-- ============================================================================
-- Breach Intelligence Platform — Core Schema (PostgreSQL 14+)
-- ============================================================================
-- Design notes:
--  * breach_source_records stores NORMALIZED METADATA about an incident as
--    reported by a given source (company name, dates, industry, location,
--    threat actor, URLs to the disclosure/article/filing/leak-post).
--  * It intentionally has NO column for raw personal data (emails, passwords,
--    SSNs, etc). Lookup-style sources (HIBP / DeHashed / Intelx) are queried
--    on-demand per company/domain for enrichment, and only the resulting
--    breach-level facts (record count, data classes exposed, date) are
--    persisted here — never the underlying credential/PII contents. See
--    backend/app/collectors/sources/dehashed_intelx.py for the rationale.
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;     -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS pg_trgm;      -- fuzzy name matching / trigram indexes
CREATE EXTENSION IF NOT EXISTS btree_gin;

-- ----------------------------------------------------------------------------
-- 1. Source registry
-- ----------------------------------------------------------------------------
CREATE TABLE breach_data_sources (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug            TEXT UNIQUE NOT NULL,         -- e.g. 'ransomware_live'
    name            TEXT NOT NULL,
    base_url        TEXT NOT NULL,
    category        TEXT NOT NULL CHECK (category IN (
                        'ransomware_leak_tracker', 'state_ag_notification',
                        'federal_regulatory', 'sec_filing', 'security_news',
                        'breach_lookup_service', 'nonprofit_tracker',
                        'government_advisory', 'eu_uk_regulatory'
                    )),
    feed_type       TEXT NOT NULL CHECK (feed_type IN (
                        'json_api', 'csv', 'xlsx', 'xml', 'rss', 'html_scrape'
                    )),
    feed_url        TEXT,                          -- discovered feed/API endpoint, if any
    requires_api_key BOOLEAN NOT NULL DEFAULT FALSE,
    collection_mode TEXT NOT NULL DEFAULT 'scheduled'
                        CHECK (collection_mode IN ('scheduled', 'on_demand_lookup')),
    polling_interval_minutes INTEGER NOT NULL DEFAULT 360,  -- 6 hours
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    robots_checked_at TIMESTAMPTZ,
    notes           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ----------------------------------------------------------------------------
-- 2. Raw (but normalized-on-write) per-source records
-- ----------------------------------------------------------------------------
CREATE TABLE breach_source_records (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id           UUID NOT NULL REFERENCES breach_data_sources(id),
    external_id         TEXT,                       -- ID/slug from the source, if any
    fetched_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    source_published_at TIMESTAMPTZ,                -- when the source says this happened

    -- normalized fields (see backend/app/normalize/*)
    company_name_raw    TEXT NOT NULL,
    company_name_norm   TEXT NOT NULL,               -- lowercased, legal-suffix-stripped
    industry            TEXT,                        -- mapped to a controlled taxonomy
    country             TEXT,
    region_state        TEXT,
    ransomware_group_raw TEXT,
    ransomware_group_norm TEXT,                       -- alias-resolved
    incident_date        DATE,                        -- normalized disclosure/incident date
    records_affected_est BIGINT,
    data_types_exposed   TEXT[],                      -- e.g. {'name','address','ssn'} — categories only
    summary              TEXT,
    source_record_url    TEXT NOT NULL,
    document_type         TEXT CHECK (document_type IN (
                        'leak_site_post', 'ag_notification_letter', 'hhs_breach_report',
                        'sec_filing', 'news_article', 'lookup_summary', 'advisory',
                        'regulatory_action'
                    )),

    -- dedup + correlation bookkeeping
    content_fingerprint  TEXT NOT NULL,               -- sha256 of normalized payload, dedup key
    matched_breach_id    UUID,                        -- FK added below, after breaches exists
    match_confidence     NUMERIC(4,3),                -- 0.000–1.000
    raw_payload          JSONB NOT NULL DEFAULT '{}', -- original parsed fields (no PII contents)

    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- breaches table is forward-referenced above; declared properly below.
-- (Postgres requires this ordering fix — see note at bottom of file.)

-- ----------------------------------------------------------------------------
-- 3. Master breach records (one row per real-world incident)
-- ----------------------------------------------------------------------------
CREATE TABLE breaches (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id          UUID,                          -- FK added below, after breach_companies exists
    canonical_name      TEXT NOT NULL,
    industry            TEXT,
    country             TEXT,
    region_state        TEXT,
    ransomware_group    TEXT,
    incident_date       DATE,
    disclosed_date      DATE,
    records_affected_est BIGINT,
    data_types_exposed  TEXT[],
    cves                TEXT[] NOT NULL DEFAULT '{}',   -- CVE ids parsed from source text
    attack_techniques   TEXT[] NOT NULL DEFAULT '{}',   -- MITRE ATT&CK technique ids inferred from source text
    severity            TEXT CHECK (severity IN ('low','moderate','high','critical')),
    status              TEXT NOT NULL DEFAULT 'confirmed'
                            CHECK (status IN ('confirmed','disputed','retracted')),
    source_count        INTEGER NOT NULL DEFAULT 0,   -- denormalized for fast listing
    confidence_avg      NUMERIC(4,3),
    summary             TEXT,
    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    search_vector       TSVECTOR
);

ALTER TABLE breach_source_records
    ADD CONSTRAINT fk_matched_breach FOREIGN KEY (matched_breach_id) REFERENCES breaches(id);

-- ----------------------------------------------------------------------------
-- 4. Companies (entity registry, deduplicated across breaches)
-- ----------------------------------------------------------------------------
CREATE TABLE breach_companies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    canonical_name  TEXT NOT NULL,
    name_aliases    TEXT[] NOT NULL DEFAULT '{}',
    domain          TEXT,
    industry        TEXT,
    country         TEXT,
    region_state    TEXT,
    employee_range  TEXT,
    breach_count    INTEGER NOT NULL DEFAULT 0,
    first_breach_at DATE,
    last_breach_at  DATE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE breaches
    ADD CONSTRAINT fk_breach_company FOREIGN KEY (company_id) REFERENCES breach_companies(id);

-- ----------------------------------------------------------------------------
-- 5. Uncertain-match review queue
-- ----------------------------------------------------------------------------
CREATE TABLE breach_match_queue (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_record_id    UUID NOT NULL REFERENCES breach_source_records(id),
    candidate_breach_id UUID REFERENCES breaches(id),
    confidence          NUMERIC(4,3) NOT NULL,
    match_reasons        JSONB NOT NULL DEFAULT '{}',  -- {name_score, date_delta_days, industry_match, ...}
    status               TEXT NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending','approved','rejected','merged_new')),
    reviewed_by          TEXT,
    reviewed_at          TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ----------------------------------------------------------------------------
-- 6. Threat actor / ransomware group reference data
-- ----------------------------------------------------------------------------
CREATE TABLE threat_actors (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    canonical_name  TEXT UNIQUE NOT NULL,
    aliases         TEXT[] NOT NULL DEFAULT '{}',
    actor_type      TEXT CHECK (actor_type IN ('ransomware_group','state_sponsored','unattributed')),
    active          BOOLEAN NOT NULL DEFAULT TRUE,
    first_observed  DATE,
    last_observed   DATE,
    victim_count    INTEGER NOT NULL DEFAULT 0,
    notes           TEXT,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ----------------------------------------------------------------------------
-- 7. Collector run log
-- ----------------------------------------------------------------------------
CREATE TABLE breach_collector_log (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id           UUID NOT NULL REFERENCES breach_data_sources(id),
    started_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at         TIMESTAMPTZ,
    status              TEXT NOT NULL DEFAULT 'running'
                            CHECK (status IN ('running','success','partial_failure','failed')),
    feed_type_used       TEXT,                 -- which feed type actually succeeded this run
    records_fetched      INTEGER DEFAULT 0,
    records_new          INTEGER DEFAULT 0,
    records_deduped      INTEGER DEFAULT 0,
    records_matched_auto INTEGER DEFAULT 0,
    records_queued       INTEGER DEFAULT 0,
    error_message        TEXT
);

-- ----------------------------------------------------------------------------
-- 8. News-watch — 7-day title-correlation buffer
-- ----------------------------------------------------------------------------
-- Stores ONLY the title + URL + publish date of recent security-news
-- headlines (never article content). Headlines are correlated by company
-- name to ledger breaches and surfaced as "related coverage"; unmatched rows
-- are pruned after ~7 days. This table NEVER creates or edits a breach — see
-- backend/app/news_watch.py. Created idempotently by that daily job too.
CREATE TABLE IF NOT EXISTS news_watch (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_slug       TEXT NOT NULL,
    source_name       TEXT NOT NULL,
    title             TEXT NOT NULL,
    url               TEXT NOT NULL UNIQUE,
    published_at      TIMESTAMPTZ,
    title_hash        TEXT NOT NULL,               -- sha256 of normalized title
    org_guess         TEXT,                        -- victim org parsed from the headline
    org_norm          TEXT,                        -- normalized org, for trigram matching
    keywords          TEXT[] NOT NULL DEFAULT '{}',
    similarity        NUMERIC(4,3),                -- name-match score when matched
    matched_breach_id UUID REFERENCES breaches(id) ON DELETE SET NULL,
    first_seen        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_news_watch_matched ON news_watch (matched_breach_id);
CREATE INDEX IF NOT EXISTS idx_news_watch_first_seen ON news_watch (first_seen);
CREATE INDEX IF NOT EXISTS idx_news_watch_title_hash ON news_watch (title_hash);
CREATE INDEX IF NOT EXISTS idx_news_watch_org_trgm ON news_watch USING gin (org_norm gin_trgm_ops);

-- ----------------------------------------------------------------------------
-- 9. Threat Radar — fresh threat signals behind the site's live ticker
-- ----------------------------------------------------------------------------
-- Compact "what's happening now" rows (latest ransomware victims, newly
-- exploited CVEs, etc.) pulled server-side from public feeds. Read-only decor
-- for researchers; NEVER a breach source. See backend/app/threat_radar.py.
CREATE TABLE IF NOT EXISTS threat_radar (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind         TEXT NOT NULL,          -- ransomware_victim | kev_cve | otx_pulse | malware_url
    source_slug  TEXT NOT NULL,
    source_name  TEXT NOT NULL,
    external_id  TEXT NOT NULL,
    title        TEXT NOT NULL,
    subtitle     TEXT,
    url          TEXT,
    published_at TIMESTAMPTZ,
    first_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (source_slug, external_id)
);

CREATE INDEX IF NOT EXISTS idx_threat_radar_published ON threat_radar (published_at DESC);
CREATE INDEX IF NOT EXISTS idx_threat_radar_first_seen ON threat_radar (first_seen);

-- ============================================================================
-- Indexes
-- ============================================================================
CREATE INDEX idx_bsr_source ON breach_source_records (source_id);
CREATE INDEX idx_bsr_fingerprint ON breach_source_records (content_fingerprint);
CREATE UNIQUE INDEX uq_bsr_dedup ON breach_source_records (source_id, content_fingerprint);
CREATE INDEX idx_bsr_company_trgm ON breach_source_records USING gin (company_name_norm gin_trgm_ops);
CREATE INDEX idx_bsr_matched_breach ON breach_source_records (matched_breach_id);
CREATE INDEX idx_bsr_incident_date ON breach_source_records (incident_date);

CREATE INDEX idx_breaches_company ON breaches (company_id);
CREATE INDEX idx_breaches_industry ON breaches (industry);
CREATE INDEX idx_breaches_date ON breaches (incident_date DESC);
CREATE INDEX idx_breaches_ransomware_group ON breaches (ransomware_group);
CREATE INDEX idx_breaches_search ON breaches USING gin (search_vector);
CREATE INDEX idx_breaches_name_trgm ON breaches USING gin (canonical_name gin_trgm_ops);

CREATE INDEX idx_companies_name_trgm ON breach_companies USING gin (canonical_name gin_trgm_ops);
CREATE INDEX idx_companies_domain ON breach_companies (domain);

CREATE INDEX idx_match_queue_status ON breach_match_queue (status);
CREATE INDEX idx_collector_log_source_started ON breach_collector_log (source_id, started_at DESC);

-- search_vector maintenance
CREATE OR REPLACE FUNCTION breaches_search_vector_trigger() RETURNS trigger AS $$
BEGIN
    NEW.search_vector :=
        setweight(to_tsvector('english', coalesce(NEW.canonical_name,'')), 'A') ||
        setweight(to_tsvector('english', coalesce(NEW.industry,'')), 'B') ||
        setweight(to_tsvector('english', coalesce(NEW.ransomware_group,'')), 'B') ||
        setweight(to_tsvector('english', coalesce(NEW.summary,'')), 'C');
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_breaches_search_vector
BEFORE INSERT OR UPDATE ON breaches
FOR EACH ROW EXECUTE FUNCTION breaches_search_vector_trigger();

-- updated_at maintenance (generic)
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_sources_updated_at BEFORE UPDATE ON breach_data_sources
FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_companies_updated_at BEFORE UPDATE ON breach_companies
FOR EACH ROW EXECUTE FUNCTION set_updated_at();
