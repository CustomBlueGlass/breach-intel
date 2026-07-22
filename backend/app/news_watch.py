"""
News-watch: a 7-day title-correlation pipeline.

WHAT THIS IS (and is deliberately NOT)
--------------------------------------
This module runs once a day and pulls ONLY the *title + URL + publish date*
of recent stories from a handful of security-news outlets. It stores NO
article body, NO scraped page content — just the headline metadata. Those
headlines live in `news_watch` for ~7 days and are correlated, by company
name, against breaches already in the ledger. When a headline confidently
matches a breach, it is surfaced in that breach's dossier as *"Related news
coverage"* — a read-only link out to the outlet.

It is a CORRELATION AID, never a breach source:

  * news-watch NEVER creates, edits, merges, or deletes a breach;
  * a matched headline only sets `matched_breach_id` on its own news row;
  * unmatched headlines are purged after 7 days, so the table stays small
    and never becomes a general-purpose news archive.

This keeps the ledger a list of breached *companies* (the site's whole
premise) while still giving analysts the "who else is writing about this?"
context that commercial CTI platforms charge for.

WHY TRIGRAM + RAPIDFUZZ, NOT EMBEDDINGS
---------------------------------------
The matching target is a company *name* embedded in a headline, not semantic
meaning — "Acme Corp confirms data breach" vs a ledger entry "Acme
Corporation". Trigram/token-sort string similarity solves that exactly and
for free (pg_trgm ships with Postgres; rapidfuzz is already a dependency).
A sentence-embedding model would add a model dependency, GPU/CPU cost, and a
vector column for zero accuracy gain on short proper-noun matching — and
would actually *hurt* precision by matching on topical similarity ("another
healthcare ransomware attack") rather than the specific victim. So: no
embeddings. Cost of the whole daily run is ~5 HTTP GETs and a few hundred
cheap string comparisons.

FALSE-POSITIVE CONTROLS
-----------------------
  * candidate retrieval is gated by a pg_trgm similarity floor on the name;
  * a match requires a high token-sort name score (>= 0.90);
  * the headline's publish date must fall within a window of the breach's
    incident/disclosure date (news about a breach clusters around its
    disclosure) — unless the name match is near-exact (>= 0.95);
  * headlines whose guessed org is too short/generic (e.g. "hackers",
    "data") are skipped entirely;
  * dedup is by URL (a story pulled again tomorrow doesn't duplicate).
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import re

import feedparser
import httpx
from sqlalchemy import text

from app.collectors.rss_collector import RSSCollector, RSS_HEADERS
from app.db import get_session
from app.normalize.company_name import normalize_company_name

logger = logging.getLogger("breach_intel.news_watch")

# Title + URL only, from these outlets. (source_slug, display name, feed URL.)
# BleepingComputer's feed 403s some datacenter IP ranges (CDN bot rules); we
# still try it every day — GitHub-hosted runners frequently get through, and a
# 403 just yields zero rows that run rather than an error.
NEWS_FEEDS = [
    ("bleepingcomputer", "BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("theregister", "The Register (Security)", "https://www.theregister.com/security/headlines.atom"),
    ("darkreading", "Dark Reading", "https://www.darkreading.com/rss.xml"),
    ("cybernews", "Cybernews", "https://cybernews.com/feed/"),
    ("securityweek", "SecurityWeek", "https://www.securityweek.com/feed/"),
]

RETENTION_DAYS = 7

# Matching thresholds — see FALSE-POSITIVE CONTROLS above.
NAME_MATCH_MIN = 0.90          # token-sort name score to link at all
NAME_MATCH_NO_DATE_MIN = 0.95  # stricter bar when neither side has a date
DATE_WINDOW_DAYS = 30          # headline date vs breach incident/disclosure date
TRGM_FLOOR = 0.30              # pg_trgm similarity floor for candidate retrieval
MIN_ORG_LEN = 4                # skip org guesses shorter than this

# Org guesses that are headline noise, not a victim organization.
ORG_STOPWORDS = {
    "hackers", "ransomware", "data breach", "data", "cyber", "cyberattack",
    "cybersecurity", "security", "breach", "attackers", "threat actors",
    "malware", "phishing", "report", "researchers", "police", "government",
    "millions", "thousands", "users", "customers", "the", "new",
}

_WORD_RE = re.compile(r"[a-z0-9][a-z0-9\-]+")


def _title_hash(title: str) -> str:
    norm = re.sub(r"\s+", " ", (title or "").strip().lower())
    return hashlib.sha256(norm.encode()).hexdigest()


def _keywords(title: str) -> list[str]:
    """A few lowercase content tokens from the title (for display/grouping)."""
    toks = [t for t in _WORD_RE.findall((title or "").lower()) if t not in ORG_STOPWORDS and len(t) > 3]
    seen: list[str] = []
    for t in toks:
        if t not in seen:
            seen.append(t)
    return seen[:8]


CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS news_watch (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_slug      TEXT NOT NULL,
    source_name      TEXT NOT NULL,
    title            TEXT NOT NULL,
    url              TEXT NOT NULL UNIQUE,
    published_at     TIMESTAMPTZ,
    title_hash       TEXT NOT NULL,
    org_guess        TEXT,
    org_norm         TEXT,
    keywords         TEXT[] NOT NULL DEFAULT '{}',
    similarity       NUMERIC(4,3),
    matched_breach_id UUID REFERENCES breaches(id) ON DELETE SET NULL,
    first_seen       TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""

CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_news_watch_matched ON news_watch (matched_breach_id)",
    "CREATE INDEX IF NOT EXISTS idx_news_watch_first_seen ON news_watch (first_seen)",
    "CREATE INDEX IF NOT EXISTS idx_news_watch_title_hash ON news_watch (title_hash)",
    "CREATE INDEX IF NOT EXISTS idx_news_watch_org_trgm ON news_watch USING gin (org_norm gin_trgm_ops)",
]

# The public site reads news_watch directly (Supabase anon) to show related
# coverage in the breach dossier, so mirror the read-only RLS + grants that
# maintenance.py applies to every other public table. Idempotent.
ENSURE_PUBLIC_READ = """
DO $$
BEGIN
    IF NOT (SELECT relrowsecurity FROM pg_class WHERE oid = 'public.news_watch'::regclass) THEN
        EXECUTE 'ALTER TABLE news_watch ENABLE ROW LEVEL SECURITY';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public' AND tablename = 'news_watch' AND policyname = 'public read'
    ) THEN
        EXECUTE 'CREATE POLICY "public read" ON news_watch FOR SELECT USING (true)';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
        EXECUTE 'GRANT SELECT ON news_watch TO anon';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        EXECUTE 'GRANT SELECT ON news_watch TO authenticated';
    END IF;
END $$
"""


# Must match maintenance.DDL_ADVISORY_LOCK — serializes schema/RLS DDL against
# a concurrent ingest maintenance pass so the two don't deadlock on table locks
# (news_watch's CREATE TABLE references breaches, which maintenance also locks).
DDL_ADVISORY_LOCK = 918273645


async def ensure_schema(session) -> None:
    # Acquire the shared DDL lock before CREATE TABLE takes any table locks.
    await session.execute(text("SELECT pg_advisory_xact_lock(CAST(:k AS bigint))"), {"k": DDL_ADVISORY_LOCK})
    await session.execute(text(CREATE_TABLE))
    for stmt in CREATE_INDEXES:
        await session.execute(text(stmt))
    await session.execute(text(ENSURE_PUBLIC_READ))


def _org_from_title(title: str) -> str | None:
    """Guess the victim org from a headline, reusing the RSS collector's
    splitter, then reject guesses that are headline noise rather than a name."""
    guess = RSSCollector._guess_company_from_title(title).strip()
    norm = normalize_company_name(guess)
    if not norm or len(norm) < MIN_ORG_LEN:
        return None
    if norm in ORG_STOPWORDS or guess.lower() in ORG_STOPWORDS:
        return None
    # When a headline has no "X confirms/discloses/…" separator, the guesser
    # falls back to the whole title, which is usually a sentence, not an org
    # ("Hackers steal data from millions"). Reject guesses that lead with a
    # noise word or read as a full headline rather than a name.
    tokens = norm.split(" ")
    if tokens[0] in ORG_STOPWORDS or len(tokens) > 6:
        return None
    return guess


async def pull(session) -> int:
    """Fetch title+URL+date from each feed and upsert new rows. Returns the
    number of newly inserted headlines."""
    inserted = 0
    async with httpx.AsyncClient(timeout=30.0, headers=RSS_HEADERS, follow_redirects=True) as client:
        for slug, name, url in NEWS_FEEDS:
            try:
                resp = await client.get(url)
                resp.raise_for_status()
                raw = resp.text
            except Exception as exc:  # noqa: BLE001 — one bad feed must not stop the rest
                logger.warning("news-watch fetch failed for %s (%s): %s", slug, url, exc)
                continue

            parsed = feedparser.parse(raw)
            for entry in parsed.entries:
                title = (getattr(entry, "title", "") or "").strip()
                link = getattr(entry, "link", None)
                if not title or not link:
                    continue

                published = None
                if getattr(entry, "published_parsed", None):
                    from datetime import datetime
                    published = datetime(*entry.published_parsed[:6])

                org = _org_from_title(title)
                res = await session.execute(
                    text(
                        """
                        INSERT INTO news_watch
                            (source_slug, source_name, title, url, published_at,
                             title_hash, org_guess, org_norm, keywords)
                        VALUES (:slug, :name, :title, :url, :published,
                                :hash, :org, :org_norm, :kw)
                        ON CONFLICT (url) DO NOTHING
                        """
                    ),
                    {
                        "slug": slug,
                        "name": name,
                        "title": title[:500],
                        "url": link,
                        "published": published,
                        "hash": _title_hash(title),
                        "org": org,
                        "org_norm": normalize_company_name(org) if org else None,
                        "kw": _keywords(title),
                    },
                )
                if res.rowcount:
                    inserted += 1
    logger.info("news-watch pulled %d new headlines", inserted)
    return inserted


CANDIDATE_QUERY = text(
    """
    SELECT b.id, b.canonical_name, b.incident_date, b.disclosed_date
    FROM breaches b
    WHERE similarity(b.canonical_name, :org) > :floor
    ORDER BY similarity(b.canonical_name, :org) DESC
    LIMIT 8
    """
)


def _score_name(org_norm: str, canonical_name: str) -> float:
    from rapidfuzz import fuzz
    return fuzz.token_sort_ratio(org_norm or "", normalize_company_name(canonical_name or "")) / 100.0


def _date_ok(news_dt, incident_date, disclosed_date) -> tuple[bool, bool]:
    """Return (has_any_date, within_window). A breach date within
    DATE_WINDOW_DAYS of the headline is the time-correlation signal."""
    if news_dt is None:
        return (incident_date is not None or disclosed_date is not None, False)
    news_d = news_dt.date() if hasattr(news_dt, "date") else news_dt
    deltas = [
        abs((d - news_d).days)
        for d in (incident_date, disclosed_date)
        if d is not None
    ]
    if not deltas:
        return (False, False)
    return (True, min(deltas) <= DATE_WINDOW_DAYS)


async def match(session) -> int:
    """Correlate still-unmatched headlines against ledger breaches. Sets
    matched_breach_id + similarity on the news row only; touches no breach.
    Returns the number of headlines newly matched."""
    rows = (
        await session.execute(
            text(
                """
                SELECT id, org_guess, org_norm, published_at
                FROM news_watch
                WHERE matched_breach_id IS NULL AND org_norm IS NOT NULL
                """
            )
        )
    ).fetchall()

    matched = 0
    for r in rows:
        if not r.org_norm or len(r.org_norm) < MIN_ORG_LEN:
            continue
        candidates = (
            await session.execute(
                CANDIDATE_QUERY, {"org": r.org_guess, "floor": TRGM_FLOOR}
            )
        ).fetchall()
        best = None
        best_score = 0.0
        for c in candidates:
            score = _score_name(r.org_norm, c.canonical_name)
            if score <= best_score:
                continue
            has_date, within = _date_ok(r.published_at, c.incident_date, c.disclosed_date)
            # Time-correlation is the whole point: a strong name match must
            # also land inside the date window. Only when the breach carries
            # no date at all do we fall back to a near-exact name alone.
            if score >= NAME_MATCH_MIN and within:
                ok = True
            elif score >= NAME_MATCH_NO_DATE_MIN and not has_date:
                ok = True
            else:
                ok = False
            if ok:
                best, best_score = c, score
        if best is not None:
            await session.execute(
                text(
                    "UPDATE news_watch SET matched_breach_id = :bid, similarity = :sim "
                    "WHERE id = :id AND matched_breach_id IS NULL"
                ),
                {"bid": str(best.id), "sim": round(best_score, 3), "id": str(r.id)},
            )
            matched += 1
    if matched:
        logger.info("news-watch matched %d headlines to ledger breaches", matched)
    return matched


async def sweep(session) -> int:
    """Delete unmatched headlines older than the retention window. Matched
    headlines are kept — they are the dossier's related-coverage links."""
    res = await session.execute(
        text(
            "DELETE FROM news_watch "
            "WHERE matched_breach_id IS NULL "
            f"  AND first_seen < now() - INTERVAL '{RETENTION_DAYS} days'"
        )
    )
    if res.rowcount:
        logger.info("news-watch swept %d expired unmatched headlines", res.rowcount)
    return res.rowcount or 0


async def run() -> None:
    async with get_session() as session:
        await ensure_schema(session)
    async with get_session() as session:
        await pull(session)
    async with get_session() as session:
        await match(session)
    async with get_session() as session:
        await sweep(session)
    logger.info("news-watch run complete.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run())
