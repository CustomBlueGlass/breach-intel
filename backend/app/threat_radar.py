"""
Threat Radar — the data behind the site's live ticker.

A small scheduled job (runs alongside the 6-hourly ingest) pulls a handful of
*fresh threat signals* from public feeds and stores compact rows that the
frontend renders as a scrolling ticker. It is intentionally NOT a breach
source — it never touches the `breaches` table — it's an at-a-glance "what's
happening right now" band for researchers landing on the site.

WHY SERVER-SIDE (and not fetched from the browser)
--------------------------------------------------
The public frontend has no server and holds no secrets. It can't call these
APIs directly: keyed ones would leak the key in page source, and most block
cross-origin browser requests (CORS). So this job runs on the GitHub Actions
runner — full egress, secrets available — and writes the results to Postgres,
which the frontend reads through the same read-only anon path as everything
else.

SOURCES
-------
Keyless (always on, zero setup):
  * ransomware.live  — latest ransomware leak-site victims
  * CISA KEV         — CVEs just added to the Known Exploited Vulns catalog

Keyed (activate automatically when the secret is present):
  * AlienVault OTX   — latest subscribed threat pulses      (OTX_API_KEY)
  * URLhaus          — latest malware distribution URLs      (URLHAUS_AUTH_KEY)

Each source is best-effort and isolated: one feed failing (or a key being
absent) never stops the others. Rows older than the retention window are
pruned so the ticker always reflects the last few weeks.
"""
from __future__ import annotations

import asyncio
import logging
import os

import httpx
from sqlalchemy import text

from app.db import get_session
from app.normalize.date_parser import parse_any_date
from app.normalize.ransomware_group_aliases import normalize_ransomware_group

logger = logging.getLogger("breach_intel.threat_radar")

RETENTION_DAYS = 30
UA = {"User-Agent": "Mozilla/5.0 (compatible; BreachIntelRadar/1.0)"}

RANSOMWARE_LIVE_URL = "https://api.ransomware.live/v2/recentvictims"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OTX_PULSES_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
URLHAUS_RECENT_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

# How many freshest items to keep per source each run.
PER_SOURCE_LIMIT = 15


CREATE_TABLE = """
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
)
"""

CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_threat_radar_published ON threat_radar (published_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_threat_radar_first_seen ON threat_radar (first_seen)",
]

ENSURE_PUBLIC_READ = """
DO $$
BEGIN
    EXECUTE 'ALTER TABLE threat_radar ENABLE ROW LEVEL SECURITY';
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public' AND tablename = 'threat_radar' AND policyname = 'public read'
    ) THEN
        EXECUTE 'CREATE POLICY "public read" ON threat_radar FOR SELECT USING (true)';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
        EXECUTE 'GRANT SELECT ON threat_radar TO anon';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        EXECUTE 'GRANT SELECT ON threat_radar TO authenticated';
    END IF;
END $$
"""


async def ensure_schema(session) -> None:
    await session.execute(text(CREATE_TABLE))
    for stmt in CREATE_INDEXES:
        await session.execute(text(stmt))
    await session.execute(text(ENSURE_PUBLIC_READ))


UPSERT = text(
    """
    INSERT INTO threat_radar (kind, source_slug, source_name, external_id, title, subtitle, url, published_at)
    VALUES (:kind, :slug, :name, :ext, :title, :subtitle, :url, :published)
    ON CONFLICT (source_slug, external_id) DO UPDATE
        SET title = EXCLUDED.title,
            subtitle = EXCLUDED.subtitle,
            url = EXCLUDED.url,
            published_at = EXCLUDED.published_at
    """
)


async def _store(session, rows: list[dict]) -> int:
    n = 0
    for r in rows:
        if not r.get("title") or not r.get("ext"):
            continue
        await session.execute(UPSERT, r)
        n += 1
    return n


# --------------------------------------------------------------------------- #
# Keyless sources                                                             #
# --------------------------------------------------------------------------- #

async def pull_ransomware(session, client: httpx.AsyncClient) -> int:
    resp = await client.get(RANSOMWARE_LIVE_URL)
    resp.raise_for_status()
    items = resp.json()
    if isinstance(items, dict):  # some deployments wrap the list
        items = items.get("data") or items.get("victims") or []
    rows = []
    for it in items[:PER_SOURCE_LIMIT]:
        victim = it.get("post_title") or it.get("victim")
        if not victim:
            continue
        group = normalize_ransomware_group(it.get("group_name") or it.get("group"))
        post = it.get("post_url") or it.get("url")
        if not post and str(it.get("link", "")).startswith("/"):
            post = f"https://www.ransomware.live{it['link']}"
        rows.append({
            "kind": "ransomware_victim",
            "slug": "ransomware_live",
            "name": "ransomware.live",
            "ext": str(it.get("id") or f"{victim}|{group}"),
            "title": victim[:200],
            "subtitle": group or "unattributed",
            "url": post or f"https://www.ransomware.live/#/search?search={victim}",
            "published": parse_any_date(it.get("discovered") or it.get("published")),
        })
    stored = await _store(session, rows)
    logger.info("threat-radar: ransomware.live +%d", stored)
    return stored


async def pull_kev(session, client: httpx.AsyncClient) -> int:
    resp = await client.get(CISA_KEV_URL)
    resp.raise_for_status()
    vulns = (resp.json() or {}).get("vulnerabilities", [])
    # newest additions first
    vulns.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)
    rows = []
    for v in vulns[:PER_SOURCE_LIMIT]:
        cve = v.get("cveID")
        if not cve:
            continue
        vendor = " ".join(filter(None, [v.get("vendorProject"), v.get("product")])).strip()
        rows.append({
            "kind": "kev_cve",
            "slug": "cisa_kev",
            "name": "CISA KEV",
            "ext": cve,
            "title": cve,
            "subtitle": (vendor or v.get("vulnerabilityName") or "actively exploited")[:200],
            "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
            "published": parse_any_date(v.get("dateAdded")),
        })
    stored = await _store(session, rows)
    logger.info("threat-radar: CISA KEV +%d", stored)
    return stored


# --------------------------------------------------------------------------- #
# Keyed sources — no-op unless the secret is set                              #
# --------------------------------------------------------------------------- #

async def pull_otx(session, client: httpx.AsyncClient) -> int:
    key = os.getenv("OTX_API_KEY")
    if not key:
        return 0
    resp = await client.get(
        OTX_PULSES_URL, params={"limit": PER_SOURCE_LIMIT, "page": 1},
        headers={**UA, "X-OTX-API-KEY": key},
    )
    resp.raise_for_status()
    results = (resp.json() or {}).get("results", [])
    rows = []
    for p in results[:PER_SOURCE_LIMIT]:
        pid = p.get("id")
        name = p.get("name")
        if not pid or not name:
            continue
        author = (p.get("author_name") or "").strip()
        rows.append({
            "kind": "otx_pulse",
            "slug": "otx",
            "name": "AlienVault OTX",
            "ext": str(pid),
            "title": name[:200],
            "subtitle": (f"by {author}" if author else "threat pulse"),
            "url": f"https://otx.alienvault.com/pulse/{pid}",
            "published": parse_any_date(p.get("modified") or p.get("created")),
        })
    stored = await _store(session, rows)
    logger.info("threat-radar: OTX +%d", stored)
    return stored


async def pull_urlhaus(session, client: httpx.AsyncClient) -> int:
    key = os.getenv("URLHAUS_AUTH_KEY")
    if not key:
        return 0
    resp = await client.get(URLHAUS_RECENT_URL, headers={**UA, "Auth-Key": key})
    resp.raise_for_status()
    payload = resp.json() or {}
    urls = payload.get("urls", []) if isinstance(payload, dict) else []
    rows = []
    for u in urls[:PER_SOURCE_LIMIT]:
        uid = u.get("id")
        raw_url = u.get("url")
        if not uid or not raw_url:
            continue
        host = raw_url.split("/")[2] if "://" in raw_url else raw_url[:60]
        rows.append({
            "kind": "malware_url",
            "slug": "urlhaus",
            "name": "URLhaus",
            "ext": str(uid),
            "title": host[:200],
            "subtitle": (u.get("threat") or "malware_download").replace("_", " "),
            "url": u.get("urlhaus_reference") or "https://urlhaus.abuse.ch/",
            "published": parse_any_date(u.get("date_added")),
        })
    stored = await _store(session, rows)
    logger.info("threat-radar: URLhaus +%d", stored)
    return stored


async def prune(session) -> int:
    res = await session.execute(
        text(f"DELETE FROM threat_radar WHERE first_seen < now() - INTERVAL '{RETENTION_DAYS} days'")
    )
    if res.rowcount:
        logger.info("threat-radar: pruned %d stale rows", res.rowcount)
    return res.rowcount or 0


async def run() -> None:
    async with get_session() as s:
        await ensure_schema(s)
    async with httpx.AsyncClient(timeout=30.0, headers=UA, follow_redirects=True) as client:
        for puller in (pull_ransomware, pull_kev, pull_otx, pull_urlhaus):
            try:
                async with get_session() as s:
                    await puller(s, client)
            except Exception as exc:  # noqa: BLE001 — isolate one bad feed
                logger.warning("threat-radar: %s failed: %s", puller.__name__, exc)
    async with get_session() as s:
        await prune(s)
    logger.info("threat-radar run complete.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run())
