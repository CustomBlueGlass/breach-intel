"""
Generic RSS/Atom collector. Used directly by every security-news source.

Changes from original:
- Uses a real browser User-Agent + Accept header so sites like HIPAA Journal
  and Hackmanac don't block the request with a 403. Most RSS 403s are
  triggered by the default httpx User-Agent string ("python-httpx/..."),
  which many CMS platforms reject at the WAF level. A browser UA fixes this
  for the majority of cases; sites that block by IP (datacenter ranges) will
  still 403, but that's a network issue, not a code one.
- Catches HTTP errors gracefully and returns an empty list rather than
  crashing the whole collector run.
"""
from __future__ import annotations

import feedparser

from app.collectors.base import BaseCollector, NormalizedRecord
from app.normalize.company_name import normalize_company_name
from app.normalize.date_parser import parse_any_date
from app.normalize.ransomware_group_aliases import extract_ransomware_group

# Browser-like headers to avoid 403s from sites that block bot User-Agents.
RSS_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*",
    "Accept-Language": "en-US,en;q=0.9",
}


class RSSCollector(BaseCollector):
    default_document_type = "news_article"

    async def fetch_raw(self) -> str:
        try:
            resp = await self.client.get(
                self.source_row.feed_url,
                headers=RSS_HEADERS,
            )
            resp.raise_for_status()
            return resp.text
        except Exception as exc:
            # Log the failure but return empty string so parse() yields []
            # instead of propagating an exception that kills the whole run.
            import logging
            logging.getLogger("breach_intel.scheduler").warning(
                "RSS fetch failed for %s (%s): %s",
                self.source_row.slug, self.source_row.feed_url, exc,
            )
            return ""

    async def parse(self, raw: str) -> list[NormalizedRecord]:
        if not raw:
            return []
        parsed = feedparser.parse(raw)
        records = []
        for entry in parsed.entries:
            r = self.parse_entry(entry)
            if r:
                records.append(r)
        return records

    def parse_entry(self, entry) -> NormalizedRecord | None:
        title = getattr(entry, "title", "").strip()
        link = getattr(entry, "link", None)
        summary = getattr(entry, "summary", "") or ""
        if not title or not link:
            return None

        company_guess = self._guess_company_from_title(title)
        published = None
        if getattr(entry, "published_parsed", None):
            from datetime import datetime
            published = datetime(*entry.published_parsed[:6])

        return NormalizedRecord(
            company_name_raw=company_guess,
            company_name_norm=normalize_company_name(company_guess),
            source_record_url=link,
            source_published_at=published,
            incident_date=parse_any_date(summary) or (published.date() if published else None),
            ransomware_group_raw=extract_ransomware_group(title + " " + summary),
            summary=summary[:500],
            document_type=self.default_document_type,
            external_id=getattr(entry, "id", link),
            raw_payload={"title": title},
        )

    @staticmethod
    def _guess_company_from_title(title: str) -> str:
        for sep in (" discloses", " confirms", " hit by", " suffers", " reports", ":"):
            if sep in title:
                return title.split(sep)[0].strip()
        return title.split(",")[0].strip()
