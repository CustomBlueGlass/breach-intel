"""
Generic RSS/Atom collector. Used directly by every security-news source
(BleepingComputer, SecurityWeek, The Record, CyberScoop, Dark Reading,
DataBreaches.net, HIPAA Journal, NCSC UK, CISA advisories, Hackmanac).

A source-specific subclass only needs to override `parse_entry()` if a feed
embeds non-standard fields (e.g. an industry or ransomware-group taxonomy
term in a custom XML namespace); otherwise this base class is sufficient.
"""
from __future__ import annotations

import feedparser

from app.collectors.base import BaseCollector, NormalizedRecord
from app.normalize.company_name import normalize_company_name
from app.normalize.date_parser import parse_any_date
from app.normalize.ransomware_group_aliases import extract_ransomware_group


class RSSCollector(BaseCollector):
    default_document_type = "news_article"

    async def fetch_raw(self) -> str:
        resp = await self.client.get(self.source_row.feed_url)
        resp.raise_for_status()
        return resp.text

    async def parse(self, raw: str) -> list[NormalizedRecord]:
        parsed = feedparser.parse(raw)
        records = []
        for entry in parsed.entries:
            records.append(self.parse_entry(entry))
        return [r for r in records if r is not None]

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
        """
        Cheap heuristic — most breach-news headlines follow
        "<Company> discloses/confirms/hit by ... breach". A production
        deployment should replace this with an NER model (e.g. spaCy)
        for materially better precision; this keeps the framework
        dependency-light for the reference implementation.
        """
        for sep in (" discloses", " confirms", " hit by", " suffers", " reports", ":"):
            if sep in title:
                return title.split(sep)[0].strip()
        return title.split(",")[0].strip()
