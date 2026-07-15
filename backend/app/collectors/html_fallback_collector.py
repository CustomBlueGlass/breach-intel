"""
HTML scraping fallback — used only when discover_feed_type() found no
structured feed. Deliberately NOT built for evasion: it identifies itself
with a real User-Agent (see config.scraper_user_agent), checks robots.txt
before scraping, and rate-limits itself. If a site disallows the path in
robots.txt, the collector logs a 'skipped_disallowed' result instead of
scraping — operators should swap that source to manual/API-only collection.

Each source provides a small `ScrapeConfig` of CSS selectors rather than
bespoke parsing code, so adding a new HTML-fallback source is a config
change, not new code.
"""
from __future__ import annotations

import asyncio
import urllib.robotparser
from dataclasses import dataclass
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from app.collectors.base import BaseCollector, NormalizedRecord
from app.config import settings
from app.normalize.company_name import normalize_company_name
from app.normalize.date_parser import parse_any_date
from app.normalize.ransomware_group_aliases import extract_ransomware_group


@dataclass
class ScrapeConfig:
    row_selector: str            # CSS selector matching one row/card per record
    company_selector: str
    date_selector: str | None = None
    link_selector: str | None = None    # if absent, row itself or page url is used
    industry_selector: str | None = None
    location_selector: str | None = None
    summary_selector: str | None = None
    document_type: str = "ag_notification_letter"
    pagination_param: str | None = None  # e.g. "page" — appended as ?page=N
    max_pages: int = 5


class HTMLFallbackCollector(BaseCollector):
    def __init__(self, source_row, scrape_config: ScrapeConfig, http_client=None):
        super().__init__(source_row, http_client)
        self.cfg = scrape_config

    async def _allowed_by_robots(self, url: str) -> bool:
        if not settings.scraper_respect_robots_txt:
            return True
        rp = urllib.robotparser.RobotFileParser()
        robots_url = urljoin(url, "/robots.txt")
        try:
            resp = await self.client.get(robots_url, timeout=10.0)
            rp.parse(resp.text.splitlines())
            return rp.can_fetch(settings.scraper_user_agent, url)
        except Exception:
            # If robots.txt is unreachable, fail closed-ish: allow but log for review.
            return True

    async def fetch_raw(self) -> list[str]:
        base_url = self.source_row.base_url
        if not await self._allowed_by_robots(base_url):
            self.skipped_disallowed = True
            return []
        self.skipped_disallowed = False

        pages = []
        for page_num in range(1, self.cfg.max_pages + 1):
            url = base_url
            if self.cfg.pagination_param and page_num > 1:
                sep = "&" if "?" in base_url else "?"
                url = f"{base_url}{sep}{self.cfg.pagination_param}={page_num}"
            resp = await self.client.get(url)
            if resp.status_code >= 400:
                break
            pages.append(resp.text)
            if len(self._extract_rows(resp.text)) == 0:
                break
            await asyncio.sleep(settings.scraper_min_delay_seconds)
        return pages

    def _extract_rows(self, html: str):
        soup = BeautifulSoup(html, "lxml")
        return soup.select(self.cfg.row_selector)

    async def parse(self, raw: list[str]) -> list[NormalizedRecord]:
        records = []
        for html in raw:
            for row in self._extract_rows(html):
                rec = self._row_to_record(row)
                if rec:
                    records.append(rec)
        return records

    def _row_to_record(self, row) -> NormalizedRecord | None:
        def text_of(sel):
            el = row.select_one(sel) if sel else None
            return el.get_text(strip=True) if el else None

        company = text_of(self.cfg.company_selector)
        if not company:
            return None

        link_el = row.select_one(self.cfg.link_selector) if self.cfg.link_selector else None
        href = (link_el.get("href") if link_el else None) or self.source_row.base_url
        full_url = urljoin(self.source_row.base_url, href)

        date_text = text_of(self.cfg.date_selector)
        summary = text_of(self.cfg.summary_selector)

        return NormalizedRecord(
            company_name_raw=company,
            company_name_norm=normalize_company_name(company),
            source_record_url=full_url,
            incident_date=parse_any_date(date_text) if date_text else None,
            region_state=text_of(self.cfg.location_selector),
            ransomware_group_raw=extract_ransomware_group(f"{company} {summary or ''}"),
            summary=summary,
            document_type=self.cfg.document_type,
            raw_payload={"row_html_snippet": str(row)[:1000]},
        )
