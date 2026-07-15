"""
Base collector contract.

Every concrete collector implements `discover()` and `fetch_raw()` and
returns a list of `NormalizedRecord`. The framework (not each collector)
handles fingerprinting, dedup, persistence, and correlation — so collectors
stay simple and only deal with "how do I get records out of this source".

Auto-discovery order, per the spec: CSV, JSON, XLSX, XML, RSS, or API feed
first; HTML scraping only as a fallback when nothing structured exists.
"""
from __future__ import annotations

import abc
import hashlib
import json
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any

import httpx

from app.config import settings

FEED_PROBE_ORDER = ("json_api", "csv", "xlsx", "xml", "rss", "html_scrape")


@dataclass
class NormalizedRecord:
    company_name_raw: str
    source_record_url: str
    company_name_norm: str | None = None
    industry: str | None = None
    country: str | None = None
    region_state: str | None = None
    ransomware_group_raw: str | None = None
    ransomware_group_norm: str | None = None
    incident_date: date | None = None
    source_published_at: datetime | None = None
    records_affected_est: int | None = None
    data_types_exposed: list[str] = field(default_factory=list)
    summary: str | None = None
    document_type: str = "news_article"
    external_id: str | None = None
    raw_payload: dict[str, Any] = field(default_factory=dict)

    def fingerprint(self) -> str:
        """Stable hash used for dedup — independent of fetch time."""
        key = json.dumps(
            {
                "company": self.company_name_norm or self.company_name_raw,
                "date": str(self.incident_date),
                "url": self.source_record_url,
                "group": self.ransomware_group_norm,
            },
            sort_keys=True,
        )
        return hashlib.sha256(key.encode()).hexdigest()


class BaseCollector(abc.ABC):
    """Subclass this for each source."""

    slug: str
    category: str
    default_document_type: str = "news_article"

    def __init__(self, source_row, http_client: httpx.AsyncClient | None = None):
        self.source_row = source_row  # row from breach_data_sources
        self.client = http_client or httpx.AsyncClient(
            timeout=30.0,
            headers={"User-Agent": settings.scraper_user_agent},
            follow_redirects=True,
        )

    @abc.abstractmethod
    async def fetch_raw(self) -> Any:
        """Pull the raw feed/page payload. Implemented per feed_type subclass."""

    @abc.abstractmethod
    async def parse(self, raw: Any) -> list[NormalizedRecord]:
        """Turn the raw payload into NormalizedRecord objects."""

    async def collect(self) -> list[NormalizedRecord]:
        raw = await self.fetch_raw()
        return await self.parse(raw)


async def discover_feed_type(base_url: str, client: httpx.AsyncClient) -> tuple[str, str | None]:
    """
    Best-effort auto-discovery: probe common feed locations/headers and
    return (feed_type, feed_url). Falls back to ('html_scrape', None).
    Run periodically (e.g. weekly) rather than every 6h — sites rarely
    change their feed offerings between collector runs.
    """
    candidates = [
        ("rss", "/feed/"),
        ("rss", "/feed"),
        ("rss", "/rss.xml"),
        ("json_api", "/api/"),
        ("csv", "/export.csv"),
        ("xml", "/sitemap.xml"),
    ]
    for feed_type, suffix in candidates:
        url = base_url.rstrip("/") + suffix
        try:
            resp = await client.head(url, timeout=10.0)
            if resp.status_code < 400:
                return feed_type, url
        except httpx.HTTPError:
            continue
    return "html_scrape", None
