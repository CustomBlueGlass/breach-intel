"""
Oregon DOJ Consumer Protection — data breach notifications at
https://justice.oregon.gov/consumer/DataBreach/. The page is a plain HTML
table (verified via the probe workflow); cells carry no classes, so rows
are parsed positionally:

    td[0] organization name
    td[1] date reported to DOJ (public disclosure)
    td[2] date(s) of breach, possibly a "start - end" range
    td[5] number of Oregonians affected

Reuses HTMLFallbackCollector's robots.txt check and polite fetching; only
the parsing is bespoke.
"""
from __future__ import annotations

import re
from datetime import datetime, time

from bs4 import BeautifulSoup

from app.collectors.html_fallback_collector import HTMLFallbackCollector, ScrapeConfig
from app.collectors.base import NormalizedRecord
from app.normalize.company_name import normalize_company_name
from app.normalize.date_parser import parse_any_date

_DATE_RE = re.compile(r"\d{1,2}/\d{1,2}/\d{4}")

OREGON_CONFIG = ScrapeConfig(
    row_selector="table tr",
    company_selector="td",  # unused — parse() below is bespoke
    document_type="ag_notification_letter",
)


class OregonDOJCollector(HTMLFallbackCollector):
    slug = "oregon_doj"
    category = "state_ag_notification"

    def __init__(self, source_row, http_client=None):
        super().__init__(source_row, OREGON_CONFIG, http_client)

    async def parse(self, raw: list[str]) -> list[NormalizedRecord]:
        records = []
        for html in raw:
            soup = BeautifulSoup(html, "lxml")
            for tr in soup.select("table tr"):
                cells = tr.find_all("td")
                if len(cells) < 6:
                    continue  # header row or layout row
                rec = self._cells_to_record([c.get_text(" ", strip=True) for c in cells])
                if rec:
                    records.append(rec)
        return records

    def _cells_to_record(self, cells: list[str]) -> NormalizedRecord | None:
        name = cells[0].strip()
        if not name or _DATE_RE.fullmatch(name):
            return None

        reported = parse_any_date(cells[1])
        breach_dates = _DATE_RE.findall(cells[2])
        incident = parse_any_date(breach_dates[0]) if breach_dates else reported

        digits = re.sub(r"[^\d]", "", cells[5])
        affected = int(digits) if digits else None

        return NormalizedRecord(
            company_name_raw=name,
            company_name_norm=normalize_company_name(name),
            source_record_url=self.source_row.base_url,
            incident_date=incident,
            source_published_at=datetime.combine(reported, time()) if reported else None,
            country="US",
            region_state="OR",
            records_affected_est=affected,
            summary="Data breach notification filed with the Oregon DOJ",
            document_type="ag_notification_letter",
            external_id=f"{name}|{cells[1]}",
            raw_payload={"cells": cells[:6]},
        )
