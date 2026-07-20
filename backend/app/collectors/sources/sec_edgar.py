"""
SEC EDGAR full-text search — 8-K filings disclosing material cybersecurity
incidents (Item 1.05, mandatory since Dec 2023). The documented JSON API at
efts.sec.gov needs no key; payload shape verified against the live endpoint
(see .github/workflows/probe.yml):

    hits.hits[]._source = {
        "display_names": ["LEE ENTERPRISES, Inc  (LEE)  (CIK 0000058361)"],
        "ciks": ["0000058361"],
        "adsh": "0001628280-25-005855",
        "file_date": "2025-02-18",        # filing (public disclosure) date
        "period_ending": "2025-02-12",    # date of report (incident event)
        "biz_locations": ["Davenport, IA"],
        "items": ["1.05", ...],           # 1.05 = Material Cybersecurity Incidents
    }
    hits.hits[]._id = "<adsh>:<primary document filename>"
"""
from __future__ import annotations

import re
from datetime import date, datetime, time, timedelta

from app.collectors.base import NormalizedRecord
from app.collectors.json_api_collector import JSONAPICollector
from app.normalize.company_name import normalize_company_name
from app.normalize.date_parser import parse_any_date
from app.normalize.location_normalize import normalize_location

# "LEE ENTERPRISES, Inc  (LEE)  (CIK 0000058361)" -> "LEE ENTERPRISES, Inc"
_DISPLAY_NAME_RE = re.compile(r"\s*\((?:[A-Z0-9.,-]{1,10})\)\s*\(CIK \d+\)\s*$")

LOOKBACK_DAYS = 90  # full-text search ranks by relevance; a date window keeps results recent


class SECEdgarCollector(JSONAPICollector):
    slug = "sec_edgar_search"
    category = "sec_filing"
    default_document_type = "sec_filing"

    def endpoint(self) -> str:
        return self.source_row.feed_url

    def request_params(self):
        today = date.today()
        return {
            "startdt": (today - timedelta(days=LOOKBACK_DAYS)).isoformat(),
            "enddt": today.isoformat(),
        }

    def items_from_response(self, payload):
        return (payload.get("hits") or {}).get("hits") or []

    def map_item(self, item: dict) -> NormalizedRecord | None:
        src = item.get("_source") or {}
        # Only Item 1.05 filings are confirmed material-cybersecurity-incident
        # disclosures; the phrase query alone also matches filings that merely
        # cite the rule.
        if "1.05" not in (src.get("items") or []):
            return None

        display = (src.get("display_names") or [None])[0]
        if not display:
            return None
        company = _DISPLAY_NAME_RE.sub("", display).strip()

        adsh = src.get("adsh") or ""
        doc_id = item.get("_id") or ""
        filename = doc_id.split(":", 1)[1] if ":" in doc_id else ""
        cik = (src.get("ciks") or [""])[0].lstrip("0") or "0"
        url = (
            f"https://www.sec.gov/Archives/edgar/data/{cik}/{adsh.replace('-', '')}/{filename}"
            if adsh and filename
            else f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={cik}"
        )

        location = (src.get("biz_locations") or [None])[0]
        country, region = normalize_location(location.split(",")[-1].strip() if location else None)

        file_date = parse_any_date(src.get("file_date"))
        incident = parse_any_date(src.get("period_ending")) or file_date

        return NormalizedRecord(
            company_name_raw=company,
            company_name_norm=normalize_company_name(company),
            source_record_url=url,
            incident_date=incident,
            source_published_at=datetime.combine(file_date, time()) if file_date else None,
            country=country or "US",
            region_state=region,
            summary=f"8-K Item 1.05 (Material Cybersecurity Incident) filed {src.get('file_date')}",
            document_type="sec_filing",
            external_id=adsh,
            raw_payload={"adsh": adsh, "items": src.get("items"), "display_name": display},
        )
