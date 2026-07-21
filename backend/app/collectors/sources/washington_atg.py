"""
Washington AG breach notifications via the state's official Socrata open-data
API (dataset sb4j-ca4h, "Data Breach Notifications Affecting Washington
Residents") — no key required, updated daily. Field names verified against
the live catalog via the probe workflow:

    name, datestart (incident), datesubmitted (notice to the AG =
    public disclosure), washingtoniansaffected, industrytype, entitystate,
    databreachcause (Cyberattack / Unauthorized access / ...),
    cyberattacktype (Malware, Ransomware, Phishing, Skimmers, ...), id
"""
from __future__ import annotations

from datetime import datetime, time

from app.collectors.base import NormalizedRecord
from app.collectors.json_api_collector import JSONAPICollector
from app.normalize.company_name import normalize_company_name
from app.normalize.date_parser import parse_any_date
from app.normalize.location_normalize import normalize_location

INDUSTRY_MAP = {
    "Education": "education",
    "Finance": "financial_services",
    "Government": "government",
    "Health": "healthcare",
    "Nonprofit or Charity": "nonprofit",
}


class WashingtonAGCollector(JSONAPICollector):
    slug = "washington_atg"
    category = "state_ag_notification"
    default_document_type = "ag_notification_letter"

    def endpoint(self) -> str:
        return self.source_row.feed_url

    def request_params(self):
        # Most recent notices first; 500 per run is far more than a 6-hour
        # window ever produces, and dedup drops the overlap.
        return {"$limit": 500, "$order": "datesubmitted DESC"}

    def map_item(self, item: dict) -> NormalizedRecord | None:
        name = (item.get("name") or "").strip()
        if not name:
            return None

        affected = item.get("washingtoniansaffected")
        try:
            records = int(float(affected)) if affected is not None else None
        except (TypeError, ValueError):
            records = None

        submitted = parse_any_date(item.get("datesubmitted"))
        cause = item.get("databreachcause")
        attack_type = item.get("cyberattacktype")
        summary_bits = [b for b in (cause, attack_type) if b and b.lower() != "unknown"]
        summary = (
            f"Reported to the Washington AG ({' — '.join(summary_bits)})"
            if summary_bits else "Reported to the Washington AG"
        )

        country, region = normalize_location(item.get("entitystate"))

        return NormalizedRecord(
            company_name_raw=name,
            company_name_norm=normalize_company_name(name),
            source_record_url="https://www.atg.wa.gov/data-breach-notifications",
            incident_date=parse_any_date(item.get("datestart")) or submitted,
            source_published_at=datetime.combine(submitted, time()) if submitted else None,
            industry=INDUSTRY_MAP.get(item.get("industrytype")),
            country=country or "US",
            region_state=region,
            records_affected_est=records,
            summary=summary,
            document_type="ag_notification_letter",
            external_id=str(item.get("id") or name),
            raw_payload={k: item.get(k) for k in (
                "id", "industrytype", "databreachcause", "cyberattacktype",
                "datestart", "dateend", "datesubmitted", "washingtoniansaffected",
            )},
        )
