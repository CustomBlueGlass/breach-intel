"""
The HHS OCR breach portal ("Wall of Shame") exposes a CSV export of
HIPAA-covered breaches affecting 500+ individuals. Column names below
match the portal's current export; re-verify after any portal redesign.
"""
from app.collectors.base import NormalizedRecord
from app.collectors.csv_collector import TabularCollector
from app.normalize.company_name import normalize_company_name
from app.normalize.date_parser import parse_any_date
from app.normalize.location_normalize import normalize_location


class HHSOCRCollector(TabularCollector):
    slug = "hhs_ocr_breach_portal"
    category = "federal_regulatory"
    default_document_type = "hhs_breach_report"
    file_kind = "csv"

    def map_row(self, row: dict) -> NormalizedRecord | None:
        name = row.get("Name of Covered Entity") or row.get("Covered Entity")
        if not name:
            return None
        country, region = normalize_location(row.get("State"))
        records = row.get("Individuals Affected") or row.get("Total Individuals Affected")
        return NormalizedRecord(
            company_name_raw=name,
            company_name_norm=normalize_company_name(name),
            source_record_url="https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf",
            incident_date=parse_any_date(row.get("Breach Submission Date")),
            country=country or "US",
            region_state=region,
            records_affected_est=int(records) if str(records).strip().isdigit() else None,
            data_types_exposed=["protected_health_information"],
            summary=row.get("Type of Breach"),
            document_type="hhs_breach_report",
            external_id=name + str(row.get("Breach Submission Date", "")),
            raw_payload=row,
        )
