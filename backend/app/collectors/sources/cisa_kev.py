"""
CISA's KEV catalog is an official JSON feed of actively-exploited
vulnerabilities. It isn't a breach record on its own, but cross-referencing
which CVEs ransomware groups exploited around a victim's disclosure date is
useful enrichment for analysts reading a breach's dossier — included here
as a `government_advisory` source rather than a `breaches` row generator.
"""
from app.collectors.base import NormalizedRecord
from app.collectors.json_api_collector import JSONAPICollector
from app.normalize.date_parser import parse_any_date


class CISAKEVCollector(JSONAPICollector):
    slug = "cisa_kev"
    category = "government_advisory"
    default_document_type = "advisory"

    def endpoint(self) -> str:
        return self.source_row.feed_url

    def items_from_response(self, payload):
        return payload.get("vulnerabilities", [])

    def map_item(self, item: dict) -> NormalizedRecord | None:
        cve = item.get("cveID")
        if not cve:
            return None
        # KEV entries describe vulnerabilities, not specific victim companies;
        # we still emit a record so it's searchable/linkable from breach
        # dossiers where the ransomware group is known to exploit this CVE.
        return NormalizedRecord(
            company_name_raw=f"[CVE advisory] {cve}",
            source_record_url=f"https://nvd.nist.gov/vuln/detail/{cve}",
            incident_date=parse_any_date(item.get("dateAdded")),
            summary=item.get("shortDescription"),
            document_type="advisory",
            external_id=cve,
            raw_payload=item,
        )
