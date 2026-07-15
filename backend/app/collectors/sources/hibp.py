"""
HIBP's /api/v3/breaches endpoint returns metadata for every breach in its
database (name, domain, breach date, data classes exposed, record count) —
it does NOT return individual credentials. That makes it the one
"breach lookup service" in this list that's safe to poll on a schedule and
store directly, matching the spec's "ransomware groups" / "data types
exposed" normalization requirement without touching any actual PII.
"""
from app.collectors.base import NormalizedRecord
from app.collectors.json_api_collector import JSONAPICollector
from app.config import settings
from app.normalize.company_name import normalize_company_name
from app.normalize.date_parser import parse_any_date


class HIBPCollector(JSONAPICollector):
    slug = "haveibeenpwned"
    category = "breach_lookup_service"
    default_document_type = "lookup_summary"

    def endpoint(self) -> str:
        return self.source_row.feed_url

    def auth_headers(self) -> dict[str, str]:
        # HIBP requires a key even for the breaches-list endpoint as of
        # their current API terms; the collector simply no-ops if unset.
        if not settings.hibp_api_key:
            return {}
        return {"hibp-api-key": settings.hibp_api_key}

    async def fetch_raw(self):
        if not settings.hibp_api_key:
            return []  # collector disables itself gracefully without a key
        return await super().fetch_raw()

    def map_item(self, item: dict) -> NormalizedRecord | None:
        name = item.get("Title") or item.get("Name")
        if not name:
            return None
        return NormalizedRecord(
            company_name_raw=name,
            company_name_norm=normalize_company_name(name),
            source_record_url=f"https://haveibeenpwned.com/PwnedWebsites#{item.get('Name')}",
            incident_date=parse_any_date(item.get("BreachDate")),
            records_affected_est=item.get("PwnCount"),
            data_types_exposed=item.get("DataClasses", []),
            summary=None,  # HIBP's Description field contains HTML marketing copy; intentionally dropped
            document_type="lookup_summary",
            external_id=item.get("Name"),
            raw_payload={"Name": item.get("Name"), "Domain": item.get("Domain")},
        )
