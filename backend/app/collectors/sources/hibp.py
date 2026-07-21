"""
HIBP's /api/v3/breaches endpoint returns metadata for every breach in its
database (name, domain, breach date, data classes exposed, record count) —
it does NOT return individual credentials, and (verified against the live
endpoint) it requires NO API key: only the per-account lookup endpoints do.
That makes it a free, scheduled bulk source of ~800 confirmed breaches with
record counts and exposed-data classes.
"""
from __future__ import annotations

from datetime import datetime

from app.collectors.base import NormalizedRecord
from app.collectors.json_api_collector import JSONAPICollector
from app.config import settings
from app.normalize.company_name import normalize_company_name
from app.normalize.date_parser import parse_any_date

# Entries that aren't a specific company's breach incident: credential-stuffing
# compilations, spam lists, malware/stealer logs, and fabricated sets would
# pollute the company ledger.
_SKIP_FLAGS = ("IsFabricated", "IsSpamList", "IsMalware", "IsStealerLog", "IsRetired")


class HIBPCollector(JSONAPICollector):
    slug = "haveibeenpwned"
    category = "breach_lookup_service"
    default_document_type = "lookup_summary"

    def endpoint(self) -> str:
        return self.source_row.feed_url

    def auth_headers(self) -> dict[str, str]:
        # Optional: a key raises rate limits but is not required for /breaches.
        if not settings.hibp_api_key:
            return {}
        return {"hibp-api-key": settings.hibp_api_key}

    def map_item(self, item: dict) -> NormalizedRecord | None:
        if any(item.get(flag) for flag in _SKIP_FLAGS):
            return None
        name = item.get("Title") or item.get("Name")
        if not name:
            return None

        added = item.get("AddedDate")
        data_classes = [
            str(c).strip().lower().replace(" ", "_") for c in item.get("DataClasses", [])
        ]

        return NormalizedRecord(
            company_name_raw=name,
            company_name_norm=normalize_company_name(name),
            source_record_url=f"https://haveibeenpwned.com/PwnedWebsites#{item.get('Name')}",
            incident_date=parse_any_date(item.get("BreachDate")),
            source_published_at=None if not added else datetime.fromisoformat(str(added).replace("Z", "+00:00")).replace(tzinfo=None),
            records_affected_est=item.get("PwnCount"),
            data_types_exposed=data_classes,
            summary=None,  # HIBP's Description field contains HTML marketing copy; intentionally dropped
            document_type="lookup_summary",
            external_id=item.get("Name"),
            raw_payload={
                "Name": item.get("Name"),
                "Domain": item.get("Domain"),
                "IsVerified": item.get("IsVerified"),
                "Attribution": item.get("Attribution"),
                "DisclosureUrl": item.get("DisclosureUrl"),
            },
        )
