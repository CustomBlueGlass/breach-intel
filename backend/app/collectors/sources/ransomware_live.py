"""
Ransomware.live exposes a public JSON API of recent ransomware victims —
no scraping needed. https://api.ransomware.live/v2/recentvictims
"""
from app.collectors.base import NormalizedRecord
from app.collectors.json_api_collector import JSONAPICollector
from app.normalize.company_name import normalize_company_name
from app.normalize.date_parser import parse_any_date
from app.normalize.ransomware_group_aliases import normalize_ransomware_group


class RansomwareLiveCollector(JSONAPICollector):
    slug = "ransomware_live"
    category = "ransomware_leak_tracker"
    default_document_type = "leak_site_post"

    def endpoint(self) -> str:
        return self.source_row.feed_url

    def map_item(self, item: dict) -> NormalizedRecord | None:
        company = item.get("post_title") or item.get("victim")
        if not company:
            return None
        return NormalizedRecord(
            company_name_raw=company,
            company_name_norm=normalize_company_name(company),
            source_record_url=item.get("post_url") or self.source_row.base_url,
            incident_date=parse_any_date(item.get("discovered") or item.get("published")),
            ransomware_group_raw=item.get("group_name"),
            ransomware_group_norm=normalize_ransomware_group(item.get("group_name")),
            country=item.get("country"),
            summary=item.get("description"),
            document_type="leak_site_post",
            external_id=str(item.get("id") or item.get("post_title")),
            raw_payload=item,
        )
