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

    IMAGE_HOST = "https://images.ransomware.live"

    def _screenshot_url(self, item: dict) -> str | None:
        # The API exposes a leak-site post capture as either a full URL
        # ("screenshot") or a path relative to the image host ("screen",
        # e.g. "screenshots/safepay/acme.png"). Normalize to an absolute URL.
        shot = item.get("screenshot") or item.get("screen")
        if not shot:
            return None
        if shot.startswith("http"):
            return shot
        return f"{self.IMAGE_HOST}/{shot.lstrip('/')}"

    def map_item(self, item: dict) -> NormalizedRecord | None:
        company = item.get("post_title") or item.get("victim")
        if not company:
            return None
        # Keep the raw item plus a normalized absolute screenshot URL so the
        # dossier can show the leak-site post as evidence (hotlinked from
        # ransomware.live's CDN, never re-hosted).
        payload = dict(item)
        shot = self._screenshot_url(item)
        if shot:
            payload["screenshot"] = shot
        return NormalizedRecord(
            company_name_raw=company,
            company_name_norm=normalize_company_name(company),
            source_record_url=item.get("post_url") or (
                f"https://www.ransomware.live{item['link']}" if item.get("link", "").startswith("/")
                else item.get("url") or self.source_row.base_url
            ),
            incident_date=parse_any_date(item.get("discovered") or item.get("published")),
            ransomware_group_raw=item.get("group_name") or item.get("group"),
            ransomware_group_norm=normalize_ransomware_group(item.get("group_name") or item.get("group")),
            country=item.get("country"),
            summary=item.get("description"),
            document_type="leak_site_post",
            external_id=str(item.get("id") or item.get("post_title") or item.get("victim")),
            raw_payload=payload,
        )
