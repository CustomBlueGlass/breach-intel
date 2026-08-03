"""
RansomLook (https://www.ransomlook.io) publishes a keyless JSON API of recent
ransomware leak-site victims — an independent second tracker alongside
ransomware.live, so a victim seen on both corroborates to two sources instead
of one. Endpoint verified live via .github/workflows/probe.yml: GET /api/recent
returns a JSON list of
  {post_title, discovered, description, link, magnet, screen, misp_uuid, group_name}.
"""
from app.collectors.base import NormalizedRecord
from app.collectors.json_api_collector import JSONAPICollector
from app.normalize.company_name import normalize_company_name
from app.normalize.date_parser import parse_any_date
from app.normalize.ransomware_group_aliases import normalize_ransomware_group


class RansomLookCollector(JSONAPICollector):
    slug = "ransomlook"
    category = "ransomware_leak_tracker"
    default_document_type = "leak_site_post"

    SITE = "https://www.ransomlook.io"

    def endpoint(self) -> str:
        return self.source_row.feed_url or f"{self.SITE}/api/recent"

    def map_item(self, item: dict) -> NormalizedRecord | None:
        company = item.get("post_title")
        if not company:
            return None
        link = item.get("link")
        url = (
            f"{self.SITE}{link}" if isinstance(link, str) and link.startswith("/")
            else (link or self.source_row.base_url)
        )
        # Drop the screenshot path: 'screen' is relative to RansomLook's own host,
        # but the dossier's screenshot handling assumes ransomware.live's CDN, so a
        # raw 'screen' here would render a broken cross-host image. The post link +
        # description are the evidence we keep.
        payload = {k: v for k, v in item.items() if k not in ("screen", "screenshot")}
        return NormalizedRecord(
            company_name_raw=company,
            company_name_norm=normalize_company_name(company),
            source_record_url=url,
            incident_date=parse_any_date(item.get("discovered")),
            ransomware_group_raw=item.get("group_name"),
            ransomware_group_norm=normalize_ransomware_group(item.get("group_name")),
            summary=item.get("description"),
            document_type="leak_site_post",
            external_id=str(item.get("misp_uuid") or item.get("post_title")),
            raw_payload=payload,
        )
