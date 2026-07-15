"""
Registry wiring every row in breach_data_sources to a concrete collector.

Plain RSS sources need no custom code at all — RSSCollector(source_row) is
enough. JSON/CSV/HTML sources with source-specific field names get a small
dedicated module under collectors/sources/. Sources marked
`collection_mode='on_demand_lookup'` (DeHashed, Intelx) are excluded from
the scheduled registry entirely — see sources/dehashed_intelx.py.

This reference implementation fully wires the sources that exercise each
feed-type path end-to-end (RSS, JSON API, CSV, HTML fallback) plus the
two on-demand lookup services. The remaining state-AG / nonprofit-tracker
sources reuse HTMLFallbackCollector with a placeholder ScrapeConfig —
update `row_selector` etc. for each (see ca_ag.py for the pattern) before
enabling them in production; the collector log will report
records_fetched=0 until selectors are filled in, rather than silently
inserting garbage.
"""
from app.collectors.html_fallback_collector import HTMLFallbackCollector, ScrapeConfig
from app.collectors.rss_collector import RSSCollector
from app.collectors.sources.ca_ag import CaliforniaOAGCollector
from app.collectors.sources.cisa_kev import CISAKEVCollector
from app.collectors.sources.hhs_ocr import HHSOCRCollector
from app.collectors.sources.hibp import HIBPCollector
from app.collectors.sources.ransomware_live import RansomwareLiveCollector

RSS_SLUGS = {
    "hackmanac", "hipaa_journal", "databreaches_net", "bleepingcomputer",
    "thedfirreport", "securityweek", "therecord_media", "cyberscoop",
    "darkreading", "cisa_advisories", "ncsc_uk",
}

EXPLICIT_COLLECTORS = {
    "ransomware_live": RansomwareLiveCollector,
    "cisa_kev": CISAKEVCollector,
    "hhs_ocr_breach_portal": HHSOCRCollector,
    "haveibeenpwned": HIBPCollector,
    "california_oag": CaliforniaOAGCollector,
}

# Sources awaiting a hand-tuned ScrapeConfig (see module docstring). Each
# uses a generic placeholder selector set that MUST be reviewed against the
# live page before `enabled` is flipped to TRUE in breach_data_sources.
PLACEHOLDER_HTML_SLUGS = {
    "ransom_db", "maine_ag", "mass_ag_breaches", "vermont_ag", "oregon_doj",
    "indiana_ag", "montana_doj", "delaware_ag", "north_dakota_ag",
    "idtheftcenter", "privacyrights_breaches", "enforcementtracker",
    "ic3", "ico_enforcement", "edpb", "sec_cyber_disclosures",
}

ON_DEMAND_ONLY_SLUGS = {"dehashed", "intelx"}  # never scheduled — see sources/dehashed_intelx.py

GENERIC_PLACEHOLDER_CONFIG = ScrapeConfig(
    row_selector="table tr, .breach-row, article",
    company_selector="td:first-child, .org-name, h2 a",
    date_selector="td.date, time, .published",
    summary_selector="td.description, p",
)


def build_collector(source_row, http_client=None):
    slug = source_row.slug

    if slug in ON_DEMAND_ONLY_SLUGS:
        return None  # handled via enrich_company(), not the scheduler

    if slug in EXPLICIT_COLLECTORS:
        return EXPLICIT_COLLECTORS[slug](source_row, http_client)

    if source_row.feed_type == "rss" or slug in RSS_SLUGS:
        return RSSCollector(source_row, http_client)

    if slug in PLACEHOLDER_HTML_SLUGS or source_row.feed_type == "html_scrape":
        return HTMLFallbackCollector(source_row, GENERIC_PLACEHOLDER_CONFIG, http_client)

    raise ValueError(f"No collector wired for source '{slug}' (feed_type={source_row.feed_type})")
