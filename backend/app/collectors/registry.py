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
sources need a hand-tuned ScrapeConfig (see ca_ag.py for the pattern)
before they can run — until then they are skipped entirely rather than
scraped with generic selectors, which used to insert headline/nav-text
garbage into the ledger as if it were real AG notification data.
"""
import logging

from app.collectors.rss_collector import RSSCollector
from app.collectors.sources.ca_ag import CaliforniaOAGCollector
from app.collectors.sources.cisa_kev import CISAKEVCollector
from app.collectors.sources.hhs_ocr import HHSOCRCollector
from app.collectors.sources.hibp import HIBPCollector
from app.collectors.sources.oregon_doj import OregonDOJCollector
from app.collectors.sources.ransomware_live import RansomwareLiveCollector
from app.collectors.sources.sec_edgar import SECEdgarCollector
from app.collectors.sources.washington_atg import WashingtonAGCollector

logger = logging.getLogger("breach_intel.scheduler")

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
    "sec_edgar_search": SECEdgarCollector,
    "washington_atg": WashingtonAGCollector,
    "oregon_doj": OregonDOJCollector,
}

# Sources awaiting a hand-tuned ScrapeConfig (see module docstring). Each is
# skipped until real selectors are written for it — running them with a
# generic placeholder config scrapes navigation/headline text and pollutes
# the ledger. db/seed_sources.sql now ships them with enabled=FALSE too.
PLACEHOLDER_HTML_SLUGS = {
    "ransom_db", "maine_ag", "mass_ag_breaches", "vermont_ag",
    "indiana_ag", "montana_doj", "delaware_ag", "north_dakota_ag",
    "idtheftcenter", "privacyrights_breaches", "enforcementtracker",
    "ic3", "ico_enforcement", "edpb", "sec_cyber_disclosures",
}

ON_DEMAND_ONLY_SLUGS = {"dehashed", "intelx"}  # never scheduled — see sources/dehashed_intelx.py

# Sources that have a csv/json_api feed_type in the seed but don't yet have
# a dedicated collector implemented. Logged as skipped rather than crashing.
NOT_YET_IMPLEMENTED_SLUGS = {
    "mass_ag_reports", "leakix_ransomware", "privacyrights_chronology",
}


def collector_available(source_row) -> bool:
    """
    Decide (and log) whether a scheduled collector exists for this source,
    WITHOUT instantiating anything — instantiation opens an HTTP client, so
    the scheduler calls this first and only builds collectors it will run.
    """
    slug = source_row.slug

    if slug in ON_DEMAND_ONLY_SLUGS:
        return False  # handled via enrich_company(), not the scheduler

    if slug in NOT_YET_IMPLEMENTED_SLUGS:
        logger.info(
            "Collector for '%s' (feed_type=%s) not yet implemented — skipping",
            slug, source_row.feed_type,
        )
        return False

    if slug in EXPLICIT_COLLECTORS:
        return True

    if source_row.feed_type == "rss" or slug in RSS_SLUGS:
        return True

    if slug in PLACEHOLDER_HTML_SLUGS or source_row.feed_type == "html_scrape":
        logger.info(
            "HTML source '%s' has no tuned ScrapeConfig yet — skipping "
            "(write selectors like collectors/sources/ca_ag.py to enable it)",
            slug,
        )
        return False

    logger.warning(
        "No collector wired for source '%s' (feed_type=%s) — skipping",
        slug, source_row.feed_type,
    )
    return False


def build_collector(source_row, http_client=None):
    """Instantiate the collector for a source collector_available() said yes to."""
    slug = source_row.slug

    if slug in EXPLICIT_COLLECTORS:
        return EXPLICIT_COLLECTORS[slug](source_row, http_client)

    if source_row.feed_type == "rss" or slug in RSS_SLUGS:
        return RSSCollector(source_row, http_client)

    return None
