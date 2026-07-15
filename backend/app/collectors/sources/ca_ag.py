"""
California OAG publishes its breach list as a sortable HTML table with no
CSV/API export discovered — this is a worked example of the HTML-fallback
path. The selectors below are illustrative; inspect the live table markup
before deploying, since a site redesign will silently break a CSS-selector
scraper (the collector log will show records_fetched=0 when that happens —
alert on that, don't just retry blindly).
"""
from app.collectors.html_fallback_collector import HTMLFallbackCollector, ScrapeConfig

CA_OAG_CONFIG = ScrapeConfig(
    row_selector="table.breach-list tbody tr",
    company_selector="td.organization-name",
    date_selector="td.date-reported",
    link_selector="td.organization-name a",
    summary_selector="td.breach-description",
    document_type="ag_notification_letter",
    pagination_param="page",
    max_pages=10,
)


class CaliforniaOAGCollector(HTMLFallbackCollector):
    slug = "california_oag"
    category = "state_ag_notification"

    def __init__(self, source_row, http_client=None):
        super().__init__(source_row, CA_OAG_CONFIG, http_client)
