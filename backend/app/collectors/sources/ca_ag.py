"""
California OAG publishes every SB24 breach notification as one big static
HTML table at /privacy/databreach/list (no CSV/JSON export). Verified live
via .github/workflows/probe.yml: a Drupal "views-table" whose data rows are

  <tr class="odd|even ...">
    <td class="views-field-field-sb24-org-name"><a href="…/reports/sb24-NNN">Org</a></td>
    <td class="views-field-field-sb24-breach-date"><span …>MM/DD/YYYY</span>[, …]</td>
    <td class="views-field-created">MM/DD/YYYY</td>  (date reported to the AG)
  </tr>

The whole catalogue (~5k rows) renders on a single page, so there is no
pagination; we cap to the most recent rows (the table is sorted newest-first)
to keep the first correlation pass from becoming an HIBP-scale storm.
"""
from app.collectors.html_fallback_collector import HTMLFallbackCollector, ScrapeConfig

CA_OAG_CONFIG = ScrapeConfig(
    # Data rows live in <tbody>; the <thead> header row is excluded, and any
    # stray header still yields no org cell and is skipped.
    row_selector="table.views-table tbody tr",
    company_selector="td.views-field-field-sb24-org-name",
    date_selector="td.views-field-field-sb24-breach-date",
    link_selector="td.views-field-field-sb24-org-name a",
    document_type="ag_notification_letter",
    max_rows=800,
)


class CaliforniaOAGCollector(HTMLFallbackCollector):
    slug = "california_oag"
    category = "state_ag_notification"

    def __init__(self, source_row, http_client=None):
        super().__init__(source_row, CA_OAG_CONFIG, http_client)
