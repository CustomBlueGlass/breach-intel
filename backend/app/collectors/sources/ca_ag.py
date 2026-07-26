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
rather than push the entire catalogue through candidate correlation in one run.

The first pass (cap 800) is already ingested, and those rows now dedup in
seconds on their content_fingerprint, so only rows newly exposed by a raised
cap incur correlation cost. We walk the cap up over successive runs to backfill
older California breaches a bounded chunk at a time; going straight to ~5k would
exceed the ingest job's CI timeout (see .github/workflows/ingest.yml).
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
    max_rows=2000,
)


class CaliforniaOAGCollector(HTMLFallbackCollector):
    slug = "california_oag"
    category = "state_ag_notification"

    def __init__(self, source_row, http_client=None):
        super().__init__(source_row, CA_OAG_CONFIG, http_client)
