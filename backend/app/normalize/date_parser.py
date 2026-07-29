"""
Date normalization. Sources report dates in wildly inconsistent formats and
sometimes only mention a date inline in prose ("...discovered on March 3,
2026..."). This module centralizes every date-parsing heuristic so the rest
of the codebase only ever sees a clean `date` object.
"""
import re
from datetime import date, timedelta

from dateutil import parser as dateutil_parser

# A breach cannot be disclosed or have occurred in the future, and this ledger
# does not track incidents before online breach reporting existed. dateutil's
# fuzzy=True mode will happily assemble a date from a stray number in prose
# (a case number, a ZIP+4, a report id), producing impossible values like
# 2027-11-20 that then sort to the top of the ledger. Discard anything outside
# this window rather than poison the data. The small future grace absorbs
# timezone edges around "today".
_MIN_PLAUSIBLE_YEAR = 2000
_FUTURE_GRACE_DAYS = 2

_INLINE_DATE_RE = re.compile(
    r"(January|February|March|April|May|June|July|August|September|"
    r"October|November|December)\s+\d{1,2},?\s+\d{4}"
    r"|\d{4}-\d{2}-\d{2}"
    r"|\d{1,2}/\d{1,2}/\d{2,4}",
    re.IGNORECASE,
)


def parse_any_date(text: str | None) -> date | None:
    if not text:
        return None
    match = _INLINE_DATE_RE.search(text)
    candidate = match.group(0) if match else text
    try:
        parsed = dateutil_parser.parse(candidate, fuzzy=True).date()
    except (ValueError, OverflowError):
        return None
    if parsed.year < _MIN_PLAUSIBLE_YEAR or parsed > date.today() + timedelta(days=_FUTURE_GRACE_DAYS):
        return None
    return parsed


def days_between(a: date | None, b: date | None) -> int | None:
    if a is None or b is None:
        return None
    return abs((a - b).days)
