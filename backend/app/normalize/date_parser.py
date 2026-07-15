"""
Date normalization. Sources report dates in wildly inconsistent formats and
sometimes only mention a date inline in prose ("...discovered on March 3,
2026..."). This module centralizes every date-parsing heuristic so the rest
of the codebase only ever sees a clean `date` object.
"""
import re
from datetime import date

from dateutil import parser as dateutil_parser

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
        return dateutil_parser.parse(candidate, fuzzy=True).date()
    except (ValueError, OverflowError):
        return None


def days_between(a: date | None, b: date | None) -> int | None:
    if a is None or b is None:
        return None
    return abs((a - b).days)
