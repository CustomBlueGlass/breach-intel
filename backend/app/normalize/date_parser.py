"""
Date normalization. Sources report dates in wildly inconsistent formats and
sometimes only mention a date inline in prose ("...discovered on March 3,
2026..."). This module centralizes every date-parsing heuristic so the rest
of the codebase only ever sees a clean `date` object.
"""
import re
from datetime import date, timedelta

from dateutil import parser as dateutil_parser

_INLINE_DATE_RE = re.compile(
    r"(January|February|March|April|May|June|July|August|September|"
    r"October|November|December)\s+\d{1,2},?\s+\d{4}"
    r"|\d{4}-\d{2}-\d{2}"
    r"|\d{1,2}/\d{1,2}/\d{2,4}",
    re.IGNORECASE,
)


def parse_any_date(text: str | None) -> date | None:
    """Parse a date from a source string as faithfully as possible. Sources
    occasionally publish an impossible date (a typo — e.g. a CA OAG notice that
    lists 2027 as the breach year). We record what the source said here; the
    maintenance pass (flag_implausible_dates) is what blanks such a value to
    UNKNOWN on the breach and tags it for manual review, so a bad date is
    surfaced for correction rather than silently altered at parse time."""
    if not text:
        return None
    match = _INLINE_DATE_RE.search(text)
    candidate = match.group(0) if match else text
    try:
        return dateutil_parser.parse(candidate, fuzzy=True).date()
    except (ValueError, OverflowError):
        return None


# A breach cannot have occurred or been disclosed in the future, and this ledger
# does not track incidents before online breach reporting existed. A date
# outside this window is a source typo. Kept in one place so the Python side and
# the maintenance SQL agree on what "implausible" means.
MIN_PLAUSIBLE_YEAR = 2000
FUTURE_GRACE_DAYS = 2


def is_plausible_date(d: date | None) -> bool:
    """False for a missing, future, or pre-2000 date (i.e. a source typo)."""
    if d is None:
        return False
    return d.year >= MIN_PLAUSIBLE_YEAR and d <= date.today() + timedelta(days=FUTURE_GRACE_DAYS)


def days_between(a: date | None, b: date | None) -> int | None:
    if a is None or b is None:
        return None
    return abs((a - b).days)
