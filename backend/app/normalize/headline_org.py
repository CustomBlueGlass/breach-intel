"""
Guess the victim organisation from a breach headline, with no ML dependency.

Breach headlines fall into a small number of shapes:

  leading-org:   "Acme Corp confirms data breach affecting 2M customers"
                 "Acme Corp hit by ransomware"
                 "Acme Corp data breach exposes patient records"
  anchored-org:  "Data breach at Acme Corp exposes 2M records"
                 "Ransomware attack on Acme Corp"
                 "Hackers steal data from Acme Corp"
                 "Cyberattack hits Acme Corp"
                 "1.2 million records exposed in Acme Corp breach"

This module pulls the organisation span out of those shapes with a small set
of regexes, then trims it back to just the name. It is deliberately rule-based
(only ``re``): the target is a proper noun in a short string, which string
rules handle well and cheaply, and the downstream matcher is strict (a high
token-sort score against a ledger company plus a date window), so an imperfect
guess that is not a real company simply fails to match rather than creating a
false link. The bias here is therefore toward recall.
"""
from __future__ import annotations

import re

# --- anchors -----------------------------------------------------------------

# Verbs / noun phrases that FOLLOW the organisation (org is to the left).
# Deliberately limited to verbs a VICTIM uses about itself ("confirms",
# "discloses", "notifies", "suffered", "hit by"). Reporter-style verbs
# ("warns", "reveals", "says", "investigates", "probes", "finds") are left out
# on purpose: those usually name the security vendor or outlet, not the victim
# ("Google warns of Acme breach"), so anchoring on them would misattribute.
_LEADING_ANCHORS = (
    r"confirms?|confirmed|disclos\w+|suffers?|suffered|reports?|reported|"
    r"notif\w+|admits?|admitted|announces?|announced|experienc\w+|"
    r"hit by|hit with|hit in|targeted by|victim of|"
    r"data breach|breach|ransomware|cyber ?attack|hack|data leak|leak|"
    r"security (?:breach|incident)|cyber incident"
)
_LEADING_ORG_RE = re.compile(
    r"^(?P<org>.{2,60}?)\s+(?:" + _LEADING_ANCHORS + r")\b",
    re.IGNORECASE,
)

# Phrases AFTER which the organisation appears (org is to the right).
_TRAILING_ANCHORS = (
    r"data breach at|breach at|breach affecting|data leak at|leak at|"
    r"attack on|attack against|attack at|ransomware attack on|"
    r"ransomware attack at|cyber ?attack on|cyber ?attack at|"
    r"exposed in|leaked in|stolen in|compromised in|hacked in|impacted in|"
    r"data from|records from|information from|info from|"
    r"stolen from|stole from|breach of|breach hits|"
    r"customers of|patients of|users of|clients of|"
    r"hits|hit|strikes|struck|targeting|targets|"
    r"breached|compromised|infiltrated|hacked|"
    r"leaks|leaked|dumps|dumped|publishes|posts"
)
_TRAILING_ORG_RE = re.compile(
    r"\b(?:" + _TRAILING_ANCHORS + r")\s+(?P<org>.{2,60})$",
    re.IGNORECASE,
)

# Titles that begin with a breach noun / quantity, so the org is NOT at the
# front and the anchored-org shape should be preferred.
_STARTS_NON_ORG_RE = re.compile(
    r"^\s*(?:data breach|breach|ransomware|cyber ?attack|hackers?|attackers?|"
    r"data leak|leak|threat actors?|\d[\d,.]*|millions?|thousands?|hundreds?|"
    r"tens of|scores of|dozens of)\b",
    re.IGNORECASE,
)

# A leading editorial label to peel off first ("Exclusive:", "Report -", ...).
_LABEL_RE = re.compile(
    r"^\s*(?:exclusive|report|update|breaking|alert|opinion|analysis|watch|"
    r"just in|developing)\s*[:\-–—]\s*",
    re.IGNORECASE,
)

# Once one of these words appears, the organisation name has ended. It keeps
# breach ACTION/impact words and quantities but omits subject verbs (confirms,
# reports, warns, reveals, ...): a subject verb only appears when the leading
# regex over-captured a subject ("Google warns of Acme Corp breach"), and
# trimming there would wrongly keep the subject ("Google") instead of dropping
# the whole non-victim span. It also omits "and"/"of"/"&" so multi-word names
# ("Marks and Spencer", "Bank of America", "Johnson & Johnson") survive.
_BOUNDARY_RE = re.compile(
    r"\b(?:"
    r"hit|hits|breached|hacked|leaks?|leaked|dumps?|dumped|exposes?|exposed|"
    r"exposing|affecting|affected|impacts?|impacted|targeted|"
    r"data|breach|hack|ransomware|cyber\w*|attack|incident|leak|"
    r"after|following|amid|over|due|"
    r"customers?|users?|clients?|records?|million|billion|thousand|patients?|"
    r"employees?|accounts?|victims?|people|individuals|residents?|"
    r"last|this|recently|again|yesterday|today|week|weeks|month|months|"
    r"year|years|day|days"
    r")\b",
    re.IGNORECASE,
)

# A leading count phrase captured together with the org ("1.2 million Acme").
_LEADING_QTY_RE = re.compile(
    r"^(?:(?:\d[\d,.]*|a|an|one|two|several|many|multiple|tens|hundreds|"
    r"thousands|millions|dozens)\s+"
    r"(?:million|billion|thousand|hundred|k|m)?\s*(?:of\s+)?)+",
    re.IGNORECASE,
)

# Dangling connective words left at the tail after a boundary cut.
_TRAIL_PREP_RE = re.compile(
    r"(?:\s+(?:in|on|at|to|for|with|as|by|of|and|the|a|an|amid|after|over|due|"
    r"following))+$",
    re.IGNORECASE,
)

# First-token rejects that mean a leading-org guess is really headline noise.
_LEAD_REJECT = {
    "new", "report", "update", "exclusive", "breaking", "the", "a", "an",
    "millions", "thousands", "hundreds", "data", "breach", "hackers", "hacker",
    "attackers", "ransomware", "cyberattack", "cyber", "how", "why", "what",
    "when", "major", "massive", "huge", "another",
}


def _trim_org(span: str) -> str:
    s = (span or "").strip().strip("\"'“”‘’")
    s = s.split(",")[0]                       # drop ", 2M affected" tails
    s = _LEADING_QTY_RE.sub("", s)            # drop a leading "1.2 million" count
    s = re.sub(r"[’']s\b", "", s)         # possessive
    m = _BOUNDARY_RE.search(s)
    if m and m.start() > 0:
        s = s[: m.start()]
    s = _TRAIL_PREP_RE.sub("", s)             # drop a dangling "in"/"at"/...
    s = re.sub(r"\s+", " ", s).strip(" -–—:.|")
    return s


def _good_lead(guess: str) -> bool:
    if not guess or len(guess) < 2:
        return False
    return guess.split()[0].lower() not in _LEAD_REJECT


def guess_company_from_title(title: str) -> str:
    """Best-effort victim-organisation guess from a headline. Always returns a
    string (never None); an unusable guess is filtered downstream by the
    stopword/length checks and the strict name matcher."""
    t = (title or "").strip()
    t = _LABEL_RE.sub("", t)
    if not t:
        return ""

    lead = _LEADING_ORG_RE.match(t)
    lead_org = _trim_org(lead.group("org")) if lead else ""

    trail = _TRAILING_ORG_RE.search(t)
    trail_org = _trim_org(trail.group("org")) if trail else ""

    # When the headline opens with a breach noun or a raw count, the org is not
    # at the front: prefer the anchored (trailing) capture.
    if _STARTS_NON_ORG_RE.match(t) and trail_org:
        return trail_org
    if _good_lead(lead_org):
        return lead_org
    if trail_org:
        return trail_org
    # Legacy fallback: the old splitter's behaviour, so we never regress to
    # empty where it would have returned something.
    for sep in (" discloses", " confirms", " hit by", " suffers", " reports", ":"):
        if sep in t:
            return t.split(sep)[0].strip()
    return t.split(",")[0].strip()
