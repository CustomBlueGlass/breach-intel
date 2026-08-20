"""
Rule-based detector for post-incident *developments* on a breach: regulatory
fines, litigation (class actions, lawsuits) and monetary settlements that land
in the months and years after the breach itself is disclosed.

Input is a single piece of already-breach-matched text (a news headline the
news-watch job correlated to a breach, or a source record's summary). Output is
a structured classification or None. No ML, only `re`, so it is deterministic,
auditable and cheap to run over every matched row on each maintenance pass.

Design choices that keep false positives low:
  * a "fine" or "settlement" is only recognised when a money amount is present
    in the same text, so the everyday senses of "fine" ("a fine example") and
    "penalty" do not trigger one;
  * "litigation" needs an explicit legal-action phrase (class action, lawsuit,
    sued, files suit, litigation, plaintiff), never a bare word like "court";
  * the caller only ever passes text already tied to a breach, so the subject
    matter is not in doubt — only the development type is.
"""
from __future__ import annotations

import re
from typing import Optional

# Money: a currency symbol or trailing currency word, a number, and an optional
# scale word. Two shapes: symbol-first ("£2.3 million", "$50,000") and
# word-trailing ("4.4 million dollars", "20 million euros").
_SCALE = {
    "k": 1_000, "thousand": 1_000,
    "m": 1_000_000, "mm": 1_000_000, "mn": 1_000_000, "million": 1_000_000,
    "b": 1_000_000_000, "bn": 1_000_000_000, "billion": 1_000_000_000,
}
_SYM_CUR = {"£": "GBP", "$": "USD", "€": "EUR"}
_WORD_CUR = {
    "pound": "GBP", "pounds": "GBP", "gbp": "GBP",
    "dollar": "USD", "dollars": "USD", "usd": "USD",
    "euro": "EUR", "euros": "EUR", "eur": "EUR",
}

_MONEY_SYM_RE = re.compile(
    r"(?P<sym>[£$€])\s?(?P<num>\d[\d,]*(?:\.\d+)?)\s?(?P<scale>k|mm|mn|m|bn|b|million|billion|thousand)?\b",
    re.I,
)
_MONEY_WORD_RE = re.compile(
    r"\b(?P<num>\d[\d,]*(?:\.\d+)?)\s?(?P<scale>million|billion|thousand)?\s?"
    r"(?P<cur>pounds?|dollars?|euros?|gbp|usd|eur)\b",
    re.I,
)

_FINE_RE = re.compile(r"\b(fine[ds]?|fined|penalt(?:y|ies)|penali[sz]e[sd]?)\b", re.I)
_SETTLE_RE = re.compile(r"\b(settle[sd]?|settlement|settlements|payout|payouts)\b", re.I)
_LITIG_RE = re.compile(
    r"\b(class[- ]actions?|lawsuits?|law suits?|sued|sues|files? suit|litigation|plaintiffs?)\b",
    re.I,
)

# Named enforcers, most specific first, so "ICO" wins over the generic "AG".
_REGULATORS = [
    ("ICO", re.compile(r"\b(ICO|Information Commissioner'?s? Office|Information Commissioner)\b")),
    ("FTC", re.compile(r"\b(FTC|Federal Trade Commission)\b")),
    ("SEC", re.compile(r"\b(SEC|Securities and Exchange Commission)\b")),
    ("CNIL", re.compile(r"\bCNIL\b")),
    ("DPC", re.compile(r"\b(DPC|Data Protection Commission)\b")),
    ("HHS OCR", re.compile(r"\b(HHS|Office for Civil Rights|OCR)\b")),
    ("NYDFS", re.compile(r"\b(NYDFS|Department of Financial Services)\b")),
    ("OFAC", re.compile(r"\bOFAC\b")),
    ("State AG", re.compile(r"\b(Attorney General|State AG)\b")),
]

# Regulators whose remit is only data protection, so naming one is itself proof
# the money is breach-related even when no breach word appears ("ICO fines X
# £20m"). Mixed-remit bodies (FTC, SEC, NYDFS, OFAC, State AG) are not enough on
# their own: they also fine for unrelated matters, so those need a breach term.
_PRIVACY_ONLY_REGULATORS = {"ICO", "CNIL", "DPC"}

# Breach / privacy / cyber nexus. The caller has already tied the text to a
# breach by company name, but the same company can be fined or sued over things
# that have nothing to do with the breach ("fined for late filing", "sues a
# former employee"). Requiring a nexus term (or a data-protection-only
# regulator) keeps those out while costing almost no recall: a genuine breach
# development nearly always names the breach, the data, or the privacy angle.
_NEXUS_RE = re.compile(
    r"\b(breach(?:es|ed)?|data|privacy|personal (?:data|information)|cyber\w*|"
    r"hack\w*|ransomware|malware|leak\w*|expos\w*|compromis\w*|"
    r"gdpr|hipaa|ccpa|data protection|information commissioner|"
    r"security incident|identity theft|records?)\b",
    re.I,
)


def _parse_amount(num: str, scale: Optional[str]) -> Optional[float]:
    try:
        val = float(num.replace(",", ""))
    except ValueError:
        return None
    if scale:
        val *= _SCALE.get(scale.lower(), 1)
    return val


def _find_money(text: str) -> Optional[dict]:
    """Largest money amount in the text, with its currency. Fines and
    settlements lead with the headline number, so the max is the right pick."""
    best = None
    for m in _MONEY_SYM_RE.finditer(text):
        amt = _parse_amount(m.group("num"), m.group("scale"))
        if amt is None:
            continue
        cand = {"amount": amt, "currency": _SYM_CUR.get(m.group("sym"), None)}
        if best is None or amt > best["amount"]:
            best = cand
    for m in _MONEY_WORD_RE.finditer(text):
        amt = _parse_amount(m.group("num"), m.group("scale"))
        if amt is None:
            continue
        cand = {"amount": amt, "currency": _WORD_CUR.get(m.group("cur").lower(), None)}
        if best is None or amt > best["amount"]:
            best = cand
    return best


def _find_regulator(text: str) -> Optional[str]:
    for name, rx in _REGULATORS:
        if rx.search(text):
            return name
    return None


def classify_development(text: Optional[str]) -> Optional[dict]:
    """Classify one breach-matched text as a post-incident development.

    Returns {"kind", "detail"} or None. `kind` is one of 'regulatory_fine',
    'settlement', 'litigation'. `detail` carries the structured bits found
    (amount, currency, regulator) and is safe to store as JSON.
    """
    if not text:
        return None
    t = " ".join(text.split())  # collapse whitespace
    money = _find_money(t)
    reg = _find_regulator(t)

    # Gate every classification on a breach nexus, so a fine or suit against the
    # same company over an unrelated matter is not attached to the breach.
    if not (_NEXUS_RE.search(t) or reg in _PRIVACY_ONLY_REGULATORS):
        return None

    # Fine: a regulator penalty. Requires a money amount so the word "fine" in
    # its everyday sense never triggers one.
    if _FINE_RE.search(t) and money:
        detail = {"amount": money["amount"], "currency": money["currency"]}
        if reg:
            detail["regulator"] = reg
        return {"kind": "regulatory_fine", "detail": detail}

    # Settlement: money paid to close a claim. Checked before litigation so a
    # "$X settlement in the class action" is recorded as the settlement.
    if _SETTLE_RE.search(t) and money:
        return {"kind": "settlement", "detail": {"amount": money["amount"], "currency": money["currency"]}}

    # Litigation: an explicit legal-action phrase. Money is optional; include it
    # when present (e.g. "seeks $X in damages").
    if _LITIG_RE.search(t):
        detail = {}
        if money:
            detail = {"amount": money["amount"], "currency": money["currency"]}
        return {"kind": "litigation", "detail": detail}

    return None
