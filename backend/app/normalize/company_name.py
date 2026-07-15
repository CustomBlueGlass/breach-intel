"""
Company name normalization. Goal: "Acme Corp.", "ACME CORPORATION", and
"Acme Corp (dba AcmeCo)" should all normalize to a comparable key so the
correlation engine can match them across sources without being thrown off
by punctuation, legal suffixes, or casing.
"""
import re

LEGAL_SUFFIXES = (
    "inc", "incorporated", "corp", "corporation", "co", "company", "llc",
    "ltd", "limited", "lp", "llp", "plc", "pllc", "pc", "group", "holdings",
    "na", "n.a",
)

_DBA_RE = re.compile(r"\(?d/?b/?a\.?\s+.*?\)?$", re.IGNORECASE)
_PUNCT_RE = re.compile(r"[^\w\s&]")
_WS_RE = re.compile(r"\s+")


def normalize_company_name(raw: str) -> str:
    if not raw:
        return ""
    name = raw.strip()
    name = _DBA_RE.sub("", name)
    name = _PUNCT_RE.sub(" ", name)
    name = _WS_RE.sub(" ", name).strip().lower()

    tokens = [t for t in name.split(" ") if t]
    while tokens and tokens[-1].rstrip(".") in LEGAL_SUFFIXES:
        tokens.pop()

    return " ".join(tokens)


def candidate_aliases(raw: str) -> set[str]:
    """A few cheap variants used to widen fuzzy-match recall."""
    norm = normalize_company_name(raw)
    variants = {norm, norm.replace(" ", "")}
    if " " in norm:
        variants.add(norm.split(" ")[0])  # first token, e.g. brand name only
    return {v for v in variants if v}
