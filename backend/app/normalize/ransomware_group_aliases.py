"""
Resolves messy threat-actor naming across sources to a canonical group
name. Ransomware groups rebrand constantly and different trackers spell
them differently (e.g. "Lockbit", "LockBit 3.0", "Lockbit3"); this keeps
analytics ("top ransomware groups") from fragmenting.

In production, sync ALIASES from `threat_actors.aliases` in the DB on
startup (and refresh periodically) rather than hardcoding — this static
seed is just the reference set.
"""
import re

ALIASES: dict[str, list[str]] = {
    "LockBit": ["lockbit", "lockbit 2.0", "lockbit 3.0", "lockbit3", "lockbit black"],
    "ALPHV/BlackCat": ["alphv", "blackcat", "black cat"],
    "Clop": ["clop", "cl0p"],
    "Akira": ["akira"],
    "Play": ["play ransomware", "playcrypt"],
    "8Base": ["8base"],
    "BlackBasta": ["black basta", "blackbasta"],
    "Medusa": ["medusa ransomware", "medusalocker"],
    "Royal": ["royal ransomware"],
    "Rhysida": ["rhysida"],
    "Hunters International": ["hunters international"],
    "RansomHub": ["ransomhub"],
    "Qilin": ["qilin", "agenda ransomware"],
}

_PATTERNS = {
    canonical: re.compile(r"|".join(re.escape(a) for a in aliases), re.IGNORECASE)
    for canonical, aliases in ALIASES.items()
}


def normalize_ransomware_group(raw: str | None) -> str | None:
    if not raw:
        return None
    lower = raw.strip().lower()
    for canonical, aliases in ALIASES.items():
        if lower in aliases or lower == canonical.lower():
            return canonical
    return raw.strip()


def extract_ransomware_group(text: str | None) -> str | None:
    """Scan free text (headline/summary) for a known group mention."""
    if not text:
        return None
    for canonical, pattern in _PATTERNS.items():
        if pattern.search(text):
            return canonical
    return None
