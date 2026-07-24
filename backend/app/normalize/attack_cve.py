"""
Extract CVE identifiers and infer MITRE ATT&CK techniques from the text a
breach's sources already carry (news titles/summaries, AG-letter text,
leak-site descriptions). This is derivation from real source reporting, not
fabricated attribution: CVEs are matched by their exact identifier, and each
ATT&CK technique is inferred only when the source text uses language that
maps to it. Both are shown as "inferred from source reporting" in the UI.
"""
from __future__ import annotations

import re

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def extract_cves(*texts: str | None) -> list[str]:
    found: list[str] = []
    for t in texts:
        if not t:
            continue
        for m in CVE_RE.findall(t):
            cve = m.upper()
            if cve not in found:
                found.append(cve)
    return sorted(found)


# ATT&CK technique -> (display name, keyword patterns). Patterns are matched
# case-insensitively against the combined source text. Kept conservative and
# specific to breach reporting to limit false positives; ordering is by
# technique id in the output.
ATTACK_TECHNIQUES: dict[str, tuple[str, tuple[str, ...]]] = {
    "T1078": ("Valid Accounts", (
        "stolen credential", "compromised credential", "leaked credential",
        "reused password", "valid account", "credential stuffing", "stolen login",
    )),
    "T1110": ("Brute Force", ("brute force", "brute-force", "password spray", "credential spray")),
    "T1133": ("External Remote Services", ("vpn appliance", "vpn gateway", " rdp ", "remote desktop", "remote access service", "citrix")),
    "T1190": ("Exploit Public-Facing Application", (
        "cve-", "zero-day", "0-day", "zero day", "unpatched", "public-facing",
        "remote code execution", "rce ", "sql injection", "exploited a vulnerability",
        "exploited a flaw", "security flaw", "software vulnerability", "known vulnerability",
        "moveit", "goanywhere", "file transfer", "oracle e-business", "fortinet", "ivanti",
    )),
    "T1195": ("Supply Chain Compromise", ("supply chain", "third-party vendor", "third party vendor", "compromised software", "vendor breach", "supplier breach")),
    "T1204": ("User Execution", ("malicious attachment", "opened an attachment", "malicious macro", "malicious link")),
    "T1213": ("Data from Information Repositories", ("support system", "ticketing system", "sharepoint", "confluence", "help desk system")),
    "T1486": ("Data Encrypted for Impact", ("ransomware", "ransom note", "encrypted their", "deployed ransomware", "file-encrypting")),
    "T1530": ("Data from Cloud Storage", ("misconfigured", "unsecured database", "exposed database", "open bucket", "unsecured s3", "public s3", "elasticsearch exposed", "unprotected server")),
    "T1566": ("Phishing", ("phishing", "phish", "spear-phish", "business email compromise", " bec ", "malicious email")),
    "T1567": ("Exfiltration Over Web Service", ("exfiltrat", "data was stolen", "stole data", "downloaded data", "data theft", "copied files")),
    "T1657": ("Financial Theft", ("extort", "double extortion", "ransom demand", "leak site", "data-leak site", "pay a ransom")),
}

ATTACK_NAMES = {tid: name for tid, (name, _) in ATTACK_TECHNIQUES.items()}


def map_techniques(*texts: str | None) -> list[str]:
    blob = " ".join(t for t in texts if t).lower()
    if not blob:
        return []
    hits = [tid for tid, (_, kws) in ATTACK_TECHNIQUES.items() if any(k in blob for k in kws)]
    return sorted(hits)
