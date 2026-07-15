"""
DeHashed and Intelligence X are query-based lookup APIs: you search a
specific email/domain/company and get back matching breach exposure,
which can include actual leaked credential fields (passwords, hashes,
sometimes plaintext). Two deliberate design decisions here, different from
every other collector in this codebase:

1. These do NOT run on the 6-hour schedule like the other 38 sources.
   There's nothing to "poll" — the API needs a target. Call
   `enrich_company(domain)` on demand when an analyst opens a breach
   dossier for a company and wants to check exposure, or batch it once
   nightly against your own `breach_companies` table if you want broader
   coverage.

2. `_strip_to_metadata()` is mandatory and non-optional in this module.
   Whatever the API returns, only the breach name, source breach date, and
   a *count* of matching records are kept — never the email/password/hash
   fields themselves. Storing other people's live credentials in your own
   database turns this product into a major liability and a high-value
   target for attackers; it also isn't needed for anything in the
   `breaches` / `breach_companies` schema, which is incident-level, not
   individual-level. If your use case genuinely requires per-credential
   detail (e.g. for an account-takeover-prevention product warning a user
   about their own exposed password), that is a fundamentally different,
   consent-scoped product surface than this breach-intelligence ledger and
   should not share this database.
"""
from __future__ import annotations

import httpx

from app.config import settings
from app.normalize.company_name import normalize_company_name
from app.normalize.date_parser import parse_any_date


def _strip_to_metadata(raw_entry: dict) -> dict:
    """Discard everything except incident-level facts. See module docstring."""
    return {
        "breach_name": raw_entry.get("database_name") or raw_entry.get("bucket_name"),
        "incident_date": raw_entry.get("breach_date") or raw_entry.get("date"),
        "matching_record_count": raw_entry.get("matches") or raw_entry.get("count") or None,
        # explicitly NOT copied: email, password, password_hash, name, address,
        # phone, ip_address, or any other per-record field the API returns.
    }


async def enrich_company_dehashed(domain: str, client: httpx.AsyncClient) -> list[dict]:
    if not settings.dehashed_api_key:
        return []
    resp = await client.get(
        "https://api.dehashed.com/search",
        params={"query": f"domain:{domain}"},
        headers={"Authorization": f"Bearer {settings.dehashed_api_key}"},
        timeout=20.0,
    )
    resp.raise_for_status()
    entries = resp.json().get("entries", [])
    return [_strip_to_metadata(e) for e in entries]


async def enrich_company_intelx(domain: str, client: httpx.AsyncClient) -> list[dict]:
    if not settings.intelx_api_key:
        return []
    resp = await client.post(
        "https://2.intelx.io/intelligent/search",
        json={"term": domain, "maxresults": 50, "media": 0},
        headers={"x-key": settings.intelx_api_key},
        timeout=20.0,
    )
    resp.raise_for_status()
    entries = resp.json().get("records", [])
    return [_strip_to_metadata(e) for e in entries]


async def enrich_company(domain: str, company_name: str, client: httpx.AsyncClient) -> dict:
    """
    Call this on demand (e.g. from a button in the breach dossier UI:
    "Check dark-web exposure for this company"), not from the scheduler.
    Returns metadata-only enrichment results, tagged by source, ready to be
    inserted as breach_source_records via the normal ingest_record() path —
    NOT a separate raw-credential table.
    """
    dehashed = await enrich_company_dehashed(domain, client)
    intelx = await enrich_company_intelx(domain, client)
    return {
        "company_name_norm": normalize_company_name(company_name),
        "domain": domain,
        "dehashed_results": dehashed,
        "intelx_results": intelx,
        "incident_dates": [parse_any_date(r.get("incident_date")) for r in dehashed + intelx],
    }
