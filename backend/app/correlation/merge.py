"""
The ingestion pipeline. Called once per NormalizedRecord by the collector
runner (see scheduler.py). Everything here runs inside a single DB
transaction per record-batch — if linking a record to its master breach
fails partway through, the whole insert rolls back rather than leaving an
orphaned source record.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from types import SimpleNamespace

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.correlation.matcher import MatchResult, best_match, classify, score_candidate
from app.normalize.company_name import normalize_company_name
from app.normalize.industry_map import normalize_industry
from app.normalize.location_normalize import normalize_location
from app.normalize.ransomware_group_aliases import normalize_ransomware_group


@dataclass
class IngestOutcome:
    inserted: bool
    deduped: bool
    action: str  # 'auto_merge' | 'queue_for_review' | 'new_breach' | 'stored_unlinked' | 'deduped'
    breach_id: str | None = None


# Only documents that positively identify a victim organization may create a
# new breach (and company) row. News articles and government advisories are
# kept as source records for the evidence log on an existing breach — they
# enrich dossiers via auto-merge/review-queue but never mint new companies,
# because their "company name" is guessed from a headline. This is what keeps
# the ledger a list of breached companies rather than a news feed.
BREACH_CREATING_DOC_TYPES = {
    "leak_site_post",
    "ag_notification_letter",
    "hhs_breach_report",
    "sec_filing",
    "lookup_summary",
    "regulatory_action",
}


# FIX: Previously used PostgreSQL's :: cast operator (:incident_date::date)
# which conflicts with SQLAlchemy's named-parameter syntax (:incident_date).
# SQLAlchemy tries to parse "incident_date::date" as the parameter name,
# generating invalid SQL and a PostgresSyntaxError at runtime.
# Fix: use CAST(:param AS date) instead of :param::date throughout.
CANDIDATE_QUERY = text(
    """
    SELECT id, canonical_name, industry, region_state, ransomware_group, incident_date
    FROM breaches
    WHERE incident_date IS NULL
       OR incident_date BETWEEN (CAST(:incident_date AS date) - INTERVAL '45 days')
                             AND (CAST(:incident_date AS date) + INTERVAL '45 days')
       OR CAST(:incident_date AS date) IS NULL
    ORDER BY similarity(canonical_name, :name_norm) DESC
    LIMIT 8
    """
)


async def find_candidates(session: AsyncSession, record) -> list[Any]:
    rows = (
        await session.execute(
            CANDIDATE_QUERY,
            {"name_norm": record.company_name_norm, "incident_date": record.incident_date},
        )
    ).fetchall()
    return rows


async def is_duplicate(session: AsyncSession, source_id: str, fingerprint: str) -> bool:
    row = await session.execute(
        text(
            "SELECT 1 FROM breach_source_records WHERE source_id = :sid "
            "AND content_fingerprint = :fp LIMIT 1"
        ),
        {"sid": source_id, "fp": fingerprint},
    )
    return row.first() is not None


async def upsert_company(session: AsyncSession, breach_row) -> str:
    # Look up first, then insert. breach_companies has no unique constraint on
    # canonical_name, so INSERT ... ON CONFLICT DO NOTHING never conflicts and
    # every breach used to mint a duplicate company row.
    found = await session.execute(
        text(
            "SELECT id FROM breach_companies WHERE canonical_name = :name "
            "OR :name = ANY(name_aliases) LIMIT 1"
        ),
        {"name": breach_row["canonical_name"]},
    )
    found_row = found.first()
    if found_row:
        await session.execute(
            text(
                """
                UPDATE breach_companies
                SET breach_count = breach_count + 1,
                    first_breach_at = LEAST(coalesce(first_breach_at, :date), :date),
                    last_breach_at = GREATEST(coalesce(last_breach_at, :date), :date)
                WHERE id = :id
                """
            ),
            {"id": found_row.id, "date": breach_row["incident_date"]},
        )
        return str(found_row.id)

    row = await session.execute(
        text(
            """
            INSERT INTO breach_companies (canonical_name, industry, country, region_state,
                                           breach_count, first_breach_at, last_breach_at)
            VALUES (:name, :industry, :country, :region, 1, :date, :date)
            RETURNING id
            """
        ),
        {
            "name": breach_row["canonical_name"],
            "industry": breach_row["industry"],
            "country": breach_row.get("country"),
            "region": breach_row["region_state"],
            "date": breach_row["incident_date"],
        },
    )
    return str(row.first().id)


async def create_new_breach(session: AsyncSession, record) -> str:
    company_id = await upsert_company(
        session,
        {
            "canonical_name": record.company_name_norm.title() or record.company_name_raw,
            "industry": record.industry,
            "country": record.country,
            "region_state": record.region_state,
            "incident_date": record.incident_date,
        },
    )
    row = await session.execute(
        text(
            """
            INSERT INTO breaches (company_id, canonical_name, industry, country, region_state,
                                   ransomware_group, incident_date, disclosed_date,
                                   records_affected_est, data_types_exposed, source_count,
                                   confidence_avg, summary)
            VALUES (:company_id, :name, :industry, :country, :region, :group, :inc_date,
                    :disc_date, :records, :data_types, 0, 1.0, :summary)
            RETURNING id
            """
        ),
        {
            "company_id": company_id,
            "name": record.company_name_raw,
            "industry": record.industry,
            "country": record.country,
            "region": record.region_state,
            "group": record.ransomware_group_norm,
            "inc_date": record.incident_date,
            "disc_date": record.source_published_at.date() if record.source_published_at else None,
            "records": record.records_affected_est,
            "data_types": record.data_types_exposed,
            "summary": record.summary,
        },
    )
    return str(row.first().id)


# Severity derived from scale + sensitivity of exposed data. Reused by the
# maintenance backfill (WHERE true) and per-breach after each merge.
SENSITIVE_DATA_TYPES = (
    "ssn", "social_security_number", "protected_health_information", "medical",
    "passwords", "password_hints", "financial_account", "bank_account",
    "credit_card", "payment_card", "drivers_license", "passport",
)

SEVERITY_RECOMPUTE_SQL = """
UPDATE breaches b SET severity = sub.new_severity
FROM (
    SELECT id,
        CASE
            WHEN records_affected_est >= 10000000 THEN 'critical'
            WHEN records_affected_est >= 1000000
                 OR (records_affected_est >= 100000 AND data_types_exposed && CAST(:sensitive AS text[]))
                THEN 'high'
            WHEN records_affected_est >= 10000
                 OR data_types_exposed && CAST(:sensitive AS text[])
                 OR ransomware_group IS NOT NULL
                THEN 'moderate'
            WHEN records_affected_est IS NOT NULL THEN 'low'
            ELSE NULL
        END AS new_severity
    FROM breaches
    {where}
) sub
WHERE sub.id = b.id AND sub.new_severity IS DISTINCT FROM b.severity
"""


async def recompute_severity(session: AsyncSession, breach_id: str | None = None) -> None:
    where = "WHERE id = :bid" if breach_id else ""
    await session.execute(
        text(SEVERITY_RECOMPUTE_SQL.format(where=where)),
        {"sensitive": list(SENSITIVE_DATA_TYPES), **({"bid": breach_id} if breach_id else {})},
    )


async def link_record_to_breach(
    session: AsyncSession, source_record_id: str, breach_id: str, confidence: float, record=None
) -> None:
    await session.execute(
        text(
            "UPDATE breach_source_records SET matched_breach_id = :bid, match_confidence = :c "
            "WHERE id = :rid"
        ),
        {"bid": breach_id, "c": confidence, "rid": source_record_id},
    )
    await session.execute(
        text(
            """
            UPDATE breaches
            SET source_count = source_count + 1,
                last_updated_at = now(),
                confidence_avg = (coalesce(confidence_avg, 1.0) * source_count + :c) / (source_count + 1)
            WHERE id = :bid
            """
        ),
        {"c": confidence, "bid": breach_id},
    )
    if record is not None:
        # Each merged source fills in facts the breach is still missing:
        # a leak-site post names the group, an HHS report brings the record
        # count, a news article brings the earliest public date. This is what
        # keeps the ledger's threat-actor/disclosed/records columns populated
        # instead of "—".
        await session.execute(
            text(
                """
                UPDATE breaches SET
                    ransomware_group = COALESCE(ransomware_group, :group),
                    summary = COALESCE(summary, :summary),
                    incident_date = LEAST(
                        COALESCE(incident_date, CAST(:inc AS date)),
                        COALESCE(CAST(:inc AS date), incident_date)),
                    disclosed_date = LEAST(
                        COALESCE(disclosed_date, CAST(:disc AS date)),
                        COALESCE(CAST(:disc AS date), disclosed_date)),
                    records_affected_est = CASE
                        WHEN CAST(:records AS bigint) IS NULL THEN records_affected_est
                        ELSE GREATEST(COALESCE(records_affected_est, 0), CAST(:records AS bigint))
                    END,
                    data_types_exposed = CASE
                        WHEN CAST(:dt AS text[]) IS NULL OR CAST(:dt AS text[]) = '{}'::text[]
                            THEN data_types_exposed
                        ELSE (SELECT array_agg(DISTINCT x)
                              FROM unnest(COALESCE(data_types_exposed, '{}'::text[]) || CAST(:dt AS text[])) AS x)
                    END
                WHERE id = :bid
                """
            ),
            {
                "bid": breach_id,
                "group": record.ransomware_group_norm,
                "summary": record.summary,
                "inc": record.incident_date,
                "disc": record.source_published_at.date() if record.source_published_at else None,
                "records": record.records_affected_est,
                "dt": record.data_types_exposed or None,
            },
        )
        await recompute_severity(session, breach_id)


async def queue_for_review(
    session: AsyncSession, source_record_id: str, match: MatchResult
) -> None:
    await session.execute(
        text(
            """
            INSERT INTO breach_match_queue (source_record_id, candidate_breach_id, confidence, match_reasons)
            VALUES (:rid, :bid, :conf, :reasons)
            """
        ),
        {
            "rid": source_record_id,
            "bid": match.breach_id,
            "conf": match.confidence,
            "reasons": json.dumps(match.reasons),
        },
    )


# Unlinked news/advisory records that plausibly describe the same incident as
# a just-created breach. Kept tight (trigram similarity + date window) — the
# real scoring happens in score_candidate below.
ATTACH_UNLINKED_QUERY = text(
    """
    SELECT id, company_name_norm, incident_date, industry, region_state, ransomware_group_norm
    FROM breach_source_records
    WHERE matched_breach_id IS NULL
      AND similarity(company_name_norm, :name_norm) > 0.4
      AND (incident_date IS NULL OR CAST(:incident_date AS date) IS NULL
           OR incident_date BETWEEN (CAST(:incident_date AS date) - INTERVAL '45 days')
                                AND (CAST(:incident_date AS date) + INTERVAL '45 days'))
    LIMIT 25
    """
)


async def attach_unlinked_records(session: AsyncSession, breach_id: str, record) -> int:
    """
    News records arrive before regulators confirm a breach. When an
    authoritative report finally creates the breach row, sweep up earlier
    unlinked news/advisory records that clearly describe the same incident.
    """
    rows = (
        await session.execute(
            ATTACH_UNLINKED_QUERY,
            {"name_norm": record.company_name_norm, "incident_date": record.incident_date},
        )
    ).fetchall()
    breach_as_candidate = SimpleNamespace(
        id=breach_id,
        canonical_name=record.company_name_norm,
        industry=record.industry,
        region_state=record.region_state,
        ransomware_group=record.ransomware_group_norm,
        incident_date=record.incident_date,
    )
    attached = 0
    for row in rows:
        match = score_candidate(row, breach_as_candidate)
        # News/advisory records rarely carry industry/location metadata, so
        # their blended score tops out around 0.75 even on an exact company
        # name — treat a near-exact name inside the date window as a link,
        # and send the merely-plausible ones to the human review queue.
        strong_name = match.reasons.get("name_score", 0.0) >= 0.95
        if match.confidence >= settings.auto_merge_confidence_threshold or (
            strong_name and match.confidence >= settings.queue_confidence_threshold
        ):
            await link_record_to_breach(session, str(row.id), breach_id, match.confidence)
            attached += 1
        elif match.confidence >= settings.queue_confidence_threshold:
            await queue_for_review(session, str(row.id), match)
    return attached


async def ingest_record(session: AsyncSession, source_id: str, record) -> IngestOutcome:
    # 1. normalize fully
    record.company_name_norm = normalize_company_name(record.company_name_raw)
    record.industry = normalize_industry(record.industry)
    record.ransomware_group_norm = normalize_ransomware_group(record.ransomware_group_raw)
    if not record.country and not record.region_state:
        record.country, record.region_state = normalize_location(record.region_state)

    fingerprint = record.fingerprint()

    # 2. dedup
    if await is_duplicate(session, source_id, fingerprint):
        return IngestOutcome(inserted=False, deduped=True, action="deduped")

    # 3. insert the raw/normalized source record
    # raw_payload must be JSON-serialized — asyncpg cannot encode a raw Python
    # dict as JSONB; it expects a pre-serialized string.
    inserted = await session.execute(
        text(
            """
            INSERT INTO breach_source_records (
                source_id, external_id, source_published_at, company_name_raw, company_name_norm,
                industry, country, region_state, ransomware_group_raw, ransomware_group_norm,
                incident_date, records_affected_est, data_types_exposed, summary,
                source_record_url, document_type, content_fingerprint, raw_payload
            ) VALUES (
                :source_id, :external_id, :published_at, :company_raw, :company_norm,
                :industry, :country, :region, :group_raw, :group_norm,
                :incident_date, :records_affected, :data_types, :summary,
                :url, :doc_type, :fingerprint, :raw_payload
            )
            RETURNING id
            """
        ),
        {
            "source_id": source_id,
            "external_id": record.external_id,
            "published_at": record.source_published_at,
            "company_raw": record.company_name_raw,
            "company_norm": record.company_name_norm,
            "industry": record.industry,
            "country": record.country,
            "region": record.region_state,
            "group_raw": record.ransomware_group_raw,
            "group_norm": record.ransomware_group_norm,
            "incident_date": record.incident_date,
            "records_affected": record.records_affected_est,
            "data_types": record.data_types_exposed,
            "summary": record.summary,
            "url": record.source_record_url,
            "doc_type": record.document_type,
            "fingerprint": fingerprint,
            "raw_payload": json.dumps(record.raw_payload, default=str),
        },
    )
    source_record_id = str(inserted.first().id)

    # 4. correlate against existing master breaches
    candidates = await find_candidates(session, record)
    match = best_match(record, candidates)
    action = classify(match)

    # News/advisory records carry too little metadata to reach the blended
    # auto-merge threshold even on an exact company-name match — promote a
    # near-exact name inside the candidate date window to a merge instead of
    # burying obvious coverage in the review queue. Authoritative documents
    # keep the strict threshold: two similarly-named companies must not merge
    # on name alone.
    if (
        action == "queue_for_review"
        and record.document_type not in BREACH_CREATING_DOC_TYPES
        and match.reasons.get("name_score", 0.0) >= 0.95
    ):
        action = "auto_merge"

    if action == "auto_merge":
        await link_record_to_breach(
            session, source_record_id, match.breach_id, match.confidence, record=record
        )
        return IngestOutcome(True, False, action, match.breach_id)

    if action == "queue_for_review":
        await queue_for_review(session, source_record_id, match)
        return IngestOutcome(True, False, action)

    # 5. no good candidate. Authoritative documents create a new, distinct
    # breach; news/advisory documents stay stored as unlinked source records
    # so a later authoritative report can pick them up during correlation.
    if record.document_type not in BREACH_CREATING_DOC_TYPES:
        return IngestOutcome(True, False, "stored_unlinked")

    new_breach_id = await create_new_breach(session, record)
    await link_record_to_breach(session, source_record_id, new_breach_id, 1.0, record=record)
    await attach_unlinked_records(session, new_breach_id, record)
    return IngestOutcome(True, False, "new_breach", new_breach_id)
