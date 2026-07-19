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

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.correlation.matcher import MatchResult, best_match, classify
from app.normalize.company_name import normalize_company_name
from app.normalize.industry_map import normalize_industry
from app.normalize.location_normalize import normalize_location
from app.normalize.ransomware_group_aliases import normalize_ransomware_group


@dataclass
class IngestOutcome:
    inserted: bool
    deduped: bool
    action: str  # 'auto_merge' | 'queue_for_review' | 'new_breach' | 'deduped'
    breach_id: str | None = None


CANDIDATE_QUERY = text(
    """
    SELECT id, canonical_name, industry, region_state, ransomware_group, incident_date
    FROM breaches
    WHERE incident_date IS NULL
       OR incident_date BETWEEN (:incident_date::date - INTERVAL '45 days')
                             AND (:incident_date::date + INTERVAL '45 days')
       OR :incident_date IS NULL
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
    row = await session.execute(
        text(
            """
            INSERT INTO breach_companies (canonical_name, industry, country, region_state,
                                           breach_count, first_breach_at, last_breach_at)
            VALUES (:name, :industry, :country, :region, 1, :date, :date)
            ON CONFLICT DO NOTHING
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
    existing = row.first()
    if existing:
        return str(existing.id)

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
                    last_breach_at = GREATEST(coalesce(last_breach_at, :date), :date)
                WHERE id = :id
                """
            ),
            {"id": found_row.id, "date": breach_row["incident_date"]},
        )
        return str(found_row.id)
    raise RuntimeError("company upsert failed unexpectedly")


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
                    :disc_date, :records, :data_types, 1, 1.0, :summary)
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


async def link_record_to_breach(
    session: AsyncSession, source_record_id: str, breach_id: str, confidence: float
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


async def ingest_record(session: AsyncSession, source_id: str, record) -> IngestOutcome:
    # 1. normalize fully (collectors do a first pass; this is the authoritative pass)
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
    # FIX: raw_payload must be serialized to a JSON string before passing to
    # asyncpg — passing a plain Python dict causes a DataError because asyncpg's
    # JSONB encoder expects a pre-encoded string, not a dict object.
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
            # json.dumps() is required — asyncpg cannot encode a raw dict as JSONB
            "raw_payload": json.dumps(record.raw_payload, default=str),
        },
    )
    source_record_id = str(inserted.first().id)

    # 4. correlate against existing master breaches
    candidates = await find_candidates(session, record)
    match = best_match(record, candidates)
    action = classify(match)

    if action == "auto_merge":
        await link_record_to_breach(session, source_record_id, match.breach_id, match.confidence)
        return IngestOutcome(True, False, action, match.breach_id)

    if action == "queue_for_review":
        await queue_for_review(session, source_record_id, match)
        return IngestOutcome(True, False, action)

    # 5. no good candidate -> this is a new, distinct breach
    new_breach_id = await create_new_breach(session, record)
    await link_record_to_breach(session, source_record_id, new_breach_id, 1.0)
    return IngestOutcome(True, False, "new_breach", new_breach_id)
