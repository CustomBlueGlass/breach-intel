"""
Read-only production diagnostics. Run via .github/workflows/diagnose.yml with
the DATABASE_URL secret to see the real data distribution behind reported
issues (filters, source counts) — never writes anything.
"""
from __future__ import annotations

import asyncio

from sqlalchemy import text

from app.db import get_session


QUERIES = {
    "total breaches": "SELECT count(*) FROM breaches",
    "source_count distribution": """
        SELECT source_count, count(*) AS breaches
        FROM breaches GROUP BY source_count ORDER BY source_count
    """,
    "status distribution": "SELECT status, count(*) FROM breaches GROUP BY status ORDER BY 2 DESC",
    "breaches with a ransomware_group": "SELECT count(*) FROM breaches WHERE ransomware_group IS NOT NULL",
    "top ransomware_group values in breaches": """
        SELECT ransomware_group, count(*) FROM breaches
        WHERE ransomware_group IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 15
    """,
    "mv_top_ransomware_groups contents": "SELECT ransomware_group, victim_count FROM mv_top_ransomware_groups LIMIT 15",
    "actual source records per breach (top)": """
        SELECT b.canonical_name, b.source_count,
               count(r.id) AS actual_linked_records
        FROM breaches b
        LEFT JOIN breach_source_records r ON r.matched_breach_id = b.id
        GROUP BY b.id, b.canonical_name, b.source_count
        ORDER BY count(r.id) DESC LIMIT 10
    """,
    "source records per source slug": """
        SELECT s.slug, count(*) AS source_records
        FROM breach_source_records r
        JOIN breach_data_sources s ON s.id = r.source_id
        GROUP BY s.slug ORDER BY 2 DESC
    """,
    "breaches touched by california_oag": """
        SELECT count(DISTINCT r.matched_breach_id)
        FROM breach_source_records r
        JOIN breach_data_sources s ON s.id = r.source_id
        WHERE s.slug = 'california_oag' AND r.matched_breach_id IS NOT NULL
    """,
    "breaches sourced ONLY from california_oag (net-new CA entries)": """
        SELECT count(*) FROM (
            SELECT r.matched_breach_id
            FROM breach_source_records r
            JOIN breach_data_sources s ON s.id = r.source_id
            WHERE r.matched_breach_id IS NOT NULL
            GROUP BY r.matched_breach_id
            HAVING bool_and(s.slug = 'california_oag')
        ) x
    """,
    "unlinked source records (never matched)": """
        SELECT count(*) FROM breach_source_records WHERE matched_breach_id IS NULL
    """,
    "records in review queue": "SELECT count(*) FROM breach_match_queue WHERE status = 'pending'",
    "same-name companies as SEPARATE breaches (missed merges)": """
        SELECT canonical_name_norm, count(*) AS separate_breaches, sum(source_count) AS total_sources
        FROM (
            SELECT lower(regexp_replace(canonical_name, '[^a-zA-Z0-9]', '', 'g')) AS canonical_name_norm,
                   source_count
            FROM breaches
        ) x
        GROUP BY canonical_name_norm HAVING count(*) > 1
        ORDER BY count(*) DESC LIMIT 15
    """,
    "ledger group values vs mv_top group values (mismatch check)": """
        SELECT
          (SELECT count(DISTINCT ransomware_group) FROM mv_breach_ledger WHERE ransomware_group IS NOT NULL) AS ledger_groups,
          (SELECT count(*) FROM mv_top_ransomware_groups) AS mv_groups,
          (SELECT count(*) FROM mv_top_ransomware_groups t
             WHERE NOT EXISTS (SELECT 1 FROM mv_breach_ledger l WHERE l.ransomware_group = t.ransomware_group)) AS mv_groups_absent_from_ledger
    """,
    "anon grants on views": """
        SELECT table_name, privilege_type
        FROM information_schema.role_table_grants
        WHERE grantee = 'anon' AND table_name LIKE 'mv_%'
        ORDER BY table_name
    """,
}


async def main() -> None:
    async with get_session() as session:
        for label, q in QUERIES.items():
            print(f"\n=== {label} ===")
            try:
                rows = (await session.execute(text(q))).fetchall()
                if not rows:
                    print("  (no rows)")
                for r in rows:
                    print("  " + " | ".join(str(v) for v in r))
            except Exception as exc:  # noqa: BLE001 — diagnostics must not abort
                print(f"  ERROR: {exc}")


if __name__ == "__main__":
    asyncio.run(main())
