"""
Correlation / entity-resolution scoring.

For each new source record we pull a small set of *candidate* breaches
(via trigram similarity on company name + a date window — see
candidates_for()) and score each candidate. The weighted score blends:

  * company name similarity (rapidfuzz token-sort ratio)         weight 0.50
  * date proximity (incident dates within N days)                weight 0.20
  * industry match                                               weight 0.15
  * ransomware group match (when both records name one)          weight 0.10
  * location/state match                                         weight 0.05

>= settings.auto_merge_confidence_threshold  -> auto-merge into that breach
>= settings.queue_confidence_threshold       -> send to breach_match_queue
otherwise                                    -> treated as a new, distinct breach
"""
from __future__ import annotations

from dataclasses import dataclass

from rapidfuzz import fuzz

from app.config import settings
from app.normalize.company_name import normalize_company_name
from app.normalize.date_parser import days_between

DATE_WINDOW_DAYS = 45  # candidates outside this window aren't considered


@dataclass
class MatchResult:
    breach_id: str | None
    confidence: float
    reasons: dict


def score_candidate(record, candidate) -> MatchResult:
    # Normalize the candidate's canonical_name before comparing — it stores
    # the display name ("Initech Software Inc."), and comparing that raw form
    # against the record's normalized name depressed every name score by the
    # casing/legal-suffix difference.
    name_score = fuzz.token_sort_ratio(
        record.company_name_norm or "",
        normalize_company_name(candidate.canonical_name or ""),
    ) / 100.0

    delta_days = days_between(record.incident_date, candidate.incident_date)
    if delta_days is None:
        date_score = 0.3  # neutral-low when either date is missing
    else:
        date_score = max(0.0, 1 - (delta_days / DATE_WINDOW_DAYS))

    industry_score = 1.0 if record.industry and record.industry == candidate.industry else 0.0
    group_score = (
        1.0
        if record.ransomware_group_norm
        and record.ransomware_group_norm == candidate.ransomware_group
        else (0.5 if not record.ransomware_group_norm and not candidate.ransomware_group else 0.0)
    )
    location_score = (
        1.0 if record.region_state and record.region_state == candidate.region_state else 0.0
    )

    confidence = (
        0.50 * name_score
        + 0.20 * date_score
        + 0.15 * industry_score
        + 0.10 * group_score
        + 0.05 * location_score
    )

    return MatchResult(
        breach_id=str(candidate.id),
        confidence=round(confidence, 3),
        reasons={
            "name_score": round(name_score, 3),
            "date_delta_days": delta_days,
            "industry_match": bool(industry_score),
            "ransomware_group_match": bool(group_score == 1.0),
            "location_match": bool(location_score),
        },
    )


def best_match(record, candidates: list) -> MatchResult | None:
    if not candidates:
        return None
    scored = [score_candidate(record, c) for c in candidates]
    return max(scored, key=lambda m: m.confidence)


def classify(match: MatchResult | None) -> str:
    if match is None:
        return "new_breach"
    if match.confidence >= settings.auto_merge_confidence_threshold:
        return "auto_merge"
    if match.confidence >= settings.queue_confidence_threshold:
        return "queue_for_review"
    return "new_breach"
