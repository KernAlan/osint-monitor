"""Cross-modal signal fusion engine.

Correlates signals across different intelligence modalities (network, seismic,
thermal, financial, narrative, aviation) to detect events that no single
source can identify alone.  This is the core analytical differentiator —
the thing that makes the platform more than the sum of its parts.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import or_
from sqlalchemy.orm import Session

from osint_monitor.core.database import Event, EventItem, RawItem, Source

logger = logging.getLogger(__name__)

# Time window for considering signals as potentially correlated
CORRELATION_WINDOW_HOURS = 6

# Source type to modality mapping
SOURCE_MODALITY: dict[str, str] = {
    # Narrative / social
    "rss": "narrative",
    "twitter": "narrative",
    "twitter_nitter": "narrative",
    "telegram": "narrative",
    "webhook": "narrative",
    "browser": "narrative",
    "custom": "narrative",
    # Structured data feeds
    "structured_api": "structured",
    # Regulatory / government
    "sanctions": "regulatory",
    "government": "regulatory",
    # SIGINT sub-types
    "sigint_displacement": "humanitarian",
    "sigint_vuln": "cyber",
    "sigint_currency": "financial",
    "sigint_econ": "financial",
    "sigint_trade": "financial",
    "sigint_nuclear": "regulatory",
    "sigint_imint": "imagery",
    # Infrastructure / network
    "infrastructure": "infrastructure",
    # Financial
    "financial": "financial",
    # Spectrum / RF
    "spectrum": "spectrum",
    # Aviation & maritime tracking
    "adsb": "aviation",
    "aviation": "aviation",
    "ais": "maritime",
}


def classify_modality(source_type: str) -> str:
    """Map a source type to an intelligence modality."""
    modality = SOURCE_MODALITY.get(source_type)
    if modality is None:
        logger.warning(
            "Unmapped source_type %r in classify_modality — defaulting to 'narrative'. "
            "Add it to SOURCE_MODALITY in fusion.py.",
            source_type,
        )
        return "narrative"
    return modality


# ───────────────────────────────────────────────────────────────────────────
# Signal correlation patterns
# ───────────────────────────────────────────────────────────────────────────

# When these modality combinations appear within the correlation window,
# the confidence multiplier applies.  More diverse modalities = higher
# confidence that something real is happening.
CORRELATION_PATTERNS: list[dict[str, Any]] = [
    {
        "name": "Infrastructure Strike",
        "required_modalities": {"infrastructure", "narrative"},
        "optional_modalities": {"aviation", "imagery", "financial"},
        "description": "Network/DNS disruption + news reporting = confirmed infrastructure strike",
        "base_confidence": 0.7,
        "per_optional_bonus": 0.1,
    },
    {
        "name": "Major Military Event",
        "required_modalities": {"narrative", "aviation"},
        "optional_modalities": {"infrastructure", "financial", "regulatory"},
        "description": "News + military aviation pattern change = major military event",
        "base_confidence": 0.65,
        "per_optional_bonus": 0.1,
    },
    {
        "name": "Nuclear Incident",
        "required_modalities": {"narrative", "regulatory"},
        "optional_modalities": {"infrastructure", "imagery", "spectrum"},
        "description": "News + IAEA/regulatory reporting = nuclear safety event",
        "base_confidence": 0.6,
        "per_optional_bonus": 0.15,
    },
    {
        "name": "Economic Warfare Escalation",
        "required_modalities": {"financial", "narrative"},
        "optional_modalities": {"regulatory", "infrastructure"},
        "description": "Market movement + news = economic warfare or sanctions impact",
        "base_confidence": 0.5,
        "per_optional_bonus": 0.1,
    },
    {
        "name": "Communications Disruption",
        "required_modalities": {"infrastructure"},
        "optional_modalities": {"narrative", "spectrum"},
        "description": "BGP/DNS/cable disruption — may precede or accompany strikes",
        "base_confidence": 0.4,
        "per_optional_bonus": 0.15,
    },
    {
        "name": "Conflict Escalation",
        "required_modalities": {"narrative", "structured"},
        "optional_modalities": {"aviation", "financial", "humanitarian", "imagery"},
        "description": "News + structured conflict data (ACLED/GDELT) = confirmed conflict escalation",
        "base_confidence": 0.6,
        "per_optional_bonus": 0.08,
    },
    {
        "name": "Pre-narrative Signal",
        "required_modalities": {"financial"},
        "optional_modalities": {"aviation", "infrastructure"},
        "description": "Financial movement WITHOUT narrative = market knows before media",
        "anti_modalities": {"narrative"},  # signal is strongest when narrative is ABSENT
        "base_confidence": 0.35,
        "per_optional_bonus": 0.15,
    },
]


# ───────────────────────────────────────────────────────────────────────────
# Core fusion engine
# ───────────────────────────────────────────────────────────────────────────

def fuse_signals(
    session: Session,
    hours_back: int = 24,
) -> list[dict[str, Any]]:
    """Cross-correlate signals across modalities within a time window.

    Groups all recent items by their 1-hour time bucket and region, then
    checks which correlation patterns are satisfied by the modality mix
    present in each bucket.

    Returns a list of detected cross-modal correlations, sorted by
    confidence descending.
    """
    cutoff = datetime.utcnow() - timedelta(hours=hours_back)

    # Fetch all recent items with source info
    items = (
        session.query(RawItem, Source.type, Source.name)
        .join(Source, Source.id == RawItem.source_id)
        .filter(RawItem.fetched_at >= cutoff)
        .order_by(RawItem.fetched_at.asc())
        .all()
    )

    if not items:
        return []

    # Bucket items by 1-hour windows
    buckets: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "modalities": set(),
        "items": [],
        "sources": set(),
        "regions": set(),
    })

    for item, source_type, source_name in items:
        ts = item.published_at or item.fetched_at
        if ts is None:
            continue

        bucket_key = ts.strftime("%Y-%m-%d %H:00")
        modality = classify_modality(source_type)

        buckets[bucket_key]["modalities"].add(modality)
        buckets[bucket_key]["items"].append({
            "id": item.id,
            "title": item.title,
            "source": source_name,
            "modality": modality,
            "timestamp": ts.isoformat() if ts else None,
        })
        buckets[bucket_key]["sources"].add(source_name)

        # Try to detect region from item content/title
        text = f"{item.title or ''} {(item.content or '')[:200]}".lower()
        for region, keywords in _REGION_KEYWORDS.items():
            if any(kw in text for kw in keywords):
                buckets[bucket_key]["regions"].add(region)

    # Check each bucket against correlation patterns
    correlations: list[dict[str, Any]] = []

    for bucket_key, bucket in buckets.items():
        present = bucket["modalities"]

        for pattern in CORRELATION_PATTERNS:
            required = pattern["required_modalities"]
            optional = pattern.get("optional_modalities", set())
            anti = pattern.get("anti_modalities", set())

            # Check required modalities are present
            if not required.issubset(present):
                continue

            # Check anti-modalities are absent (for pre-narrative signals)
            if anti and anti.intersection(present):
                continue

            # Count optional modalities present
            optional_present = optional.intersection(present)
            confidence = pattern["base_confidence"] + (
                len(optional_present) * pattern["per_optional_bonus"]
            )
            confidence = min(confidence, 1.0)

            # Get items from matching modalities
            matching_items = [
                item for item in bucket["items"]
                if item["modality"] in (required | optional_present)
            ]

            correlations.append({
                "pattern": pattern["name"],
                "description": pattern["description"],
                "time_bucket": bucket_key,
                "confidence": round(confidence, 3),
                "modalities_present": sorted(present),
                "modalities_matched": sorted(required | optional_present),
                "regions": sorted(bucket["regions"]),
                "source_count": len(bucket["sources"]),
                "item_count": len(matching_items),
                "sample_items": matching_items[:10],
            })

    # Sort by confidence descending
    correlations.sort(key=lambda c: c["confidence"], reverse=True)

    # Deduplicate: keep only the highest-confidence pattern per time bucket
    seen_buckets: dict[str, float] = {}
    deduped: list[dict[str, Any]] = []
    for corr in correlations:
        key = corr["time_bucket"]
        if key in seen_buckets and seen_buckets[key] >= corr["confidence"]:
            continue
        seen_buckets[key] = corr["confidence"]
        deduped.append(corr)

    logger.info(
        "Signal fusion: %d time buckets, %d correlations detected",
        len(buckets), len(deduped),
    )
    return deduped


# ───────────────────────────────────────────────────────────────────────────
# Region detection keywords
# ───────────────────────────────────────────────────────────────────────────

_REGION_KEYWORDS: dict[str, list[str]] = {
    "iran": ["iran", "tehran", "irgc", "hormuz", "persian gulf", "natanz", "fordow"],
    "ukraine": ["ukraine", "kyiv", "donbas", "crimea", "zaporizhzhia"],
    "russia": ["russia", "moscow", "kremlin", "putin"],
    "china": ["china", "beijing", "taiwan", "south china sea", "pla"],
    "middle_east": ["israel", "gaza", "lebanon", "hezbollah", "syria", "yemen", "houthi"],
    "north_korea": ["north korea", "dprk", "pyongyang", "kim jong"],
}


# ───────────────────────────────────────────────────────────────────────────
# Absence detection — what SHOULD be there but ISN'T
# ───────────────────────────────────────────────────────────────────────────

def detect_signal_gaps(
    session: Session,
    hours_back: int = 24,
) -> list[dict[str, Any]]:
    """Detect suspicious signal absences.

    Sometimes the most important signal is what's missing. If news is
    reporting strikes but there are zero thermal anomalies in FIRMS data,
    either the strikes didn't happen or they're using weapons that don't
    produce thermal signatures.

    If BGP shows Iranian networks are up but DNS shows government domains
    are down, that's a deliberate shutdown, not collateral damage.
    """
    cutoff = datetime.utcnow() - timedelta(hours=hours_back)

    # Count items per source type
    source_counts: dict[str, int] = {}
    sources = session.query(Source).all()
    for src in sources:
        count = (
            session.query(RawItem)
            .filter(
                RawItem.source_id == src.id,
                RawItem.fetched_at >= cutoff,
            )
            .count()
        )
        modality = classify_modality(src.type)
        source_counts[modality] = source_counts.get(modality, 0) + count

    gaps: list[dict[str, Any]] = []

    # Check for expected modalities that are missing
    expected_modalities = {
        "narrative": "News/social media reporting",
        "infrastructure": "BGP/DNS/network monitoring",
        "financial": "Commodity and stock market signals",
        "aviation": "ADS-B military aircraft tracking",
        "imagery": "Satellite imagery or FIRMS thermal data",
    }

    for modality, description in expected_modalities.items():
        if source_counts.get(modality, 0) == 0:
            gaps.append({
                "gap_type": "missing_modality",
                "modality": modality,
                "description": f"No {description} in last {hours_back}h",
                "significance": "Cannot cross-correlate without this signal type",
            })

    # Check for contradictions
    has_narrative_about_strikes = False
    has_thermal = source_counts.get("imagery", 0) > 0
    has_infrastructure = source_counts.get("infrastructure", 0) > 0

    # Check if narrative mentions strikes
    strike_items = (
        session.query(RawItem)
        .filter(
            RawItem.fetched_at >= cutoff,
            or_(
                RawItem.title.ilike("%strike%"),
                RawItem.title.ilike("%bomb%"),
                RawItem.title.ilike("%attack%"),
                RawItem.content.ilike("%airstrike%"),
            ),
        )
        .count()
    )
    if strike_items > 3:
        has_narrative_about_strikes = True

    if has_narrative_about_strikes and not has_thermal:
        gaps.append({
            "gap_type": "contradiction",
            "modality": "imagery",
            "description": (
                f"News reports {strike_items} items about strikes/attacks but "
                f"no thermal anomaly data (FIRMS) is present in the database. "
                f"Either strikes are precision-only (no large thermal signature), "
                f"FIRMS data wasn't collected, or reporting is exaggerated."
            ),
            "significance": "Cannot independently confirm reported strikes",
        })

    if has_narrative_about_strikes and has_infrastructure:
        # Check if infrastructure data shows damage
        infra_anomalies = (
            session.query(RawItem)
            .join(Source)
            .filter(
                Source.type == "infrastructure",
                RawItem.fetched_at >= cutoff,
                or_(
                    RawItem.title.ilike("%ANOMALY%"),
                    RawItem.title.ilike("%DOWN%"),
                    RawItem.title.ilike("%UNREACHABLE%"),
                ),
            )
            .count()
        )
        if infra_anomalies == 0:
            gaps.append({
                "gap_type": "negative_confirmation",
                "modality": "infrastructure",
                "description": (
                    "Infrastructure monitoring shows NO disruptions despite active "
                    "conflict reporting. Networks are intact — damage is physical, "
                    "not digital, or the internet shutdown is government-imposed."
                ),
                "significance": "Distinguishes deliberate shutdown from collateral damage",
            })

    return gaps


# ───────────────────────────────────────────────────────────────────────────
# Temporal cross-correlation
# ───────────────────────────────────────────────────────────────────────────

def find_leading_indicators(
    session: Session,
    event_id: int,
    hours_before: int = 6,
) -> list[dict[str, Any]]:
    """Find signals from non-narrative sources that preceded an event.

    Given a clustered event, looks backwards in time for financial, aviation,
    infrastructure, or other signals that appeared BEFORE the first news
    report.  These are potential leading indicators — signals that moved
    before the narrative.
    """
    # Get event's first reported time
    event = session.query(Event).filter(Event.id == event_id).first()
    if not event or not event.first_reported_at:
        return []

    first_reported = event.first_reported_at
    search_start = first_reported - timedelta(hours=hours_before)

    # Find non-narrative items in the window before first reporting
    leading = (
        session.query(RawItem, Source.type, Source.name)
        .join(Source, Source.id == RawItem.source_id)
        .filter(
            RawItem.fetched_at >= search_start,
            RawItem.fetched_at < first_reported,
            Source.type.notin_(["rss", "twitter", "telegram", "webhook"]),
        )
        .order_by(RawItem.fetched_at.asc())
        .all()
    )

    indicators: list[dict[str, Any]] = []
    for item, source_type, source_name in leading:
        ts = item.published_at or item.fetched_at
        lead_time = (first_reported - ts).total_seconds() / 3600 if ts else 0

        indicators.append({
            "item_id": item.id,
            "title": item.title,
            "source": source_name,
            "modality": classify_modality(source_type),
            "timestamp": ts.isoformat() if ts else None,
            "lead_time_hours": round(lead_time, 2),
            "lead_type": "pre-narrative" if lead_time > 0.5 else "concurrent",
        })

    indicators.sort(key=lambda i: i["lead_time_hours"], reverse=True)

    if indicators:
        logger.info(
            "Event %d: found %d leading indicators (up to %.1fh before first report)",
            event_id, len(indicators),
            max(i["lead_time_hours"] for i in indicators),
        )

    return indicators
