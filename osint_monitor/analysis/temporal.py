"""Temporal intelligence: event timeline reconstruction and predictive indicators."""

from __future__ import annotations

import logging
import math
from collections import defaultdict
from datetime import datetime, timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from osint_monitor.core.database import (
    Entity,
    Event,
    EventEntity,
    EventItem,
    ItemEntity,
    RawItem,
    Source,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 1. Event timeline
# ---------------------------------------------------------------------------

def build_event_timeline(session: Session, event_id: int) -> list[dict]:
    """Build a chronological timeline for an event from all linked items.

    Each entry contains:
        - timestamp: ISO-formatted publication time
        - source: name of the reporting source
        - title: item headline
        - item_id: database ID of the raw item
        - is_first_report: True only for the earliest item
        - propagation_seconds: seconds elapsed since the first report (0 for the first)
    """
    rows = (
        session.query(RawItem, Source.name)
        .join(EventItem, EventItem.item_id == RawItem.id)
        .join(Source, Source.id == RawItem.source_id)
        .filter(EventItem.event_id == event_id)
        .order_by(RawItem.published_at.asc())
        .all()
    )

    if not rows:
        return []

    first_ts = rows[0][0].published_at
    timeline: list[dict] = []

    for idx, (item, source_name) in enumerate(rows):
        ts = item.published_at
        delta = (ts - first_ts).total_seconds() if ts and first_ts else 0.0
        timeline.append({
            "timestamp": ts.isoformat() if ts else None,
            "source": source_name,
            "title": item.title,
            "item_id": item.id,
            "is_first_report": idx == 0,
            "propagation_seconds": delta,
        })

    return timeline


# ---------------------------------------------------------------------------
# 2. Entity timeline
# ---------------------------------------------------------------------------

def build_entity_timeline(
    session: Session, entity_id: int, days: int = 30
) -> list[dict]:
    """Build a day-by-day timeline of all mentions of an entity.

    Returns a list of day-buckets, each containing:
        - date: "YYYY-MM-DD"
        - mention_count: number of items that day
        - items: list of {item_id, title, source, timestamp}
        - events: list of {event_id, summary} linked that day
    """
    cutoff = datetime.utcnow() - timedelta(days=days)

    rows = (
        session.query(RawItem, Source.name)
        .join(ItemEntity, ItemEntity.item_id == RawItem.id)
        .join(Source, Source.id == RawItem.source_id)
        .filter(
            ItemEntity.entity_id == entity_id,
            RawItem.published_at >= cutoff,
        )
        .order_by(RawItem.published_at.asc())
        .all()
    )

    # Gather event associations for these items
    item_ids = [r[0].id for r in rows]
    event_map: dict[int, list[dict]] = defaultdict(list)
    if item_ids:
        ev_rows = (
            session.query(EventItem.item_id, Event.id, Event.summary)
            .join(Event, Event.id == EventItem.event_id)
            .filter(EventItem.item_id.in_(item_ids))
            .all()
        )
        for ei_item_id, ev_id, ev_summary in ev_rows:
            event_map[ei_item_id].append({
                "event_id": ev_id,
                "summary": ev_summary,
            })

    # Group by day
    by_day: dict[str, dict] = {}
    for item, source_name in rows:
        ts = item.published_at
        day_key = ts.strftime("%Y-%m-%d") if ts else "unknown"
        if day_key not in by_day:
            by_day[day_key] = {
                "date": day_key,
                "mention_count": 0,
                "items": [],
                "events": [],
            }
        bucket = by_day[day_key]
        bucket["mention_count"] += 1
        bucket["items"].append({
            "item_id": item.id,
            "title": item.title,
            "source": source_name,
            "timestamp": ts.isoformat() if ts else None,
        })
        # Add events (deduplicated by event_id)
        seen_events = {e["event_id"] for e in bucket["events"]}
        for ev in event_map.get(item.id, []):
            if ev["event_id"] not in seen_events:
                bucket["events"].append(ev)
                seen_events.add(ev["event_id"])

    return sorted(by_day.values(), key=lambda d: d["date"])


# ---------------------------------------------------------------------------
# 3. Narrative propagation detection
# ---------------------------------------------------------------------------

def detect_narrative_propagation(session: Session, event_id: int) -> dict:
    """Track how a story propagated across sources.

    Returns:
        origin_source: the source that first reported the event
        propagation_chain: ordered list of {source, timestamp, item_id, lag_seconds}
        unique_reporting: count of distinct sources
        echo_score: 0.0 (all independent) to 1.0 (single-origin echo chamber)
    """
    timeline = build_event_timeline(session, event_id)
    if not timeline:
        return {
            "origin_source": None,
            "propagation_chain": [],
            "unique_reporting": 0,
            "echo_score": 0.0,
        }

    origin_source = timeline[0]["source"]
    unique_sources: set[str] = set()
    propagation_chain: list[dict] = []

    for entry in timeline:
        unique_sources.add(entry["source"])
        propagation_chain.append({
            "source": entry["source"],
            "timestamp": entry["timestamp"],
            "item_id": entry["item_id"],
            "lag_seconds": entry["propagation_seconds"],
        })

    unique_count = len(unique_sources)
    total_items = len(timeline)

    # Echo score: high if many items but few unique sources, and most
    # items arrived well after the first report (suggesting copying).
    # Simple heuristic: 1 - (unique_sources / total_items)
    # Clamped to [0, 1].  A single source reporting once => 0.0.
    if total_items <= 1:
        echo_score = 0.0
    else:
        echo_score = max(0.0, min(1.0, 1.0 - (unique_count / total_items)))

    return {
        "origin_source": origin_source,
        "propagation_chain": propagation_chain,
        "unique_reporting": unique_count,
        "echo_score": round(echo_score, 3),
    }


# ---------------------------------------------------------------------------
# 4. Temporal relevance (exponential decay)
# ---------------------------------------------------------------------------

def compute_temporal_relevance(
    published_at: datetime, half_life_hours: float = 48.0
) -> float:
    """Exponential decay relevance score.

    Items from *now* score ~1.0, items one half-life old score ~0.5, items
    from a week ago score ~0.1.

    Args:
        published_at: when the item was published (UTC assumed).
        half_life_hours: number of hours for the score to halve.

    Returns:
        Float in (0, 1].
    """
    now = datetime.utcnow()
    age_hours = max(0.0, (now - published_at).total_seconds() / 3600.0)
    decay_constant = math.log(2) / half_life_hours
    return math.exp(-decay_constant * age_hours)


# ---------------------------------------------------------------------------
# 5. Historical parallels
# ---------------------------------------------------------------------------

def find_historical_parallels(
    session: Session,
    entity_name: str,
    event_type: str,
    lookback_days: int = 90,
) -> list[dict]:
    """Find past events of the same type involving the same entity.

    "Last time [entity] was involved in [event_type], what happened next?"

    Returns a list of historical episodes, each containing:
        - event_id, summary, event_type, severity
        - first_reported_at
        - aftermath: list of subsequent events (within 7 days) involving
          the same entity, ordered chronologically.
    """
    cutoff = datetime.utcnow() - timedelta(days=lookback_days)

    # Resolve entity by canonical name
    entity = (
        session.query(Entity)
        .filter(Entity.canonical_name == entity_name)
        .first()
    )
    if entity is None:
        return []

    # Find past events of matching type linked to this entity
    past_events = (
        session.query(Event)
        .join(EventEntity, EventEntity.event_id == Event.id)
        .filter(
            EventEntity.entity_id == entity.id,
            Event.event_type == event_type,
            Event.first_reported_at >= cutoff,
        )
        .order_by(Event.first_reported_at.asc())
        .all()
    )

    results: list[dict] = []
    for ev in past_events:
        # Look for subsequent events involving the same entity within 7 days
        aftermath_start = ev.first_reported_at
        aftermath_end = aftermath_start + timedelta(days=7)
        aftermath_events = (
            session.query(Event)
            .join(EventEntity, EventEntity.event_id == Event.id)
            .filter(
                EventEntity.entity_id == entity.id,
                Event.id != ev.id,
                Event.first_reported_at > aftermath_start,
                Event.first_reported_at <= aftermath_end,
            )
            .order_by(Event.first_reported_at.asc())
            .all()
        )

        results.append({
            "event_id": ev.id,
            "summary": ev.summary,
            "event_type": ev.event_type,
            "severity": ev.severity,
            "first_reported_at": ev.first_reported_at.isoformat()
            if ev.first_reported_at
            else None,
            "aftermath": [
                {
                    "event_id": ae.id,
                    "summary": ae.summary,
                    "event_type": ae.event_type,
                    "severity": ae.severity,
                    "first_reported_at": ae.first_reported_at.isoformat()
                    if ae.first_reported_at
                    else None,
                }
                for ae in aftermath_events
            ],
        })

    return results
