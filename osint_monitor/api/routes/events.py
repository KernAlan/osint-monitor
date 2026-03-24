"""Events API routes."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel

from osint_monitor.core.database import Event, EventItem, EventEntity, RawItem, get_session
from osint_monitor.api.routes import utc_iso

router = APIRouter()


class EventResponse(BaseModel):
    id: int
    summary: str
    event_type: Optional[str]
    severity: float
    first_reported_at: str
    last_updated_at: str
    location_name: Optional[str]
    lat: Optional[float]
    lon: Optional[float]
    region: Optional[str]
    source_count: int
    model_config = {"from_attributes": True}


class EventDetailResponse(EventResponse):
    items: list[dict]
    entities: list[dict]


@router.get("")
def list_events(
    region: Optional[str] = None,
    min_severity: float = 0.0,
    hours_back: int = Query(default=72, ge=1, le=720),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = 0,
):
    session = get_session()
    try:
        cutoff = datetime.utcnow() - timedelta(hours=hours_back)
        q = session.query(Event).filter(
            Event.last_updated_at >= cutoff,
            Event.severity >= min_severity,
        )
        if region:
            q = q.filter(Event.region == region)

        total = q.count()
        events = q.order_by(Event.severity.desc()).offset(offset).limit(limit).all()

        results = []
        for ev in events:
            results.append({
                "id": ev.id,
                "summary": ev.summary,
                "event_type": ev.event_type,
                "severity": ev.severity,
                "first_reported_at": utc_iso(ev.first_reported_at),
                "last_updated_at": utc_iso(ev.last_updated_at),
                "location_name": ev.location_name,
                "lat": ev.lat,
                "lon": ev.lon,
                "region": ev.region,
                "source_count": ev.source_count or 0,
                "admiralty_rating": ev.admiralty_rating,
                "corroboration_level": ev.corroboration_level or "UNVERIFIED",
                "has_contradictions": ev.has_contradictions or False,
            })

        return {"total": total, "events": results}
    finally:
        session.close()


@router.get("/{event_id}")
def get_event(event_id: int):
    session = get_session()
    try:
        event = session.get(Event, event_id)
        if not event:
            return {"error": "Event not found"}, 404

        # Get linked items
        event_items = session.query(EventItem).filter_by(event_id=event_id).all()
        items = []
        for ei in event_items:
            item = session.get(RawItem, ei.item_id)
            if item:
                items.append({
                    "id": item.id,
                    "title": item.title,
                    "url": item.url,
                    "source": item.source.name if item.source else "Unknown",
                    "published_at": utc_iso(item.published_at),
                    "similarity_score": ei.similarity_score,
                })

        # Get linked entities
        event_entities = session.query(EventEntity).filter_by(event_id=event_id).all()
        entities = []
        for ee in event_entities:
            entities.append({
                "id": ee.entity_id,
                "name": ee.entity.canonical_name if ee.entity else "",
                "type": ee.entity.entity_type if ee.entity else "",
                "role": ee.role,
            })

        return {
            "id": event.id,
            "summary": event.summary,
            "event_type": event.event_type,
            "severity": event.severity,
            "first_reported_at": utc_iso(event.first_reported_at),
            "last_updated_at": utc_iso(event.last_updated_at),
            "location_name": event.location_name,
            "lat": event.lat,
            "lon": event.lon,
            "region": event.region,
            "items": items,
            "entities": entities,
        }
    finally:
        session.close()
