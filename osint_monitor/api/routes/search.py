"""Search API route using SQLite FTS or LIKE fallback."""

from __future__ import annotations

from fastapi import APIRouter, Query

from osint_monitor.core.database import Entity, Event, RawItem, get_session
from osint_monitor.api.routes import utc_iso

router = APIRouter()


@router.get("")
def search(
    q: str = Query(..., min_length=2, description="Search query"),
    limit: int = Query(default=30, ge=1, le=100),
):
    """Search across items, events, and entities."""
    session = get_session()
    try:
        pattern = f"%{q}%"

        # Search items
        items = (
            session.query(RawItem)
            .filter(
                (RawItem.title.ilike(pattern)) | (RawItem.content.ilike(pattern))
            )
            .order_by(RawItem.fetched_at.desc())
            .limit(limit)
            .all()
        )

        # Search events
        events = (
            session.query(Event)
            .filter(Event.summary.ilike(pattern))
            .order_by(Event.severity.desc())
            .limit(limit)
            .all()
        )

        # Search entities
        entities = (
            session.query(Entity)
            .filter(Entity.canonical_name.ilike(pattern))
            .order_by(Entity.last_seen_at.desc())
            .limit(limit)
            .all()
        )

        return {
            "query": q,
            "items": [
                {
                    "id": i.id,
                    "title": i.title,
                    "url": i.url,
                    "source": i.source.name if i.source else "Unknown",
                    "published_at": utc_iso(i.published_at),
                }
                for i in items
            ],
            "events": [
                {
                    "id": e.id,
                    "summary": e.summary,
                    "severity": e.severity,
                    "region": e.region,
                }
                for e in events
            ],
            "entities": [
                {
                    "id": e.id,
                    "canonical_name": e.canonical_name,
                    "entity_type": e.entity_type,
                }
                for e in entities
            ],
        }
    finally:
        session.close()
