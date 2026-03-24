"""Entities API routes."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Query

from osint_monitor.core.database import Entity, ItemEntity, get_session
from osint_monitor.analysis.graph import build_entity_graph, ego_graph, n_hop_neighbors
from osint_monitor.api.routes import utc_iso

router = APIRouter()


@router.get("")
def list_entities(
    entity_type: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = 0,
):
    session = get_session()
    try:
        q = session.query(Entity)
        if entity_type:
            q = q.filter(Entity.entity_type == entity_type)
        if search:
            q = q.filter(Entity.canonical_name.ilike(f"%{search}%"))

        total = q.count()
        entities = q.order_by(Entity.last_seen_at.desc()).offset(offset).limit(limit).all()

        results = []
        for ent in entities:
            mention_count = session.query(ItemEntity).filter_by(entity_id=ent.id).count()
            results.append({
                "id": ent.id,
                "canonical_name": ent.canonical_name,
                "entity_type": ent.entity_type,
                "aliases": ent.aliases or [],
                "wikidata_id": ent.wikidata_id,
                "first_seen_at": utc_iso(ent.first_seen_at),
                "last_seen_at": utc_iso(ent.last_seen_at),
                "mention_count": mention_count,
            })

        return {"total": total, "entities": results}
    finally:
        session.close()


@router.get("/{entity_id}")
def get_entity(entity_id: int):
    session = get_session()
    try:
        entity = session.get(Entity, entity_id)
        if not entity:
            return {"error": "Entity not found"}, 404

        # Get mentions with items
        item_entities = (
            session.query(ItemEntity)
            .filter_by(entity_id=entity_id)
            .order_by(ItemEntity.id.desc())
            .limit(50)
            .all()
        )

        mentions = []
        for ie in item_entities:
            item = ie.item
            if item:
                mentions.append({
                    "item_id": item.id,
                    "title": item.title,
                    "url": item.url,
                    "source": item.source.name if item.source else "Unknown",
                    "published_at": utc_iso(item.published_at),
                    "role": ie.role,
                    "confidence": ie.confidence,
                })

        return {
            "id": entity.id,
            "canonical_name": entity.canonical_name,
            "entity_type": entity.entity_type,
            "aliases": entity.aliases or [],
            "wikidata_id": entity.wikidata_id,
            "first_seen_at": utc_iso(entity.first_seen_at),
            "last_seen_at": utc_iso(entity.last_seen_at),
            "mentions": mentions,
        }
    finally:
        session.close()


@router.get("/{entity_id}/graph")
def get_entity_graph(entity_id: int, radius: int = Query(default=2, ge=1, le=4)):
    session = get_session()
    try:
        G = build_entity_graph(session)
        return ego_graph(G, entity_id, radius=radius)
    finally:
        session.close()


@router.get("/{entity_id}/trend")
def get_entity_trend(entity_id: int, days: int = Query(default=30, ge=1, le=365)):
    from osint_monitor.analysis.trends import get_entity_trend as _get_trend
    session = get_session()
    try:
        return {"trend": _get_trend(session, entity_id, days)}
    finally:
        session.close()
