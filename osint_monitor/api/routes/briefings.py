"""Briefings API routes."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Query

from osint_monitor.core.database import Briefing, get_session
from osint_monitor.api.routes import utc_iso

router = APIRouter()


@router.get("")
def list_briefings(
    briefing_type: Optional[str] = None,
    limit: int = Query(default=20, ge=1, le=100),
):
    session = get_session()
    try:
        q = session.query(Briefing)
        if briefing_type:
            q = q.filter(Briefing.briefing_type == briefing_type)

        briefings = q.order_by(Briefing.created_at.desc()).limit(limit).all()

        return {
            "briefings": [
                {
                    "id": b.id,
                    "briefing_type": b.briefing_type,
                    "model_used": b.model_used,
                    "covering_from": utc_iso(b.covering_from),
                    "covering_to": utc_iso(b.covering_to),
                    "created_at": utc_iso(b.created_at),
                    "content_preview": b.content_md[:300] if b.content_md else "",
                }
                for b in briefings
            ]
        }
    finally:
        session.close()


@router.get("/{briefing_id}")
def get_briefing(briefing_id: int):
    session = get_session()
    try:
        briefing = session.get(Briefing, briefing_id)
        if not briefing:
            return {"error": "Briefing not found"}, 404
        return {
            "id": briefing.id,
            "briefing_type": briefing.briefing_type,
            "content_md": briefing.content_md,
            "model_used": briefing.model_used,
            "covering_from": utc_iso(briefing.covering_from),
            "covering_to": utc_iso(briefing.covering_to),
            "created_at": utc_iso(briefing.created_at),
        }
    finally:
        session.close()


@router.post("/generate")
def generate_briefing(
    briefing_type: str = "daily",
    hours_back: int = 24,
    provider: Optional[str] = None,
):
    from osint_monitor.analysis.briefing import generate_daily_briefing, generate_flash_briefing

    session = get_session()
    try:
        if briefing_type == "daily":
            result = generate_daily_briefing(session, hours_back=hours_back, provider=provider)
        else:
            return {"error": f"Unsupported briefing type for generation: {briefing_type}"}

        return {
            "briefing_type": result.briefing_type.value,
            "content_md": result.content_md,
            "model_used": result.model_used,
        }
    except Exception as e:
        return {"error": str(e)}
    finally:
        session.close()
