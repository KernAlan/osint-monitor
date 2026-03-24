"""Alerts API routes."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Query

from osint_monitor.core.database import Alert, get_session
from osint_monitor.api.routes import utc_iso

router = APIRouter()


@router.get("")
def list_alerts(
    alert_type: Optional[str] = None,
    acknowledged: Optional[bool] = None,
    min_severity: float = 0.0,
    hours_back: int = Query(default=72, ge=1, le=720),
    limit: int = Query(default=50, ge=1, le=200),
):
    session = get_session()
    try:
        cutoff = datetime.utcnow() - timedelta(hours=hours_back)
        q = session.query(Alert).filter(
            Alert.created_at >= cutoff,
            Alert.severity >= min_severity,
        )
        if alert_type:
            q = q.filter(Alert.alert_type == alert_type)
        if acknowledged is not None:
            q = q.filter(Alert.acknowledged == acknowledged)

        total = q.count()
        alerts = q.order_by(Alert.created_at.desc()).limit(limit).all()

        return {
            "total": total,
            "alerts": [
                {
                    "id": a.id,
                    "alert_type": a.alert_type,
                    "severity": a.severity,
                    "title": a.title,
                    "detail": a.detail,
                    "acknowledged": a.acknowledged,
                    "delivered_via": a.delivered_via,
                    "created_at": utc_iso(a.created_at),
                    "event_id": a.event_id,
                    "item_id": a.item_id,
                }
                for a in alerts
            ],
        }
    finally:
        session.close()


@router.post("/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: int):
    session = get_session()
    try:
        alert = session.get(Alert, alert_id)
        if not alert:
            return {"error": "Alert not found"}, 404
        alert.acknowledged = True
        session.commit()
        return {"status": "acknowledged", "id": alert_id}
    finally:
        session.close()
