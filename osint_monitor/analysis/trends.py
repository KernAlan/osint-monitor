"""Anomaly detection and rolling metrics for entity trends."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

import numpy as np
from scipy import stats as scipy_stats
from sqlalchemy import func
from sqlalchemy.orm import Session

from osint_monitor.core.database import (
    Alert, Entity, ItemEntity, RawItem, TrendSnapshot,
    get_session, init_db,
)
from osint_monitor.core.models import AlertType, TrendPoint

logger = logging.getLogger(__name__)

# Windows for rolling metrics (hours)
WINDOWS = [6, 24, 168]  # 6h, 24h, 7d
ANOMALY_SIGMA = 2.0
HISTORICAL_DAYS = 30


def compute_entity_mention_counts(
    session: Session,
    window_hours: int = 24,
) -> dict[int, int]:
    """Count mentions per entity in the given window."""
    cutoff = datetime.utcnow() - timedelta(hours=window_hours)

    rows = (
        session.query(
            ItemEntity.entity_id,
            func.count(ItemEntity.id).label("mention_count"),
        )
        .join(RawItem, RawItem.id == ItemEntity.item_id)
        .filter(RawItem.fetched_at >= cutoff)
        .group_by(ItemEntity.entity_id)
        .all()
    )

    return {entity_id: count for entity_id, count in rows}


def snapshot_trends(session: Session):
    """Compute and store trend snapshots for all entities across all windows."""
    now = datetime.utcnow()

    for window_hours in WINDOWS:
        counts = compute_entity_mention_counts(session, window_hours)

        for entity_id, count in counts.items():
            snapshot = TrendSnapshot(
                entity_id=entity_id,
                metric_name="mention_count",
                metric_value=float(count),
                window_start=now - timedelta(hours=window_hours),
                window_end=now,
            )
            session.add(snapshot)

    session.commit()
    logger.info(f"Stored trend snapshots for {len(WINDOWS)} windows")


def detect_anomalies(session: Session) -> list[TrendPoint]:
    """Detect entities with anomalous mention counts.

    Anomaly = current 24h count > 2 sigma above 30-day rolling mean of 24h counts.
    """
    now = datetime.utcnow()
    current_counts = compute_entity_mention_counts(session, 24)

    anomalies: list[TrendPoint] = []

    for entity_id, current_count in current_counts.items():
        # Get historical 24h snapshots for this entity
        historical_cutoff = now - timedelta(days=HISTORICAL_DAYS)
        historical = (
            session.query(TrendSnapshot)
            .filter(
                TrendSnapshot.entity_id == entity_id,
                TrendSnapshot.metric_name == "mention_count",
                TrendSnapshot.window_end >= historical_cutoff,
                # Only 24h window snapshots
                func.julianday(TrendSnapshot.window_end)
                - func.julianday(TrendSnapshot.window_start) > 0.9,
            )
            .all()
        )

        if len(historical) < 5:
            continue  # Not enough history

        values = [s.metric_value for s in historical]
        mean = np.mean(values)
        std = np.std(values)

        if std == 0:
            continue

        sigma = (current_count - mean) / std

        if sigma >= ANOMALY_SIGMA:
            entity = session.get(Entity, entity_id)
            anomalies.append(TrendPoint(
                entity_name=entity.canonical_name if entity else f"entity_{entity_id}",
                metric_name="mention_count_24h",
                metric_value=float(current_count),
                window_start=now - timedelta(hours=24),
                window_end=now,
                is_anomaly=True,
                sigma=sigma,
            ))
            logger.info(
                f"ANOMALY: {entity.canonical_name if entity else entity_id} "
                f"at {current_count} mentions ({sigma:.1f} sigma)"
            )

    return anomalies


def create_trend_alerts(session: Session, anomalies: list[TrendPoint]):
    """Create TREND alerts for detected anomalies."""
    for anomaly in anomalies:
        alert = Alert(
            alert_type=AlertType.TREND.value,
            severity=min(0.5 + anomaly.sigma * 0.1, 1.0),
            title=f"Anomalous activity: {anomaly.entity_name}",
            detail=(
                f"{anomaly.entity_name} has {anomaly.metric_value:.0f} mentions "
                f"in the last 24h ({anomaly.sigma:.1f} sigma above 30-day average)"
            ),
        )
        session.add(alert)

    session.commit()


def get_entity_trend(
    session: Session,
    entity_id: int,
    days: int = 30,
) -> list[dict]:
    """Get trend data for a specific entity."""
    cutoff = datetime.utcnow() - timedelta(days=days)
    snapshots = (
        session.query(TrendSnapshot)
        .filter(
            TrendSnapshot.entity_id == entity_id,
            TrendSnapshot.window_end >= cutoff,
        )
        .order_by(TrendSnapshot.window_end)
        .all()
    )

    return [
        {
            "metric": s.metric_name,
            "value": s.metric_value,
            "window_start": s.window_start.isoformat(),
            "window_end": s.window_end.isoformat(),
        }
        for s in snapshots
    ]
