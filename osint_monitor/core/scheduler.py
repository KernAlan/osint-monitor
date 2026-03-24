"""APScheduler-based tiered pipeline orchestration.

Three collection tiers run at different intervals:
  - hot  (2.5 min): ADS-B, BGP, DNS, currency, commodities, defense stocks, seismic
  - warm (10 min):   RSS, Nitter, travel advisories, OONI, flight routes, GDELT, cables
  - cold (60 min):   FIRMS, USGS, ACLED, sanctions, NVD, UNHCR, IAEA, Wikipedia, SEC, finance

Each tier collects, processes deltas (dedup + NLP on new items only), and triggers
post-processing (clustering, fusion, I&W) only when new items appear. If a tier is
still running when its next tick fires, the tick is skipped.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime
from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler

from osint_monitor.core.database import get_session, init_db

logger = logging.getLogger(__name__)

# Per-tier locks: if a tier is still running when its next tick fires, skip it.
_tier_locks = {
    "hot": threading.Lock(),
    "warm": threading.Lock(),
    "cold": threading.Lock(),
}

# Pause flag file: when this file exists, all tier jobs skip their tick.
_PAUSE_FLAG = Path(__file__).parent.parent.parent / "data" / "pause"

# Module-level reference to the active scheduler (set by create_scheduler)
_active_scheduler: BackgroundScheduler | None = None


def is_paused() -> bool:
    """Check whether the pipeline is paused."""
    return _PAUSE_FLAG.exists()


def pause():
    """Pause all tier collection. Creates the pause flag file."""
    _PAUSE_FLAG.parent.mkdir(parents=True, exist_ok=True)
    _PAUSE_FLAG.write_text(datetime.utcnow().isoformat())
    logger.info("Pipeline PAUSED")


def resume():
    """Resume tier collection. Removes the pause flag file."""
    try:
        _PAUSE_FLAG.unlink()
    except FileNotFoundError:
        pass
    logger.info("Pipeline RESUMED")


def get_status() -> dict:
    """Return current daemon status."""
    paused = is_paused()
    jobs = []
    if _active_scheduler:
        for job in _active_scheduler.get_jobs():
            jobs.append({
                "id": job.id,
                "name": job.name,
                "next_run": job.next_run_time.isoformat() if job.next_run_time else None,
            })
    return {
        "running": _active_scheduler is not None,
        "paused": paused,
        "paused_since": _PAUSE_FLAG.read_text().strip() if paused else None,
        "jobs": jobs,
    }


def _run_tier_job(tier: str):
    """Run collection + delta processing for a single tier."""
    if is_paused():
        logger.debug(f"[{tier}] Pipeline paused, skipping")
        return

    lock = _tier_locks[tier]
    if not lock.acquire(blocking=False):
        logger.info(f"[{tier}] Still running from previous tick, skipping")
        return
    try:
        from osint_monitor.processors.pipeline import run_tier
        stats = run_tier(tier, quiet=True)
        new = stats.get("new_items", 0)
        if new > 0:
            logger.info(
                f"[{tier}] Tick complete: {new} new items, "
                f"{stats.get('events_created', 0)} events, "
                f"{stats.get('iw_elevated', 0)} I&W elevated"
            )
            # Push to SSE event bus
            try:
                from osint_monitor.api.websocket import broadcast
                broadcast({
                    "type": "tier_update",
                    "tier": tier,
                    "new_items": new,
                    "events_created": stats.get("events_created", 0),
                    "iw_elevated": stats.get("iw_elevated", 0),
                    "timestamp": datetime.utcnow().isoformat(),
                })
            except Exception:
                pass  # SSE not running (daemon-only mode)
    except Exception as e:
        logger.error(f"[{tier}] Tier job failed: {e}")
    finally:
        lock.release()


def _run_analysis_job():
    """Scheduled job: run trend analysis + anomaly detection."""
    from osint_monitor.analysis.trends import snapshot_trends, detect_anomalies, create_trend_alerts
    try:
        session = get_session()
        snapshot_trends(session)
        anomalies = detect_anomalies(session)
        if anomalies:
            create_trend_alerts(session, anomalies)
        session.close()
    except Exception as e:
        logger.error(f"Analysis job failed: {e}")


def _run_alert_job():
    """Scheduled job: evaluate alert rules."""
    from osint_monitor.alerting.engine import AlertEngine
    from osint_monitor.alerting.channels import build_channels, dispatch_alerts
    from osint_monitor.core.config import load_alerts_config
    try:
        session = get_session()
        engine = AlertEngine(session)
        alerts = engine.evaluate_all(hours_back=1)
        engine.escalate_unacknowledged()

        if alerts:
            config = load_alerts_config()
            channels = build_channels([c.model_dump() for c in config.channels])
            dispatch_alerts(alerts, channels)

        session.close()
    except Exception as e:
        logger.error(f"Alert job failed: {e}")


def _run_daily_briefing_job():
    """Scheduled job: generate daily briefing."""
    from osint_monitor.analysis.briefing import generate_daily_briefing
    try:
        result = generate_daily_briefing()
        logger.info(f"Daily briefing generated: {len(result.content_md)} chars")
    except Exception as e:
        logger.error(f"Daily briefing job failed: {e}")


def create_scheduler() -> BackgroundScheduler:
    """Create and configure the tiered background scheduler."""
    from osint_monitor.core.config import load_sources_config
    config = load_sources_config()
    tier_cfg = config.tiers

    global _active_scheduler
    scheduler = BackgroundScheduler()
    _active_scheduler = scheduler

    # --- Tiered collection ---
    scheduler.add_job(
        _run_tier_job,
        "interval",
        seconds=tier_cfg.hot_interval_seconds,
        args=["hot"],
        id="tier_hot",
        name=f"Hot tier ({tier_cfg.hot_interval_seconds}s)",
        max_instances=1,
        coalesce=True,
    )
    scheduler.add_job(
        _run_tier_job,
        "interval",
        seconds=tier_cfg.warm_interval_seconds,
        args=["warm"],
        id="tier_warm",
        name=f"Warm tier ({tier_cfg.warm_interval_seconds}s)",
        max_instances=1,
        coalesce=True,
    )
    scheduler.add_job(
        _run_tier_job,
        "interval",
        seconds=tier_cfg.cold_interval_seconds,
        args=["cold"],
        id="tier_cold",
        name=f"Cold tier ({tier_cfg.cold_interval_seconds}s)",
        max_instances=1,
        coalesce=True,
    )

    # --- Non-collection jobs ---
    scheduler.add_job(
        _run_analysis_job,
        "interval",
        hours=2,
        id="analysis",
        name="Trend analysis",
    )

    scheduler.add_job(
        _run_alert_job,
        "interval",
        minutes=10,
        id="alerts",
        name="Alert evaluation",
    )

    scheduler.add_job(
        _run_daily_briefing_job,
        "cron",
        hour=6,
        minute=0,
        id="daily_briefing",
        name="Daily briefing",
    )

    return scheduler
