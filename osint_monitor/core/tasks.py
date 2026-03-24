"""Celery task definitions for asynchronous pipeline execution.

Falls back to synchronous direct function calls if Celery is not installed.
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Celery setup (optional)
# ---------------------------------------------------------------------------

try:
    from celery import Celery

    celery_app = Celery("osint_monitor")
    celery_app.config_from_object({
        "broker_url": os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0"),
        "result_backend": os.environ.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/0"),
        "task_serializer": "json",
        "accept_content": ["json"],
        "result_serializer": "json",
        "timezone": "UTC",
        "enable_utc": True,
    })
    HAS_CELERY = True
    logger.info("Celery available -- tasks will be dispatched asynchronously")
except ImportError:
    celery_app = None
    HAS_CELERY = False
    logger.debug("Celery not installed -- tasks will run synchronously")


# ---------------------------------------------------------------------------
# Decorator helper
# ---------------------------------------------------------------------------

def _maybe_task(**task_kwargs):
    """Decorator that registers a function as a Celery task when available,
    otherwise returns the plain function."""
    def decorator(func):
        if HAS_CELERY and celery_app is not None:
            return celery_app.task(**task_kwargs)(func)
        return func
    return decorator


# ---------------------------------------------------------------------------
# Task definitions
# ---------------------------------------------------------------------------

@_maybe_task(name="osint_monitor.collect")
def task_collect():
    """Run source collection."""
    from osint_monitor.processors.pipeline import run_collection
    from osint_monitor.core.database import get_session

    session = get_session()
    try:
        items = run_collection(session)
        return {"collected": len(items)}
    finally:
        session.close()


@_maybe_task(name="osint_monitor.process_pipeline")
def task_process_pipeline():
    """Run the full processing pipeline (collect + NLP + cluster + score)."""
    from osint_monitor.processors.pipeline import run_pipeline

    stats = run_pipeline()
    return stats


@_maybe_task(name="osint_monitor.generate_briefing")
def task_generate_briefing():
    """Generate the daily intelligence briefing."""
    from osint_monitor.analysis.briefing import generate_daily_briefing

    result = generate_daily_briefing()
    return {"chars": len(result.content_md)}


@_maybe_task(name="osint_monitor.evaluate_alerts")
def task_evaluate_alerts():
    """Evaluate all alert rules and dispatch notifications."""
    from osint_monitor.alerting.engine import AlertEngine
    from osint_monitor.alerting.channels import build_channels, dispatch_alerts
    from osint_monitor.core.config import load_alerts_config
    from osint_monitor.core.database import get_session

    session = get_session()
    try:
        engine = AlertEngine(session)
        alerts = engine.evaluate_all(hours_back=1)
        engine.escalate_unacknowledged()

        if alerts:
            config = load_alerts_config()
            channels = build_channels([c.model_dump() for c in config.channels])
            dispatch_alerts(alerts, channels)

        return {"alerts_fired": len(alerts)}
    finally:
        session.close()


@_maybe_task(name="osint_monitor.snapshot_trends")
def task_snapshot_trends():
    """Compute and store trend snapshots."""
    from osint_monitor.analysis.trends import snapshot_trends
    from osint_monitor.core.database import get_session

    session = get_session()
    try:
        snapshot_trends(session)
        return {"status": "ok"}
    finally:
        session.close()


@_maybe_task(name="osint_monitor.enrich_fulltext")
def task_enrich_fulltext():
    """Enrich recent items with full-text content."""
    from osint_monitor.processors.fulltext import enrich_recent_items
    from osint_monitor.core.database import get_session

    session = get_session()
    try:
        count = enrich_recent_items(session)
        return {"enriched": count}
    finally:
        session.close()


@_maybe_task(name="osint_monitor.geocode_events")
def task_geocode_events():
    """Geocode all events that lack coordinates."""
    from osint_monitor.processors.geocoding import geocode_all_events
    from osint_monitor.core.database import get_session

    session = get_session()
    try:
        count = geocode_all_events(session)
        return {"geocoded": count}
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Dispatch helper
# ---------------------------------------------------------------------------

def dispatch(task_func, *args, **kwargs):
    """Dispatch a task asynchronously via Celery, or call it directly.

    If Celery is available and the function is a registered task,
    uses ``.delay()`` for async execution. Otherwise calls the
    function synchronously and returns the result.

    Args:
        task_func: One of the task_* functions defined above.
        *args, **kwargs: Arguments forwarded to the task.

    Returns:
        An AsyncResult (Celery) or the direct return value (sync).
    """
    if HAS_CELERY and hasattr(task_func, "delay"):
        logger.info(f"Dispatching task async: {task_func.name}")
        return task_func.delay(*args, **kwargs)
    else:
        logger.info(f"Running task synchronously: {task_func.__name__}")
        return task_func(*args, **kwargs)
