"""Server-Sent Events (SSE) for live push updates.

Uses an in-process event bus: tier jobs call broadcast() to push events
to all connected SSE clients immediately. Falls back to DB polling for
alerts and events that arrive outside the tier pipeline (e.g., manual inserts).
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from collections import deque
from datetime import datetime

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from osint_monitor.core.database import Alert, Event, get_session
from osint_monitor.api.routes import utc_iso

logger = logging.getLogger(__name__)
router = APIRouter()

# ---------------------------------------------------------------------------
# Event bus: sync producers (tier jobs) -> async consumers (SSE clients)
# ---------------------------------------------------------------------------

# Thread-safe buffer that tier jobs write to; SSE clients drain from.
_event_buffer: deque[dict] = deque(maxlen=500)
_buffer_lock = threading.Lock()
_buffer_event = asyncio.Event()  # Set when new data arrives

# Track the asyncio event loop so sync threads can signal it
_loop: asyncio.AbstractEventLoop | None = None


def broadcast(event_data: dict):
    """Push an event from a sync context (tier job thread) to all SSE clients.

    Thread-safe. Called from APScheduler threads.
    """
    with _buffer_lock:
        _event_buffer.append(event_data)

    # Wake up the SSE generator if an event loop is running
    if _loop is not None and _loop.is_running():
        _loop.call_soon_threadsafe(_buffer_event.set)


def _drain_buffer() -> list[dict]:
    """Drain all pending events from the buffer."""
    events = []
    with _buffer_lock:
        while _event_buffer:
            events.append(_event_buffer.popleft())
    return events


@router.get("/stream")
async def event_stream():
    """SSE endpoint for live updates."""
    return StreamingResponse(
        _generate_events(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


async def _generate_events():
    """Generate SSE events from the event bus + periodic DB checks."""
    global _loop
    _loop = asyncio.get_event_loop()

    last_db_check = datetime.utcnow()

    while True:
        # 1. Drain any events pushed by tier jobs (instant)
        pushed_events = _drain_buffer()
        for evt in pushed_events:
            evt_type = evt.get("type", "update")
            yield f"event: {evt_type}\ndata: {json.dumps(evt)}\n\n"

        # 2. Periodic DB check for alerts/events not from tier pipeline (every 15s)
        now = datetime.utcnow()
        if (now - last_db_check).total_seconds() >= 15:
            try:
                session = get_session()

                new_alerts = (
                    session.query(Alert)
                    .filter(Alert.created_at > last_db_check)
                    .order_by(Alert.created_at.desc())
                    .limit(10)
                    .all()
                )
                for alert in new_alerts:
                    data = json.dumps({
                        "type": "alert",
                        "id": alert.id,
                        "severity": alert.severity,
                        "title": alert.title,
                        "alert_type": alert.alert_type,
                        "created_at": utc_iso(alert.created_at),
                    })
                    yield f"event: alert\ndata: {data}\n\n"

                new_events = (
                    session.query(Event)
                    .filter(Event.last_updated_at > last_db_check)
                    .order_by(Event.last_updated_at.desc())
                    .limit(10)
                    .all()
                )
                for event in new_events:
                    data = json.dumps({
                        "type": "event",
                        "id": event.id,
                        "summary": event.summary,
                        "severity": event.severity,
                        "region": event.region,
                        "last_updated_at": utc_iso(event.last_updated_at),
                    })
                    yield f"event: event_update\ndata: {data}\n\n"

                last_db_check = now
                session.close()

            except Exception as e:
                logger.error(f"SSE DB check error: {e}")
                yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"

        # Heartbeat
        yield f": heartbeat {datetime.utcnow().isoformat()}\n\n"

        # Wait for either a push event or 5s timeout (much more responsive than 15s sleep)
        _buffer_event.clear()
        try:
            await asyncio.wait_for(_buffer_event.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            pass
