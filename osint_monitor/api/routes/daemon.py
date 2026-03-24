"""Daemon control API: pause/resume/status for the tiered pipeline."""

from fastapi import APIRouter

from osint_monitor.core.scheduler import get_status, is_paused, pause, resume

router = APIRouter()


@router.get("/status")
async def daemon_status():
    """Get current daemon status including pause state and job schedule."""
    return get_status()


@router.post("/pause")
async def daemon_pause():
    """Pause all tier collection. Jobs stay scheduled but skip their ticks."""
    pause()
    return {"status": "paused", "message": "Pipeline paused. All tiers will skip until resumed."}


@router.post("/resume")
async def daemon_resume():
    """Resume tier collection."""
    resume()
    return {"status": "running", "message": "Pipeline resumed. Tiers will collect on next tick."}


@router.post("/toggle")
async def daemon_toggle():
    """Toggle pause/resume."""
    if is_paused():
        resume()
        return {"status": "running", "message": "Pipeline resumed."}
    else:
        pause()
        return {"status": "paused", "message": "Pipeline paused."}
