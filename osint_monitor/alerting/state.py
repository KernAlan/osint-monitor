"""State tracking for alert transition detection.

Stores and retrieves the last known state for each domain (I&W scores,
fusion patterns, corroboration levels, etc.) so the alert engine can
detect when something actually changed.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from osint_monitor.core.database import StateSnapshot

logger = logging.getLogger(__name__)


class StateTracker:
    """Read/write state snapshots for transition detection."""

    def __init__(self, session: Session):
        self.session = session

    def get(self, key: str) -> dict | None:
        """Get the last known state for a key."""
        snap = self.session.query(StateSnapshot).filter_by(key=key).first()
        if snap:
            return snap.value
        return None

    def set(self, key: str, value: dict):
        """Store the current state for a key."""
        snap = self.session.query(StateSnapshot).filter_by(key=key).first()
        if snap:
            snap.value = value
            snap.updated_at = datetime.utcnow()
        else:
            snap = StateSnapshot(key=key, value=value, updated_at=datetime.utcnow())
            self.session.add(snap)
        self.session.flush()

    def get_or_default(self, key: str, default: dict) -> dict:
        """Get state, returning default if not yet stored."""
        return self.get(key) or default
