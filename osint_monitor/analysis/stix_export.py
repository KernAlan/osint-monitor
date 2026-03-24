"""STIX 2.1 / TAXII export for interoperability with real intel tooling.

Generates STIX 2.1 JSON bundles directly (no stix2 library dependency).
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from osint_monitor.core.database import (
    Alert,
    Entity,
    Event,
    EventEntity,
    EventItem,
    RawItem,
)

logger = logging.getLogger(__name__)

STIX_SPEC_VERSION = "2.1"
OSINT_MONITOR_IDENTITY_ID = "identity--a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
OSINT_MONITOR_IDENTITY = {
    "type": "identity",
    "spec_version": STIX_SPEC_VERSION,
    "id": OSINT_MONITOR_IDENTITY_ID,
    "created": "2025-01-01T00:00:00.000Z",
    "modified": "2025-01-01T00:00:00.000Z",
    "name": "OSINT-Monitor",
    "identity_class": "system",
    "description": "Automated OSINT monitoring and analysis system",
}


# ---------------------------------------------------------------------------
# Deterministic UUIDs from database IDs
# ---------------------------------------------------------------------------

_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # URL namespace


def _deterministic_uuid(prefix: str, db_id: int) -> str:
    """Generate a deterministic STIX UUID from a DB type and ID."""
    seed = f"osint-monitor:{prefix}:{db_id}"
    return str(uuid.uuid5(_NAMESPACE, seed))


def _stix_id(stix_type: str, db_prefix: str, db_id: int) -> str:
    """Build a full STIX id like 'report--<uuid>'."""
    return f"{stix_type}--{_deterministic_uuid(db_prefix, db_id)}"


def _ts(dt: datetime | None) -> str:
    """Format a datetime as STIX timestamp string."""
    if dt is None:
        dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


# ---------------------------------------------------------------------------
# Entity -> STIX SDO
# ---------------------------------------------------------------------------

def entity_to_stix(entity: Entity) -> dict[str, Any]:
    """Convert a single Entity DB row to a STIX 2.1 SDO.

    Mapping:
        GPE          -> location
        ORG          -> identity (identity_class="organization")
        PERSON       -> identity (identity_class="individual")
        WEAPON_SYSTEM -> tool  (closest STIX mapping for weapons/systems)
        LOC          -> location
        FACILITY     -> location (with description)
        Others       -> identity (identity_class="unknown")
    """
    created = _ts(entity.first_seen_at)
    modified = _ts(entity.last_seen_at)

    etype = entity.entity_type

    if etype == "GPE" or etype == "LOC":
        stix_type = "location"
        stix_id = _stix_id("location", "entity", entity.id)
        obj: dict[str, Any] = {
            "type": "location",
            "spec_version": STIX_SPEC_VERSION,
            "id": stix_id,
            "created": created,
            "modified": modified,
            "name": entity.canonical_name,
            "created_by_ref": OSINT_MONITOR_IDENTITY_ID,
        }
        if etype == "GPE":
            obj["region"] = "unknown"  # could be enriched later
        return obj

    if etype == "ORG":
        stix_id = _stix_id("identity", "entity", entity.id)
        return {
            "type": "identity",
            "spec_version": STIX_SPEC_VERSION,
            "id": stix_id,
            "created": created,
            "modified": modified,
            "name": entity.canonical_name,
            "identity_class": "organization",
            "created_by_ref": OSINT_MONITOR_IDENTITY_ID,
        }

    if etype == "PERSON":
        stix_id = _stix_id("identity", "entity", entity.id)
        return {
            "type": "identity",
            "spec_version": STIX_SPEC_VERSION,
            "id": stix_id,
            "created": created,
            "modified": modified,
            "name": entity.canonical_name,
            "identity_class": "individual",
            "created_by_ref": OSINT_MONITOR_IDENTITY_ID,
        }

    if etype == "WEAPON_SYSTEM":
        stix_id = _stix_id("tool", "entity", entity.id)
        return {
            "type": "tool",
            "spec_version": STIX_SPEC_VERSION,
            "id": stix_id,
            "created": created,
            "modified": modified,
            "name": entity.canonical_name,
            "description": f"Weapon system tracked by OSINT Monitor: {entity.canonical_name}",
            "tool_types": ["unknown"],
            "created_by_ref": OSINT_MONITOR_IDENTITY_ID,
        }

    if etype == "FACILITY":
        stix_id = _stix_id("location", "entity", entity.id)
        return {
            "type": "location",
            "spec_version": STIX_SPEC_VERSION,
            "id": stix_id,
            "created": created,
            "modified": modified,
            "name": entity.canonical_name,
            "description": f"Facility: {entity.canonical_name}",
            "created_by_ref": OSINT_MONITOR_IDENTITY_ID,
        }

    # Fallback for NORP, EVENT, PRODUCT, etc.
    stix_id = _stix_id("identity", "entity", entity.id)
    return {
        "type": "identity",
        "spec_version": STIX_SPEC_VERSION,
        "id": stix_id,
        "created": created,
        "modified": modified,
        "name": entity.canonical_name,
        "identity_class": "unknown",
        "description": f"Entity type: {etype}",
        "created_by_ref": OSINT_MONITOR_IDENTITY_ID,
    }


# ---------------------------------------------------------------------------
# Alert -> STIX Indicator
# ---------------------------------------------------------------------------

def alert_to_stix_indicator(alert: Alert) -> dict[str, Any]:
    """Convert an Alert DB row to a STIX 2.1 indicator object.

    Alerts map to indicators with a textual pattern (STIX patterning is
    typically cyber-focused; we use a human-readable description instead).
    """
    stix_id = _stix_id("indicator", "alert", alert.id)
    created = _ts(alert.created_at)

    # Build a simple STIX pattern placeholder -- real STIX patterns are
    # cyber-observable focused, so we use a descriptive approach
    pattern = f"[x-osint-alert:title = '{alert.title}']"

    indicator: dict[str, Any] = {
        "type": "indicator",
        "spec_version": STIX_SPEC_VERSION,
        "id": stix_id,
        "created": created,
        "modified": created,
        "name": alert.title,
        "description": alert.detail or "",
        "indicator_types": [_alert_type_to_indicator_type(alert.alert_type)],
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": created,
        "confidence": _severity_to_confidence(alert.severity),
        "created_by_ref": OSINT_MONITOR_IDENTITY_ID,
    }

    if alert.event_id:
        indicator["x_osint_event_id"] = alert.event_id
    if alert.item_id:
        indicator["x_osint_item_id"] = alert.item_id

    return indicator


def _alert_type_to_indicator_type(alert_type: str) -> str:
    """Map our alert types to STIX indicator-type vocabulary."""
    mapping = {
        "keyword": "anomalous-activity",
        "anomaly": "anomalous-activity",
        "trend": "anomalous-activity",
        "threshold": "anomalous-activity",
        "compound": "anomalous-activity",
    }
    return mapping.get(alert_type, "unknown")


def _severity_to_confidence(severity: float) -> int:
    """Map 0-1 severity to STIX confidence (0-100)."""
    return max(0, min(100, int(severity * 100)))


# ---------------------------------------------------------------------------
# RawItem -> STIX Note
# ---------------------------------------------------------------------------

def _item_to_stix_note(item: RawItem) -> dict[str, Any]:
    """Convert a RawItem to a STIX note SDO with external references."""
    stix_id = _stix_id("note", "item", item.id)
    created = _ts(item.fetched_at)
    published = _ts(item.published_at) if item.published_at else created

    note: dict[str, Any] = {
        "type": "note",
        "spec_version": STIX_SPEC_VERSION,
        "id": stix_id,
        "created": created,
        "modified": created,
        "abstract": item.title[:250] if item.title else "Untitled item",
        "content": (item.content or "")[:5000],
        "created_by_ref": OSINT_MONITOR_IDENTITY_ID,
    }

    external_refs = []
    if item.url:
        external_refs.append({
            "source_name": item.source.name if item.source else "unknown",
            "url": item.url,
        })
    if external_refs:
        note["external_references"] = external_refs

    return note


# ---------------------------------------------------------------------------
# Relationship helper
# ---------------------------------------------------------------------------

def _relationship(
    source_id: str,
    relationship_type: str,
    target_id: str,
    created: str | None = None,
) -> dict[str, Any]:
    """Build a STIX relationship object."""
    if created is None:
        created = _ts(None)
    # Deterministic ID from source+target+type
    seed = f"osint-monitor:rel:{source_id}:{relationship_type}:{target_id}"
    rel_uuid = str(uuid.uuid5(_NAMESPACE, seed))
    return {
        "type": "relationship",
        "spec_version": STIX_SPEC_VERSION,
        "id": f"relationship--{rel_uuid}",
        "created": created,
        "modified": created,
        "relationship_type": relationship_type,
        "source_ref": source_id,
        "target_ref": target_id,
        "created_by_ref": OSINT_MONITOR_IDENTITY_ID,
    }


# ---------------------------------------------------------------------------
# Event -> STIX Bundle
# ---------------------------------------------------------------------------

def event_to_stix_bundle(session: Session, event_id: int) -> dict[str, Any]:
    """Convert an Event + its entities + source items into a STIX 2.1 Bundle.

    Returns a dict representing a STIX Bundle JSON object.
    """
    event = session.query(Event).filter(Event.id == event_id).first()
    if event is None:
        logger.warning("Event %d not found", event_id)
        return _empty_bundle()

    objects: list[dict[str, Any]] = []
    objects.append(OSINT_MONITOR_IDENTITY)

    # --- Event as a STIX Report ---
    report_id = _stix_id("report", "event", event.id)
    created = _ts(event.first_reported_at)
    modified = _ts(event.last_updated_at)

    object_refs: list[str] = []

    report: dict[str, Any] = {
        "type": "report",
        "spec_version": STIX_SPEC_VERSION,
        "id": report_id,
        "created": created,
        "modified": modified,
        "name": event.summary[:250],
        "description": event.summary,
        "published": created,
        "report_types": ["event-report"],
        "confidence": _severity_to_confidence(event.severity),
        "created_by_ref": OSINT_MONITOR_IDENTITY_ID,
    }

    if event.location_name:
        report["x_osint_location"] = event.location_name
    if event.region:
        report["x_osint_region"] = event.region

    # --- Entities ---
    event_entities = (
        session.query(EventEntity)
        .filter(EventEntity.event_id == event_id)
        .all()
    )
    entity_ids_seen: set[int] = set()
    for ee in event_entities:
        if ee.entity_id in entity_ids_seen:
            continue
        entity_ids_seen.add(ee.entity_id)
        entity = ee.entity
        if entity is None:
            continue
        stix_obj = entity_to_stix(entity)
        objects.append(stix_obj)
        object_refs.append(stix_obj["id"])

        # Relationship: report -> entity
        rel = _relationship(report_id, "mentions", stix_obj["id"], created)
        objects.append(rel)

    # --- Source items as notes ---
    event_items = (
        session.query(EventItem)
        .filter(EventItem.event_id == event_id)
        .all()
    )
    for ei in event_items:
        item = ei.item
        if item is None:
            continue
        note = _item_to_stix_note(item)
        objects.append(note)
        object_refs.append(note["id"])

        # Relationship: report -> note
        rel = _relationship(report_id, "derived-from", note["id"], created)
        objects.append(rel)

    report["object_refs"] = object_refs
    objects.append(report)

    return _make_bundle(objects)


# ---------------------------------------------------------------------------
# Export all recent events
# ---------------------------------------------------------------------------

def export_all_events_stix(
    session: Session, hours_back: int = 24
) -> dict[str, Any]:
    """Export all events from the last `hours_back` hours as one STIX bundle."""
    cutoff = datetime.utcnow() - timedelta(hours=hours_back)
    events = (
        session.query(Event)
        .filter(Event.first_reported_at >= cutoff)
        .all()
    )

    if not events:
        logger.info("No events in the last %d hours for STIX export", hours_back)
        return _empty_bundle()

    all_objects: list[dict[str, Any]] = [OSINT_MONITOR_IDENTITY]
    seen_ids: set[str] = {OSINT_MONITOR_IDENTITY_ID}

    for event in events:
        bundle = event_to_stix_bundle(session, event.id)
        for obj in bundle.get("objects", []):
            if obj["id"] not in seen_ids:
                seen_ids.add(obj["id"])
                all_objects.append(obj)

    return _make_bundle(all_objects)


# ---------------------------------------------------------------------------
# Bundle helpers
# ---------------------------------------------------------------------------

def _make_bundle(objects: list[dict[str, Any]]) -> dict[str, Any]:
    """Wrap a list of STIX objects into a Bundle."""
    bundle_uuid = hashlib.sha256(
        "|".join(sorted(o["id"] for o in objects)).encode()
    ).hexdigest()[:32]
    # Format as UUID-like string
    formatted = (
        f"{bundle_uuid[:8]}-{bundle_uuid[8:12]}-"
        f"{bundle_uuid[12:16]}-{bundle_uuid[16:20]}-{bundle_uuid[20:32]}"
    )
    return {
        "type": "bundle",
        "id": f"bundle--{formatted}",
        "objects": objects,
    }


def _empty_bundle() -> dict[str, Any]:
    """Return an empty STIX bundle."""
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [],
    }
