"""Geocoding pipeline: coordinate extraction, location geocoding, and geofencing.

Dependencies: geopy (pip install geopy)
"""

from __future__ import annotations

import logging
import math
import re
import time
from collections import Counter
from typing import Optional

from sqlalchemy.orm import Session

from osint_monitor.core.database import (
    Entity,
    Event,
    EventEntity,
    EventItem,
    ItemEntity,
    RawItem,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory geocode cache and rate-limiter state
# ---------------------------------------------------------------------------

_geocode_cache: dict[str, dict | None] = {}
_last_nominatim_call: float = 0.0

# ---------------------------------------------------------------------------
# Regex patterns for coordinate extraction
# ---------------------------------------------------------------------------

# Decimal degrees: 41.4025, 2.1743  or  41.4025, -2.1743
_RE_DECIMAL = re.compile(
    r"(?P<lat>[+-]?\d{1,3}\.\d{2,10})\s*[,\s]\s*(?P<lon>[+-]?\d{1,3}\.\d{2,10})"
)

# Decimal degrees with cardinal suffixes: 41.4025°N, 2.1743°E
_RE_DECIMAL_CARDINAL = re.compile(
    r"(?P<lat>\d{1,3}\.\d{2,10})\s*°?\s*(?P<lat_d>[NSns])\s*[,\s]\s*"
    r"(?P<lon>\d{1,3}\.\d{2,10})\s*°?\s*(?P<lon_d>[EWew])"
)

# DMS: 41°24'09"N 2°10'27"E  (various quote styles)
_RE_DMS = re.compile(
    r"(?P<lat_d>\d{1,3})\s*°\s*(?P<lat_m>\d{1,2})\s*[′']\s*(?P<lat_s>\d{1,2}(?:\.\d+)?)\s*[″\"]\s*(?P<lat_dir>[NSns])"
    r"\s*[,\s]\s*"
    r"(?P<lon_d>\d{1,3})\s*°\s*(?P<lon_m>\d{1,2})\s*[′']\s*(?P<lon_s>\d{1,2}(?:\.\d+)?)\s*[″\"]\s*(?P<lon_dir>[EWew])"
)

# MGRS: 38TLN1234567890  (grid zone + 100km square + even-length easting/northing)
_RE_MGRS = re.compile(
    r"\b(?P<mgrs>\d{1,2}[C-HJ-NP-X][A-HJ-NP-Z]{2}\d{4,10})\b"
)

# Earth radius in km (mean)
_EARTH_RADIUS_KM = 6371.0


# ---------------------------------------------------------------------------
# Coordinate extraction
# ---------------------------------------------------------------------------

def _dms_to_decimal(degrees: float, minutes: float, seconds: float, direction: str) -> float:
    """Convert DMS to decimal degrees."""
    dec = degrees + minutes / 60.0 + seconds / 3600.0
    if direction.upper() in ("S", "W"):
        dec = -dec
    return dec


def _mgrs_to_latlon(mgrs_str: str) -> tuple[float, float] | None:
    """Best-effort MGRS to lat/lon conversion.

    Uses the ``mgrs`` library if available; otherwise returns None.
    """
    try:
        import mgrs as mgrs_lib
        m = mgrs_lib.MGRS()
        lat, lon = m.toLatLon(mgrs_str.encode() if isinstance(mgrs_str, str) else mgrs_str)
        return (lat, lon)
    except Exception:
        logger.debug(f"Could not convert MGRS string '{mgrs_str}' (mgrs library may not be installed)")
        return None


def extract_coordinates_from_text(text: str) -> list[dict]:
    """Extract geographic coordinates from free text.

    Supported formats:
      - Decimal degrees: ``41.4025, 2.1743`` or ``41.4025°N, 2.1743°E``
      - DMS: ``41°24'09"N 2°10'27"E``
      - MGRS: ``38TLN1234567890``

    Returns a list of dicts with keys ``lat``, ``lon``, ``format``, ``raw``.
    """
    results: list[dict] = []

    # 1. DMS (check first so we don't partially match as decimal)
    for m in _RE_DMS.finditer(text):
        lat = _dms_to_decimal(
            float(m.group("lat_d")), float(m.group("lat_m")),
            float(m.group("lat_s")), m.group("lat_dir"),
        )
        lon = _dms_to_decimal(
            float(m.group("lon_d")), float(m.group("lon_m")),
            float(m.group("lon_s")), m.group("lon_dir"),
        )
        results.append({"lat": lat, "lon": lon, "format": "dms", "raw": m.group(0)})

    # 2. Decimal degrees with cardinal suffixes
    for m in _RE_DECIMAL_CARDINAL.finditer(text):
        lat = float(m.group("lat"))
        if m.group("lat_d").upper() == "S":
            lat = -lat
        lon = float(m.group("lon"))
        if m.group("lon_d").upper() == "W":
            lon = -lon
        results.append({"lat": lat, "lon": lon, "format": "decimal_cardinal", "raw": m.group(0)})

    # 3. Plain decimal degrees (only if not already captured by cardinal pattern)
    cardinal_spans = {m.span() for m in _RE_DECIMAL_CARDINAL.finditer(text)}
    for m in _RE_DECIMAL.finditer(text):
        # Skip if this overlaps with a cardinal match
        if any(m.start() >= cs[0] and m.end() <= cs[1] for cs in cardinal_spans):
            continue
        lat = float(m.group("lat"))
        lon = float(m.group("lon"))
        if -90 <= lat <= 90 and -180 <= lon <= 180:
            results.append({"lat": lat, "lon": lon, "format": "decimal", "raw": m.group(0)})

    # 4. MGRS
    for m in _RE_MGRS.finditer(text):
        coords = _mgrs_to_latlon(m.group("mgrs"))
        if coords:
            results.append({"lat": coords[0], "lon": coords[1], "format": "mgrs", "raw": m.group(0)})

    return results


# ---------------------------------------------------------------------------
# Nominatim geocoding (via geopy)
# ---------------------------------------------------------------------------

def _rate_limit_nominatim() -> None:
    """Enforce >= 1 second between Nominatim requests (TOS compliance)."""
    global _last_nominatim_call
    elapsed = time.monotonic() - _last_nominatim_call
    if elapsed < 1.0:
        time.sleep(1.0 - elapsed)
    _last_nominatim_call = time.monotonic()


def geocode_location_name(name: str) -> dict | None:
    """Geocode a location name using Nominatim (free, no API key).

    Results are cached in memory. Rate-limited to 1 request per second per
    Nominatim Terms of Service.

    Returns ``{"lat": float, "lon": float, "display_name": str}`` or ``None``.
    """
    name_key = name.strip().lower()
    if not name_key or len(name_key) < 3:
        return None

    # Skip known non-location strings that confuse geocoders
    _GEOCODE_BLOCKLIST = {
        "ai", "us", "uk", "eu", "rt", "bbc", "cnn", "nato", "csis",
        "war on the rocks", "operation epic fury", "article 5",
        "the middle east", "the gulf", "the strait",
    }
    if name_key in _GEOCODE_BLOCKLIST:
        return None

    # Check cache
    if name_key in _geocode_cache:
        return _geocode_cache[name_key]

    try:
        from geopy.geocoders import Nominatim

        geolocator = Nominatim(user_agent="osint-monitor/1.0")
        _rate_limit_nominatim()
        location = geolocator.geocode(name_key, timeout=10)

        if location is None:
            _geocode_cache[name_key] = None
            return None

        result = {
            "lat": location.latitude,
            "lon": location.longitude,
            "display_name": location.address,
        }
        _geocode_cache[name_key] = result
        logger.debug(f"Geocoded '{name}' -> {result['lat']:.4f}, {result['lon']:.4f}")
        return result

    except Exception as exc:
        logger.warning(f"Geocoding failed for '{name}': {exc}")
        _geocode_cache[name_key] = None
        return None


# ---------------------------------------------------------------------------
# Item-level geocoding via entities
# ---------------------------------------------------------------------------

_LOCATION_ENTITY_TYPES = {"LOC", "GPE", "FAC", "LOCATION", "FACILITY"}


def geocode_entities_for_item(session: Session, item_id: int) -> dict | None:
    """Look up LOCATION/GPE/FAC entities linked to an item, geocode the first
    one found, and return its coordinates.

    Returns ``{"lat": float, "lon": float, "display_name": str}`` or ``None``.
    """
    item_entities = (
        session.query(ItemEntity)
        .join(Entity, ItemEntity.entity_id == Entity.id)
        .filter(
            ItemEntity.item_id == item_id,
            Entity.entity_type.in_(_LOCATION_ENTITY_TYPES),
        )
        .all()
    )

    for ie in item_entities:
        entity = ie.entity
        result = geocode_location_name(entity.canonical_name)
        if result is not None:
            return result

    return None


# ---------------------------------------------------------------------------
# Event-level geocoding
# ---------------------------------------------------------------------------

def geocode_event(session: Session, event_id: int) -> dict | None:
    """Geocode an event by finding the most frequently mentioned location
    entity across all items in the event, then update the event's lat/lon/
    location_name fields.

    Returns the geocode result dict or ``None``.
    """
    # Gather all items in the event
    event_items = (
        session.query(EventItem)
        .filter(EventItem.event_id == event_id)
        .all()
    )
    item_ids = [ei.item_id for ei in event_items]

    if not item_ids:
        return None

    # Find all location entities across these items
    location_entities = (
        session.query(ItemEntity)
        .join(Entity, ItemEntity.entity_id == Entity.id)
        .filter(
            ItemEntity.item_id.in_(item_ids),
            Entity.entity_type.in_(_LOCATION_ENTITY_TYPES),
        )
        .all()
    )

    if not location_entities:
        return None

    # Count entity mentions to find the most common location
    name_counter: Counter[str] = Counter()
    name_to_entity: dict[str, Entity] = {}
    for ie in location_entities:
        cname = ie.entity.canonical_name
        name_counter[cname] += 1
        name_to_entity[cname] = ie.entity

    # Geocode the most frequently mentioned location
    for location_name, _count in name_counter.most_common():
        result = geocode_location_name(location_name)
        if result is not None:
            # Update the event record
            event_obj = session.get(Event, event_id)
            if event_obj:
                event_obj.lat = result["lat"]
                event_obj.lon = result["lon"]
                event_obj.location_name = result["display_name"]
                session.commit()
                logger.info(
                    f"Event {event_id} geocoded to '{result['display_name']}' "
                    f"({result['lat']:.4f}, {result['lon']:.4f})"
                )
            return result

    return None


# ---------------------------------------------------------------------------
# Geofence check (Haversine)
# ---------------------------------------------------------------------------

def check_geofence(
    lat: float,
    lon: float,
    fence_lat: float,
    fence_lon: float,
    radius_km: float,
) -> bool:
    """Return True if (lat, lon) is within *radius_km* of the geofence centre.

    Uses the Haversine formula for great-circle distance.
    """
    lat1 = math.radians(lat)
    lat2 = math.radians(fence_lat)
    dlat = math.radians(fence_lat - lat)
    dlon = math.radians(fence_lon - lon)

    a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    distance_km = _EARTH_RADIUS_KM * c

    return distance_km <= radius_km


# ---------------------------------------------------------------------------
# Batch geocoding
# ---------------------------------------------------------------------------

def geocode_all_events(session: Session) -> int:
    """Batch geocode all events that have ``region IS NULL`` or ``lat IS NULL``.

    Returns the number of events successfully geocoded.
    """
    events = (
        session.query(Event)
        .filter(
            (Event.region.is_(None)) | (Event.lat.is_(None))
        )
        .all()
    )

    geocoded_count = 0
    for ev in events:
        result = geocode_event(session, ev.id)
        if result is not None:
            geocoded_count += 1

    logger.info(f"Batch geocoding complete: {geocoded_count}/{len(events)} events geocoded")
    return geocoded_count
