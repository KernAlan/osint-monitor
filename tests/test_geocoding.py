"""Tests for osint_monitor.processors.geocoding (pure functions, no API calls)."""

import pytest

from osint_monitor.processors.geocoding import (
    extract_coordinates_from_text,
    check_geofence,
)


# ---------------------------------------------------------------------------
# extract_coordinates_from_text
# ---------------------------------------------------------------------------

def test_extract_dd():
    """Decimal-degree coordinates are extracted correctly."""
    results = extract_coordinates_from_text("Located at 41.4025, 2.1743 near Barcelona")
    assert len(results) >= 1
    coord = results[0]
    assert abs(coord["lat"] - 41.4025) < 0.001
    assert abs(coord["lon"] - 2.1743) < 0.001


def test_extract_dms():
    """DMS coordinates are parsed and converted to decimal degrees."""
    text = """41\u00b024'09"N 2\u00b010'27"E"""
    results = extract_coordinates_from_text(text)
    assert len(results) >= 1
    coord = results[0]
    # 41 + 24/60 + 9/3600 = 41.4025
    assert abs(coord["lat"] - 41.4025) < 0.01
    # 2 + 10/60 + 27/3600 = 2.1742
    assert abs(coord["lon"] - 2.175) < 0.01


# ---------------------------------------------------------------------------
# check_geofence (Haversine)
# ---------------------------------------------------------------------------

def test_check_geofence_inside():
    """A point ~1 km from the center is inside a 5 km geofence."""
    # Center: 51.5074, -0.1278 (London)
    # Point roughly 1 km north
    assert check_geofence(51.516, -0.1278, 51.5074, -0.1278, radius_km=5.0) is True


def test_check_geofence_outside():
    """A point ~100 km away is outside a 5 km geofence."""
    # Center: 51.5074, -0.1278 (London)
    # Point: 52.4862, -1.8904 (Birmingham, ~160 km away)
    assert check_geofence(52.4862, -1.8904, 51.5074, -0.1278, radius_km=5.0) is False
