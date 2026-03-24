"""Tests for osint_monitor.analysis.indicators (pure helper functions)."""

import math
from datetime import datetime, timedelta

from osint_monitor.analysis.indicators import (
    compute_temporal_weight,
    _score_to_status,
)


# ---------------------------------------------------------------------------
# compute_temporal_weight
# ---------------------------------------------------------------------------

def test_temporal_weight_now():
    """A timestamp at (approximately) now should yield a weight close to 1.0."""
    weight = compute_temporal_weight(datetime.utcnow())
    assert abs(weight - 1.0) < 0.01


def test_temporal_weight_halflife():
    """A timestamp exactly one half-life ago should yield ~0.5."""
    half_life = 24.0
    ts = datetime.utcnow() - timedelta(hours=half_life)
    weight = compute_temporal_weight(ts, half_life_hours=half_life)
    assert abs(weight - 0.5) < 0.05


def test_temporal_weight_old():
    """A timestamp 7 days ago (168 h) with 24 h half-life should be very small."""
    ts = datetime.utcnow() - timedelta(days=7)
    weight = compute_temporal_weight(ts, half_life_hours=24.0)
    # 2^(-168/24) = 2^(-7) = 0.0078125
    assert weight < 0.02


# ---------------------------------------------------------------------------
# _score_to_status
# ---------------------------------------------------------------------------

def test_score_to_status_elevated():
    assert _score_to_status(0.6) == "ELEVATED"


def test_score_to_status_warning():
    assert _score_to_status(0.35) == "WARNING"


def test_score_to_status_baseline():
    assert _score_to_status(0.05) == "BASELINE"
