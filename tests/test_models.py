"""Tests for osint_monitor.core.models (Pydantic model validation)."""

from datetime import datetime

from osint_monitor.core.models import (
    AlertType,
    ClaimModel,
    EntityType,
    RawItemModel,
)


def test_raw_item_model():
    """Valid data creates a RawItemModel without errors."""
    item = RawItemModel(
        title="Test headline",
        content="Some body text",
        url="https://example.com/article",
        published_at=datetime(2025, 1, 15, 12, 0, 0),
        source_name="test-source",
    )
    assert item.title == "Test headline"
    assert item.content == "Some body text"
    assert item.source_name == "test-source"
    assert isinstance(item.fetched_at, datetime)


def test_claim_model():
    """Valid claim data creates a ClaimModel without errors."""
    claim = ClaimModel(
        subject="Russia",
        verb="attacked",
        object="Ukraine",
        claim_text="Russia attacked Ukraine",
        claim_type="assertion",
        source_name="reuters",
        confidence=0.95,
    )
    assert claim.subject == "Russia"
    assert claim.verb == "attacked"
    assert claim.claim_type == "assertion"
    assert claim.confidence == 0.95


def test_alert_type_enum():
    """All AlertType enum values are accessible and valid."""
    expected_values = {"keyword", "anomaly", "trend", "threshold", "compound"}
    actual_values = {member.value for member in AlertType}
    assert actual_values == expected_values
