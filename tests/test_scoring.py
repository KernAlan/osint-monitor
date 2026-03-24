"""Tests for osint_monitor.processors.scoring (pure functions, no DB)."""

from unittest.mock import patch

from osint_monitor.core.models import EntityType, EntityRole, ExtractedEntity
from osint_monitor.processors.scoring import (
    compute_keyword_score,
    compute_entity_salience,
    compute_composite_severity,
    W_KEYWORD,
    W_ENTITY_SALIENCE,
    W_SOURCE_CREDIBILITY,
    W_NOVELTY,
)


# ---------------------------------------------------------------------------
# Keyword scoring
# ---------------------------------------------------------------------------

def test_keyword_score_critical():
    assert compute_keyword_score("Report on nuclear weapon deployment") == 1.0


def test_keyword_score_high():
    assert compute_keyword_score("Confirmed missile strike on target") == 0.75


def test_keyword_score_medium():
    assert compute_keyword_score("New sanction package announced today") == 0.5


def test_keyword_score_none():
    assert compute_keyword_score("Weather forecast for the weekend") == 0.0


# ---------------------------------------------------------------------------
# Entity salience
# ---------------------------------------------------------------------------

def test_entity_salience_empty():
    assert compute_entity_salience([]) == 0.0


def test_entity_salience_high():
    entities = [
        ExtractedEntity(text="Vladimir Putin", entity_type=EntityType.PERSON),
        ExtractedEntity(text="Russia", entity_type=EntityType.GPE),
        ExtractedEntity(text="Ukraine", entity_type=EntityType.GPE),
        ExtractedEntity(text="NATO", entity_type=EntityType.ORG),
        ExtractedEntity(text="Volodymyr Zelenskyy", entity_type=EntityType.PERSON),
    ]
    score = compute_entity_salience(entities)
    # 5 total entities -> base = 5/10 = 0.5
    # 5 high-salience (PERSON, GPE, GPE, ORG, PERSON) -> type_bonus = 5/5 = 1.0
    # score = 0.5 * 0.5 + 0.5 * 1.0 = 0.75
    assert score == 0.75


# ---------------------------------------------------------------------------
# Composite severity
# ---------------------------------------------------------------------------

def test_composite_severity():
    """Verify the weighted combination of all component scores."""
    entities = [
        ExtractedEntity(text="Iran", entity_type=EntityType.GPE),
        ExtractedEntity(text="IAEA", entity_type=EntityType.ORG),
    ]

    # Mock source credibility to avoid loading config files
    with patch(
        "osint_monitor.processors.scoring.compute_source_credibility",
        return_value=0.8,
    ):
        result = compute_composite_severity(
            text="nuclear weapon threat detected",
            entities=entities,
            source_name="test-source",
            novelty_score=0.9,
        )

    assert "severity" in result
    assert "keyword_score" in result
    assert "entity_salience" in result
    assert "source_credibility" in result
    assert "novelty_score" in result

    # keyword_score should be 1.0 (critical: "nuclear weapon")
    assert result["keyword_score"] == 1.0
    assert result["source_credibility"] == 0.8
    assert result["novelty_score"] == 0.9

    # Verify the weighted sum
    expected = (
        W_KEYWORD * result["keyword_score"]
        + W_ENTITY_SALIENCE * result["entity_salience"]
        + W_SOURCE_CREDIBILITY * result["source_credibility"]
        + W_NOVELTY * result["novelty_score"]
    )
    assert abs(result["severity"] - min(expected, 1.0)) < 1e-9
