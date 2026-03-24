"""Tests for osint_monitor.processors.entity_resolver (pure functions, no DB)."""

from osint_monitor.core.models import EntityType
from osint_monitor.processors.entity_resolver import (
    normalise,
    correct_entity_type,
    COREFERENCE_MAP,
)


# ---------------------------------------------------------------------------
# normalise()
# ---------------------------------------------------------------------------

def test_normalise_strips_articles():
    assert normalise("the United States") == "united states"


def test_normalise_expands_abbreviations():
    assert normalise("U.S.") == "united states"


def test_normalise_coreference():
    # "moscow" is in the coreference map -> "russia"
    assert normalise("Moscow") == "russia"
    assert "moscow" in COREFERENCE_MAP


def test_normalise_strips_twitter():
    assert normalise("@bellingcat") == "bellingcat"


# ---------------------------------------------------------------------------
# correct_entity_type()
# ---------------------------------------------------------------------------

def test_correct_entity_type_trump():
    # spaCy sometimes tags "Trump" as ORG; should be corrected to PERSON
    result = correct_entity_type("Trump", EntityType.ORG)
    assert result == EntityType.PERSON


def test_correct_entity_type_putin():
    result = correct_entity_type("Putin", EntityType.ORG)
    assert result == EntityType.PERSON


def test_correct_entity_type_no_change():
    # "NATO" is a genuine ORG; should stay ORG
    result = correct_entity_type("NATO", EntityType.ORG)
    assert result == EntityType.ORG
