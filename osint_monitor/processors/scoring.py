"""Composite threat scoring for items."""

from __future__ import annotations

import logging
import re

from osint_monitor.core.config import load_sources_config
from osint_monitor.core.models import ExtractedEntity, ProcessedItem

logger = logging.getLogger(__name__)

# Weights for composite score
W_KEYWORD = 0.30
W_ENTITY_SALIENCE = 0.20
W_SOURCE_CREDIBILITY = 0.25
W_NOVELTY = 0.25

# Keyword severity tiers (lemmatized forms)
CRITICAL_KEYWORDS = {
    "defcon", "nuclear weapon", "missile launch", "declaration of war",
    "military mobilization", "article 5", "nuclear strike", "wmd",
}

HIGH_KEYWORDS = {
    "troop movement", "naval deployment", "air strike", "embassy evacuated",
    "energy infrastructure", "cyber attack", "missile strike", "invasion",
    "drone strike", "chemical weapon", "biological weapon", "coup",
    "martial law", "blockade", "no-fly zone",
}

MEDIUM_KEYWORDS = {
    "sanction", "military exercise", "arms deal", "weapons shipment",
    "ceasefire", "peace talks", "border clash", "proxy war", "escalation",
}

# High-salience entity types
HIGH_SALIENCE_TYPES = {"PERSON", "ORG", "GPE", "WEAPON_SYSTEM"}


def compute_keyword_score(text: str) -> float:
    """Score based on keyword matches against normalized text."""
    text_lower = text.lower()

    for kw in CRITICAL_KEYWORDS:
        if kw in text_lower:
            return 1.0

    for kw in HIGH_KEYWORDS:
        if kw in text_lower:
            return 0.75

    for kw in MEDIUM_KEYWORDS:
        if kw in text_lower:
            return 0.5

    return 0.0


def compute_entity_salience(entities: list[ExtractedEntity]) -> float:
    """Score based on number and type of entities extracted."""
    if not entities:
        return 0.0

    high_salience = sum(
        1 for e in entities if e.entity_type.value in HIGH_SALIENCE_TYPES
    )
    total = len(entities)

    # More entities = more newsworthy; high-salience types matter more
    base = min(total / 10.0, 1.0)
    type_bonus = min(high_salience / 5.0, 1.0)
    return 0.5 * base + 0.5 * type_bonus


def compute_source_credibility(source_name: str) -> float:
    """Look up source credibility from config."""
    try:
        config = load_sources_config()
        for feed in config.rss_feeds:
            if feed.name == source_name:
                return feed.credibility_score
    except Exception:
        pass
    return 0.5  # default


def compute_composite_severity(
    text: str,
    entities: list[ExtractedEntity],
    source_name: str,
    novelty_score: float = 1.0,
) -> dict:
    """Compute composite severity score.

    Returns dict with component scores and final severity.
    """
    kw = compute_keyword_score(text)
    es = compute_entity_salience(entities)
    sc = compute_source_credibility(source_name)
    ns = novelty_score

    severity = W_KEYWORD * kw + W_ENTITY_SALIENCE * es + W_SOURCE_CREDIBILITY * sc + W_NOVELTY * ns

    return {
        "severity": min(severity, 1.0),
        "keyword_score": kw,
        "entity_salience": es,
        "source_credibility": sc,
        "novelty_score": ns,
    }
