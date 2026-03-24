"""NER and event extraction via spaCy."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import spacy
from spacy.language import Language

from osint_monitor.core.config import get_settings, load_entities_config
from osint_monitor.core.models import EntityRole, EntityType, ExtractedEntity

if TYPE_CHECKING:
    from spacy.tokens import Doc

logger = logging.getLogger(__name__)

# Map spaCy labels to our EntityType
SPACY_LABEL_MAP: dict[str, EntityType] = {
    "PERSON": EntityType.PERSON,
    "ORG": EntityType.ORG,
    "GPE": EntityType.GPE,
    "NORP": EntityType.NORP,
    "FAC": EntityType.FAC,
    "EVENT": EntityType.EVENT,
    "PRODUCT": EntityType.PRODUCT,
    "LOC": EntityType.LOC,
}

# Action verbs that indicate event types
EVENT_VERB_MAP: dict[str, str] = {
    "attack": "military_action",
    "strike": "military_action",
    "bomb": "military_action",
    "shell": "military_action",
    "invade": "military_action",
    "deploy": "military_deployment",
    "mobilize": "military_deployment",
    "move": "troop_movement",
    "launch": "missile_launch",
    "fire": "military_action",
    "sanction": "sanctions",
    "negotiate": "diplomacy",
    "sign": "diplomacy",
    "agree": "diplomacy",
    "meet": "diplomacy",
    "warn": "escalation",
    "threaten": "escalation",
    "test": "weapons_test",
    "detonate": "weapons_test",
    "arrest": "law_enforcement",
    "seize": "law_enforcement",
    "hack": "cyber_attack",
    "breach": "cyber_attack",
    "evacuate": "humanitarian",
    "flee": "humanitarian",
    "protest": "civil_unrest",
    "revolt": "civil_unrest",
    "coup": "regime_change",
    "elect": "political",
    "resign": "political",
    "assassinate": "assassination",
}

_nlp_instance: Language | None = None


def get_nlp() -> Language:
    """Load spaCy model (cached singleton)."""
    global _nlp_instance
    if _nlp_instance is not None:
        return _nlp_instance

    settings = get_settings()
    model_name = settings.spacy_model

    try:
        _nlp_instance = spacy.load(model_name)
        logger.info(f"Loaded spaCy model: {model_name}")
    except OSError:
        logger.warning(f"{model_name} not found, falling back to en_core_web_sm")
        try:
            _nlp_instance = spacy.load("en_core_web_sm")
        except OSError:
            logger.warning("No spaCy model found. Downloading en_core_web_sm...")
            spacy.cli.download("en_core_web_sm")
            _nlp_instance = spacy.load("en_core_web_sm")

    # Add custom EntityRuler for weapons systems etc.
    _add_entity_ruler(_nlp_instance)
    return _nlp_instance


def _add_entity_ruler(nlp: Language):
    """Add custom entity patterns from entities.yaml."""
    patterns = []
    try:
        entities = load_entities_config()
        for ent in entities:
            # Add canonical name pattern
            patterns.append({
                "label": ent.entity_type,
                "pattern": ent.canonical_name,
            })
            # Add alias patterns
            for alias in ent.aliases:
                patterns.append({
                    "label": ent.entity_type,
                    "pattern": alias,
                })
    except Exception as e:
        logger.debug(f"Could not load entity seeds: {e}")

    if patterns:
        ruler = nlp.add_pipe("entity_ruler", before="ner", config={"overwrite_ents": False})
        ruler.add_patterns(patterns)
        logger.info(f"Added {len(patterns)} custom entity patterns")


def extract_entities(text: str) -> list[ExtractedEntity]:
    """Extract named entities from text."""
    nlp = get_nlp()
    doc = nlp(text[:10000])  # limit input size

    entities: list[ExtractedEntity] = []
    seen: set[str] = set()

    for ent in doc.ents:
        etype = SPACY_LABEL_MAP.get(ent.label_)
        if etype is None:
            continue

        key = f"{ent.text.lower()}:{etype}"
        if key in seen:
            continue
        seen.add(key)

        role = EntityRole.LOCATION if etype in (EntityType.GPE, EntityType.LOC, EntityType.FAC) else EntityRole.SUBJECT

        entities.append(ExtractedEntity(
            text=ent.text,
            entity_type=etype,
            role=role,
            confidence=1.0,
        ))

    return entities


def extract_event_triples(text: str) -> list[dict]:
    """Extract (ACTOR, ACTION, TARGET) triples via dependency parsing."""
    nlp = get_nlp()
    doc = nlp(text[:10000])
    triples = []

    for token in doc:
        if token.pos_ != "VERB":
            continue

        lemma = token.lemma_.lower()
        event_type = EVENT_VERB_MAP.get(lemma)
        if event_type is None:
            continue

        # Find subject and object
        subj = None
        obj = None
        for child in token.children:
            if child.dep_ in ("nsubj", "nsubjpass") and child.ent_type_:
                subj = child.text
            elif child.dep_ in ("dobj", "pobj") and child.ent_type_:
                obj = child.text

        if subj or obj:
            triples.append({
                "actor": subj,
                "action": lemma,
                "target": obj,
                "event_type": event_type,
            })

    return triples
