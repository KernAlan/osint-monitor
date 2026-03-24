"""Transformer-based and rule-based relation extraction.

Upgrades the basic (ACTOR, ACTION, TARGET) triples from ``nlp.py`` with:
  - Structured LLM-driven extraction (``extract_relations_llm``)
  - spaCy DependencyMatcher patterns for common geopolitical relationships
  - Database persistence via EntityRelationship records
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from osint_monitor.core.database import Entity, EntityRelationship

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pydantic model for parsed LLM output
# ---------------------------------------------------------------------------

class ExtractedRelation(BaseModel):
    """A single extracted relation."""
    subject: str
    predicate: str
    object: str
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)


class RelationExtractionResult(BaseModel):
    """Wrapper for a list of extracted relations (for JSON parsing)."""
    relations: list[ExtractedRelation] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# spaCy DependencyMatcher pattern definitions
# ---------------------------------------------------------------------------

# Each pattern definition has:
#   - ``label``:   the relationship predicate to emit
#   - ``pattern``: a spaCy DependencyMatcher-compatible pattern list
#   - ``subj_id``: which named node is the subject
#   - ``obj_id``:  which named node is the object
#
# These are compiled lazily into actual DependencyMatcher patterns.

RELATION_PATTERNS: list[dict] = [
    {
        "label": "attacked",
        "pattern": [
            {"RIGHT_ID": "verb", "RIGHT_ATTRS": {"LEMMA": {"IN": ["attack", "strike", "bomb", "shell"]}, "POS": "VERB"}},
            {"LEFT_ID": "verb", "REL_OP": ">", "RIGHT_ID": "subject", "RIGHT_ATTRS": {"DEP": {"IN": ["nsubj", "nsubjpass"]}, "ENT_TYPE": {"IN": ["GPE", "ORG", "PERSON"]}}},
            {"LEFT_ID": "verb", "REL_OP": ">", "RIGHT_ID": "object", "RIGHT_ATTRS": {"DEP": {"IN": ["dobj", "pobj"]}, "ENT_TYPE": {"IN": ["GPE", "ORG", "FAC", "LOC"]}}},
        ],
        "subj_id": "subject",
        "obj_id": "object",
    },
    {
        "label": "signed_agreement_with",
        "pattern": [
            {"RIGHT_ID": "verb", "RIGHT_ATTRS": {"LEMMA": "sign", "POS": "VERB"}},
            {"LEFT_ID": "verb", "REL_OP": ">", "RIGHT_ID": "subject", "RIGHT_ATTRS": {"DEP": "nsubj", "ENT_TYPE": {"IN": ["GPE", "ORG"]}}},
            {"LEFT_ID": "verb", "REL_OP": ">", "RIGHT_ID": "agreement", "RIGHT_ATTRS": {"DEP": "dobj"}},
            {"LEFT_ID": "verb", "REL_OP": ">>", "RIGHT_ID": "object", "RIGHT_ATTRS": {"ENT_TYPE": {"IN": ["GPE", "ORG"]}, "DEP": "pobj"}},
        ],
        "subj_id": "subject",
        "obj_id": "object",
    },
    {
        "label": "sanctioned",
        "pattern": [
            {"RIGHT_ID": "verb", "RIGHT_ATTRS": {"LEMMA": "sanction", "POS": "VERB"}},
            {"LEFT_ID": "verb", "REL_OP": ">", "RIGHT_ID": "subject", "RIGHT_ATTRS": {"DEP": "nsubj", "ENT_TYPE": {"IN": ["GPE", "ORG"]}}},
            {"LEFT_ID": "verb", "REL_OP": ">", "RIGHT_ID": "object", "RIGHT_ATTRS": {"DEP": {"IN": ["dobj", "pobj"]}, "ENT_TYPE": {"IN": ["GPE", "ORG", "PERSON"]}}},
        ],
        "subj_id": "subject",
        "obj_id": "object",
    },
    {
        "label": "met_with",
        "pattern": [
            {"RIGHT_ID": "verb", "RIGHT_ATTRS": {"LEMMA": "meet", "POS": "VERB"}},
            {"LEFT_ID": "verb", "REL_OP": ">", "RIGHT_ID": "subject", "RIGHT_ATTRS": {"DEP": "nsubj", "ENT_TYPE": {"IN": ["PERSON", "GPE", "ORG"]}}},
            {"LEFT_ID": "verb", "REL_OP": ">>", "RIGHT_ID": "object", "RIGHT_ATTRS": {"ENT_TYPE": {"IN": ["PERSON", "GPE", "ORG"]}, "DEP": "pobj"}},
        ],
        "subj_id": "subject",
        "obj_id": "object",
    },
    {
        "label": "deployed_to",
        "pattern": [
            {"RIGHT_ID": "verb", "RIGHT_ATTRS": {"LEMMA": "deploy", "POS": "VERB"}},
            {"LEFT_ID": "verb", "REL_OP": ">", "RIGHT_ID": "subject", "RIGHT_ATTRS": {"DEP": "nsubj", "ENT_TYPE": {"IN": ["GPE", "ORG"]}}},
            {"LEFT_ID": "verb", "REL_OP": ">>", "RIGHT_ID": "object", "RIGHT_ATTRS": {"ENT_TYPE": {"IN": ["GPE", "LOC", "FAC"]}, "DEP": "pobj"}},
        ],
        "subj_id": "subject",
        "obj_id": "object",
    },
    {
        "label": "arms_deal",
        "pattern": [
            {"RIGHT_ID": "verb", "RIGHT_ATTRS": {"LEMMA": {"IN": ["sell", "supply", "deliver", "provide"]}, "POS": "VERB"}},
            {"LEFT_ID": "verb", "REL_OP": ">", "RIGHT_ID": "subject", "RIGHT_ATTRS": {"DEP": "nsubj", "ENT_TYPE": {"IN": ["GPE", "ORG"]}}},
            {"LEFT_ID": "verb", "REL_OP": ">>", "RIGHT_ID": "object", "RIGHT_ATTRS": {"ENT_TYPE": {"IN": ["GPE", "ORG"]}, "DEP": "pobj"}},
        ],
        "subj_id": "subject",
        "obj_id": "object",
    },
    {
        "label": "accused_of",
        "pattern": [
            {"RIGHT_ID": "verb", "RIGHT_ATTRS": {"LEMMA": {"IN": ["accuse", "blame", "charge"]}, "POS": "VERB"}},
            {"LEFT_ID": "verb", "REL_OP": ">", "RIGHT_ID": "subject", "RIGHT_ATTRS": {"DEP": "nsubj", "ENT_TYPE": {"IN": ["GPE", "ORG", "PERSON"]}}},
            {"LEFT_ID": "verb", "REL_OP": ">", "RIGHT_ID": "object", "RIGHT_ATTRS": {"DEP": "dobj", "ENT_TYPE": {"IN": ["GPE", "ORG", "PERSON"]}}},
        ],
        "subj_id": "subject",
        "obj_id": "object",
    },
]

# Cache for compiled DependencyMatcher
_dep_matcher = None
_pattern_label_map: dict[str, str] = {}  # match_id name -> relation label
_pattern_node_map: dict[str, tuple[str, str]] = {}  # match_id name -> (subj_id, obj_id)


def _get_dep_matcher():
    """Build and cache the spaCy DependencyMatcher from RELATION_PATTERNS."""
    global _dep_matcher, _pattern_label_map, _pattern_node_map

    if _dep_matcher is not None:
        return _dep_matcher

    from spacy.matcher import DependencyMatcher
    from osint_monitor.processors.nlp import get_nlp

    nlp = get_nlp()
    _dep_matcher = DependencyMatcher(nlp.vocab)

    for i, pdef in enumerate(RELATION_PATTERNS):
        name = f"REL_{i}_{pdef['label']}"
        _dep_matcher.add(name, [pdef["pattern"]])
        _pattern_label_map[name] = pdef["label"]
        _pattern_node_map[name] = (pdef["subj_id"], pdef["obj_id"])

    logger.debug("Built DependencyMatcher with %d relation patterns", len(RELATION_PATTERNS))
    return _dep_matcher


# ---------------------------------------------------------------------------
# 1. LLM-based relation extraction
# ---------------------------------------------------------------------------

def extract_relations_llm(
    text: str,
    entities: list[str],
    provider: str | None = None,
) -> list[dict]:
    """Use an LLM to extract structured relations from *text*.

    Args:
        text: The source text to analyse.
        entities: Pre-identified entity names to focus on.
        provider: Optional LLM provider name (``"openai"``, ``"anthropic"``, etc.).

    Returns:
        List of ``{"subject": str, "predicate": str, "object": str, "confidence": float}``
    """
    from osint_monitor.analysis.llm import get_llm

    if not entities:
        return []

    entity_list = ", ".join(entities[:30])  # cap to avoid token overflow

    system_prompt = (
        "Extract relationships between the given entities from the text. "
        "For each relationship, provide: subject, predicate, object, and "
        "confidence (0-1). Output as a JSON object with a single key "
        '"relations" containing a JSON array of objects with keys: '
        '"subject", "predicate", "object", "confidence".'
    )

    user_prompt = (
        f"Entities: {entity_list}\n\n"
        f"Text:\n{text[:6000]}\n\n"
        "Extract all relationships between these entities."
    )

    try:
        llm = get_llm(provider=provider)
        result = llm.generate_json(
            user_prompt,
            system=system_prompt,
            model_class=RelationExtractionResult,
        )
        if isinstance(result, RelationExtractionResult):
            return [r.model_dump() for r in result.relations]
        # If raw dict was returned
        if isinstance(result, dict) and "relations" in result:
            parsed = RelationExtractionResult(**result)
            return [r.model_dump() for r in parsed.relations]
        return []
    except Exception as exc:
        logger.warning("LLM relation extraction failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# 2. Rule-based / pattern-based relation extraction
# ---------------------------------------------------------------------------

def extract_relations_pattern(text: str) -> list[dict]:
    """Extract relations using spaCy DependencyMatcher patterns.

    Returns same format as :func:`extract_relations_llm`.
    """
    from osint_monitor.processors.nlp import get_nlp

    nlp = get_nlp()
    doc = nlp(text[:10_000])

    matcher = _get_dep_matcher()
    matches = matcher(doc)

    relations: list[dict] = []
    seen: set[tuple[str, str, str]] = set()

    for match_id, token_ids in matches:
        match_name = nlp.vocab.strings[match_id]
        label = _pattern_label_map.get(match_name)
        subj_key, obj_key = _pattern_node_map.get(match_name, ("subject", "object"))

        if label is None:
            continue

        # Map named node IDs to token indices.
        # The DependencyMatcher returns token_ids in the order the pattern
        # nodes were defined.  We look up the pattern to identify which
        # index corresponds to subj/obj.
        pattern_idx = int(match_name.split("_")[1])
        pdef = RELATION_PATTERNS[pattern_idx]
        node_names = [n.get("RIGHT_ID", "") for n in pdef["pattern"]]

        subj_idx = node_names.index(subj_key) if subj_key in node_names else None
        obj_idx = node_names.index(obj_key) if obj_key in node_names else None

        if subj_idx is None or obj_idx is None:
            continue
        if subj_idx >= len(token_ids) or obj_idx >= len(token_ids):
            continue

        subj_token = doc[token_ids[subj_idx]]
        obj_token = doc[token_ids[obj_idx]]

        subj_text = _ent_span_text(subj_token, doc)
        obj_text = _ent_span_text(obj_token, doc)

        dedup_key = (subj_text.lower(), label, obj_text.lower())
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        relations.append({
            "subject": subj_text,
            "predicate": label,
            "object": obj_text,
            "confidence": 0.75,
        })

    return relations


def _ent_span_text(token, doc) -> str:
    """If *token* is part of a named entity span, return the full entity text.
    Otherwise return the token text."""
    for ent in doc.ents:
        if ent.start <= token.i < ent.end:
            return ent.text
    return token.text


# ---------------------------------------------------------------------------
# 3. Unified extraction entry point
# ---------------------------------------------------------------------------

def extract_relations(
    text: str,
    entities: list[str] | None = None,
    use_llm: bool = False,
    provider: str | None = None,
) -> list[dict]:
    """Extract relations from *text*, merging pattern-based and (optionally) LLM results.

    Args:
        text: Source text.
        entities: Pre-identified entity names (used only for LLM extraction).
        use_llm: If True and an LLM provider is available, include LLM results.
        provider: LLM provider name override.

    Returns:
        Deduplicated list of ``{"subject", "predicate", "object", "confidence"}``.
    """
    # Always run pattern-based extraction
    results = extract_relations_pattern(text)

    # Optionally augment with LLM extraction
    if use_llm and entities:
        try:
            llm_results = extract_relations_llm(text, entities, provider=provider)
            results.extend(llm_results)
        except Exception as exc:
            logger.debug("LLM relation extraction skipped: %s", exc)

    # Deduplicate by (subject, predicate, object) keeping highest confidence
    deduped: dict[tuple[str, str, str], dict] = {}
    for rel in results:
        key = (rel["subject"].lower(), rel["predicate"].lower(), rel["object"].lower())
        existing = deduped.get(key)
        if existing is None or rel["confidence"] > existing["confidence"]:
            deduped[key] = rel

    return list(deduped.values())


# ---------------------------------------------------------------------------
# 4. Persist relations to database
# ---------------------------------------------------------------------------

def persist_relations(
    session: "Session",
    item_id: int,
    relations: list[dict],
) -> list[EntityRelationship]:
    """Resolve relation subjects/objects to Entity IDs and persist as
    :class:`EntityRelationship` records.

    Args:
        session: Active SQLAlchemy session.
        item_id: The RawItem ID that is the evidence for these relations.
        relations: Output from :func:`extract_relations`.

    Returns:
        List of created or existing :class:`EntityRelationship` instances.
    """
    from osint_monitor.core.models import EntityType, ExtractedEntity
    from osint_monitor.processors.entity_resolver import EntityResolver

    resolver = EntityResolver(session)
    created: list[EntityRelationship] = []

    for rel in relations:
        subj_text = rel.get("subject", "").strip()
        obj_text = rel.get("object", "").strip()
        predicate = rel.get("predicate", "").strip()
        confidence = float(rel.get("confidence", 1.0))

        if not subj_text or not obj_text or not predicate:
            continue

        # Resolve subject entity
        try:
            subj_entity = resolver.resolve(ExtractedEntity(
                text=subj_text,
                entity_type=EntityType.ORG,  # default; resolver will type-correct
            ))
        except Exception as exc:
            logger.debug("Could not resolve subject '%s': %s", subj_text, exc)
            continue

        # Resolve object entity
        try:
            obj_entity = resolver.resolve(ExtractedEntity(
                text=obj_text,
                entity_type=EntityType.ORG,
            ))
        except Exception as exc:
            logger.debug("Could not resolve object '%s': %s", obj_text, exc)
            continue

        # Check if this relationship already exists
        existing = (
            session.query(EntityRelationship)
            .filter_by(
                source_entity_id=subj_entity.id,
                target_entity_id=obj_entity.id,
                relationship_type=predicate,
            )
            .first()
        )

        if existing:
            # Update evidence list if this item is new evidence
            evidence_ids = existing.evidence_item_ids or []
            if item_id not in evidence_ids:
                evidence_ids.append(item_id)
                existing.evidence_item_ids = evidence_ids
                # Boost confidence slightly with additional evidence
                existing.confidence = min(existing.confidence + 0.05, 1.0)
            created.append(existing)
            continue

        # Create new relationship
        er = EntityRelationship(
            source_entity_id=subj_entity.id,
            target_entity_id=obj_entity.id,
            relationship_type=predicate,
            confidence=confidence,
            evidence_item_ids=[item_id],
        )
        session.add(er)
        created.append(er)

    try:
        session.flush()
    except Exception as exc:
        logger.warning("Failed to flush relation records: %s", exc)
        session.rollback()

    if created:
        logger.info(
            "Persisted %d relation(s) for item %d",
            len(created),
            item_id,
        )

    return created
