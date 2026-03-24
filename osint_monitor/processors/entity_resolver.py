"""Entity resolution: normalisation, coreference, type-correction, then
alias-based + fuzzy matching."""

from __future__ import annotations

import logging
import re
from datetime import datetime

from rapidfuzz import fuzz
from sqlalchemy.orm import Session

from osint_monitor.core.config import load_entities_config
from osint_monitor.core.database import Entity
from osint_monitor.core.models import EntityType, ExtractedEntity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------
FUZZY_THRESHOLD_SAME_TYPE = 80   # same entity-type comparison
FUZZY_THRESHOLD_CROSS_TYPE = 85  # cross-type comparison

# ---------------------------------------------------------------------------
# 1. Abbreviation expansion (applied *before* fuzzy matching)
# ---------------------------------------------------------------------------
ABBREVIATION_MAP: dict[str, str] = {
    "u.s.":   "united states",
    "u.s":    "united states",
    "us":     "united states",
    "usa":    "united states",
    "uk":     "united kingdom",
    "eu":     "european union",
    "uae":    "united arab emirates",
    "dprk":   "north korea",
    "prc":    "china",
    "roc":    "taiwan",
}

# ---------------------------------------------------------------------------
# 2. Coreference map – known geopolitical / org synonyms
#    Maps every variant (lowercased) to a single canonical form.
# ---------------------------------------------------------------------------
_COREFERENCE_GROUPS: list[tuple[str, list[str]]] = [
    ("United States", [
        "united states", "u.s.", "u.s", "us", "usa",
        "america", "united states of america",
        "washington",  # as country, not city
    ]),
    ("Russia", [
        "russia", "russian federation", "moscow",
    ]),
    ("China", [
        "china", "people's republic of china", "prc", "beijing",
    ]),
    ("Iran", [
        "iran", "islamic republic of iran", "tehran",
    ]),
    ("Israel", [
        "israel", "tel aviv",
    ]),
    ("Ukraine", [
        "ukraine", "kyiv", "kiev",
    ]),
    ("North Korea", [
        "north korea", "dprk", "pyongyang",
    ]),
    ("U.S. Central Command", [
        "centcom", "u.s. central command", "united states central command",
    ]),
    ("Department of Defense", [
        "pentagon", "department of defense", "dod",
    ]),
    ("NATO", [
        "nato", "north atlantic treaty organization",
    ]),
]

COREFERENCE_MAP: dict[str, str] = {}
for _canonical, _variants in _COREFERENCE_GROUPS:
    for _v in _variants:
        COREFERENCE_MAP[_v] = _canonical.lower()

# ---------------------------------------------------------------------------
# 3. Type-correction table – spaCy mis-tags these as ORG
# ---------------------------------------------------------------------------
KNOWN_PERSONS: set[str] = {
    "trump", "donald trump",
    "putin", "vladimir putin",
    "xi jinping", "xi",
    "zelenskyy", "zelensky", "volodymyr zelenskyy",
    "netanyahu", "benjamin netanyahu",
    "khamenei", "ali khamenei",
    "hegseth", "pete hegseth",
}

# ---------------------------------------------------------------------------
# Leading-article regex
# ---------------------------------------------------------------------------
_ARTICLE_RE = re.compile(r"^(the|a|an)\s+", re.IGNORECASE)
_TWITTER_RE = re.compile(r"^@")


# ---------------------------------------------------------------------------
# Normalisation helper
# ---------------------------------------------------------------------------

def normalise(text: str) -> str:
    """Return a normalised form used for comparison / lookup.

    Steps:
      1. Strip & lowercase
      2. Strip leading articles ("the ", "a ", "an ")
      3. Strip @ prefix (Twitter handles)
      4. Expand known abbreviations
      5. Apply coreference map
    """
    t = text.strip().lower()
    t = _ARTICLE_RE.sub("", t).strip()
    t = _TWITTER_RE.sub("", t).strip()

    # Full-text abbreviation replacement (if the *entire* normalised string
    # matches an abbreviation key, expand it).
    if t in ABBREVIATION_MAP:
        t = ABBREVIATION_MAP[t]

    # Coreference collapse
    if t in COREFERENCE_MAP:
        t = COREFERENCE_MAP[t]

    return t


def correct_entity_type(text: str, entity_type: EntityType) -> EntityType:
    """Fix known mis-classifications (e.g. 'Trump' tagged ORG -> PERSON)."""
    if normalise(text) in KNOWN_PERSONS or text.strip().lower() in KNOWN_PERSONS:
        if entity_type != EntityType.PERSON:
            logger.debug(
                "Type-corrected '%s' from %s -> PERSON", text, entity_type
            )
            return EntityType.PERSON
    return entity_type


# ---------------------------------------------------------------------------
# Main resolver
# ---------------------------------------------------------------------------

class EntityResolver:
    """Resolves extracted entity mentions to canonical entities in the DB.

    Resolution order:
      0. Normalise text, correct entity type
      1. Exact alias match (on normalised text)
      2. Coreference-map match
      3. Fuzzy match (rapidfuzz) – threshold varies by type match
      4. Create new entity if no match
    """

    def __init__(self, session: Session):
        self.session = session
        self._alias_map: dict[str, int] | None = None
        # Secondary map: normalised-form -> entity_id (for normalisation hits)
        self._norm_map: dict[str, int] | None = None

    # ------------------------------------------------------------------
    # Alias / normalisation caches
    # ------------------------------------------------------------------

    def _build_alias_map(self) -> dict[str, int]:
        """Build lowercase alias -> entity_id lookup."""
        if self._alias_map is not None:
            return self._alias_map

        self._alias_map = {}
        self._norm_map = {}
        entities = self.session.query(Entity).all()
        for ent in entities:
            key = ent.canonical_name.lower()
            self._alias_map[key] = ent.id
            self._norm_map[normalise(ent.canonical_name)] = ent.id
            if ent.aliases:
                for alias in ent.aliases:
                    self._alias_map[alias.lower()] = ent.id
                    self._norm_map[normalise(alias)] = ent.id
        return self._alias_map

    def _get_norm_map(self) -> dict[str, int]:
        if self._norm_map is None:
            self._build_alias_map()
        assert self._norm_map is not None
        return self._norm_map

    def _entity_type_for_id(self, eid: int) -> str | None:
        """Return the entity_type string for a given entity id (cheap)."""
        ent = self.session.get(Entity, eid)
        return ent.entity_type if ent else None

    # ------------------------------------------------------------------
    # Core resolution
    # ------------------------------------------------------------------

    def resolve(self, extracted: ExtractedEntity) -> Entity:
        """Resolve an extracted entity to a database Entity.

        0. Normalise + type-correct
        1. Exact alias match (raw lowercase & normalised form)
        2. Fuzzy match (rapidfuzz) with type-aware thresholds
        3. Create new entity if no match
        """
        # --- Step 0: normalise & type-correct --------------------------------
        corrected_type = correct_entity_type(
            extracted.text, extracted.entity_type
        )
        extracted = extracted.model_copy(
            update={"entity_type": corrected_type}
        )

        text_lower = extracted.text.strip().lower()
        text_norm = normalise(extracted.text)

        alias_map = self._build_alias_map()
        norm_map = self._get_norm_map()

        # --- Step 1: Exact match (raw lowercase) ----------------------------
        if text_lower in alias_map:
            entity = self.session.get(Entity, alias_map[text_lower])
            if entity:
                entity.last_seen_at = datetime.utcnow()
                return entity

        # --- Step 1b: Exact match (normalised form) -------------------------
        if text_norm in norm_map:
            entity = self.session.get(Entity, norm_map[text_norm])
            if entity:
                # Register the raw text as a new alias so future lookups are
                # instant.
                self._register_alias(entity, extracted.text)
                entity.last_seen_at = datetime.utcnow()
                return entity

        # --- Step 2: Fuzzy match with type-aware thresholds ------------------
        best_score = 0.0
        best_id: int | None = None

        for alias, eid in alias_map.items():
            # Compare normalised forms for better fuzzy performance
            alias_norm = normalise(alias)
            score = fuzz.ratio(text_norm, alias_norm)
            if score > best_score:
                best_score = score
                best_id = eid

        if best_id is not None:
            target_type = self._entity_type_for_id(best_id)
            threshold = (
                FUZZY_THRESHOLD_SAME_TYPE
                if target_type == corrected_type.value
                else FUZZY_THRESHOLD_CROSS_TYPE
            )

            if best_score >= threshold:
                entity = self.session.get(Entity, best_id)
                if entity:
                    self._register_alias(entity, extracted.text)
                    entity.last_seen_at = datetime.utcnow()
                    logger.debug(
                        "Fuzzy matched '%s' -> '%s' (%.0f%%, threshold=%d)",
                        extracted.text,
                        entity.canonical_name,
                        best_score,
                        threshold,
                    )
                    return entity

        # --- Step 3: Create new entity --------------------------------------
        canonical = extracted.canonical_name or extracted.text
        entity = Entity(
            canonical_name=canonical,
            entity_type=corrected_type.value,
            aliases=[extracted.text] if extracted.text != canonical else [],
            first_seen_at=datetime.utcnow(),
            last_seen_at=datetime.utcnow(),
        )
        self.session.add(entity)
        self.session.flush()  # get the ID

        # Update caches
        self._alias_map[canonical.lower()] = entity.id
        self._norm_map[normalise(canonical)] = entity.id
        if extracted.text.lower() != canonical.lower():
            self._alias_map[extracted.text.lower()] = entity.id
            self._norm_map[normalise(extracted.text)] = entity.id

        logger.debug(
            "Created new entity: %s (%s)", canonical, corrected_type.value
        )
        return entity

    # ------------------------------------------------------------------
    # Alias management
    # ------------------------------------------------------------------

    def _register_alias(self, entity: Entity, raw_text: str) -> None:
        """Add *raw_text* as an alias of *entity* (if not already present)."""
        aliases = entity.aliases or []
        if raw_text.lower() not in [a.lower() for a in aliases]:
            aliases.append(raw_text)
            entity.aliases = aliases

        # Keep caches warm
        self._alias_map[raw_text.lower()] = entity.id
        norm = normalise(raw_text)
        if self._norm_map is not None:
            self._norm_map[norm] = entity.id

    # ------------------------------------------------------------------
    # Seeding from config
    # ------------------------------------------------------------------

    def seed_from_config(self):
        """Seed entities from entities.yaml into the database."""
        seeds = load_entities_config()
        count = 0
        for seed in seeds:
            existing = self.session.query(Entity).filter_by(
                canonical_name=seed.canonical_name
            ).first()
            if existing:
                # Update aliases
                existing_aliases = set(existing.aliases or [])
                existing_aliases.update(seed.aliases)
                existing.aliases = list(existing_aliases)
                if seed.wikidata_id:
                    existing.wikidata_id = seed.wikidata_id
                continue

            entity = Entity(
                canonical_name=seed.canonical_name,
                entity_type=seed.entity_type,
                aliases=seed.aliases,
                wikidata_id=seed.wikidata_id,
            )
            self.session.add(entity)
            count += 1

        self.session.commit()
        if count:
            logger.info("Seeded %d new entities from config", count)
        self._alias_map = None  # invalidate cache
        self._norm_map = None
