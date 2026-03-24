"""Multilingual support: language detection, translation, and entity extraction."""

from __future__ import annotations

import logging
import os
import re
from typing import Optional

from osint_monitor.core.models import ExtractedEntity, RawItemModel

logger = logging.getLogger(__name__)

# Simple in-memory translation cache: (text_hash, src, tgt) -> translated
_translation_cache: dict[tuple[str, str, str], str] = {}


# ---------------------------------------------------------------------------
# 1. Language detection (character-set heuristic)
# ---------------------------------------------------------------------------

# Unicode ranges for script detection
_CYRILLIC_RE = re.compile(r"[\u0400-\u04FF]")
_ARABIC_RE = re.compile(r"[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF]")
_PERSIAN_EXTRA_RE = re.compile(r"[\u06CC\u06A9\u067E\u0686\u06AF\u06BE]")
_CHINESE_RE = re.compile(r"[\u4E00-\u9FFF\u3400-\u4DBF]")
_KOREAN_RE = re.compile(r"[\uAC00-\uD7AF\u1100-\u11FF\u3130-\u318F]")
_HIRAGANA_RE = re.compile(r"[\u3040-\u309F]")
_KATAKANA_RE = re.compile(r"[\u30A0-\u30FF]")


def detect_language(text: str) -> str:
    """Detect the primary language of *text* using character-set heuristics.

    Returns an ISO 639-1 code: "ru", "ar", "fa", "zh", "ko", "ja", or "en"
    (default).  This avoids heavyweight dependencies like ``langdetect``.
    """
    if not text:
        return "en"

    # Sample a reasonable chunk to avoid scanning enormous texts
    sample = text[:5000]

    # Persian check must come before Arabic (Persian uses Arabic script +
    # a few extra characters)
    persian_hits = len(_PERSIAN_EXTRA_RE.findall(sample))
    arabic_hits = len(_ARABIC_RE.findall(sample))
    if persian_hits >= 3 and persian_hits / max(arabic_hits, 1) > 0.1:
        return "fa"

    if arabic_hits > 20:
        return "ar"

    if len(_CYRILLIC_RE.findall(sample)) > 20:
        return "ru"

    if len(_CHINESE_RE.findall(sample)) > 10:
        return "zh"

    if len(_KOREAN_RE.findall(sample)) > 10:
        return "ko"

    if (
        len(_HIRAGANA_RE.findall(sample)) > 5
        or len(_KATAKANA_RE.findall(sample)) > 5
    ):
        return "ja"

    return "en"


# ---------------------------------------------------------------------------
# 2. Translation
# ---------------------------------------------------------------------------

def translate_text(
    text: str,
    source_lang: str,
    target_lang: str = "en",
) -> str:
    """Translate *text* from *source_lang* to *target_lang*.

    Primary backend: OpenAI API (gpt-4o-mini).
    Fallback: returns original text prefixed with ``[untranslated:{lang}]``.

    Translations are cached in-memory to avoid redundant API calls.
    """
    if source_lang == target_lang:
        return text

    # Check cache
    cache_key = (text[:200], source_lang, target_lang)  # key on prefix to bound memory
    cached = _translation_cache.get(cache_key)
    if cached is not None:
        return cached

    translated = _translate_via_openai(text, source_lang, target_lang)
    if translated is not None:
        _translation_cache[cache_key] = translated
        return translated

    # Fallback: return untranslated with a tag
    fallback = f"[untranslated:{source_lang}] {text}"
    _translation_cache[cache_key] = fallback
    return fallback


def _translate_via_openai(
    text: str, source_lang: str, target_lang: str
) -> str | None:
    """Attempt translation using OpenAI."""
    try:
        from osint_monitor.analysis.llm import get_llm

        llm = get_llm(provider="openai")
        prompt = (
            f"Translate the following text from {source_lang} to {target_lang}. "
            "Output ONLY the translated text, nothing else.\n\n"
            f"{text}"
        )
        result = llm.generate(prompt, temperature=0.1)
        return result.strip() if result else None
    except Exception:
        logger.debug("OpenAI translation unavailable.", exc_info=True)
        return None


# ---------------------------------------------------------------------------
# 3. Multilingual item processing
# ---------------------------------------------------------------------------

def process_multilingual_item(raw_item: RawItemModel) -> RawItemModel:
    """Detect language, translate if non-English, and annotate the item.

    The returned ``RawItemModel`` has:
    - ``title`` / ``content`` in English (translated if necessary)
    - ``source_name`` prefixed with the detected language code when
      non-English, so downstream processors can reference it.

    The original-language text is preserved in the content field as a
    trailing block when translation occurs.
    """
    combined = (raw_item.title or "") + " " + (raw_item.content or "")
    lang = detect_language(combined)

    if lang == "en":
        return raw_item

    logger.info(
        "Detected language '%s' for item: %s", lang, raw_item.title[:80]
    )

    # Translate title and content separately for quality
    translated_title = translate_text(raw_item.title, lang, "en") if raw_item.title else ""
    translated_content = translate_text(raw_item.content, lang, "en") if raw_item.content else ""

    # Preserve originals as a trailing block
    original_block = (
        f"\n\n---\n[Original ({lang})]\n"
        f"Title: {raw_item.title}\n"
        f"Content: {raw_item.content[:1000]}"
    )

    return raw_item.model_copy(
        update={
            "title": translated_title,
            "content": translated_content + original_block,
            "source_name": f"[{lang}] {raw_item.source_name}" if raw_item.source_name else f"[{lang}]",
        }
    )


# ---------------------------------------------------------------------------
# 4. Multilingual entity extraction
# ---------------------------------------------------------------------------

def extract_entities_multilingual(
    text: str, lang: str
) -> list[ExtractedEntity]:
    """Extract named entities from *text* in the given language.

    Strategy per language:
    - ``en``: use existing spaCy English pipeline.
    - ``ru``: try ``ru_core_news_lg``, else translate-then-extract.
    - ``ar``, ``zh``, ``fa``, ``ko``, ``ja``: translate to English, extract.

    Entities include the original-language surface form when translation
    was used.
    """
    if lang == "en":
        return _extract_english(text)

    if lang == "ru":
        result = _extract_russian(text)
        if result is not None:
            return result
        # Fall through to translate-then-extract

    # Translate to English, then extract
    english_text = translate_text(text, lang, "en")

    # If translation failed (still prefixed with [untranslated:...]), return empty
    if english_text.startswith("[untranslated:"):
        logger.warning("Cannot extract entities: translation unavailable for '%s'.", lang)
        return []

    entities = _extract_english(english_text)

    # Tag entities as originating from translated text
    for ent in entities:
        if ent.canonical_name is None:
            ent.canonical_name = ent.text  # English form becomes canonical

    return entities


def _extract_english(text: str) -> list[ExtractedEntity]:
    """Extract entities using the standard English spaCy pipeline."""
    from osint_monitor.processors.nlp import extract_entities

    return extract_entities(text)


def _extract_russian(text: str) -> list[ExtractedEntity] | None:
    """Try extracting entities with a Russian spaCy model.

    Returns ``None`` if no Russian model is available (caller should
    fall back to translate-then-extract).
    """
    try:
        import spacy

        nlp = spacy.load("ru_core_news_lg")
    except OSError:
        logger.debug("ru_core_news_lg not available; falling back to translation.")
        return None

    from osint_monitor.core.models import EntityRole, EntityType
    from osint_monitor.processors.nlp import SPACY_LABEL_MAP

    doc = nlp(text[:10000])
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

        role = (
            EntityRole.LOCATION
            if etype in (EntityType.GPE, EntityType.LOC, EntityType.FAC)
            else EntityRole.SUBJECT
        )

        entities.append(
            ExtractedEntity(
                text=ent.text,
                entity_type=etype,
                role=role,
                confidence=0.9,  # slight discount for non-English model
            )
        )

    return entities
