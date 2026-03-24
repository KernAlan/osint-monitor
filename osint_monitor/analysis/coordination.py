"""Coordination and influence detection.

Identifies coordinated inauthentic behaviour, tracks narrative evolution,
maps amplification networks, and detects narrative shifts around entities.
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from datetime import datetime, timedelta
from itertools import combinations

import numpy as np
from sqlalchemy import or_
from sqlalchemy.orm import Session

from osint_monitor.core.database import (
    Entity,
    Event,
    EventItem,
    ItemEntity,
    RawItem,
    Source,
)
from osint_monitor.processors.embeddings import (
    blob_to_embedding,
    cosine_similarity,
    embed_text,
    embed_texts,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Coordinated Posting Detection
# ---------------------------------------------------------------------------

def detect_coordinated_posting(
    session: Session,
    hours_back: int = 24,
    time_window_seconds: int = 60,
) -> list[dict]:
    """Find accounts that post suspiciously close together with similar content.

    Groups items by source, then finds pairs from *different* sources that were
    published within ``time_window_seconds`` of each other.  If the content
    similarity (via embeddings) exceeds 0.7, the pair is flagged as potentially
    coordinated.

    Returns a list of dicts:
        {
            "source_a": str,
            "source_b": str,
            "time_diff_seconds": int,
            "similarity": float,
            "items": [{"id": int, "title": str, "source": str, "published_at": str}, ...]
        }
    """
    cutoff = datetime.utcnow() - timedelta(hours=hours_back)

    items = (
        session.query(RawItem)
        .filter(
            RawItem.published_at >= cutoff,
            RawItem.published_at.isnot(None),
        )
        .order_by(RawItem.published_at.asc())
        .all()
    )

    if len(items) < 2:
        return []

    # Pre-load source names
    source_cache: dict[int, str] = {}
    for item in items:
        if item.source_id not in source_cache:
            source = session.get(Source, item.source_id)
            source_cache[item.source_id] = source.name if source else f"source_{item.source_id}"

    # Build list of (item, source_name, published_at) tuples sorted by time
    timed_items = [
        (item, source_cache[item.source_id], item.published_at)
        for item in items
        if item.published_at is not None
    ]
    timed_items.sort(key=lambda t: t[2])

    # Sliding window to find temporally close pairs from different sources
    coordinated: list[dict] = []
    seen_pairs: set[tuple[int, int]] = set()

    for i in range(len(timed_items)):
        item_a, src_a, time_a = timed_items[i]

        for j in range(i + 1, len(timed_items)):
            item_b, src_b, time_b = timed_items[j]

            diff_seconds = abs((time_b - time_a).total_seconds())
            if diff_seconds > time_window_seconds:
                break  # sorted by time, so all subsequent will be further apart

            # Skip same source
            if item_a.source_id == item_b.source_id:
                continue

            # Skip already-checked pairs
            pair_key = (min(item_a.id, item_b.id), max(item_a.id, item_b.id))
            if pair_key in seen_pairs:
                continue
            seen_pairs.add(pair_key)

            # Compute content similarity via embeddings
            try:
                emb_a = _get_embedding(item_a)
                emb_b = _get_embedding(item_b)
                similarity = cosine_similarity(emb_a, emb_b)
            except Exception:
                continue

            if similarity > 0.7:
                coordinated.append({
                    "source_a": src_a,
                    "source_b": src_b,
                    "time_diff_seconds": int(diff_seconds),
                    "similarity": round(float(similarity), 4),
                    "items": [
                        {
                            "id": item_a.id,
                            "title": item_a.title,
                            "source": src_a,
                            "published_at": time_a.isoformat(),
                        },
                        {
                            "id": item_b.id,
                            "title": item_b.title,
                            "source": src_b,
                            "published_at": time_b.isoformat(),
                        },
                    ],
                })

    # Sort by highest similarity first
    coordinated.sort(key=lambda d: d["similarity"], reverse=True)

    if coordinated:
        logger.info(
            f"Coordinated posting detection: found {len(coordinated)} suspicious "
            f"pair(s) in the last {hours_back}h"
        )

    return coordinated


# ---------------------------------------------------------------------------
# Narrative Tracking
# ---------------------------------------------------------------------------

def track_narrative(
    session: Session,
    keywords: list[str],
    hours_back: int = 72,
) -> dict:
    """Track how a narrative evolves over time.

    Finds all items matching any of the given keywords, groups them into
    6-hour time buckets, and tracks mention count, source spread, and a
    simple sentiment proxy per bucket.

    Returns:
        {
            "keyword": str,
            "timeline": [
                {"window": str, "count": int, "sources": [str, ...]},
                ...
            ],
            "peak_time": str,
            "spread_velocity": float,
        }
    """
    cutoff = datetime.utcnow() - timedelta(hours=hours_back)
    keyword_pattern = "|".join(re.escape(kw) for kw in keywords)
    keyword_display = ", ".join(keywords)

    # Query items containing any of the keywords (case-insensitive via LIKE)
    filters = [
        or_(
            RawItem.title.ilike(f"%{kw}%"),
            RawItem.content.ilike(f"%{kw}%"),
        )
        for kw in keywords
    ]

    items = (
        session.query(RawItem)
        .filter(
            RawItem.fetched_at >= cutoff,
            or_(*filters),
        )
        .order_by(RawItem.published_at.asc())
        .all()
    )

    # Pre-load source names
    source_cache: dict[int, str] = {}
    for item in items:
        if item.source_id not in source_cache:
            source = session.get(Source, item.source_id)
            source_cache[item.source_id] = source.name if source else f"source_{item.source_id}"

    # Build 6-hour time buckets
    bucket_size = timedelta(hours=6)
    buckets: dict[str, dict] = {}  # window_label -> {"count": int, "sources": set}

    # Generate all bucket labels from cutoff to now
    current = cutoff
    now = datetime.utcnow()
    while current < now:
        label = current.strftime("%Y-%m-%d %H:%M")
        buckets[label] = {"start": current, "end": current + bucket_size, "count": 0, "sources": set()}
        current += bucket_size

    # Assign items to buckets
    for item in items:
        ts = item.published_at or item.fetched_at
        for label, bucket in buckets.items():
            if bucket["start"] <= ts < bucket["end"]:
                bucket["count"] += 1
                bucket["sources"].add(source_cache.get(item.source_id, "unknown"))
                break

    # Build timeline
    timeline: list[dict] = []
    peak_count = 0
    peak_time = ""

    for label in sorted(buckets.keys()):
        bucket = buckets[label]
        entry = {
            "window": label,
            "count": bucket["count"],
            "sources": sorted(bucket["sources"]),
        }
        timeline.append(entry)

        if bucket["count"] > peak_count:
            peak_count = bucket["count"]
            peak_time = label

    # Compute spread velocity: how quickly the narrative appears in new sources
    # Measured as unique sources per hour over the active period
    all_sources: set[str] = set()
    first_mention_time: datetime | None = None
    last_mention_time: datetime | None = None

    for item in items:
        ts = item.published_at or item.fetched_at
        all_sources.add(source_cache.get(item.source_id, "unknown"))
        if first_mention_time is None or ts < first_mention_time:
            first_mention_time = ts
        if last_mention_time is None or ts > last_mention_time:
            last_mention_time = ts

    spread_velocity = 0.0
    if first_mention_time and last_mention_time and first_mention_time != last_mention_time:
        active_hours = max((last_mention_time - first_mention_time).total_seconds() / 3600.0, 0.1)
        spread_velocity = round(len(all_sources) / active_hours, 4)

    return {
        "keyword": keyword_display,
        "timeline": timeline,
        "peak_time": peak_time,
        "spread_velocity": spread_velocity,
    }


# ---------------------------------------------------------------------------
# Amplification Network Mapping
# ---------------------------------------------------------------------------

# Patterns for detecting retweet/amplification in content
_RT_PATTERNS = [
    re.compile(r"RT\s+@(\w+)", re.IGNORECASE),
    re.compile(r"(?:Retweet|retweet|RETWEET)\s+(?:by\s+)?@(\w+)", re.IGNORECASE),
    re.compile(r"via\s+@(\w+)", re.IGNORECASE),
]


def map_amplification_network(
    session: Session,
    hours_back: int = 72,
) -> dict:
    """Map who amplifies whom based on RT/retweet patterns in content.

    Scans items (primarily Twitter/Nitter) for retweet attribution patterns and
    builds a directed graph of amplification relationships.

    Returns:
        {
            "nodes": [{"name": str, "type": str, "amplification_count": int}, ...],
            "edges": [{"source": str, "target": str, "count": int}, ...],
        }
    """
    cutoff = datetime.utcnow() - timedelta(hours=hours_back)

    items = (
        session.query(RawItem)
        .filter(RawItem.fetched_at >= cutoff)
        .all()
    )

    # Pre-load source names
    source_cache: dict[int, str] = {}
    for item in items:
        if item.source_id not in source_cache:
            source = session.get(Source, item.source_id)
            source_cache[item.source_id] = source.name if source else f"source_{item.source_id}"

    # Extract amplification edges
    edge_counts: dict[tuple[str, str], int] = defaultdict(int)  # (amplifier, original_author) -> count
    node_amplify_count: dict[str, int] = defaultdict(int)       # node -> times it amplified
    node_amplified_count: dict[str, int] = defaultdict(int)     # node -> times it was amplified
    all_nodes: set[str] = set()

    for item in items:
        text = f"{item.title or ''} {item.content or ''}"
        amplifier = source_cache.get(item.source_id, "unknown")

        for pattern in _RT_PATTERNS:
            matches = pattern.findall(text)
            for original_author in matches:
                original_author = original_author.strip().lower()
                if original_author == amplifier.lower():
                    continue  # skip self-references

                edge_counts[(amplifier, original_author)] += 1
                node_amplify_count[amplifier] += 1
                node_amplified_count[original_author] += 1
                all_nodes.add(amplifier)
                all_nodes.add(original_author)

    # Build nodes list
    nodes: list[dict] = []
    for name in sorted(all_nodes):
        amp_count = node_amplify_count.get(name, 0)
        amped_count = node_amplified_count.get(name, 0)

        # Classify node type
        if amped_count > amp_count * 2 and amped_count > 0:
            node_type = "influencer"
        elif amp_count > amped_count * 2 and amp_count > 0:
            node_type = "amplifier"
        else:
            node_type = "participant"

        nodes.append({
            "name": name,
            "type": node_type,
            "amplification_count": amp_count + amped_count,
        })

    # Build edges list
    edges: list[dict] = []
    for (src, tgt), count in sorted(edge_counts.items(), key=lambda x: x[1], reverse=True):
        edges.append({
            "source": src,
            "target": tgt,
            "count": count,
        })

    if nodes:
        logger.info(
            f"Amplification network: {len(nodes)} nodes, {len(edges)} edges "
            f"over last {hours_back}h"
        )

    return {"nodes": nodes, "edges": edges}


# ---------------------------------------------------------------------------
# Narrative Shift Detection
# ---------------------------------------------------------------------------

def detect_narrative_shift(
    session: Session,
    entity_name: str,
    days: int = 14,
) -> dict:
    """Detect when the narrative around an entity changes significantly.

    Splits items mentioning the entity into two time windows:
      - recent: last 3 days
      - previous: the preceding (days - 3) days

    Computes embedding centroids for each window and measures cosine distance
    between them. A large distance indicates a narrative shift.

    Returns:
        {
            "entity": str,
            "shift_magnitude": float,
            "is_significant": bool,
            "recent_themes": [str, ...],
            "previous_themes": [str, ...],
        }
    """
    now = datetime.utcnow()
    recent_cutoff = now - timedelta(days=3)
    previous_cutoff = now - timedelta(days=days)

    # Find the entity
    entity = (
        session.query(Entity)
        .filter(Entity.canonical_name == entity_name)
        .first()
    )

    if not entity:
        return {
            "entity": entity_name,
            "shift_magnitude": 0.0,
            "is_significant": False,
            "recent_themes": [],
            "previous_themes": [],
        }

    # Get all items mentioning this entity within the time window
    item_entity_rows = (
        session.query(ItemEntity)
        .filter(ItemEntity.entity_id == entity.id)
        .all()
    )
    item_ids = [ie.item_id for ie in item_entity_rows]

    if not item_ids:
        return {
            "entity": entity_name,
            "shift_magnitude": 0.0,
            "is_significant": False,
            "recent_themes": [],
            "previous_themes": [],
        }

    items = (
        session.query(RawItem)
        .filter(
            RawItem.id.in_(item_ids),
            RawItem.fetched_at >= previous_cutoff,
        )
        .all()
    )

    # Split into recent vs previous windows
    recent_items: list[RawItem] = []
    previous_items: list[RawItem] = []

    for item in items:
        ts = item.published_at or item.fetched_at
        if ts >= recent_cutoff:
            recent_items.append(item)
        elif ts >= previous_cutoff:
            previous_items.append(item)

    if not recent_items or not previous_items:
        return {
            "entity": entity_name,
            "shift_magnitude": 0.0,
            "is_significant": False,
            "recent_themes": _extract_themes(recent_items),
            "previous_themes": _extract_themes(previous_items),
        }

    # Compute embedding centroids for each window
    recent_centroid = _compute_centroid(recent_items)
    previous_centroid = _compute_centroid(previous_items)

    if recent_centroid is None or previous_centroid is None:
        return {
            "entity": entity_name,
            "shift_magnitude": 0.0,
            "is_significant": False,
            "recent_themes": _extract_themes(recent_items),
            "previous_themes": _extract_themes(previous_items),
        }

    # Cosine distance = 1 - cosine_similarity
    sim = cosine_similarity(recent_centroid, previous_centroid)
    shift_magnitude = round(1.0 - sim, 4)

    # A shift > 0.3 is considered significant (tunable threshold)
    is_significant = shift_magnitude > 0.3

    if is_significant:
        logger.info(
            f"Narrative shift detected for '{entity_name}': "
            f"magnitude={shift_magnitude:.4f}"
        )

    return {
        "entity": entity_name,
        "shift_magnitude": shift_magnitude,
        "is_significant": is_significant,
        "recent_themes": _extract_themes(recent_items),
        "previous_themes": _extract_themes(previous_items),
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_embedding(item: RawItem) -> np.ndarray:
    """Retrieve or compute an embedding for an item."""
    if item.embedding is not None:
        try:
            return blob_to_embedding(item.embedding)
        except Exception:
            pass
    # Fall back to computing on the fly
    text = f"{item.title or ''} {(item.content or '')[:200]}".strip()
    return embed_text(text)


def _compute_centroid(items: list[RawItem]) -> np.ndarray | None:
    """Compute the mean embedding (centroid) for a list of items."""
    embeddings: list[np.ndarray] = []

    for item in items:
        try:
            emb = _get_embedding(item)
            embeddings.append(emb)
        except Exception:
            continue

    if not embeddings:
        return None

    centroid = np.mean(embeddings, axis=0).astype(np.float32)
    # Normalize the centroid
    norm = np.linalg.norm(centroid)
    if norm > 0:
        centroid = centroid / norm
    return centroid


def _extract_themes(items: list[RawItem], max_themes: int = 5) -> list[str]:
    """Extract dominant themes from a set of items using title frequency analysis.

    Returns the most common significant words/phrases from item titles as a
    simple proxy for thematic content.
    """
    if not items:
        return []

    # Collect title words, filtering out stopwords and short tokens
    stopwords = {
        "the", "a", "an", "in", "on", "at", "to", "for", "of", "and", "or",
        "is", "are", "was", "were", "be", "been", "has", "have", "had", "will",
        "with", "from", "by", "as", "it", "its", "this", "that", "not", "but",
        "he", "she", "they", "we", "you", "his", "her", "their", "our", "your",
        "who", "what", "which", "when", "where", "how", "why", "all", "each",
        "do", "does", "did", "can", "could", "would", "should", "may", "might",
        "about", "after", "before", "between", "into", "over", "under", "up",
        "out", "no", "so", "if", "than", "too", "very", "just", "also", "more",
        "says", "said", "new", "reuters", "ap", "afp",
    }

    word_counts: dict[str, int] = defaultdict(int)
    for item in items:
        title = (item.title or "").lower()
        # Extract meaningful words (3+ chars, alpha only)
        words = re.findall(r"[a-z]{3,}", title)
        for word in words:
            if word not in stopwords:
                word_counts[word] += 1

    # Return top themes by frequency
    sorted_words = sorted(word_counts.items(), key=lambda x: x[1], reverse=True)
    return [word for word, _ in sorted_words[:max_themes]]
