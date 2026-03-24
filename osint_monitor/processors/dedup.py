"""Three-layer deduplication: exact hash, semantic near-duplicate, source-aware."""

from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime, timedelta

import numpy as np
from sqlalchemy.orm import Session

from osint_monitor.core.database import RawItem, EventItem
from osint_monitor.core.models import RawItemModel
from osint_monitor.processors.embeddings import (
    blob_to_embedding,
    cosine_similarity,
    embed_item,
    embedding_to_blob,
)

logger = logging.getLogger(__name__)

NEAR_DUPE_THRESHOLD = 0.85
NEAR_DUPE_WINDOW_HOURS = 72


def compute_content_hash(title: str, content: str = "") -> str:
    """SHA-256 of normalized title + content."""
    normalized = re.sub(r"\s+", " ", f"{title} {content}".lower().strip())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


class Deduplicator:
    """Three-layer deduplication engine."""

    def __init__(self, session: Session):
        self.session = session

    def check_exact_duplicate(self, content_hash: str) -> RawItem | None:
        """Layer 1: Exact hash match."""
        return self.session.query(RawItem).filter_by(content_hash=content_hash).first()

    def check_near_duplicate(
        self,
        embedding: np.ndarray,
        window_hours: int = NEAR_DUPE_WINDOW_HOURS,
    ) -> tuple[RawItem | None, float]:
        """Layer 2: Semantic near-duplicate via cosine similarity.

        Returns (matching_item, similarity_score) or (None, 0.0).
        """
        cutoff = datetime.utcnow() - timedelta(hours=window_hours)
        recent_items = (
            self.session.query(RawItem)
            .filter(
                RawItem.fetched_at >= cutoff,
                RawItem.embedding.isnot(None),
            )
            .all()
        )

        best_item = None
        best_score = 0.0

        for item in recent_items:
            try:
                stored_emb = blob_to_embedding(item.embedding)
                score = cosine_similarity(embedding, stored_emb)
                if score > best_score:
                    best_score = score
                    best_item = item
            except Exception:
                continue

        if best_score >= NEAR_DUPE_THRESHOLD:
            return best_item, best_score
        return None, 0.0

    def deduplicate(
        self,
        raw_item: RawItemModel,
    ) -> dict:
        """Run all dedup layers.

        Returns:
            {
                "is_duplicate": bool,
                "duplicate_type": "exact" | "near" | None,
                "existing_item": RawItem | None,
                "similarity": float,
                "content_hash": str,
                "embedding": np.ndarray,
            }
        """
        content_hash = compute_content_hash(raw_item.title, raw_item.content)

        # Layer 1: Exact
        existing = self.check_exact_duplicate(content_hash)
        if existing:
            logger.debug(f"Exact duplicate: {raw_item.title[:60]}")
            return {
                "is_duplicate": True,
                "duplicate_type": "exact",
                "existing_item": existing,
                "similarity": 1.0,
                "content_hash": content_hash,
                "embedding": None,
            }

        # Layer 2: Semantic near-duplicate
        embedding = embed_item(raw_item.title, raw_item.content)
        near_item, near_score = self.check_near_duplicate(embedding)
        if near_item:
            logger.debug(
                f"Near duplicate ({near_score:.2f}): "
                f"{raw_item.title[:40]} ~ {near_item.title[:40]}"
            )
            # Layer 3: Source-aware -- different source on same event is valuable
            if raw_item.source_name != near_item.source.name:
                logger.debug("Source-aware: different source, linking to event")
                return {
                    "is_duplicate": False,  # Keep it, but link to same event
                    "duplicate_type": "near_different_source",
                    "existing_item": near_item,
                    "similarity": near_score,
                    "content_hash": content_hash,
                    "embedding": embedding,
                }
            return {
                "is_duplicate": True,
                "duplicate_type": "near",
                "existing_item": near_item,
                "similarity": near_score,
                "content_hash": content_hash,
                "embedding": embedding,
            }

        return {
            "is_duplicate": False,
            "duplicate_type": None,
            "existing_item": None,
            "similarity": 0.0,
            "content_hash": content_hash,
            "embedding": embedding,
        }
