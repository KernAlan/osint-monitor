"""HDBSCAN event clustering on embeddings."""

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from datetime import datetime, timedelta

import hdbscan
import numpy as np
from sqlalchemy.orm import Session, joinedload

from osint_monitor.core.config import load_sources_config
from osint_monitor.core.database import (
    Event, EventEntity, EventItem, ItemEntity, RawItem, Source,
)
from osint_monitor.core.models import ExtractedEntity, EntityType, EntityRole
from osint_monitor.processors.embeddings import blob_to_embedding
from osint_monitor.processors.scoring import compute_composite_severity

logger = logging.getLogger(__name__)

DEFAULT_WINDOW_HOURS = 48
MIN_CLUSTER_SIZE = 2


def cluster_recent_items(
    session: Session,
    window_hours: int = DEFAULT_WINDOW_HOURS,
    min_cluster_size: int = MIN_CLUSTER_SIZE,
) -> list[dict]:
    """Cluster recent items into events using HDBSCAN.

    Returns list of cluster dicts: {item_ids, label, summary, severity, region}.
    """
    cutoff = datetime.utcnow() - timedelta(hours=window_hours)
    items = (
        session.query(RawItem)
        .options(joinedload(RawItem.source))
        .filter(
            RawItem.fetched_at >= cutoff,
            RawItem.embedding.isnot(None),
        )
        .all()
    )

    # Temporal filtering: exclude items whose published_at is clearly old
    filtered_items = []
    for item in items:
        if item.published_at is not None and item.published_at < cutoff:
            logger.debug(
                f"Skipping item {item.id}: published_at {item.published_at} "
                f"is older than {window_hours}h window"
            )
            continue
        filtered_items.append(item)
    items = filtered_items

    if len(items) < min_cluster_size:
        logger.info(f"Only {len(items)} items with embeddings, skipping clustering")
        return []

    # Build embedding matrix
    item_ids = []
    embeddings = []
    for item in items:
        try:
            emb = blob_to_embedding(item.embedding)
            embeddings.append(emb)
            item_ids.append(item.id)
        except Exception:
            continue

    if len(embeddings) < min_cluster_size:
        return []

    X = np.array(embeddings)

    # HDBSCAN on cosine distance
    # Convert cosine similarity to distance: d = 1 - sim
    # Since embeddings are normalized, cosine_sim = dot product
    clusterer = hdbscan.HDBSCAN(
        min_cluster_size=min_cluster_size,
        metric="euclidean",
        cluster_selection_epsilon=0.2,
    )
    labels = clusterer.fit_predict(X)

    # Group by cluster label
    clusters: dict[int, list[int]] = defaultdict(list)
    for idx, label in enumerate(labels):
        if label >= 0:  # -1 = noise
            clusters[label].append(item_ids[idx])

    # Re-cluster large clusters to decompose mega-events into sub-events
    clusters = _split_large_clusters(clusters, item_ids, X)

    logger.info(f"Found {len(clusters)} clusters from {len(items)} items")

    return _build_cluster_summaries(session, clusters)


def _split_large_clusters(
    clusters: dict[int, list[int]],
    all_item_ids: list[int],
    X: np.ndarray,
    max_cluster_size: int = 15,
) -> dict[int, list[int]]:
    """Re-cluster any cluster with more than *max_cluster_size* items.

    Uses stricter HDBSCAN parameters (epsilon=0.1, min_cluster_size=2) on
    just the subset embeddings to decompose mega-events into distinct
    sub-events (e.g. separating a blockade from a missile debate).
    """
    # Build a lookup from item_id to index in X
    id_to_idx = {item_id: idx for idx, item_id in enumerate(all_item_ids)}

    result: dict[int, list[int]] = {}
    next_label = max(clusters.keys(), default=-1) + 1

    for label, ids in clusters.items():
        if len(ids) <= max_cluster_size:
            result[next_label] = ids
            next_label += 1
            continue

        # Extract the subset of embeddings for this cluster
        subset_indices = [id_to_idx[i] for i in ids if i in id_to_idx]
        if len(subset_indices) < 2:
            result[next_label] = ids
            next_label += 1
            continue

        subset_X = X[subset_indices]
        subset_ids = [ids[j] for j, i in enumerate(ids) if i in id_to_idx]

        sub_clusterer = hdbscan.HDBSCAN(
            min_cluster_size=2,
            metric="euclidean",
            cluster_selection_epsilon=0.1,
        )
        sub_labels = sub_clusterer.fit_predict(subset_X)

        sub_clusters: dict[int, list[int]] = defaultdict(list)
        noise_items: list[int] = []
        for idx, sub_label in enumerate(sub_labels):
            if sub_label >= 0:
                sub_clusters[sub_label].append(subset_ids[idx])
            else:
                noise_items.append(subset_ids[idx])

        if len(sub_clusters) <= 1:
            # Re-clustering didn't help; keep original cluster
            result[next_label] = ids
            next_label += 1
        else:
            logger.info(
                f"Split large cluster (size {len(ids)}) into "
                f"{len(sub_clusters)} sub-clusters"
            )
            for sub_ids in sub_clusters.values():
                result[next_label] = sub_ids
                next_label += 1
            # Assign noise items to the nearest sub-cluster
            if noise_items:
                # Just put them in the largest sub-cluster
                largest_key = max(result, key=lambda k: len(result[k]))
                result[largest_key].extend(noise_items)

    return result


def _build_cluster_summaries(
    session: Session,
    clusters: dict[int, list[int]],
) -> list[dict]:
    """Build event summaries for each cluster."""
    # Load region config once for all clusters
    try:
        sources_config = load_sources_config()
        regions = sources_config.regions  # dict[str, RegionConfig]
    except Exception:
        logger.warning("Could not load sources config for region assignment")
        regions = {}

    results = []
    for label, ids in clusters.items():
        items = (
            session.query(RawItem)
            .options(joinedload(RawItem.source))
            .filter(RawItem.id.in_(ids))
            .all()
        )
        if not items:
            continue

        # Pick summary from highest-credibility source
        best_item = max(items, key=lambda i: i.source.credibility_score)

        # --- Compute severity as max across all items in the cluster ---
        max_severity = 0.0
        for item in items:
            item_text = f"{item.title or ''} {item.content or ''}"
            # Build ExtractedEntity list from ItemEntity records
            item_entities = _get_extracted_entities_for_item(session, item.id)
            source_name = item.source.name if item.source else ""
            score_result = compute_composite_severity(
                text=item_text,
                entities=item_entities,
                source_name=source_name,
            )
            if score_result["severity"] > max_severity:
                max_severity = score_result["severity"]

        # --- Assign region based on keyword matching ---
        region = _assign_region(items, regions)

        results.append({
            "item_ids": ids,
            "label": label,
            "summary": best_item.title,
            "event_type": None,
            "severity": max_severity,
            "region": region,
            "source_count": len(set(i.source_id for i in items)),
        })

    return results


def _get_extracted_entities_for_item(
    session: Session, item_id: int
) -> list[ExtractedEntity]:
    """Load ItemEntity records for an item and convert to ExtractedEntity models."""
    item_entities = (
        session.query(ItemEntity)
        .filter(ItemEntity.item_id == item_id)
        .all()
    )
    result = []
    for ie in item_entities:
        try:
            entity = ie.entity
            result.append(ExtractedEntity(
                text=ie.span_text or entity.canonical_name,
                entity_type=EntityType(entity.entity_type),
                role=EntityRole(ie.role) if ie.role else EntityRole.SUBJECT,
                confidence=ie.confidence,
                canonical_name=entity.canonical_name,
            ))
        except Exception:
            continue
    return result


def _assign_region(
    items: list[RawItem],
    regions: dict,
) -> str | None:
    """Assign region by scanning item texts for region keywords.

    Returns the most common matching region, or None.
    """
    if not regions:
        return None

    region_counts: Counter = Counter()
    for item in items:
        text_lower = f"{item.title or ''} {item.content or ''}".lower()
        for region_name, region_cfg in regions.items():
            for keyword in region_cfg.keywords:
                if keyword.lower() in text_lower:
                    region_counts[region_name] += 1
                    break  # one match per region per item is enough

    if region_counts:
        return region_counts.most_common(1)[0][0]
    return None


def persist_clusters(session: Session, clusters: list[dict]):
    """Save clusters as Event records in the database."""
    for cluster in clusters:
        # Check if this cluster overlaps with an existing event
        existing_event = _find_overlapping_event(session, cluster["item_ids"])

        if existing_event:
            # Update existing event with new items
            new_item_ids = []
            for item_id in cluster["item_ids"]:
                if not session.query(EventItem).filter_by(
                    event_id=existing_event.id, item_id=item_id
                ).first():
                    session.add(EventItem(
                        event_id=existing_event.id,
                        item_id=item_id,
                        similarity_score=1.0,
                    ))
                    new_item_ids.append(item_id)
            existing_event.last_updated_at = datetime.utcnow()
            # Update severity and region if the new cluster has better values
            if cluster.get("severity", 0.0) > existing_event.severity:
                existing_event.severity = cluster["severity"]
            if cluster.get("region") and not existing_event.region:
                existing_event.region = cluster["region"]
            session.flush()

            # Populate event_entities for newly added items
            _populate_event_entities(session, existing_event.id, new_item_ids)
        else:
            # Create new event
            event = Event(
                summary=cluster["summary"],
                event_type=cluster.get("event_type"),
                severity=cluster.get("severity", 0.0),
                region=cluster.get("region"),
                first_reported_at=datetime.utcnow(),
                last_updated_at=datetime.utcnow(),
            )
            session.add(event)
            session.flush()

            for item_id in cluster["item_ids"]:
                session.add(EventItem(
                    event_id=event.id,
                    item_id=item_id,
                    similarity_score=1.0,
                ))
            session.flush()

            # Populate event_entities from all items in the cluster
            _populate_event_entities(session, event.id, cluster["item_ids"])

            # Link claims to event
            _link_claims_to_event(session, event.id, cluster["item_ids"])

    session.commit()


def _link_claims_to_event(session: Session, event_id: int, item_ids: list[int]):
    """Link existing claims from items to the event."""
    try:
        from osint_monitor.core.database import Claim
        session.query(Claim).filter(
            Claim.item_id.in_(item_ids),
            Claim.event_id.is_(None),
        ).update({"event_id": event_id}, synchronize_session="fetch")
    except Exception:
        pass  # Claim table may not exist in older DBs


def _populate_event_entities(
    session: Session, event_id: int, item_ids: list[int]
):
    """Copy unique entity references from ItemEntity to EventEntity for an event."""
    if not item_ids:
        return

    # Query all ItemEntity records for the given items
    item_entities = (
        session.query(ItemEntity)
        .filter(ItemEntity.item_id.in_(item_ids))
        .all()
    )

    # Find existing event_entity pairs to avoid duplicates
    existing_pairs = set()
    existing_event_entities = (
        session.query(EventEntity)
        .filter(EventEntity.event_id == event_id)
        .all()
    )
    for ee in existing_event_entities:
        existing_pairs.add((ee.entity_id, ee.role))

    # Add unique entity references
    seen = set()
    for ie in item_entities:
        key = (ie.entity_id, ie.role)
        if key not in seen and key not in existing_pairs:
            seen.add(key)
            session.add(EventEntity(
                event_id=event_id,
                entity_id=ie.entity_id,
                role=ie.role,
            ))

    session.flush()


def _find_overlapping_event(session: Session, item_ids: list[int]) -> Event | None:
    """Find an existing event that shares items with this cluster."""
    existing = (
        session.query(EventItem)
        .filter(EventItem.item_id.in_(item_ids))
        .first()
    )
    if existing:
        return existing.event
    return None
