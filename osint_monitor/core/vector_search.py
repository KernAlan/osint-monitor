"""pgvector integration for embedding search at scale.

On PostgreSQL with pgvector: uses native vector similarity operators.
On SQLite: falls back to brute-force cosine similarity.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

import numpy as np
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from osint_monitor.core.database import RawItem
from osint_monitor.processors.embeddings import (
    blob_to_embedding,
    cosine_similarity,
    embed_text,
    embedding_to_blob,
)

logger = logging.getLogger(__name__)

# Dimension of the embedding vectors (all-MiniLM-L6-v2)
EMBEDDING_DIM = 384


def _is_postgres(engine: Engine) -> bool:
    """Check if the engine is connected to PostgreSQL."""
    return engine.dialect.name == "postgresql"


def setup_pgvector(engine: Engine) -> None:
    """Enable the pgvector extension on PostgreSQL.

    No-op for SQLite or other dialects.
    """
    if not _is_postgres(engine):
        logger.debug("Not PostgreSQL -- skipping pgvector setup")
        return

    with engine.connect() as conn:
        conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
        conn.commit()
    logger.info("pgvector extension enabled")


def create_embedding_index(engine: Engine) -> None:
    """Create a vector similarity index on raw_items.embedding.

    Uses HNSW (preferred for recall/speed balance) if available,
    otherwise IVFFlat. Only works on PostgreSQL with pgvector.
    """
    if not _is_postgres(engine):
        logger.warning("Vector index creation requires PostgreSQL with pgvector")
        return

    with engine.connect() as conn:
        # Drop existing index if present so we can recreate
        conn.execute(text(
            "DROP INDEX IF EXISTS ix_raw_items_embedding_cosine"
        ))

        # Use HNSW index for cosine distance -- good default for most workloads
        conn.execute(text(
            "CREATE INDEX ix_raw_items_embedding_cosine "
            "ON raw_items USING hnsw (embedding vector_cosine_ops) "
            "WITH (m = 16, ef_construction = 64)"
        ))
        conn.commit()

    logger.info("HNSW vector index created on raw_items.embedding")


def search_similar_items(
    session: Session,
    embedding: np.ndarray,
    limit: int = 20,
    threshold: float = 0.7,
) -> list[dict]:
    """Find items similar to the given embedding.

    On PostgreSQL+pgvector: uses the <=> cosine distance operator for
    native vector search with index acceleration.

    On SQLite: falls back to brute-force cosine similarity over recent items.

    Returns list of {"item_id": int, "title": str, "similarity": float},
    ordered by descending similarity.
    """
    engine = session.get_bind()

    if engine.dialect.name == "postgresql":
        return _search_pgvector(session, embedding, limit, threshold)
    else:
        return _search_brute_force(session, embedding, limit, threshold)


def _search_pgvector(
    session: Session,
    embedding: np.ndarray,
    limit: int,
    threshold: float,
) -> list[dict]:
    """PostgreSQL pgvector search using cosine distance operator."""
    # pgvector cosine distance: <=> returns distance (0 = identical),
    # so similarity = 1 - distance.
    embedding_list = embedding.astype(float).tolist()
    embedding_literal = "[" + ",".join(str(v) for v in embedding_list) + "]"

    result = session.execute(
        text(
            "SELECT id, title, 1 - (embedding <=> :vec) AS similarity "
            "FROM raw_items "
            "WHERE embedding IS NOT NULL "
            "  AND 1 - (embedding <=> :vec) >= :threshold "
            "ORDER BY embedding <=> :vec "
            "LIMIT :lim"
        ),
        {"vec": embedding_literal, "threshold": threshold, "lim": limit},
    )

    return [
        {"item_id": row.id, "title": row.title, "similarity": round(row.similarity, 4)}
        for row in result
    ]


def _search_brute_force(
    session: Session,
    embedding: np.ndarray,
    limit: int,
    threshold: float,
) -> list[dict]:
    """SQLite fallback: load embeddings and compute cosine similarity in Python."""
    items = (
        session.query(RawItem.id, RawItem.title, RawItem.embedding)
        .filter(RawItem.embedding.isnot(None))
        .all()
    )

    scored = []
    for item_id, title, emb_blob in items:
        try:
            stored = blob_to_embedding(emb_blob)
            sim = float(cosine_similarity(embedding, stored))
            if sim >= threshold:
                scored.append({"item_id": item_id, "title": title, "similarity": round(sim, 4)})
        except Exception:
            continue

    scored.sort(key=lambda x: x["similarity"], reverse=True)
    return scored[:limit]


def semantic_search(
    session: Session,
    query: str,
    limit: int = 20,
    threshold: float = 0.7,
) -> list[dict]:
    """Embed a query string and search for similar items.

    Args:
        session: SQLAlchemy session.
        query: Natural-language search query.
        limit: Maximum results to return.
        threshold: Minimum cosine similarity (0-1).

    Returns:
        List of {"item_id": int, "title": str, "similarity": float}.
    """
    embedding = embed_text(query)
    return search_similar_items(session, embedding, limit=limit, threshold=threshold)
