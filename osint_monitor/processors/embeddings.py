"""Sentence embedding generation using sentence-transformers."""

from __future__ import annotations

import logging
import os
import struct
import threading
from typing import Optional

import numpy as np

from osint_monitor.core.config import get_settings

# Suppress HuggingFace unauthenticated-request warnings and unnecessary HTTP checks.
# These must be set before any huggingface_hub / transformers imports.
os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

logger = logging.getLogger(__name__)

_model = None
_model_lock = threading.Lock()


def get_embedding_model():
    """Load sentence-transformer model (thread-safe cached singleton).

    Uses a lock so that concurrent tier threads don't each load the model
    when the daemon first starts. After the first load, the fast-path
    (``_model is not None``) avoids any locking overhead.
    """
    global _model
    if _model is not None:
        return _model

    with _model_lock:
        # Double-check after acquiring lock — another thread may have loaded it.
        if _model is not None:
            return _model

        # Suppress the huggingface_hub "unauthenticated requests" warning that
        # fires on every SentenceTransformer() call when no HF token is set.
        logging.getLogger("huggingface_hub.file_download").setLevel(logging.ERROR)
        logging.getLogger("huggingface_hub.utils._http").setLevel(logging.ERROR)

        from sentence_transformers import SentenceTransformer

        settings = get_settings()
        model_name = settings.embedding_model
        logger.info(f"Loading embedding model: {model_name}")
        _model = SentenceTransformer(model_name)

        # Now that the model is loaded from cache, skip future HTTP HEAD
        # requests to HuggingFace Hub (saves ~2s latency if any other code
        # path instantiates a HF model).
        os.environ.setdefault("HF_HUB_OFFLINE", "1")

        return _model


def embed_text(text: str) -> np.ndarray:
    """Generate embedding for a single text. Returns 384-dim float32 array."""
    model = get_embedding_model()
    return model.encode(text, normalize_embeddings=True)


def embed_texts(texts: list[str]) -> np.ndarray:
    """Batch embed multiple texts. Returns (N, 384) float32 array."""
    model = get_embedding_model()
    return model.encode(texts, normalize_embeddings=True, batch_size=32, show_progress_bar=False)


def embed_item(title: str, content: str = "") -> np.ndarray:
    """Embed an item using title + first 200 chars of content."""
    text = f"{title} {content[:200]}".strip()
    return embed_text(text)


def embedding_to_blob(embedding: np.ndarray) -> bytes:
    """Convert numpy embedding to bytes for SQLite storage."""
    return embedding.astype(np.float32).tobytes()


def blob_to_embedding(blob: bytes) -> np.ndarray:
    """Convert stored blob back to numpy array."""
    return np.frombuffer(blob, dtype=np.float32)


def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    """Compute cosine similarity between two embeddings."""
    # Normalized embeddings -> dot product = cosine similarity
    return float(np.dot(a, b))


def cosine_similarity_matrix(embeddings: np.ndarray) -> np.ndarray:
    """Compute pairwise cosine similarity matrix. Input shape: (N, D)."""
    # Already normalized -> dot product gives cosine sim
    return embeddings @ embeddings.T
