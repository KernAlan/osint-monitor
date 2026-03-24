"""Tests for osint_monitor.processors.dedup.compute_content_hash (pure function)."""

from osint_monitor.processors.dedup import compute_content_hash


def test_hash_deterministic():
    """Same input produces the same SHA-256 hash."""
    h1 = compute_content_hash("Breaking News", "Content body here")
    h2 = compute_content_hash("Breaking News", "Content body here")
    assert h1 == h2


def test_hash_normalized():
    """Whitespace and case are normalized before hashing."""
    h1 = compute_content_hash("Hello World", "")
    h2 = compute_content_hash("hello  world", "")
    assert h1 == h2


def test_hash_different():
    """Different content produces different hashes."""
    h1 = compute_content_hash("Alpha", "first")
    h2 = compute_content_hash("Beta", "second")
    assert h1 != h2
