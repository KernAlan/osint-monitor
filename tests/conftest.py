"""Shared fixtures for the OSINT Monitor test suite."""

import pytest
from datetime import datetime, timedelta
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from osint_monitor.core.database import Base, Source, RawItem


@pytest.fixture()
def session():
    """Provide a clean in-memory SQLite database session per test."""
    engine = create_engine("sqlite:///:memory:", echo=False)

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_conn, connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()
    engine.dispose()


@pytest.fixture()
def sample_items(session):
    """Insert a handful of RawItem records with known content and return them.

    Creates one Source and three RawItems with distinct titles/content so that
    other tests can query or reference them.
    """
    source = Source(
        name="test-rss-feed",
        type="rss",
        url="https://example.com/feed",
        category="major_news",
        credibility_score=0.8,
    )
    session.add(source)
    session.flush()

    now = datetime.utcnow()

    items = [
        RawItem(
            source_id=source.id,
            title="Russia launches missile strike on Kyiv",
            content="Multiple cruise missiles targeted energy infrastructure in Kyiv overnight.",
            url="https://example.com/article/1",
            published_at=now - timedelta(hours=2),
            fetched_at=now - timedelta(hours=1),
            content_hash="aaa111",
        ),
        RawItem(
            source_id=source.id,
            title="IAEA inspectors denied access to Fordow facility",
            content="Iran has blocked IAEA inspector access to the Fordow enrichment site.",
            url="https://example.com/article/2",
            published_at=now - timedelta(hours=5),
            fetched_at=now - timedelta(hours=4),
            content_hash="bbb222",
        ),
        RawItem(
            source_id=source.id,
            title="Weather forecast for London",
            content="Sunny skies expected throughout the week in southern England.",
            url="https://example.com/article/3",
            published_at=now - timedelta(hours=8),
            fetched_at=now - timedelta(hours=7),
            content_hash="ccc333",
        ),
    ]

    for item in items:
        session.add(item)
    session.commit()

    return items
