"""SQLAlchemy 2.0 database models and session management."""

from datetime import datetime
from pathlib import Path

from sqlalchemy import (
    Boolean, Column, DateTime, Enum, Float, ForeignKey, Index, Integer,
    JSON, LargeBinary, String, Text, UniqueConstraint, create_engine,
    event, text,
)
from sqlalchemy.orm import (
    DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker,
    Session,
)

DEFAULT_DB_PATH = Path(__file__).parent.parent.parent / "data" / "osint.db"


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

class Source(Base):
    __tablename__ = "sources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    type: Mapped[str] = mapped_column(String(50), nullable=False)  # rss, twitter, telegram, sanctions, custom
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    category: Mapped[str | None] = mapped_column(String(100))
    credibility_score: Mapped[float] = mapped_column(Float, default=0.5)
    priority: Mapped[int] = mapped_column(Integer, default=2)
    poll_interval: Mapped[int] = mapped_column(Integer, default=900)  # seconds
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    raw_items: Mapped[list["RawItem"]] = relationship(back_populates="source")


# ---------------------------------------------------------------------------
# Raw Items
# ---------------------------------------------------------------------------

class RawItem(Base):
    __tablename__ = "raw_items"
    __table_args__ = (
        UniqueConstraint("source_id", "external_id", name="uq_source_external"),
        Index("ix_raw_items_content_hash", "content_hash"),
        Index("ix_raw_items_published", "published_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id"), nullable=False)
    external_id: Mapped[str | None] = mapped_column(String(512))
    title: Mapped[str] = mapped_column(Text, nullable=False)
    content: Mapped[str | None] = mapped_column(Text)
    url: Mapped[str | None] = mapped_column(String(2048))
    published_at: Mapped[datetime | None] = mapped_column(DateTime)
    fetched_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    # On PostgreSQL with pgvector, this column should be migrated to
    # Vector(384) type for native vector search. Use an Alembic migration:
    #   op.alter_column('raw_items', 'embedding',
    #       type_=sa.Column(Vector(384)), postgresql_using='embedding::vector(384)')
    embedding: Mapped[bytes | None] = mapped_column(LargeBinary)  # 384-dim float32
    processed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, default=None)

    source: Mapped["Source"] = relationship(back_populates="raw_items")
    item_entities: Mapped[list["ItemEntity"]] = relationship(back_populates="item")
    event_items: Mapped[list["EventItem"]] = relationship(back_populates="item")
    alerts: Mapped[list["Alert"]] = relationship(back_populates="item")


# ---------------------------------------------------------------------------
# Entities
# ---------------------------------------------------------------------------

class Entity(Base):
    __tablename__ = "entities"
    __table_args__ = (
        Index("ix_entities_type", "entity_type"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    canonical_name: Mapped[str] = mapped_column(String(500), unique=True, nullable=False)
    entity_type: Mapped[str] = mapped_column(String(50), nullable=False)  # PERSON, ORG, GPE, WEAPON_SYSTEM, FACILITY, EVENT
    aliases: Mapped[dict | None] = mapped_column(JSON)  # list of alias strings
    wikidata_id: Mapped[str | None] = mapped_column(String(20))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    item_entities: Mapped[list["ItemEntity"]] = relationship(back_populates="entity")
    event_entities: Mapped[list["EventEntity"]] = relationship(back_populates="entity")
    trend_snapshots: Mapped[list["TrendSnapshot"]] = relationship(back_populates="entity")
    outgoing_relationships: Mapped[list["EntityRelationship"]] = relationship(
        back_populates="source_entity",
        foreign_keys="EntityRelationship.source_entity_id",
    )
    incoming_relationships: Mapped[list["EntityRelationship"]] = relationship(
        back_populates="target_entity",
        foreign_keys="EntityRelationship.target_entity_id",
    )


# ---------------------------------------------------------------------------
# Item-Entity junction
# ---------------------------------------------------------------------------

class ItemEntity(Base):
    __tablename__ = "item_entities"
    __table_args__ = (
        UniqueConstraint("item_id", "entity_id", "role", name="uq_item_entity_role"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    item_id: Mapped[int] = mapped_column(ForeignKey("raw_items.id"), nullable=False)
    entity_id: Mapped[int] = mapped_column(ForeignKey("entities.id"), nullable=False)
    role: Mapped[str] = mapped_column(String(20), default="SUBJECT")  # SUBJECT, OBJECT, LOCATION
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    span_text: Mapped[str | None] = mapped_column(Text)

    item: Mapped["RawItem"] = relationship(back_populates="item_entities")
    entity: Mapped["Entity"] = relationship(back_populates="item_entities")


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    event_type: Mapped[str | None] = mapped_column(String(100))
    severity: Mapped[float] = mapped_column(Float, default=0.0)  # 0-1 composite
    first_reported_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    location_name: Mapped[str | None] = mapped_column(String(255))
    lat: Mapped[float | None] = mapped_column(Float)
    lon: Mapped[float | None] = mapped_column(Float)
    region: Mapped[str | None] = mapped_column(String(100))
    # Pre-computed corroboration (cached during pipeline run)
    source_count: Mapped[int] = mapped_column(Integer, default=0)
    admiralty_rating: Mapped[str | None] = mapped_column(String(10))  # e.g. "C1"
    corroboration_level: Mapped[str | None] = mapped_column(String(20))  # CONFIRMED/DISPUTED/UNVERIFIED
    has_contradictions: Mapped[bool] = mapped_column(Boolean, default=False)

    event_items: Mapped[list["EventItem"]] = relationship(back_populates="event")
    event_entities: Mapped[list["EventEntity"]] = relationship(back_populates="event")
    alerts: Mapped[list["Alert"]] = relationship(back_populates="event")


class EventItem(Base):
    __tablename__ = "event_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id"), nullable=False)
    item_id: Mapped[int] = mapped_column(ForeignKey("raw_items.id"), nullable=False)
    similarity_score: Mapped[float] = mapped_column(Float, default=1.0)

    event: Mapped["Event"] = relationship(back_populates="event_items")
    item: Mapped["RawItem"] = relationship(back_populates="event_items")


class EventEntity(Base):
    __tablename__ = "event_entities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id"), nullable=False)
    entity_id: Mapped[int] = mapped_column(ForeignKey("entities.id"), nullable=False)
    role: Mapped[str] = mapped_column(String(20), default="SUBJECT")

    event: Mapped["Event"] = relationship(back_populates="event_entities")
    entity: Mapped["Entity"] = relationship(back_populates="event_entities")


# ---------------------------------------------------------------------------
# Claims
# ---------------------------------------------------------------------------

class Claim(Base):
    __tablename__ = "claims"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    item_id: Mapped[int] = mapped_column(ForeignKey("raw_items.id"), nullable=False)
    event_id: Mapped[int | None] = mapped_column(ForeignKey("events.id"))
    subject: Mapped[str] = mapped_column(String(500), nullable=False)
    verb: Mapped[str] = mapped_column(String(200), nullable=False)
    object: Mapped[str | None] = mapped_column(String(500))
    claim_text: Mapped[str] = mapped_column(Text, nullable=False)
    claim_type: Mapped[str] = mapped_column(String(50), default="assertion")
    source_name: Mapped[str] = mapped_column(String(255))
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    stance_vs_consensus: Mapped[str | None] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    item: Mapped["RawItem"] = relationship()
    event: Mapped["Event | None"] = relationship()


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[int | None] = mapped_column(ForeignKey("events.id"))
    item_id: Mapped[int | None] = mapped_column(ForeignKey("raw_items.id"))
    alert_type: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[float] = mapped_column(Float, default=0.5)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    detail: Mapped[str | None] = mapped_column(Text)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    delivered_via: Mapped[str | None] = mapped_column(String(100))
    trigger_key: Mapped[str | None] = mapped_column(String(500))  # dedup key for state transitions
    superseded_by_id: Mapped[int | None] = mapped_column(Integer)  # FK to newer alert on same thread
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    event: Mapped["Event | None"] = relationship(back_populates="alerts")
    item: Mapped["RawItem | None"] = relationship(back_populates="alerts")


# ---------------------------------------------------------------------------
# Briefings
# ---------------------------------------------------------------------------

class Briefing(Base):
    __tablename__ = "briefings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    briefing_type: Mapped[str] = mapped_column(String(20), nullable=False)  # daily, flash, weekly
    content_md: Mapped[str] = mapped_column(Text, nullable=False)
    model_used: Mapped[str | None] = mapped_column(String(100))
    covering_from: Mapped[datetime | None] = mapped_column(DateTime)
    covering_to: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


# ---------------------------------------------------------------------------
# Entity Relationships
# ---------------------------------------------------------------------------

class EntityRelationship(Base):
    __tablename__ = "entity_relationships"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_entity_id: Mapped[int] = mapped_column(ForeignKey("entities.id"), nullable=False)
    target_entity_id: Mapped[int] = mapped_column(ForeignKey("entities.id"), nullable=False)
    relationship_type: Mapped[str] = mapped_column(String(100), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    evidence_item_ids: Mapped[dict | None] = mapped_column(JSON)  # list of item IDs

    source_entity: Mapped["Entity"] = relationship(
        back_populates="outgoing_relationships",
        foreign_keys=[source_entity_id],
    )
    target_entity: Mapped["Entity"] = relationship(
        back_populates="incoming_relationships",
        foreign_keys=[target_entity_id],
    )


# ---------------------------------------------------------------------------
# Trend Snapshots
# ---------------------------------------------------------------------------

class TrendSnapshot(Base):
    __tablename__ = "trend_snapshots"
    __table_args__ = (
        Index("ix_trend_entity_metric", "entity_id", "metric_name", "window_start"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    entity_id: Mapped[int] = mapped_column(ForeignKey("entities.id"), nullable=False)
    region: Mapped[str | None] = mapped_column(String(100))
    metric_name: Mapped[str] = mapped_column(String(100), nullable=False)
    metric_value: Mapped[float] = mapped_column(Float, nullable=False)
    window_start: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    entity: Mapped["Entity"] = relationship(back_populates="trend_snapshots")


# ---------------------------------------------------------------------------
# State Snapshots (for alert state-transition detection)
# ---------------------------------------------------------------------------

class StateSnapshot(Base):
    """Stores the last known state for a given domain, so the alert engine
    can detect transitions (e.g., I&W score crossed a threshold)."""
    __tablename__ = "state_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    value: Mapped[dict] = mapped_column(JSON, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


# ---------------------------------------------------------------------------
# Engine + Session
# ---------------------------------------------------------------------------

_engine = None
_SessionFactory = None


def get_engine(db_url: str | None = None):
    """Get or create the database engine."""
    global _engine
    if _engine is None:
        if db_url is None:
            DEFAULT_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
            db_url = f"sqlite:///{DEFAULT_DB_PATH}"
        _engine = create_engine(db_url, echo=False)
        # Enable WAL mode for SQLite
        if db_url.startswith("sqlite"):
            @event.listens_for(_engine, "connect")
            def set_sqlite_pragma(dbapi_conn, connection_record):
                cursor = dbapi_conn.cursor()
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()
    return _engine


def get_session(db_url: str | None = None) -> Session:
    """Get a new database session."""
    global _SessionFactory
    if _SessionFactory is None:
        engine = get_engine(db_url)
        _SessionFactory = sessionmaker(bind=engine)
    return _SessionFactory()


def init_db(db_url: str | None = None):
    """Create all tables. Enables pgvector extension on PostgreSQL."""
    engine = get_engine(db_url)
    Base.metadata.create_all(engine)

    # Migrations: add columns if missing
    with engine.connect() as conn:
        for stmt in [
            "ALTER TABLE raw_items ADD COLUMN processed_at DATETIME",
            "ALTER TABLE alerts ADD COLUMN trigger_key VARCHAR(500)",
            "ALTER TABLE alerts ADD COLUMN superseded_by_id INTEGER",
        ]:
            try:
                conn.execute(text(stmt))
                conn.commit()
            except Exception:
                pass  # Column already exists
        # Mark all existing items as already processed
        try:
            conn.execute(text("UPDATE raw_items SET processed_at = fetched_at WHERE processed_at IS NULL"))
            conn.commit()
        except Exception:
            pass

    # Enable pgvector on PostgreSQL (no-op on SQLite)
    if engine.dialect.name == "postgresql":
        from osint_monitor.core.vector_search import setup_pgvector
        setup_pgvector(engine)

    return engine


def reset_engine():
    """Reset cached engine/session (for testing)."""
    global _engine, _SessionFactory
    _engine = None
    _SessionFactory = None
