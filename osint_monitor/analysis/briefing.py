"""Automated briefing generation."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from osint_monitor.core.database import (
    Alert, Briefing, Entity, Event, EventItem, ItemEntity, RawItem,
    get_session, init_db,
)
from osint_monitor.core.models import BriefingResult, BriefingType
from osint_monitor.analysis.llm import get_llm, LLMProvider

logger = logging.getLogger(__name__)

DAILY_SYSTEM_PROMPT = """You are a senior geopolitical intelligence analyst producing a daily briefing.
Write in a professional, concise style suitable for policy-makers and security professionals.
Structure your output as markdown with these sections:
1. EXECUTIVE SUMMARY (3-5 bullet points of the most significant developments)
2. CRITICAL ALERTS (if any)
3. REGIONAL ANALYSIS (key developments by region, with assessment of significance)
4. EMERGING TRENDS (patterns or escalations worth monitoring)
5. WATCH LIST (entities or situations requiring continued monitoring)
Be specific, cite sources, and distinguish between confirmed facts and analysis."""

FLASH_SYSTEM_PROMPT = """You are a senior intelligence analyst producing a FLASH briefing on a critical event.
Be concise and actionable. Structure:
1. SITUATION: What happened (confirmed facts only)
2. ASSESSMENT: Significance and implications
3. KEY ENTITIES: Who is involved
4. RECOMMENDED ACTIONS: What decision-makers should monitor
5. CONFIDENCE LEVEL: How reliable is this information"""

ACH_SYSTEM_PROMPT = """You are an intelligence analyst conducting Analysis of Competing Hypotheses (ACH).
Given the evidence, generate a hypothesis matrix:
1. List 3-5 plausible hypotheses
2. For each piece of evidence, rate consistency with each hypothesis (++, +, 0, -, --)
3. Identify which hypothesis is best supported and which can be rejected
4. Note key indicators to watch that would confirm/deny each hypothesis
Output as structured markdown with a clear matrix table."""


def generate_daily_briefing(
    session: Session | None = None,
    hours_back: int = 24,
    provider: str | None = None,
) -> BriefingResult:
    """Generate a daily intelligence briefing."""
    if session is None:
        init_db()
        session = get_session()

    cutoff = datetime.utcnow() - timedelta(hours=hours_back)

    # Gather data
    items = (
        session.query(RawItem)
        .filter(RawItem.fetched_at >= cutoff)
        .order_by(RawItem.published_at.desc())
        .limit(200)
        .all()
    )

    events = (
        session.query(Event)
        .filter(Event.last_updated_at >= cutoff)
        .order_by(Event.severity.desc())
        .limit(50)
        .all()
    )

    alerts = (
        session.query(Alert)
        .filter(Alert.created_at >= cutoff)
        .order_by(Alert.severity.desc())
        .all()
    )

    # Build context for LLM
    context = _build_briefing_context(items, events, alerts)

    prompt = f"""Generate a daily intelligence briefing based on the following OSINT data collected in the last {hours_back} hours.

{context}

Today's date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}
Total items analyzed: {len(items)}
Events identified: {len(events)}
Alerts triggered: {len(alerts)}"""

    llm = get_llm(provider)
    content = llm.generate(prompt, system=DAILY_SYSTEM_PROMPT)

    # Prepend header
    header = f"# Daily Intelligence Briefing\n**{datetime.utcnow().strftime('%A, %B %d, %Y')} — {datetime.utcnow().strftime('%H:%M')} UTC**\n\n"
    full_content = header + content

    # Save to database
    briefing = Briefing(
        briefing_type=BriefingType.DAILY.value,
        content_md=full_content,
        model_used=f"{provider or 'default'}",
        covering_from=cutoff,
        covering_to=datetime.utcnow(),
    )
    session.add(briefing)
    session.commit()

    return BriefingResult(
        briefing_type=BriefingType.DAILY,
        content_md=full_content,
        model_used=briefing.model_used,
        covering_from=cutoff,
        covering_to=datetime.utcnow(),
    )


def generate_flash_briefing(
    session: Session,
    event_id: int,
    provider: str | None = None,
) -> BriefingResult:
    """Generate a flash briefing for a critical event."""
    event = session.get(Event, event_id)
    if not event:
        raise ValueError(f"Event {event_id} not found")

    # Get all items linked to this event
    event_items = session.query(EventItem).filter_by(event_id=event_id).all()
    items = [ei.item for ei in event_items]

    # Get entities
    entity_names = set()
    for item in items:
        for ie in item.item_entities:
            entity_names.add(f"{ie.entity.canonical_name} ({ie.entity.entity_type})")

    context = f"""EVENT: {event.summary}
Severity: {event.severity:.2f}
Region: {event.region or 'Unknown'}
First reported: {event.first_reported_at}
Sources: {len(items)}

SOURCES:
"""
    for item in items[:20]:
        context += f"- [{item.source.name}] {item.title}\n  {item.content[:200]}\n\n"

    context += f"\nENTITIES INVOLVED: {', '.join(entity_names)}"

    llm = get_llm(provider)
    content = llm.generate(
        f"Generate a FLASH briefing for this critical event:\n\n{context}",
        system=FLASH_SYSTEM_PROMPT,
    )

    header = f"# FLASH BRIEFING\n**{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}**\n\n"
    full_content = header + content

    briefing = Briefing(
        briefing_type=BriefingType.FLASH.value,
        content_md=full_content,
        model_used=f"{provider or 'default'}",
        covering_from=event.first_reported_at,
        covering_to=datetime.utcnow(),
    )
    session.add(briefing)
    session.commit()

    return BriefingResult(
        briefing_type=BriefingType.FLASH,
        content_md=full_content,
        model_used=briefing.model_used,
        covering_from=event.first_reported_at,
        covering_to=datetime.utcnow(),
    )


def generate_ach(
    session: Session,
    situation: str,
    evidence_items: list[int] | None = None,
    provider: str | None = None,
) -> str:
    """Generate Analysis of Competing Hypotheses for an ambiguous situation."""
    context = f"SITUATION: {situation}\n\n"

    if evidence_items:
        items = session.query(RawItem).filter(RawItem.id.in_(evidence_items)).all()
        context += "EVIDENCE:\n"
        for i, item in enumerate(items, 1):
            context += f"{i}. [{item.source.name}] {item.title}\n   {item.content[:300]}\n\n"

    llm = get_llm(provider)
    return llm.generate(
        f"Perform ACH analysis:\n\n{context}",
        system=ACH_SYSTEM_PROMPT,
    )


def _build_briefing_context(items, events, alerts) -> str:
    """Build text context from database objects for LLM consumption."""
    parts = []

    if alerts:
        parts.append("## ACTIVE ALERTS")
        for alert in alerts[:10]:
            parts.append(f"- [{alert.alert_type.upper()}] {alert.title} (severity: {alert.severity:.2f})")
            if alert.detail:
                parts.append(f"  {alert.detail[:200]}")

    if events:
        parts.append("\n## IDENTIFIED EVENTS")
        for event in events[:20]:
            parts.append(f"- {event.summary} (severity: {event.severity:.2f}, region: {event.region or 'unknown'})")

    parts.append("\n## RAW INTELLIGENCE ITEMS")
    # Group by source
    by_source: dict[str, list] = {}
    for item in items[:100]:
        src = item.source.name if item.source else "Unknown"
        by_source.setdefault(src, []).append(item)

    for source, source_items in by_source.items():
        parts.append(f"\n### {source}")
        for item in source_items[:10]:
            parts.append(f"- {item.title}")
            if item.content:
                parts.append(f"  {item.content[:150]}")

    return "\n".join(parts)


if __name__ == "__main__":
    result = generate_daily_briefing()
    print(result.content_md)
