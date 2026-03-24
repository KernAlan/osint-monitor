"""Export and interoperability module.

Provides CSV/JSON export of events, entities, and raw items, as well as
intelligence community report generation (CIR, IIR) and webhook ingest
support for external data sources.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime, timedelta
from typing import Optional

from pydantic import BaseModel, ValidationError
from sqlalchemy.orm import Session

from osint_monitor.core.database import (
    Entity,
    Event,
    EventEntity,
    EventItem,
    ItemEntity,
    RawItem,
    Source,
)
from osint_monitor.core.models import RawItemModel
from osint_monitor.analysis.llm import get_llm
from osint_monitor.processors.corroboration import (
    compute_claim_corroboration,
    compute_corroboration_score,
    RELIABILITY_GRADES,
    CREDIBILITY_GRADES,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CSV Exports
# ---------------------------------------------------------------------------

def export_events_csv(session: Session, hours_back: int = 24) -> str:
    """Export recent events as a CSV string.

    Columns: id, summary, severity, region, source_count, admiralty_rating,
             first_reported_at, lat, lon, location_name
    """
    cutoff = datetime.utcnow() - timedelta(hours=hours_back)

    events = (
        session.query(Event)
        .filter(Event.first_reported_at >= cutoff)
        .order_by(Event.severity.desc())
        .all()
    )

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "id", "summary", "severity", "region", "source_count",
        "admiralty_rating", "first_reported_at", "lat", "lon", "location_name",
    ])

    for ev in events:
        # Count distinct sources for this event
        event_items = (
            session.query(EventItem)
            .filter(EventItem.event_id == ev.id)
            .all()
        )
        item_ids = [ei.item_id for ei in event_items]
        source_count = 0
        if item_ids:
            items = session.query(RawItem).filter(RawItem.id.in_(item_ids)).all()
            source_count = len({it.source_id for it in items})

        # Compute admiralty rating
        try:
            corr = compute_corroboration_score(session, ev.id)
            admiralty_rating = corr["admiralty_rating"]
        except Exception:
            admiralty_rating = "F6"

        writer.writerow([
            ev.id,
            ev.summary,
            round(ev.severity, 4),
            ev.region or "",
            source_count,
            admiralty_rating,
            ev.first_reported_at.isoformat() if ev.first_reported_at else "",
            ev.lat if ev.lat is not None else "",
            ev.lon if ev.lon is not None else "",
            ev.location_name or "",
        ])

    return buf.getvalue()


def export_entities_csv(session: Session) -> str:
    """Export all entities as a CSV string.

    Columns: id, canonical_name, entity_type, mention_count, first_seen_at,
             last_seen_at, aliases
    """
    entities = session.query(Entity).order_by(Entity.last_seen_at.desc()).all()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "id", "canonical_name", "entity_type", "mention_count",
        "first_seen_at", "last_seen_at", "aliases",
    ])

    for ent in entities:
        mention_count = (
            session.query(ItemEntity)
            .filter(ItemEntity.entity_id == ent.id)
            .count()
        )

        aliases_str = ""
        if ent.aliases:
            if isinstance(ent.aliases, list):
                aliases_str = "; ".join(ent.aliases)
            elif isinstance(ent.aliases, dict):
                aliases_str = "; ".join(ent.aliases.get("names", []))
            else:
                aliases_str = str(ent.aliases)

        writer.writerow([
            ent.id,
            ent.canonical_name,
            ent.entity_type,
            mention_count,
            ent.first_seen_at.isoformat() if ent.first_seen_at else "",
            ent.last_seen_at.isoformat() if ent.last_seen_at else "",
            aliases_str,
        ])

    return buf.getvalue()


# ---------------------------------------------------------------------------
# JSON Export
# ---------------------------------------------------------------------------

def export_items_json(session: Session, hours_back: int = 24) -> list[dict]:
    """Export raw items as JSON-serialisable dicts for Jupyter / Maltego.

    Each dict includes: id, title, content, url, source, published_at,
    entities (list of names), severity_score, content_hash.
    """
    cutoff = datetime.utcnow() - timedelta(hours=hours_back)

    items = (
        session.query(RawItem)
        .filter(RawItem.fetched_at >= cutoff)
        .order_by(RawItem.published_at.desc())
        .all()
    )

    results: list[dict] = []
    for item in items:
        # Gather entity names linked to this item
        entity_names: list[str] = []
        for ie in item.item_entities:
            if ie.entity:
                entity_names.append(ie.entity.canonical_name)

        # Derive severity_score from event linkage (max event severity) or 0
        severity_score = 0.0
        for ei in item.event_items:
            if ei.event and ei.event.severity > severity_score:
                severity_score = ei.event.severity

        source_name = item.source.name if item.source else ""

        results.append({
            "id": item.id,
            "title": item.title,
            "content": item.content or "",
            "url": item.url or "",
            "source": source_name,
            "published_at": item.published_at.isoformat() if item.published_at else None,
            "entities": entity_names,
            "severity_score": round(severity_score, 4),
            "content_hash": item.content_hash,
        })

    return results


# ---------------------------------------------------------------------------
# Intelligence Community Reports
# ---------------------------------------------------------------------------

CIR_SYSTEM_PROMPT = """You are a senior intelligence analyst drafting a Current Intelligence Report (CIR).
Follow standard intelligence community formatting conventions.
Write in a professional, concise style suitable for policy-makers.
Structure the report exactly as instructed in the user prompt.
Distinguish clearly between confirmed facts, assessments, and forecasts.
Use hedge words appropriately (likely, probably, possibly, almost certainly).
Do not speculate beyond what the evidence supports."""


def generate_cir_report(
    session: Session,
    event_id: int,
    provider: str | None = None,
) -> str:
    """Generate a formatted Current Intelligence Report (CIR) using an LLM.

    Returns a markdown-formatted CIR with CLASSIFICATION, SUBJECT, REFERENCES,
    BODY (situation, background, assessment, outlook), and RELIABILITY RATING.
    """
    event = session.get(Event, event_id)
    if not event:
        raise ValueError(f"Event {event_id} not found")

    # Gather linked items and sources
    event_items = session.query(EventItem).filter_by(event_id=event_id).all()
    items = [ei.item for ei in event_items]

    # Gather entities
    entity_names: set[str] = set()
    for item in items:
        for ie in item.item_entities:
            if ie.entity:
                entity_names.add(f"{ie.entity.canonical_name} ({ie.entity.entity_type})")

    # Compute corroboration / admiralty rating
    try:
        corr = compute_corroboration_score(session, event_id)
    except Exception:
        corr = {
            "admiralty_rating": "F6",
            "corroboration_level": "UNCONFIRMED",
            "independent_sources": 0,
            "confidence": 0.0,
            "source_diversity": 0.0,
        }

    admiralty_rating = corr["admiralty_rating"]
    corroboration_level = corr["corroboration_level"]
    reliability_letter = admiralty_rating[0] if admiralty_rating else "F"
    credibility_number = admiralty_rating[1] if len(admiralty_rating) > 1 else "6"
    reliability_desc = RELIABILITY_GRADES.get(reliability_letter, "Cannot be judged")
    credibility_desc = CREDIBILITY_GRADES.get(credibility_number, "Cannot be judged")

    # Build source listing for LLM context
    source_lines: list[str] = []
    for item in items[:30]:
        src_name = item.source.name if item.source else "Unknown"
        pub_date = item.published_at.isoformat() if item.published_at else "unknown date"
        source_lines.append(
            f"- [{src_name}, {pub_date}] {item.title}\n  {(item.content or '')[:300]}"
        )

    context = f"""EVENT SUMMARY: {event.summary}
SEVERITY: {event.severity:.2f}
REGION: {event.region or 'Unknown'}
LOCATION: {event.location_name or 'Unknown'}
FIRST REPORTED: {event.first_reported_at}
INDEPENDENT SOURCES: {corr['independent_sources']}
ADMIRALTY RATING: {admiralty_rating} (Source: {reliability_desc} / Info: {credibility_desc})
CORROBORATION LEVEL: {corroboration_level}

ENTITIES INVOLVED:
{chr(10).join(f'- {e}' for e in sorted(entity_names)) if entity_names else '- None identified'}

SOURCE MATERIAL:
{chr(10).join(source_lines) if source_lines else 'No source items available.'}"""

    prompt = f"""Generate a Current Intelligence Report (CIR) based on the following event data.

Use this exact structure:
1. CLASSIFICATION: UNCLASSIFIED
2. REPORT DATE: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}
3. SUBJECT: (derived from the event summary)
4. REFERENCES: (list the source material with dates)
5. BODY:
   a. SITUATION: What has happened (confirmed facts only)
   b. BACKGROUND: Relevant context and history
   c. ASSESSMENT: Analytical judgment of significance and implications
   d. OUTLOOK: Likely developments and scenarios to monitor
6. RELIABILITY RATING: {admiralty_rating} — Source reliability: {reliability_letter} ({reliability_desc}), Information credibility: {credibility_number} ({credibility_desc}), Corroboration: {corroboration_level}

EVENT DATA:
{context}"""

    llm = get_llm(provider)
    report_body = llm.generate(prompt, system=CIR_SYSTEM_PROMPT)

    # Wrap with header
    header = (
        f"# CURRENT INTELLIGENCE REPORT\n"
        f"**Report Date:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}  \n"
        f"**Event ID:** {event_id}  \n"
        f"**Admiralty Rating:** {admiralty_rating}  \n"
        f"**Classification:** UNCLASSIFIED\n\n---\n\n"
    )

    return header + report_body


def generate_iir_report(session: Session, event_id: int) -> str:
    """Generate an Intelligence Information Report (IIR), template-based (no LLM).

    Returns a concise (~500 words max) markdown-formatted IIR with:
    - KEY JUDGMENTS section derived from claim-level corroboration
    - Items grouped by claim type (CONFIRMED ACTIONS, DISPUTED, THREATS/WARNINGS)
    - Limited to the 5 most significant items ranked by source credibility
    - Contradiction summary when claims are disputed
    """
    event = session.get(Event, event_id)
    if not event:
        raise ValueError(f"Event {event_id} not found")

    # Gather items and sources
    event_items = session.query(EventItem).filter_by(event_id=event_id).all()
    items = [ei.item for ei in event_items]

    # Compute corroboration
    try:
        corr = compute_corroboration_score(session, event_id)
    except Exception:
        corr = {
            "admiralty_rating": "F6",
            "corroboration_level": "UNCONFIRMED",
            "independent_sources": 0,
            "confidence": 0.0,
            "source_diversity": 0.0,
            "has_contradictions": False,
        }

    # Compute claim-level corroboration
    try:
        claim_corr = compute_claim_corroboration(session, event_id)
    except Exception:
        claim_corr = {
            "event_summary": event.summary,
            "claim_groups": [],
            "overall_confidence": 0.0,
            "has_contradictions": False,
            "contradiction_summary": "",
        }

    # Generate report number: IIR-{event_id:05d}-{YYYYMMDD}
    now = datetime.utcnow()
    report_number = f"IIR-{event_id:05d}-{now.strftime('%Y%m%d')}"

    # Date of information: earliest published_at among items
    pub_dates = [it.published_at for it in items if it.published_at]
    date_of_info = min(pub_dates).strftime("%Y-%m-%d %H:%M UTC") if pub_dates else "Unknown"

    # Subject
    subject = event.summary

    # Sources with reliability ratings
    source_lines: list[str] = []
    seen_sources: set[int] = set()
    for item in items:
        if item.source_id in seen_sources:
            continue
        seen_sources.add(item.source_id)
        source = item.source
        if source:
            from osint_monitor.processors.corroboration import _get_source_reliability
            grade = _get_source_reliability(source)
            grade_desc = RELIABILITY_GRADES.get(grade, "Cannot be judged")
            source_lines.append(
                f"- **{source.name}** (Type: {source.type}) "
                f"--- Reliability: {grade} ({grade_desc})"
            )

    # Select the 5 most significant items by source credibility
    items_with_cred = []
    for item in items:
        cred = item.source.credibility_score if item.source else 0.0
        items_with_cred.append((cred, item))
    items_with_cred.sort(key=lambda x: x[0], reverse=True)
    top_items = [item for _, item in items_with_cred[:5]]

    # Load claims for these items to group by type
    from osint_monitor.core.database import Claim
    item_ids = [it.id for it in top_items]
    claims_for_items = (
        session.query(Claim)
        .filter(Claim.item_id.in_(item_ids))
        .all()
    ) if item_ids else []

    # Map item_id -> dominant claim type
    from collections import Counter as _Counter
    item_claim_types: dict[int, str] = {}
    for it_id in item_ids:
        types = [c.claim_type for c in claims_for_items if c.item_id == it_id]
        if types:
            item_claim_types[it_id] = _Counter(types).most_common(1)[0][0]
        else:
            item_claim_types[it_id] = "assertion"

    # Group items by category
    confirmed_items: list[str] = []
    disputed_items: list[str] = []
    threat_items: list[str] = []

    for item in top_items:
        src_name = item.source.name if item.source else "Unknown"
        title = item.title.strip()
        ctype = item_claim_types.get(item.id, "assertion")

        bullet = f"- **[{src_name}]** {title}"

        if ctype in ("denial", "accusation"):
            disputed_items.append(bullet)
        elif ctype == "threat":
            threat_items.append(bullet)
        else:
            confirmed_items.append(bullet)

    # Also check claim_corr for disputed claim groups and add cross-source disputes
    for cg in claim_corr.get("claim_groups", []):
        if cg["consensus"] == "DISPUTED" and cg["assertions"] and cg["denials"]:
            a_sources = ", ".join(set(a["source"] for a in cg["assertions"][:2]))
            d_sources = ", ".join(set(d["source"] for d in cg["denials"][:2]))
            a_claim_short = cg["assertions"][0]["claim"][:80]
            d_claim_short = cg["denials"][0]["claim"][:80]
            dispute_line = (
                f"- **[{a_sources} claims]** {a_claim_short} "
                f"vs **[{d_sources}]** {d_claim_short}"
            )
            # Avoid duplicates
            if dispute_line not in disputed_items:
                disputed_items.append(dispute_line)

    # Build KEY JUDGMENTS from claim groups (2-3 sentences)
    key_judgments: list[str] = []
    for cg in claim_corr.get("claim_groups", [])[:3]:
        n_sources = len(set(
            a.get("source", "") for a in cg.get("assertions", []) + cg.get("denials", [])
        ))
        rating = cg.get("admiralty_rating", "F6")
        if cg["consensus"] == "CONFIRMED":
            key_judgments.append(
                f"- {cg['topic'].capitalize()} is confirmed by "
                f"{n_sources} independent source(s) ({rating})"
            )
        elif cg["consensus"] == "DISPUTED":
            key_judgments.append(
                f"- {cg['topic'].capitalize()} is disputed: "
                f"{len(cg.get('assertions', []))} assertion(s) vs "
                f"{len(cg.get('denials', []))} denial(s) ({rating})"
            )
        else:
            key_judgments.append(
                f"- {cg['topic'].capitalize()} reported but unverified ({rating})"
            )

    # Assemble the report sections
    sections: list[str] = []

    sections.append(f"""# INTELLIGENCE INFORMATION REPORT

**REPORT NUMBER:** {report_number}

**DATE OF REPORT:** {now.strftime('%Y-%m-%d %H:%M UTC')}

**DATE OF INFORMATION:** {date_of_info}

**CLASSIFICATION:** UNCLASSIFIED

---

## SUBJECT

{subject}

---

## SOURCE(S)

{chr(10).join(source_lines) if source_lines else '- No sources identified'}

---""")

    # KEY JUDGMENTS
    if key_judgments:
        sections.append(f"""
## KEY JUDGMENTS

{chr(10).join(key_judgments)}
""")

    # CONFIRMED ACTIONS
    if confirmed_items:
        sections.append(f"""
## CONFIRMED ACTIONS ({len(confirmed_items)} item(s))

{chr(10).join(confirmed_items)}
""")

    # DISPUTED
    if disputed_items:
        sections.append(f"""
## DISPUTED ({len(disputed_items)} item(s))

{chr(10).join(disputed_items)}
""")

    # THREATS/WARNINGS
    if threat_items:
        sections.append(f"""
## THREATS/WARNINGS ({len(threat_items)} item(s))

{chr(10).join(threat_items)}
""")

    # If no categorised items at all, show a generic section
    if not confirmed_items and not disputed_items and not threat_items:
        generic_bullets: list[str] = []
        for item in top_items:
            src_name = item.source.name if item.source else "Unknown"
            generic_bullets.append(f"- **[{src_name}]** {item.title.strip()}")
        sections.append(f"""
## INFORMATION ({len(generic_bullets)} item(s))

{chr(10).join(generic_bullets) if generic_bullets else '- No information items available'}
""")

    # Contradiction summary
    if claim_corr.get("has_contradictions") and claim_corr.get("contradiction_summary"):
        sections.append(f"""
## CONTRADICTION NOTE

{claim_corr['contradiction_summary']}
""")

    # COMMENTS footer
    sections.append(f"""---

**Corroboration Level:** {corr['corroboration_level']}
- Independent sources: {corr['independent_sources']}
- Admiralty rating: {corr['admiralty_rating']}
- Confidence: {corr['confidence']:.1%}

---

*Report generated automatically by OSINT Monitor on {now.strftime('%Y-%m-%d %H:%M UTC')}*
""")

    return chr(10).join(sections)


# ---------------------------------------------------------------------------
# Webhook Ingest
# ---------------------------------------------------------------------------

class WebhookPayload(BaseModel):
    """Schema for validating incoming webhook data."""
    title: str
    content: str = ""
    url: str = ""
    source_name: str = ""
    published_at: Optional[datetime] = None


def parse_webhook_payload(payload: dict) -> RawItemModel | None:
    """Parse and validate an external webhook payload into a RawItemModel.

    Expected fields: title, content, url, source_name, published_at (optional).
    Returns None if validation fails.
    """
    try:
        validated = WebhookPayload(**payload)
    except (ValidationError, TypeError) as exc:
        logger.warning(f"Webhook payload validation failed: {exc}")
        return None

    return RawItemModel(
        title=validated.title,
        content=validated.content,
        url=validated.url,
        source_name=validated.source_name,
        published_at=validated.published_at,
        fetched_at=datetime.utcnow(),
    )
