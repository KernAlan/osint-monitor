"""Intelligence analysis API routes.

Every route uses lazy imports so the server starts even if optional
heavy dependencies (sentence-transformers, spaCy, etc.) are missing.
Errors are surfaced as JSON rather than 500s.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel

from osint_monitor.core.database import get_session

router = APIRouter()


# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------

class WebhookPayload(BaseModel):
    title: str
    content: str = ""
    url: str = ""
    source_name: str = "webhook"


class ImageAnalysisRequest(BaseModel):
    url: str


# ---------------------------------------------------------------------------
# STIX export
# ---------------------------------------------------------------------------

@router.get("/stix/events/{event_id}")
def export_event_stix(event_id: int):
    """Export a single event as a STIX 2.1 bundle."""
    from osint_monitor.analysis.stix_export import event_to_stix_bundle
    session = get_session()
    try:
        bundle = event_to_stix_bundle(session, event_id)
        return JSONResponse(content=bundle, media_type="application/stix+json;version=2.1")
    finally:
        session.close()


@router.get("/stix/export")
def export_all_stix(hours_back: int = Query(default=24, ge=1, le=720)):
    """Export all recent events as a STIX 2.1 bundle."""
    from osint_monitor.analysis.stix_export import export_all_events_stix
    session = get_session()
    try:
        bundle = export_all_events_stix(session, hours_back=hours_back)
        return JSONResponse(content=bundle, media_type="application/stix+json;version=2.1")
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Corroboration (Admiralty/NATO)
# ---------------------------------------------------------------------------

@router.get("/corroboration/{event_id}")
def get_corroboration(event_id: int):
    """Get Admiralty/NATO corroboration score for an event."""
    from osint_monitor.processors.corroboration import compute_corroboration_score
    session = get_session()
    try:
        return compute_corroboration_score(session, event_id)
    finally:
        session.close()


@router.get("/corroboration/{event_id}/disagreements")
def get_disagreements(event_id: int):
    """Detect source disagreements within an event."""
    from osint_monitor.processors.corroboration import detect_source_disagreement
    session = get_session()
    try:
        return {"disagreements": detect_source_disagreement(session, event_id)}
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Indicators & Warnings
# ---------------------------------------------------------------------------

@router.get("/indicators")
def get_indicators(
    hours_back: int = Query(default=24, ge=1, le=720),
    use_llm: bool = Query(default=False, description="Use LLM scoring instead of keyword matching"),
):
    """Evaluate all I&W indicator scenarios. Set use_llm=true for LLM-scored evaluation."""
    session = get_session()
    try:
        if use_llm:
            from osint_monitor.analysis.indicators import evaluate_indicators_llm
            return {"scenarios": evaluate_indicators_llm(session, hours_back=hours_back), "scoring_method": "llm"}
        else:
            from osint_monitor.analysis.indicators import evaluate_indicators
            return {"scenarios": evaluate_indicators(session, hours_back=hours_back), "scoring_method": "keyword"}
    finally:
        session.close()


@router.get("/indicators/{scenario_key}")
def get_scenario(scenario_key: str, hours_back: int = Query(default=72, ge=1, le=720)):
    """Get detailed status for a specific I&W scenario."""
    from osint_monitor.analysis.indicators import get_scenario_status
    session = get_session()
    try:
        return get_scenario_status(session, scenario_key, hours_back=hours_back)
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Escalation probability
# ---------------------------------------------------------------------------

@router.get("/escalation/{scenario_key}")
def escalation_probability(
    scenario_key: str,
    hours_back: int = Query(default=72, ge=1, le=720),
):
    """Get escalation probability for a scenario."""
    from osint_monitor.analysis.indicators import estimate_escalation_probability
    session = get_session()
    try:
        return estimate_escalation_probability(session, scenario_key, hours_forward=168)
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Temporal intelligence
# ---------------------------------------------------------------------------

@router.get("/timeline/event/{event_id}")
def get_event_timeline(event_id: int):
    """Get temporal timeline for an event."""
    from osint_monitor.analysis.temporal import build_event_timeline
    session = get_session()
    try:
        return {"timeline": build_event_timeline(session, event_id)}
    finally:
        session.close()


@router.get("/timeline/entity/{entity_id}")
def get_entity_timeline(entity_id: int, days: int = Query(default=30, ge=1, le=365)):
    """Get mention timeline for an entity."""
    from osint_monitor.analysis.temporal import build_entity_timeline
    session = get_session()
    try:
        return {"timeline": build_entity_timeline(session, entity_id, days=days)}
    finally:
        session.close()


@router.get("/propagation/{event_id}")
def get_propagation(event_id: int):
    """Detect how a story propagated across sources."""
    from osint_monitor.analysis.temporal import detect_narrative_propagation
    session = get_session()
    try:
        return detect_narrative_propagation(session, event_id)
    finally:
        session.close()


# ---------------------------------------------------------------------------
# ADS-B
# ---------------------------------------------------------------------------

@router.get("/adsb/{region}")
def get_adsb(region: str):
    """Get current military ADS-B tracks for a region."""
    from osint_monitor.collectors.adsb import ADSBCollector
    collector = ADSBCollector(region_name=region)
    items = collector.collect()
    return {
        "region": region,
        "aircraft_count": len(items),
        "tracks": [{"title": i.title, "content": i.content, "url": i.url} for i in items],
    }


# ---------------------------------------------------------------------------
# Webhook ingest
# ---------------------------------------------------------------------------

@router.post("/webhook")
def webhook_ingest(payload: WebhookPayload):
    """Ingest an intelligence item via webhook."""
    from osint_monitor.analysis.export import parse_webhook_payload
    from osint_monitor.core.database import RawItem, Source, init_db
    from osint_monitor.processors.dedup import compute_content_hash

    item_model = parse_webhook_payload(payload.model_dump())
    if item_model is None:
        return {"error": "Invalid payload"}

    session = get_session()
    try:
        # Ensure source
        source = session.query(Source).filter_by(name=payload.source_name).first()
        if not source:
            source = Source(name=payload.source_name, type="webhook", url="", credibility_score=0.3)
            session.add(source)
            session.flush()

        db_item = RawItem(
            source_id=source.id,
            title=payload.title,
            content=payload.content,
            url=payload.url,
            fetched_at=datetime.utcnow(),
            content_hash=compute_content_hash(payload.title, payload.content),
        )
        session.add(db_item)
        session.commit()
        return {"status": "accepted", "item_id": db_item.id}
    finally:
        session.close()


# ---------------------------------------------------------------------------
# CSV / JSON export  (delegates to analysis/export.py)
# ---------------------------------------------------------------------------

@router.get("/export/events/csv", response_class=PlainTextResponse)
def export_events_csv_route(hours_back: int = Query(default=24, ge=1, le=720)):
    """Export events as CSV."""
    from osint_monitor.analysis.export import export_events_csv
    session = get_session()
    try:
        csv_str = export_events_csv(session, hours_back=hours_back)
        return PlainTextResponse(content=csv_str, media_type="text/csv")
    finally:
        session.close()


@router.get("/export/entities/csv", response_class=PlainTextResponse)
def export_entities_csv_route():
    """Export entities as CSV."""
    from osint_monitor.analysis.export import export_entities_csv
    session = get_session()
    try:
        csv_str = export_entities_csv(session)
        return PlainTextResponse(content=csv_str, media_type="text/csv")
    finally:
        session.close()


@router.get("/export/items/json")
def export_items_json_route(hours_back: int = Query(default=24, ge=1, le=720)):
    """Export raw items as JSON for Jupyter / Maltego."""
    from osint_monitor.analysis.export import export_items_json
    session = get_session()
    try:
        return {"items": export_items_json(session, hours_back=hours_back)}
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Intelligence reports (CIR / IIR)
# ---------------------------------------------------------------------------

@router.get("/report/cir/{event_id}")
def generate_cir(event_id: int, provider: Optional[str] = None):
    """Generate a Current Intelligence Report for an event (requires LLM API key)."""
    from osint_monitor.analysis.export import generate_cir_report
    session = get_session()
    try:
        report = generate_cir_report(session, event_id, provider=provider)
        return {"report": report}
    except ValueError as e:
        return {"error": str(e), "hint": "CIR generation requires an LLM API key. Set OPENAI_API_KEY environment variable."}
    finally:
        session.close()


@router.get("/report/iir/{event_id}")
def generate_iir(event_id: int):
    """Generate an Intelligence Information Report for an event."""
    from osint_monitor.analysis.export import generate_iir_report
    session = get_session()
    try:
        return {"report": generate_iir_report(session, event_id)}
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Coordination / influence detection
# ---------------------------------------------------------------------------

@router.get("/coordination/posting")
def detect_coord_posting(
    hours_back: int = Query(default=24, ge=1, le=720),
    time_window_seconds: int = Query(default=60, ge=10, le=600),
):
    """Detect coordinated posting patterns across sources."""
    from osint_monitor.analysis.coordination import detect_coordinated_posting
    session = get_session()
    try:
        return detect_coordinated_posting(session, hours_back=hours_back, time_window_seconds=time_window_seconds)
    finally:
        session.close()


@router.get("/coordination/narrative")
def track_narrative_route(
    keywords: str = Query(..., description="Comma-separated keywords"),
    hours_back: int = Query(default=72, ge=1, le=720),
):
    """Track a narrative across sources by keywords."""
    from osint_monitor.analysis.coordination import track_narrative
    keyword_list = [k.strip() for k in keywords.split(",") if k.strip()]
    session = get_session()
    try:
        return track_narrative(session, keywords=keyword_list, hours_back=hours_back)
    finally:
        session.close()


@router.get("/coordination/amplification")
def amplification_network_route(hours_back: int = Query(default=48, ge=1, le=720)):
    """Map amplification / retweet network."""
    from osint_monitor.analysis.coordination import map_amplification_network
    session = get_session()
    try:
        return map_amplification_network(session, hours_back=hours_back)
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Graph analytics  (all need build_entity_graph() first)
# ---------------------------------------------------------------------------

def _build_graph(session):
    """Helper: build the entity graph from the session."""
    from osint_monitor.analysis.graph import build_entity_graph
    return build_entity_graph(session)


@router.get("/graph/communities")
def graph_communities():
    """Detect communities in the entity relationship graph."""
    from osint_monitor.analysis.graph import detect_communities
    session = get_session()
    try:
        G = _build_graph(session)
        return {"communities": detect_communities(G)}
    finally:
        session.close()


@router.get("/graph/centrality")
def graph_centrality(limit: int = Query(default=50, ge=1, le=500)):
    """Compute centrality scores for entities."""
    from osint_monitor.analysis.graph import compute_centrality_scores
    session = get_session()
    try:
        G = _build_graph(session)
        scores = compute_centrality_scores(G)
        return {"entities": scores[:limit]}
    finally:
        session.close()


@router.get("/graph/brokers")
def graph_brokers(n: int = Query(default=10, ge=1, le=50)):
    """Identify key broker entities bridging communities."""
    from osint_monitor.analysis.graph import find_key_brokers
    session = get_session()
    try:
        G = _build_graph(session)
        return {"brokers": find_key_brokers(G, n=n)}
    finally:
        session.close()


@router.get("/graph/full")
def graph_full():
    """Export the full entity graph in vis.js compatible format."""
    from osint_monitor.analysis.graph import export_graph_json
    session = get_session()
    try:
        G = _build_graph(session)
        return export_graph_json(G)
    finally:
        session.close()


# ---------------------------------------------------------------------------
# ACH (Analysis of Competing Hypotheses)
# ---------------------------------------------------------------------------

@router.post("/ach/{event_id}")
def build_ach(event_id: int, provider: Optional[str] = None):
    """Build an ACH matrix for an event."""
    from osint_monitor.analysis.ach import build_ach_from_event
    session = get_session()
    try:
        matrix = build_ach_from_event(session, event_id, llm_provider=provider)
        return {
            "hypotheses": [{"id": h.id, "description": h.description, "prior": h.prior_probability} for h in matrix.hypotheses],
            "evidence": [{"id": e.id, "description": e.description, "source": e.source, "credibility": e.credibility} for e in matrix.evidence],
            "ratings": {f"{k[0]}:{k[1]}": v for k, v in matrix.ratings.items()},
            "scores": matrix.compute_scores(),
            "diagnostics": matrix.identify_diagnostics(),
        }
    finally:
        session.close()


@router.get("/ach/{event_id}/markdown")
def ach_markdown(event_id: int, provider: Optional[str] = None):
    """Return the ACH matrix for an event as markdown."""
    from osint_monitor.analysis.ach import build_ach_from_event, ach_to_markdown
    session = get_session()
    try:
        matrix = build_ach_from_event(session, event_id, llm_provider=provider)
        md = ach_to_markdown(matrix)
        return PlainTextResponse(content=md, media_type="text/markdown")
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Stance detection
# ---------------------------------------------------------------------------

@router.get("/stance/{event_id}")
def detect_stance(event_id: int):
    """Detect claim-level stance (agree/disagree) across sources in an event."""
    from osint_monitor.processors.stance import detect_source_stance
    session = get_session()
    try:
        return {"stances": detect_source_stance(session, event_id)}
    finally:
        session.close()


# ---------------------------------------------------------------------------
# IMINT (image analysis)
# ---------------------------------------------------------------------------

@router.post("/imint/analyze")
def analyze_image_route(payload: ImageAnalysisRequest):
    """Analyze an image URL for EXIF, OCR, manipulation, and object detection."""
    from osint_monitor.processors.imint import analyze_image
    return analyze_image(payload.url)
