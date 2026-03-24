"""Processing pipeline orchestrator: collect -> dedup -> NLP -> score -> store.

Supports tiered execution for near-realtime delta processing:
  - hot  (2.5 min): ADS-B, BGP, DNS, currency, commodities, defense stocks, seismic
  - warm (10 min):   RSS, Nitter, travel advisories, OONI, flight routes, GDELT, cables
  - cold (60 min):   FIRMS, USGS, ACLED, sanctions, NVD, UNHCR, IAEA, Wikipedia, SEC, finance
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime

from sqlalchemy.orm import Session

from osint_monitor.core.config import load_sources_config, get_settings
from osint_monitor.core.database import (
    Event, EventItem, ItemEntity, RawItem, Source, get_session, init_db,
)
from osint_monitor.core.models import RawItemModel
from osint_monitor.collectors.base import BaseCollector
from osint_monitor.collectors.rss import NitterCollector, RSSCollector
from osint_monitor.processors.dedup import Deduplicator, compute_content_hash
from osint_monitor.processors.embeddings import embed_item, embedding_to_blob
from osint_monitor.processors.entity_resolver import EntityResolver
from osint_monitor.processors.nlp import extract_entities, extract_event_triples
from osint_monitor.processors.scoring import compute_composite_severity

logger = logging.getLogger(__name__)

# Lock to serialize the processing stage (NLP/embedding/clustering) across tiers.
# Collection is I/O-bound and runs in parallel; processing is CPU-bound and serialized.
_processing_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Tier assignment — single source of truth
# ---------------------------------------------------------------------------

COLLECTOR_TIERS: dict[str, str] = {
    # Hot: lightweight real-time checks, pre-narrative signals
    "ADSBTrackCollector": "hot",
    "BGPMonitor": "hot",
    "DNSHealthMonitor": "hot",
    "CurrencyCollector": "hot",
    "CommodityMonitor": "hot",
    "DefenseStockMonitor": "hot",
    "SeismicExplosionDetector": "hot",
    # Warm: match actual source update frequency
    "RSSCollector": "warm",
    "NitterCollector": "warm",
    "TravelAdvisoryCollector": "warm",
    "OONICollector": "warm",
    "FlightRouteMonitor": "warm",
    "GDELTCollector": "warm",
    "SubmarineCableMonitor": "warm",
    # Cold: everything else (slow-updating, rate-limited, heavy)
    "NASAFIRMSCollector": "cold",
    "USGSSeismicCollector": "cold",
    "ACLEDCollector": "cold",
    "SanctionsCollector": "cold",
    "NVDCollector": "cold",
    "UNHCRCollector": "cold",
    "IAEACollector": "cold",
    "WikipediaEditMonitor": "cold",
    "SECDefenseMonitor": "cold",
    "DocumentCollector": "cold",
    "FinanceBridgeCollector": "cold",
    "CongressCollector": "cold",
    "NOTAMCollector": "cold",
    "ADSBCollector": "hot",
    "COMTRADECollector": "cold",
    "SAMContractMonitor": "cold",
    "SatelliteTracker": "cold",
    "RIPEAtlasMonitor": "hot",
    # Browser-based collectors
    "XForYouCollector": "warm",
}


def build_collectors() -> list[BaseCollector]:
    """Build collector instances from config and structured intelligence sources."""
    config = load_sources_config()
    collectors: list[BaseCollector] = []

    # RSS feeds
    for feed in config.rss_feeds:
        if feed.enabled:
            collectors.append(RSSCollector(
                name=feed.name,
                url=feed.url,
                max_items=20,
            ))

    # Twitter/Nitter
    for account in config.twitter_accounts:
        collectors.append(NitterCollector(
            username=account.username,
            instances=config.nitter_instances,
            max_items=10,
        ))

    # Sanctions (OFAC, UN)
    try:
        from osint_monitor.collectors.sanctions import SanctionsCollector
        collectors.append(SanctionsCollector(feed_name="OFAC SDN", max_items=50))
        collectors.append(SanctionsCollector(feed_name="UN Consolidated", max_items=50))
    except Exception as e:
        logger.debug(f"Sanctions collectors skipped: {e}")

    # Structured intelligence sources (all free, no API keys for basics)
    try:
        from osint_monitor.collectors.structured import (
            ACLEDCollector, GDELTCollector, USGSSeismicCollector, NASAFIRMSCollector,
        )
        collectors.append(ACLEDCollector())
        collectors.append(GDELTCollector())
        collectors.append(USGSSeismicCollector())
        collectors.append(NASAFIRMSCollector())
    except ImportError:
        logger.debug("Structured collectors not available")

    # Government intelligence sources
    try:
        from osint_monitor.collectors.govint import (
            CongressCollector, TravelAdvisoryCollector, OONICollector,
        )
        collectors.append(CongressCollector())
        collectors.append(TravelAdvisoryCollector())
        collectors.append(OONICollector())
        # NOTAMCollector only if API key available
        import os
        if os.environ.get("FAA_NOTAM_KEY"):
            from osint_monitor.collectors.govint import NOTAMCollector
            collectors.append(NOTAMCollector())
    except ImportError:
        logger.debug("Government collectors not available")

    # Signal intelligence sources
    try:
        from osint_monitor.collectors.sigint import (
            IAEACollector, NVDCollector, CurrencyCollector, UNHCRCollector,
        )
        collectors.append(IAEACollector())
        collectors.append(NVDCollector())
        collectors.append(CurrencyCollector())
        collectors.append(UNHCRCollector())
        # COMTRADE only if API key available
        if os.environ.get("COMTRADE_API_KEY"):
            from osint_monitor.collectors.sigint import COMTRADECollector
            collectors.append(COMTRADECollector())
    except ImportError:
        logger.debug("Signal intelligence collectors not available")

    # ADS-B military tracking — ADSB.lol (free, unfiltered, global)
    try:
        from osint_monitor.collectors.adsb_tracks import ADSBTrackCollector
        collectors.append(ADSBTrackCollector())
    except ImportError:
        logger.debug("ADS-B track collector not available")
        # Fallback to OpenSky
        try:
            from osint_monitor.collectors.adsb import ADSBCollector
            for region in ["persian_gulf", "black_sea", "taiwan_strait"]:
                collectors.append(ADSBCollector(region_name=region, military_only=True))
        except ImportError:
            logger.debug("ADS-B collector not available")

    # Document feeds (Federal Register, CRS Reports)
    try:
        from osint_monitor.processors.documents import DocumentCollector
        collectors.append(DocumentCollector())
    except ImportError:
        logger.debug("Document collector not available")

    # Infrastructure intelligence (BGP, DNS, flight routes, seismic explosion detection)
    try:
        from osint_monitor.collectors.infrastructure import (
            BGPMonitor, DNSHealthMonitor, FlightRouteMonitor, SeismicExplosionDetector,
        )
        collectors.append(BGPMonitor())
        collectors.append(DNSHealthMonitor())
        collectors.append(FlightRouteMonitor())
        collectors.append(SeismicExplosionDetector())
    except ImportError:
        logger.debug("Infrastructure collectors not available")

    # Financial intelligence bridge (runs finance_agent, extracts signals)
    try:
        from osint_monitor.collectors.finance_bridge import FinanceBridgeCollector
        collectors.append(FinanceBridgeCollector())
    except ImportError:
        logger.debug("Finance bridge not available")

    # Financial intelligence (commodities, defense stocks, SEC filings)
    try:
        from osint_monitor.collectors.financial import (
            CommodityMonitor, DefenseStockMonitor, SECDefenseMonitor,
        )
        collectors.append(CommodityMonitor())
        collectors.append(DefenseStockMonitor())
        collectors.append(SECDefenseMonitor())
        # SAM.gov only if API key available
        if os.environ.get("SAM_GOV_API_KEY"):
            from osint_monitor.collectors.financial import SAMContractMonitor
            collectors.append(SAMContractMonitor())
    except ImportError:
        logger.debug("Financial collectors not available")

    # Spectrum intelligence (satellite tracking, RIPE Atlas, Wikipedia edits, cable monitoring)
    try:
        from osint_monitor.collectors.spectrum import (
            WikipediaEditMonitor, SubmarineCableMonitor,
        )
        collectors.append(WikipediaEditMonitor())
        collectors.append(SubmarineCableMonitor())
        # Space-Track only if credentials set
        if os.environ.get("SPACETRACK_USER"):
            from osint_monitor.collectors.spectrum import SatelliteTracker
            collectors.append(SatelliteTracker())
        # RIPE Atlas only if API key set
        if os.environ.get("RIPE_ATLAS_KEY"):
            from osint_monitor.collectors.spectrum import RIPEAtlasMonitor
            collectors.append(RIPEAtlasMonitor())
    except ImportError:
        logger.debug("Spectrum collectors not available")

    # Browser-based X/Twitter collector (uses Playwright + Chrome profile)
    try:
        from osint_monitor.collectors.browser import XForYouCollector
        collectors.append(XForYouCollector(scroll_rounds=15, max_items=60))
    except ImportError:
        logger.debug("Browser collector not available (playwright not installed)")

    return collectors


def build_collectors_by_tier() -> dict[str, list[BaseCollector]]:
    """Build collectors grouped by tier (hot/warm/cold)."""
    all_collectors = build_collectors()
    tiers: dict[str, list[BaseCollector]] = {"hot": [], "warm": [], "cold": []}
    for c in all_collectors:
        tier = COLLECTOR_TIERS.get(type(c).__name__, "cold")
        tiers[tier].append(c)
    return tiers


def ensure_source(session: Session, name: str, source_type: str, url: str, credibility: float = 0.5) -> Source:
    """Get or create a Source record."""
    source = session.query(Source).filter_by(name=name).first()
    if source and source.type == "rss" and source_type != "rss":
        # Fix sources that were incorrectly stored as "rss"
        source.type = source_type
        session.flush()
    if not source:
        config = load_sources_config()
        # Look up credibility from config
        for feed in config.rss_feeds:
            if feed.name == name:
                credibility = feed.credibility_score
                break

        source = Source(
            name=name,
            type=source_type,
            url=url,
            credibility_score=credibility,
        )
        session.add(source)
        session.flush()
    return source


def _run_single_collector(collector: BaseCollector) -> list[RawItemModel]:
    """Run a single collector and stamp source_type. Thread-safe."""
    try:
        items = collector.collect()
        for item in items:
            if item.source_type == "rss" and collector.source_type != "rss":
                item.source_type = collector.source_type
        return items
    except Exception as e:
        logger.error(f"Collector {collector.name} failed: {e}")
        return []


def run_collection(session: Session) -> list[RawItemModel]:
    """Run all collectors concurrently and return raw items."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    collectors = build_collectors()
    all_items: list[RawItemModel] = []

    print("\n--- Collecting from sources ---")
    with ThreadPoolExecutor(max_workers=12) as pool:
        futures = {pool.submit(_run_single_collector, c): c for c in collectors}
        for future in as_completed(futures):
            items = future.result()
            all_items.extend(items)

    print(f"--- Collected {len(all_items)} total items ---\n")
    return all_items


def run_collection_for_tier(session: Session, tier: str) -> list[RawItemModel]:
    """Collect from a specific tier's sources only.

    Args:
        session: Database session.
        tier: One of "hot", "warm", "cold".

    Returns:
        List of collected raw items.
    """
    tiers = build_collectors_by_tier()
    collectors = tiers.get(tier, [])
    if not collectors:
        logger.info(f"No collectors for tier '{tier}'")
        return []

    from concurrent.futures import ThreadPoolExecutor, as_completed

    all_items: list[RawItemModel] = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(_run_single_collector, c): c for c in collectors}
        for future in as_completed(futures):
            all_items.extend(future.result())

    logger.info(f"[{tier}] Collected {len(all_items)} items from {len(collectors)} sources")
    return all_items


def process_new_items(session: Session, raw_items: list[RawItemModel]) -> dict:
    """Process raw items through dedup + NLP + entity resolution + claims.

    This is the delta processing stage — it only works on the items passed in.
    Thread-safe: acquires _processing_lock to prevent concurrent NLP runs.

    Returns:
        Stats dict with new_items, duplicates, entities_extracted counts.
    """
    stats = {
        "new_items": 0,
        "duplicates": 0,
        "entities_extracted": 0,
    }

    if not raw_items:
        return stats

    with _processing_lock:
        deduplicator = Deduplicator(session)
        resolver = EntityResolver(session)
        resolver.seed_from_config()

        for raw_item in raw_items:
            savepoint = session.begin_nested()
            try:
                _process_single_item(session, raw_item, deduplicator, resolver, stats)
                savepoint.commit()
            except Exception as e:
                savepoint.rollback()
                logger.error(f"Failed to process: {raw_item.title[:60]}: {e}")
                continue

        session.commit()

    return stats


def run_post_processing(session: Session, quiet: bool = False) -> dict:
    """Run clustering, enrichment, geocoding, corroboration, I&W, and fusion.

    This runs on all recent data and is designed to be called after any tier
    produces new items.

    Args:
        session: Database session.
        quiet: If True, suppress print output (for daemon tier jobs).

    Returns:
        Stats dict.
    """
    stats = {}

    def _print(msg: str):
        if not quiet:
            print(msg)

    # 1. Clustering
    _print("--- Clustering events ---")
    try:
        from osint_monitor.processors.clustering import cluster_recent_items, persist_clusters
        clusters = cluster_recent_items(session)
        if clusters:
            persist_clusters(session, clusters)
            stats["events_created"] = len(clusters)
            _print(f"  Created {len(clusters)} event clusters")
        else:
            _print("  No clusters formed")
    except Exception as e:
        logger.error(f"Clustering failed: {e}")

    # 2. Full-text enrichment
    _print("--- Enriching full text ---")
    try:
        from osint_monitor.processors.fulltext import enrich_recent_items
        ft_stats = enrich_recent_items(session, hours_back=24, max_items=30)
        stats["enriched"] = ft_stats.get("enriched", 0) if isinstance(ft_stats, dict) else 0
        _print(f"  Enriched {stats['enriched']} items")
    except Exception as e:
        logger.debug(f"Full-text enrichment skipped: {e}")

    # 3. Relation extraction
    _print("--- Extracting relations ---")
    try:
        from osint_monitor.processors.relations import extract_relations, persist_relations
        rel_count = 0
        recent_items = (
            session.query(RawItem)
            .order_by(RawItem.fetched_at.desc())
            .limit(50)
            .all()
        )
        for item in recent_items:
            text = f"{item.title} {item.content or ''}"
            entity_names = [ie.entity.canonical_name for ie in item.item_entities if ie.entity]
            relations = extract_relations(text, entities=entity_names)
            if relations:
                persist_relations(session, item.id, relations)
                rel_count += len(relations)
        session.commit()
        stats["relations"] = rel_count
        _print(f"  Extracted {rel_count} relations")
    except Exception as e:
        logger.debug(f"Relation extraction skipped: {e}")

    # 4. Geocoding
    _print("--- Geocoding events ---")
    try:
        from osint_monitor.processors.geocoding import geocode_all_events
        geocoded = geocode_all_events(session)
        stats["geocoded"] = geocoded
        _print(f"  Geocoded {geocoded} events")
    except Exception as e:
        logger.error(f"Geocoding failed: {e}")

    # 5. Corroboration scoring
    _print("--- Scoring corroboration ---")
    try:
        from osint_monitor.processors.corroboration import compute_corroboration_score
        events = session.query(Event).all()
        for ev in events:
            try:
                sc = compute_corroboration_score(session, ev.id)
                ev.source_count = sc.get("independent_sources", 0)
                ev.admiralty_rating = sc.get("admiralty_rating")
                ev.corroboration_level = sc.get("corroboration_level", "UNVERIFIED")
                ev.has_contradictions = sc.get("has_contradictions", False)
            except Exception:
                ev.corroboration_level = "UNVERIFIED"
        session.commit()
        _print(f"  Corroboration cached on {len(events)} events")
    except Exception as e:
        logger.debug(f"Corroboration scoring skipped: {e}")

    # 6. Indicators & Warnings
    _print("--- Evaluating I&W indicators ---")
    try:
        from osint_monitor.analysis.indicators import evaluate_indicators
        iw_results = evaluate_indicators(session, hours_back=24)
        for scenario in iw_results:
            if scenario.get("status") in ("ELEVATED", "WARNING"):
                key = scenario.get("scenario_key", scenario.get("scenario", "?"))
                score = scenario.get("threat_score", scenario.get("score", 0))
                _print(f"  [{scenario['status']}] {key}: {score:.0%}")
        stats["iw_elevated"] = sum(1 for s in iw_results if s.get("status") in ("ELEVATED", "WARNING"))
    except Exception as e:
        logger.debug(f"I&W evaluation skipped: {e}")

    # 7. Cross-modal signal fusion
    _print("--- Cross-modal signal fusion ---")
    try:
        from osint_monitor.analysis.fusion import fuse_signals, detect_signal_gaps
        correlations = fuse_signals(session, hours_back=24)
        gaps = detect_signal_gaps(session, hours_back=24)
        stats["fusion_correlations"] = len(correlations)
        stats["signal_gaps"] = len(gaps)
        for corr in correlations[:5]:
            _print(f"  [{corr['confidence']:.0%}] {corr['pattern']}: {', '.join(corr['modalities_matched'])} ({corr['time_bucket']})")
        for gap in gaps:
            _print(f"  [GAP] {gap['description'][:100]}")
    except Exception as e:
        logger.debug(f"Signal fusion skipped: {e}")

    return stats


def run_tier(tier: str, db_url: str | None = None, quiet: bool = False) -> dict:
    """Run a single tier: collect -> process deltas -> post-process if new items.

    This is the main entry point for the tiered scheduler.

    Args:
        tier: One of "hot", "warm", "cold".
        db_url: Optional database URL override.
        quiet: If True, suppress print output.

    Returns:
        Stats dict.
    """
    init_db(db_url)
    session = get_session(db_url)

    try:
        # 1. Collect this tier
        raw_items = run_collection_for_tier(session, tier)

        # 2. Process new items (delta only)
        proc_stats = process_new_items(session, raw_items)

        # 3. If we got new items, run post-processing (clustering, fusion, etc.)
        if proc_stats.get("new_items", 0) > 0:
            post_stats = run_post_processing(session, quiet=quiet)
            proc_stats.update(post_stats)
            logger.info(f"[{tier}] {proc_stats['new_items']} new items processed, post-processing complete")
        else:
            logger.info(f"[{tier}] No new items, skipping post-processing")

        return proc_stats

    except Exception as e:
        session.rollback()
        logger.error(f"[{tier}] Pipeline error: {e}")
        raise
    finally:
        session.close()


def run_pipeline(db_url: str | None = None) -> dict:
    """Run the full processing pipeline (all tiers, all stages).

    This is the backward-compatible entry point used by `python main.py collect`.
    """
    init_db(db_url)
    session = get_session(db_url)

    stats = {
        "collected": 0,
        "new_items": 0,
        "duplicates": 0,
        "entities_extracted": 0,
        "events_created": 0,
    }

    try:
        # 1. Collect all tiers at once (same as before)
        raw_items = run_collection(session)
        stats["collected"] = len(raw_items)

        if not raw_items:
            print("No items collected.")
            return stats

        # 2. Process all items
        proc_stats = process_new_items(session, raw_items)
        stats.update(proc_stats)

        # 3. Post-processing
        post_stats = run_post_processing(session)
        stats.update(post_stats)

        print(f"\n--- Pipeline complete ---")
        print(f"  Collected: {stats['collected']}")
        print(f"  New items: {stats['new_items']}")
        print(f"  Duplicates: {stats['duplicates']}")
        print(f"  Entities: {stats['entities_extracted']}")
        print(f"  Events: {stats.get('events_created', 0)}")
        print(f"  Geocoded: {stats.get('geocoded', 0)}")
        print(f"  I&W elevated: {stats.get('iw_elevated', 0)}")
        print(f"  Fusion correlations: {stats.get('fusion_correlations', 0)}")
        print(f"  Signal gaps: {stats.get('signal_gaps', 0)}")

    except Exception as e:
        session.rollback()
        logger.error(f"Pipeline error: {e}")
        raise
    finally:
        session.close()

    return stats


def _process_single_item(
    session: Session,
    raw_item: RawItemModel,
    deduplicator: Deduplicator,
    resolver: EntityResolver,
    stats: dict,
):
    """Process a single item through the pipeline."""
    # Dedup
    dedup_result = deduplicator.deduplicate(raw_item)

    if dedup_result["is_duplicate"]:
        stats["duplicates"] += 1
        return

    # Ensure source exists
    source = ensure_source(
        session,
        raw_item.source_name,
        raw_item.source_type,
        raw_item.url,
    )

    # Check if (source_id, external_id) already exists in DB — catches duplicates
    # that pass content-hash/semantic dedup but have the same external_id
    if raw_item.external_id and raw_item.external_id.strip():
        existing = (
            session.query(RawItem.id)
            .filter_by(source_id=source.id, external_id=raw_item.external_id)
            .first()
        )
        if existing:
            stats["duplicates"] += 1
            return

    # Store raw item
    embedding = dedup_result.get("embedding")
    db_item = RawItem(
        source_id=source.id,
        external_id=raw_item.external_id,
        title=raw_item.title,
        content=raw_item.content,
        url=raw_item.url,
        published_at=raw_item.published_at,
        fetched_at=raw_item.fetched_at,
        content_hash=dedup_result["content_hash"],
        embedding=embedding_to_blob(embedding) if embedding is not None else None,
    )
    session.add(db_item)
    session.flush()
    stats["new_items"] += 1

    # Multilingual: detect and translate if non-English
    try:
        from osint_monitor.processors.language import process_multilingual_item
        raw_item = process_multilingual_item(raw_item)
    except Exception:
        pass  # continue with original language

    # NLP: Extract entities
    text = f"{raw_item.title} {raw_item.content}"
    extracted = []
    try:
        extracted = extract_entities(text)
        seen_entity_roles: set[tuple[int, str]] = set()
        for ext_entity in extracted:
            entity = resolver.resolve(ext_entity)
            key = (entity.id, ext_entity.role.value)
            if key in seen_entity_roles:
                continue  # skip duplicate entity+role per item
            seen_entity_roles.add(key)
            session.add(ItemEntity(
                item_id=db_item.id,
                entity_id=entity.id,
                role=ext_entity.role.value,
                confidence=ext_entity.confidence,
                span_text=ext_entity.text,
            ))
            stats["entities_extracted"] += 1
        session.flush()
    except Exception as e:
        logger.error(f"NLP failed for item '{raw_item.title[:50]}': {e}")
        raise  # let the savepoint handle rollback

    # Claim extraction
    try:
        from osint_monitor.processors.stance import extract_and_classify_claims
        extract_and_classify_claims(session, db_item.id)
    except Exception as e:
        logger.debug(f"Claim extraction failed for item {db_item.id}: {e}")

    # Scoring
    try:
        scores = compute_composite_severity(
            text, extracted,
            raw_item.source_name,
        )
        # Store severity in event linking later
    except Exception as e:
        logger.debug(f"Scoring failed: {e}")

    # Link near-duplicates from different sources to same event
    if dedup_result["duplicate_type"] == "near_different_source":
        existing_item = dedup_result["existing_item"]
        # Find or create event for the existing item
        existing_event_item = (
            session.query(EventItem)
            .filter_by(item_id=existing_item.id)
            .first()
        )
        if existing_event_item:
            session.add(EventItem(
                event_id=existing_event_item.event_id,
                item_id=db_item.id,
                similarity_score=dedup_result["similarity"],
            ))
