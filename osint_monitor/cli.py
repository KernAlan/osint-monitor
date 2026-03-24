"""CLI entrypoint for OSINT Monitor."""

import argparse
import logging
import sys


def main():
    parser = argparse.ArgumentParser(
        description="OSINT Monitor - Geopolitical Intelligence Platform",
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # collect: run collection + processing pipeline
    sub_collect = subparsers.add_parser("collect", help="Run collection and processing pipeline")
    sub_collect.add_argument("--hours-back", type=int, default=24)

    # briefing: generate a briefing
    sub_briefing = subparsers.add_parser("briefing", help="Generate intelligence briefing")
    sub_briefing.add_argument("--type", choices=["daily", "flash"], default="daily")
    sub_briefing.add_argument("--hours-back", type=int, default=24)
    sub_briefing.add_argument("--provider", default=None)
    sub_briefing.add_argument("--output", default=None, help="Write to file instead of stdout")

    # serve: start web dashboard
    sub_serve = subparsers.add_parser("serve", help="Start web dashboard")
    sub_serve.add_argument("--host", default="0.0.0.0")
    sub_serve.add_argument("--port", type=int, default=8000)
    sub_serve.add_argument("--no-reload", action="store_true", help="Disable auto-reload")

    # daemon: run scheduler daemon
    subparsers.add_parser("daemon", help="Run background scheduler daemon")

    # migrate: initialize/update database
    subparsers.add_parser("migrate", help="Initialize or update database schema")

    # seed: seed entities from config
    subparsers.add_parser("seed", help="Seed entities from config/entities.yaml")

    # import: import old archive
    sub_import = subparsers.add_parser("import", help="Import old archive.json")
    sub_import.add_argument("--file", default=None)

    # alerts: check current alerts
    sub_alerts = subparsers.add_parser("alerts", help="Check current alerts")
    sub_alerts.add_argument("--hours-back", type=int, default=24)

    # pause/resume: toggle pipeline on/off
    subparsers.add_parser("pause", help="Pause the daemon pipeline (all tiers skip)")
    subparsers.add_parser("resume", help="Resume the daemon pipeline")
    subparsers.add_parser("status", help="Show daemon pipeline status")

    # export: dump DB to JSON for git tracking
    subparsers.add_parser("export", help="Export events, entities, claims, briefings to data/export/")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if args.command is None:
        # Default: run collection pipeline (backwards compatible)
        _cmd_collect(argparse.Namespace(hours_back=24))
    elif args.command == "collect":
        _cmd_collect(args)
    elif args.command == "briefing":
        _cmd_briefing(args)
    elif args.command == "serve":
        _cmd_serve(args)
    elif args.command == "daemon":
        _cmd_daemon()
    elif args.command == "migrate":
        _cmd_migrate()
    elif args.command == "seed":
        _cmd_seed()
    elif args.command == "import":
        _cmd_import(args)
    elif args.command == "alerts":
        _cmd_alerts(args)
    elif args.command == "pause":
        _cmd_pause()
    elif args.command == "resume":
        _cmd_resume()
    elif args.command == "status":
        _cmd_status()
    elif args.command == "export":
        _cmd_export()


def _cmd_collect(args):
    from osint_monitor.processors.pipeline import run_pipeline
    print("=" * 50)
    print("OSINT MONITOR - Starting collection")
    print("=" * 50)
    run_pipeline()


def _cmd_briefing(args):
    from osint_monitor.core.database import init_db, get_session
    from osint_monitor.analysis.briefing import generate_daily_briefing

    init_db()
    session = get_session()

    result = generate_daily_briefing(
        session=session,
        hours_back=args.hours_back,
        provider=args.provider,
    )
    session.close()

    if args.output:
        from pathlib import Path
        Path(args.output).write_text(result.content_md)
        print(f"Briefing saved to {args.output}")
    else:
        print(result.content_md)


def _cmd_serve(args):
    import uvicorn
    print(f"Starting OSINT Monitor dashboard at http://{args.host}:{args.port}")
    uvicorn.run(
        "osint_monitor.api.app:app",
        host=args.host,
        port=args.port,
        reload=not args.no_reload,
    )


def _cmd_daemon():
    from osint_monitor.core.database import init_db
    from osint_monitor.core.config import load_sources_config
    from osint_monitor.core.scheduler import create_scheduler

    init_db()
    config = load_sources_config()
    tier_cfg = config.tiers

    scheduler = create_scheduler()
    scheduler.start()

    print("OSINT Monitor daemon started (tiered pipeline). Press Ctrl+C to stop.")
    print("Schedule:")
    print(f"  - Hot tier  (ADS-B, BGP, DNS, currency, commodities):  every {tier_cfg.hot_interval_seconds}s")
    print(f"  - Warm tier (RSS, social, OONI, travel advisories):    every {tier_cfg.warm_interval_seconds}s")
    print(f"  - Cold tier (FIRMS, USGS, sanctions, NVD, IAEA, SEC):  every {tier_cfg.cold_interval_seconds}s")
    print("  - Analysis: every 2 hours")
    print("  - Alerts: every 10 minutes")
    print("  - Daily briefing: 06:00 UTC")
    print()
    print("Delta processing: each tier only processes NEW items.")
    print("Post-processing (clustering, fusion, I&W) runs after any tier with new data.")

    try:
        import time
        while True:
            time.sleep(60)
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()
        print("\nDaemon stopped.")


def _cmd_migrate():
    from osint_monitor.core.database import init_db, DEFAULT_DB_PATH
    print(f"Initializing database at {DEFAULT_DB_PATH}")
    init_db()
    print("Done.")


def _cmd_seed():
    from osint_monitor.core.database import init_db, get_session
    from osint_monitor.processors.entity_resolver import EntityResolver

    init_db()
    session = get_session()
    resolver = EntityResolver(session)
    resolver.seed_from_config()
    session.close()
    print("Entity seeding complete.")


def _cmd_import(args):
    from scripts.import_archive import import_archive
    import_archive(args.file)


def _cmd_alerts(args):
    from osint_monitor.core.database import init_db, get_session
    from osint_monitor.alerting.engine import AlertEngine

    init_db()
    session = get_session()
    engine = AlertEngine(session)
    alerts = engine.evaluate_all(hours_back=args.hours_back)

    if alerts:
        print(f"\n{len(alerts)} ALERT(S):")
        for alert in alerts:
            level = "CRITICAL" if alert.severity >= 0.9 else "HIGH" if alert.severity >= 0.7 else "MEDIUM"
            print(f"  [{level}] {alert.title}")
            if alert.detail:
                print(f"    {alert.detail[:200].encode('ascii', 'replace').decode()}")
    else:
        print("No active alerts.")

    session.close()


def _cmd_pause():
    from osint_monitor.core.scheduler import pause, is_paused
    if is_paused():
        print("Pipeline is already paused.")
    else:
        pause()
        print("Pipeline PAUSED. Daemon tiers will skip until resumed.")
        print("  Resume with: python main.py resume")


def _cmd_resume():
    from osint_monitor.core.scheduler import resume, is_paused
    if not is_paused():
        print("Pipeline is already running.")
    else:
        resume()
        print("Pipeline RESUMED. Tiers will collect on next tick.")


def _cmd_status():
    from osint_monitor.core.scheduler import is_paused, get_status
    status = get_status()
    if status["paused"]:
        print(f"Pipeline: PAUSED (since {status['paused_since']})")
    else:
        print("Pipeline: RUNNING")
    if status["jobs"]:
        print("Jobs:")
        for job in status["jobs"]:
            print(f"  {job['name']} -> next: {job['next_run']}")
    else:
        print("No daemon running (jobs only visible when daemon is active).")


def _cmd_export():
    import json
    from pathlib import Path
    from osint_monitor.core.database import (
        init_db, get_session, Event, EventItem, Entity, ItemEntity,
        RawItem, Alert, Briefing, Claim,
    )
    from sqlalchemy import func

    init_db()
    session = get_session()
    export_dir = Path(__file__).parent.parent / "data" / "export"
    export_dir.mkdir(parents=True, exist_ok=True)

    # Events
    events = []
    for ev in session.query(Event).order_by(Event.severity.desc()).all():
        src_count = session.query(EventItem).filter_by(event_id=ev.id).count()
        events.append({
            "id": ev.id,
            "summary": ev.summary,
            "severity": ev.severity,
            "region": ev.region,
            "source_count": src_count,
            "lat": ev.lat,
            "lon": ev.lon,
            "location_name": ev.location_name,
            "first_reported_at": ev.first_reported_at.isoformat() if ev.first_reported_at else None,
            "last_updated_at": ev.last_updated_at.isoformat() if ev.last_updated_at else None,
        })
    (export_dir / "events.json").write_text(json.dumps(events, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"  Exported {len(events)} events")

    # Entities (top 200 by mention count)
    top_entities = (
        session.query(Entity, func.count(ItemEntity.id).label("mentions"))
        .outerjoin(ItemEntity)
        .group_by(Entity.id)
        .order_by(func.count(ItemEntity.id).desc())
        .limit(200)
        .all()
    )
    entities = []
    for ent, mentions in top_entities:
        entities.append({
            "id": ent.id,
            "canonical_name": ent.canonical_name,
            "entity_type": ent.entity_type,
            "aliases": ent.aliases or [],
            "mentions": mentions,
            "first_seen_at": ent.first_seen_at.isoformat() if ent.first_seen_at else None,
            "last_seen_at": ent.last_seen_at.isoformat() if ent.last_seen_at else None,
        })
    (export_dir / "entities.json").write_text(json.dumps(entities, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"  Exported {len(entities)} entities")

    # Claims
    claims = []
    for c in session.query(Claim).order_by(Claim.id.desc()).limit(2000).all():
        claims.append({
            "id": c.id,
            "subject": c.subject,
            "verb": c.verb,
            "object": c.object,
            "claim_text": c.claim_text[:300],
            "claim_type": c.claim_type,
            "source_name": c.source_name,
            "event_id": c.event_id,
        })
    (export_dir / "claims.json").write_text(json.dumps(claims, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"  Exported {len(claims)} claims")

    # Alerts
    alerts = []
    for a in session.query(Alert).order_by(Alert.created_at.desc()).limit(500).all():
        alerts.append({
            "id": a.id,
            "alert_type": a.alert_type,
            "severity": a.severity,
            "title": a.title,
            "detail": (a.detail or "")[:300],
            "acknowledged": a.acknowledged,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        })
    (export_dir / "alerts.json").write_text(json.dumps(alerts, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"  Exported {len(alerts)} alerts")

    # Briefings
    briefings = []
    for b in session.query(Briefing).order_by(Briefing.created_at.desc()).limit(50).all():
        briefings.append({
            "id": b.id,
            "briefing_type": b.briefing_type,
            "model_used": b.model_used,
            "content_md": b.content_md,
            "covering_from": b.covering_from.isoformat() if b.covering_from else None,
            "covering_to": b.covering_to.isoformat() if b.covering_to else None,
            "created_at": b.created_at.isoformat() if b.created_at else None,
        })
    (export_dir / "briefings.json").write_text(json.dumps(briefings, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"  Exported {len(briefings)} briefings")

    session.close()
    print(f"\nExport complete -> {export_dir}")


if __name__ == "__main__":
    main()
