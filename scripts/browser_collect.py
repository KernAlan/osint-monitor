#!/usr/bin/env python3
"""Browser-based collector ingestion script.

Takes JSON items from stdin (or a file) and pushes them through the pipeline
as if they came from a normal collector. Used by the Claude browser agent
to feed X/Twitter and other browser-scraped content into the OSINT pipeline.

Usage:
    echo '[{"title":"...", "content":"...", ...}]' | python scripts/browser_collect.py
    python scripts/browser_collect.py items.json
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from osint_monitor.core.database import get_session, init_db, RawItem, Source
from osint_monitor.core.models import RawItemModel
from osint_monitor.processors.dedup import Deduplicator, compute_content_hash
from osint_monitor.processors.embeddings import embed_item, embedding_to_blob
from osint_monitor.processors.entity_resolver import EntityResolver
from osint_monitor.processors.pipeline import _process_single_item, ensure_source


def ingest_items(items: list[dict]) -> dict:
    """Ingest browser-collected items into the pipeline."""
    init_db()
    session = get_session()
    deduplicator = Deduplicator(session)
    resolver = EntityResolver(session)

    stats = {
        "total": len(items),
        "new_items": 0,
        "duplicates": 0,
        "entities_extracted": 0,
        "errors": 0,
    }

    for item_data in items:
        try:
            raw_item = RawItemModel(
                title=item_data.get("title", "")[:200],
                content=item_data.get("content", "")[:5000],
                url=item_data.get("url", ""),
                published_at=(
                    datetime.fromisoformat(item_data["published_at"])
                    if item_data.get("published_at")
                    else None
                ),
                source_name=item_data.get("source_name", "X-ForYou"),
                external_id=item_data.get("external_id", ""),
                fetched_at=datetime.now(timezone.utc),
            )
            _process_single_item(session, raw_item, deduplicator, resolver, stats)
        except Exception as e:
            stats["errors"] += 1
            print(f"  [err] {e}", file=sys.stderr)

    session.commit()
    session.close()
    return stats


def main():
    if len(sys.argv) > 1 and sys.argv[1] != "-":
        with open(sys.argv[1]) as f:
            data = json.load(f)
    else:
        data = json.load(sys.stdin)

    if not isinstance(data, list):
        data = [data]

    stats = ingest_items(data)
    print(f"  [ok] X Browser Feed: {stats['new_items']} new, "
          f"{stats['duplicates']} dupes, {stats['errors']} errors "
          f"(of {stats['total']} total)")


if __name__ == "__main__":
    main()
