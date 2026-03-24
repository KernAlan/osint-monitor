"""Browser-based ingest API endpoint.

Accepts JSON array of items from browser collectors (X, Reddit, etc.)
and pushes them through the pipeline.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel

from osint_monitor.core.database import get_session, init_db
from osint_monitor.core.models import RawItemModel
from osint_monitor.processors.dedup import Deduplicator
from osint_monitor.processors.entity_resolver import EntityResolver
from osint_monitor.processors.pipeline import _process_single_item

logger = logging.getLogger(__name__)

router = APIRouter()


class BrowserItem(BaseModel):
    title: str = ""
    content: str = ""
    url: str = ""
    published_at: Optional[str] = None
    source_name: str = "X-ForYou"
    external_id: str = ""


@router.post("")
async def ingest_items(items: list[BrowserItem]):
    """Ingest browser-collected items into the pipeline."""
    init_db()
    session = get_session()
    deduplicator = Deduplicator(session)
    resolver = EntityResolver(session)

    stats = {
        "new_items": 0,
        "duplicates": 0,
        "entities_extracted": 0,
        "errors": 0,
    }

    for item in items:
        try:
            pub_at = None
            if item.published_at:
                try:
                    pub_at = datetime.fromisoformat(item.published_at.replace("Z", "+00:00"))
                except ValueError:
                    pass

            raw_item = RawItemModel(
                title=item.title[:200],
                content=item.content[:5000],
                url=item.url,
                published_at=pub_at,
                source_name=item.source_name,
                external_id=item.external_id,
                fetched_at=datetime.now(timezone.utc),
            )
            _process_single_item(session, raw_item, deduplicator, resolver, stats)
        except Exception as e:
            stats["errors"] += 1
            logger.error(f"Ingest error: {e}")

    session.commit()
    session.close()

    logger.info(
        f"[browser] Ingested {stats['new_items']} new, "
        f"{stats['duplicates']} dupes from {len(items)} items"
    )

    return {
        "status": "ok",
        "total": len(items),
        **stats,
    }
