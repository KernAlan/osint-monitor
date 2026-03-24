#!/usr/bin/env python3
"""Import data from old archive.json into the new database."""

import json
import sys
from datetime import datetime
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from osint_monitor.core.database import RawItem, Source, init_db, get_session
from osint_monitor.processors.dedup import compute_content_hash


def import_archive(archive_path: str | None = None):
    """Import old archive.json into SQLite database."""
    base_dir = Path(__file__).parent.parent
    archive_path = archive_path or str(base_dir / "data" / "archive.json")

    if not Path(archive_path).exists():
        print(f"Archive not found: {archive_path}")
        return

    print(f"Loading archive from {archive_path}...")
    with open(archive_path) as f:
        archive = json.load(f)

    items = archive.get("items", [])
    print(f"Found {len(items)} items to import")

    # Initialize database
    init_db()
    session = get_session()

    imported = 0
    skipped = 0

    for item in items:
        source_name = item.get("source", "Unknown")

        # Ensure source exists
        source = session.query(Source).filter_by(name=source_name).first()
        if not source:
            source = Source(
                name=source_name,
                type="rss",
                url=item.get("link", ""),
                credibility_score=0.5,
            )
            session.add(source)
            session.flush()

        # Compute hash
        title = item.get("title", "")
        description = item.get("description", "")
        content_hash = compute_content_hash(title, description)

        # Check for existing
        if session.query(RawItem).filter_by(content_hash=content_hash).first():
            skipped += 1
            continue

        # Parse dates
        pub_date = None
        if item.get("published"):
            try:
                pub_date = datetime.fromisoformat(item["published"].replace("Z", "+00:00")).replace(tzinfo=None)
            except Exception:
                pass

        fetched_at = datetime.utcnow()
        if item.get("fetched_at"):
            try:
                fetched_at = datetime.fromisoformat(item["fetched_at"].replace("Z", "+00:00")).replace(tzinfo=None)
            except Exception:
                pass

        db_item = RawItem(
            source_id=source.id,
            external_id=item.get("link", ""),
            title=title,
            content=description,
            url=item.get("link", ""),
            published_at=pub_date,
            fetched_at=fetched_at,
            content_hash=content_hash,
        )
        session.add(db_item)
        imported += 1

    session.commit()
    session.close()

    print(f"\nImport complete:")
    print(f"  Imported: {imported}")
    print(f"  Skipped (duplicates): {skipped}")


if __name__ == "__main__":
    archive_path = sys.argv[1] if len(sys.argv) > 1 else None
    import_archive(archive_path)
