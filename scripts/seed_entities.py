#!/usr/bin/env python3
"""Seed entities from entities.yaml into the database."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from osint_monitor.core.database import init_db, get_session
from osint_monitor.processors.entity_resolver import EntityResolver


def main():
    init_db()
    session = get_session()
    resolver = EntityResolver(session)
    resolver.seed_from_config()
    session.close()
    print("Entity seeding complete.")


if __name__ == "__main__":
    main()
