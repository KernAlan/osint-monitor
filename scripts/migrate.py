#!/usr/bin/env python3
"""Database migration helper. Creates/updates all tables."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from osint_monitor.core.database import init_db, DEFAULT_DB_PATH


def main():
    print(f"Initializing database at {DEFAULT_DB_PATH}")
    init_db()
    print("Database schema created/updated successfully.")


if __name__ == "__main__":
    main()
