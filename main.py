#!/usr/bin/env python3
"""
OSINT Monitor - Autonomous Geopolitical Intelligence Platform

This is a thin CLI wrapper. The full platform is in the osint_monitor package.

Usage:
    python main.py                    # Run collection pipeline (default)
    python main.py collect            # Run collection + NLP + clustering
    python main.py briefing           # Generate daily briefing
    python main.py serve              # Start web dashboard
    python main.py daemon             # Start background scheduler
    python main.py migrate            # Initialize database
    python main.py seed               # Seed entities from config
    python main.py import             # Import old archive.json
    python main.py alerts             # Check current alerts
"""

from osint_monitor.cli import main

if __name__ == "__main__":
    main()
