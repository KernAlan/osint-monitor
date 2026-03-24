#!/bin/bash
# OSINT Monitor Runner
# Usage:
#   ./run.sh                  # Run collection pipeline
#   ./run.sh collect          # Run collection pipeline
#   ./run.sh briefing         # Generate daily briefing
#   ./run.sh serve            # Start web dashboard
#   ./run.sh daemon           # Start background scheduler
#   ./run.sh alerts           # Quick alert check
#   ./run.sh --alerts-only    # Legacy: quick alert check

cd "$(dirname "$0")"

# Activate venv if present
if [ -d "venv" ]; then
    source venv/bin/activate
fi

if [ "$1" == "--alerts-only" ]; then
    # Legacy compatibility
    python main.py alerts
else
    python main.py "$@"
fi
