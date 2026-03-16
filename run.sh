#!/bin/bash
# OSINT Monitor Runner
# Usage: ./run.sh [--alerts-only]

cd /root/.openclaw/workspace/osint-monitor
source venv/bin/activate

if [ "$1" == "--alerts-only" ]; then
    # Quick alert check (no synthesis)
    python main.py 2>/dev/null
    python synthesize.py --alerts
else
    # Full collection and synthesis
    python main.py
    python synthesize.py
fi
