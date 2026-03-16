# OSINT Monitor

Autonomous geopolitical intelligence collection and synthesis tool.

## Features

- **Multi-source collection**: RSS feeds, Twitter/X via Nitter
- **Alert detection**: Critical keyword monitoring (nuclear, DEFCON, missile launches, etc.)
- **Regional categorization**: Iran, China, Russia, Middle East focus
- **Structured briefings**: Daily intelligence summaries
- **Extensible**: Easy to add new sources and keywords

## Quick Start

```bash
# Clone and setup
git clone https://github.com/KernAlan/osint-monitor.git
cd osint-monitor
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run collection
python main.py

# Generate briefing
python synthesize.py
```

## Configuration

Edit `config/sources.yaml` to customize:
- RSS feeds to monitor
- Twitter accounts to track
- Alert keywords
- Region focus areas

## Output

- `data/archive.json` — Raw collected items
- `data/briefing.md` — Full categorized briefing
- `data/synthesis.md` — Structured intelligence summary

## Architecture

```
osint-monitor/
├── config/
│   └── sources.yaml      # All source configuration
├── collectors/           # (future) specialized collectors
├── processors/           # (future) AI analysis modules
├── main.py               # Collection orchestration
├── synthesize.py         # Briefing generation
└── run.sh                # Convenience runner
```

## Sources Included

- **News**: BBC World, Al Jazeera, Reuters, SCMP
- **Analysis**: War on the Rocks, Lawfare, CSIS
- **Defense**: Defense News, Breaking Defense
- **Government**: Defense.gov, State Dept, NATO, CENTCOM
- **OSINT Twitter**: @bellingcat, @TheIntelFrog, @AuroraIntel, and 15+ more

## Alert Keywords

Automatically flags content containing:
- **Critical**: DEFCON, nuclear weapon, missile launch detected, declaration of war
- **High**: troop movement, naval deployment, air strike, embassy evacuated

## License

MIT
