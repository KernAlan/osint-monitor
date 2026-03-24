# OSINT Monitor

Autonomous geopolitical intelligence collection and analysis platform.

## What It Does

- **Collects** from 42+ open sources across six intelligence disciplines -- RSS feeds, social media, government databases, sanctions lists, ADS-B transponders, seismic sensors, trade flows, and more.
- **Extracts** named entities, claims, and event triples using spaCy NLP and LLM-assisted analysis, then resolves them against a seeded knowledge base with alias matching.
- **Clusters** related reports into discrete events using HDBSCAN over sentence embeddings, deduplicates across sources, and tracks narrative propagation over time.
- **Produces** structured intelligence assessments including daily briefings, Admiralty-scored corroboration matrices, Analysis of Competing Hypotheses (ACH), Indicators and Warnings (I&W) evaluations, and STIX 2.1 exports.

## Quick Start

```bash
# 1. Clone and install
git clone https://github.com/kerna/osint-monitor.git
cd osint-monitor
pip install -e ".[all]"
python -m spacy download en_core_web_lg

# 2. Configure
cp .env.example .env
# Edit .env -- at minimum set OPENAI_API_KEY for briefings/ACH

# 3. Initialize
python main.py migrate
python main.py seed

# 4. Collect and process
python main.py collect

# 5. Start the dashboard
python main.py serve
# Open http://localhost:8000
```

For production deployments, start PostgreSQL and Redis via Docker Compose first:

```bash
docker compose up -d
# Set OSINT_DB_URL=postgresql://osint:osint_dev@localhost:5432/osint_monitor in .env
python main.py migrate
python main.py daemon
```

## Architecture

The processing pipeline runs as a single sequential pass or as scheduled background tasks:

```
Collectors (42+ sources)
    |
    v
Deduplication (content hash + semantic similarity)
    |
    v
Multilingual detection & translation
    |
    v
NLP entity extraction (spaCy NER + custom gazetteers)
    |
    v
Entity resolution (alias matching, coreference, Wikidata linking)
    |
    v
Claim extraction & stance classification
    |
    v
Event clustering (HDBSCAN over sentence-transformer embeddings)
    |
    v
Full-text enrichment (article body fetching)
    |
    v
Relation extraction (subject-predicate-object triples)
    |
    v
Geocoding (location resolution to coordinates)
    |
    v
Corroboration scoring (Admiralty/NATO system)
    |
    v
Indicators & Warnings evaluation
    |
    v
Alerting (desktop, Slack, Discord, email, webhook)
```

The daemon scheduler automates the pipeline on a recurring basis:

| Task           | Interval      |
|----------------|---------------|
| Collection     | Every 15 min  |
| Clustering     | Every 30 min  |
| Analysis       | Every 2 hours |
| Alerts         | Every 15 min  |
| Daily briefing | 06:00 UTC     |

## Source Coverage

Sources are organized by intelligence discipline. Most work without API keys; optional keys increase rate limits or unlock additional feeds.

| Discipline | Source Type | Examples | API Key Required |
|------------|------------|----------|------------------|
| **OSINT -- News** | RSS feeds | Reuters, BBC World, Al Jazeera, SCMP, Defense News, Breaking Defense | No |
| **OSINT -- Government** | RSS feeds | Defense.gov, State Department | No |
| **OSINT -- Analysis** | RSS feeds | War on the Rocks, Lawfare, CSIS | No |
| **OSINT -- Social** | Nitter scraping | 14 accounts (Bellingcat, CENTCOM, NATO, regional analysts) | No |
| **OSINT -- Social** | Twitter API v2 | Same accounts via official API | Optional |
| **OSINT -- Social** | Telegram | Configurable channels | Optional |
| **SIGINT -- Cyber** | NVD | CVE vulnerability feed | Optional (rate limit) |
| **SIGINT -- Nuclear** | IAEA | Nuclear event notifications | No |
| **SIGINT -- Economic** | UN COMTRADE | Trade flow anomalies | Optional |
| **SIGINT -- Economic** | Currency API | FX rate monitoring | No |
| **HUMINT -- Refugees** | UNHCR | Displacement data | No |
| **GEOINT -- Conflict** | ACLED | Armed conflict events | No |
| **GEOINT -- Events** | GDELT | Global event database | No |
| **GEOINT -- Seismic** | USGS | Earthquake monitoring (nuclear test detection) | No |
| **GEOINT -- Thermal** | NASA FIRMS | Fire/thermal anomaly detection | Optional |
| **GEOINT -- ADS-B** | OpenSky / ADS-B Exchange | Military aircraft tracking (Persian Gulf, Black Sea, Taiwan Strait) | No |
| **GEOINT -- Maritime** | AIS | Vessel tracking | No |
| **GOVINT -- Legislation** | Congress.gov | Bill and hearing tracking | Optional |
| **GOVINT -- Travel** | State Dept | Travel advisories | No |
| **GOVINT -- Airspace** | FAA NOTAM | Airspace closures and restrictions | Optional |
| **GOVINT -- Censorship** | OONI | Internet censorship measurements | No |
| **FININT -- Sanctions** | OFAC SDN | US sanctions designations | No |
| **FININT -- Sanctions** | UN Consolidated | UN Security Council sanctions | No |
| **DOCINT -- Policy** | Federal Register | Federal regulatory documents | No |

Region focus areas with keyword-based filtering: Iran, China/Taiwan, Russia/Ukraine, Middle East, North Korea, and Africa/Sahel.

## Intelligence Capabilities

### Entity Resolution with Coreference

Extracts entities via spaCy NER augmented with a custom gazetteer of weapon systems, military organizations, facilities, and key leaders. Resolves aliases (e.g., "Revolutionary Guards" to "IRGC") using fuzzy matching and Wikidata identifiers. Tracks entity mention frequency and first/last seen timestamps.

### Event Clustering with Sub-Event Decomposition

Groups related reports using HDBSCAN clustering over sentence-transformer embeddings. Near-duplicate items from different sources are linked to the same event, enabling multi-source event reconstruction. Clusters are assigned severity scores, event types, and geographic coordinates.

### Admiralty/NATO Corroboration Scoring

Implements the Admiralty (NATO) system for evaluating source reliability and information credibility. Computes corroboration scores based on independent source agreement and detects disagreements between sources reporting on the same event.

### Claim-Level Stance Detection

Extracts discrete claims from reporting and classifies source stance (agree, disagree, neutral) at the claim level rather than the article level. Enables detection of conflicting narratives across sources.

### Indicators and Warnings Framework

Evaluates predefined escalation scenarios against incoming intelligence. Each scenario contains weighted indicators with entity and keyword co-occurrence requirements. Built-in scenarios:

- Iran nuclear breakout (IAEA expulsion, enrichment levels, facility expansion)
- China-Taiwan invasion (amphibious exercises, carrier deployments, embassy evacuations)
- Russia-NATO escalation (nuclear posture, GPS jamming, Article 5, submarine surges)
- Middle East regional war (Hezbollah escalation, Hormuz closure, Houthi activity)

Includes escalation probability estimation with forward-looking threat scoring.

### Structured ACH with Bayesian Updating

Generates Analysis of Competing Hypotheses matrices for events using LLM-assisted hypothesis and evidence generation. Computes posterior probabilities, identifies diagnostic evidence, and exports formatted matrices in JSON or Markdown.

### Knowledge Graph with Community Detection

Builds an entity relationship graph from co-occurrence and extracted relations. Supports community detection (Louvain), centrality scoring (degree, betweenness, eigenvector), broker identification, and ego-graph exploration. Exports in vis.js-compatible format for interactive visualization.

### STIX 2.1 Export

Exports events, entities, and relationships as STIX 2.1 bundles for integration with threat intelligence platforms (MISP, OpenCTI, etc.). Available per-event or as bulk export.

### Narrative Propagation Tracking

Detects how a story propagates across sources over time, identifying origin sources and amplification patterns. Maps the temporal spread of narratives through the media ecosystem.

### Coordination and Influence Detection

Identifies coordinated posting patterns by detecting temporally clustered publications across sources within configurable time windows. Tracks narrative adoption by keyword across sources and maps amplification networks.

## API Reference

The API is served by FastAPI at `http://localhost:8000`. When `OSINT_API_KEY` is set, all `/api/` routes require an `X-API-Key` header.

### Events

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/events` | List events (filter by region, severity, time) |
| GET | `/api/events/{id}` | Event detail with linked items and entities |

### Entities

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/entities` | List entities (filter by type, search by name) |
| GET | `/api/entities/{id}` | Entity detail with recent mentions |
| GET | `/api/entities/{id}/graph` | Ego-graph for an entity (configurable radius) |
| GET | `/api/entities/{id}/trend` | Mention trend over time |

### Alerts

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/alerts` | List alerts (filter by type, severity, acknowledged) |
| POST | `/api/alerts/{id}/acknowledge` | Acknowledge an alert |

### Briefings

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/briefings` | List past briefings |
| GET | `/api/briefings/{id}` | Full briefing content |
| POST | `/api/briefings/generate` | Generate a new briefing (requires LLM key) |

### Search

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/search?q=` | Full-text search across items, events, entities |

### Intelligence Analysis

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/intel/stix/events/{id}` | STIX 2.1 bundle for an event |
| GET | `/api/intel/stix/export` | Bulk STIX export (configurable time window) |
| GET | `/api/intel/corroboration/{id}` | Admiralty/NATO corroboration score |
| GET | `/api/intel/corroboration/{id}/disagreements` | Source disagreement detection |
| GET | `/api/intel/indicators` | All I&W scenario evaluations |
| GET | `/api/intel/indicators/{key}` | Specific scenario status |
| GET | `/api/intel/escalation/{key}` | Escalation probability estimate |
| GET | `/api/intel/stance/{id}` | Claim-level stance detection for an event |
| POST | `/api/intel/ach/{id}` | Build ACH matrix for an event |
| GET | `/api/intel/ach/{id}/markdown` | ACH matrix as Markdown |
| GET | `/api/intel/report/cir/{id}` | Generate Current Intelligence Report |
| GET | `/api/intel/report/iir/{id}` | Generate Intelligence Information Report |

### Temporal Analysis

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/intel/timeline/event/{id}` | Event timeline |
| GET | `/api/intel/timeline/entity/{id}` | Entity mention timeline |
| GET | `/api/intel/propagation/{id}` | Narrative propagation analysis |

### Coordination Detection

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/intel/coordination/posting` | Coordinated posting detection |
| GET | `/api/intel/coordination/narrative` | Narrative tracking by keywords |
| GET | `/api/intel/coordination/amplification` | Amplification network mapping |

### Graph Analytics

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/intel/graph/communities` | Community detection |
| GET | `/api/intel/graph/centrality` | Entity centrality scores |
| GET | `/api/intel/graph/brokers` | Key broker entity identification |
| GET | `/api/intel/graph/full` | Full graph export (vis.js format) |

### Data Export

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/intel/export/events/csv` | Events as CSV |
| GET | `/api/intel/export/entities/csv` | Entities as CSV |
| GET | `/api/intel/export/items/json` | Raw items as JSON |

### Ingest

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/intel/webhook` | Ingest an item via webhook |
| POST | `/api/intel/imint/analyze` | Analyze an image URL (EXIF, OCR, manipulation) |

### Streaming

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/stream` | Server-Sent Events for live updates |

## Dashboard

The web UI is an HTMX-based dashboard served at the root URL. Pages:

| Page | Path | Description |
|------|------|-------------|
| Dashboard | `/` | Overview with recent events, alert counts, severity heatmap |
| Events | `/events` | Filterable event list with severity indicators |
| Event Detail | `/events/{id}` | Full event view with linked sources, entities, timeline |
| Entities | `/entities` | Entity browser with type filtering and search |
| Entity Detail | `/entities/{id}` | Entity profile with mentions, graph, and trend |
| I&W Scenarios | `/indicators` | Indicator and Warning scenario status with escalation probability |
| Claims | `/claims` | Claim browser grouped by type (assertions, denials, threats) |
| Timeline | `/timeline` | Event timeline with propagation tracking and first-reporter detection |
| Map | `/map` | Geographic event map with clustering |
| Graph | `/graph` | Interactive entity relationship graph |
| Briefings | `/briefings` | Historical briefings browser |
| Alerts | `/alerts` | Active and historical alert management |
| STIX Export | `/stix` | STIX 2.1 bundle preview and download |

## Configuration

### Sources (`config/sources.yaml`)

Defines RSS feeds, Twitter/Nitter accounts, alert keywords, and region focus areas. Each source has a name, URL, category, credibility score (0.0--1.0), priority tier, and poll interval in seconds.

```yaml
rss_feeds:
  - name: "Reuters World"
    url: "https://www.reutersagency.com/feed/..."
    category: "news"
    credibility_score: 0.9
    priority: 1
    poll_interval: 600
```

### Entities (`config/entities.yaml`)

Seeds the entity resolution system with canonical names, types, aliases, and optional Wikidata IDs. Supported types: `PERSON`, `ORG`, `WEAPON_SYSTEM`, `FACILITY`.

```yaml
entities:
  - canonical_name: "IRGC"
    entity_type: "ORG"
    aliases: ["Islamic Revolutionary Guard Corps", "Revolutionary Guards"]
    wikidata_id: "Q106482"
```

### Alerts (`config/alerts.yaml`)

Defines compound alert rules that fire when specific entity-keyword pairs co-occur. Supports severity thresholds, cooldown periods, quiet hours, and multiple delivery channels (desktop, Slack, Discord, email, webhook).

```yaml
rules:
  - name: "Iran nuclear escalation"
    type: compound
    conditions:
      entity: "Iran"
      keyword: "nuclear"
    severity: 0.9
    cooldown_minutes: 120
    channels: ["desktop", "slack"]
```

### Indicators and Warnings (`config/indicators.yaml`)

Defines I&W scenarios with weighted indicators. Each indicator specifies keywords and optional entity constraints. When both an entity and keyword co-occur in the same item, the indicator is considered triggered.

```yaml
iran_nuclear_breakout:
  description: "Iran moves toward nuclear weapon capability"
  indicators:
    - name: "IAEA inspector expulsion"
      weight: 0.9
      keywords: ["IAEA", "inspector", "expel", "access denied"]
      entities: ["IAEA", "Iran"]
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OSINT_DEFAULT_LLM_PROVIDER` | No | `openai` | LLM provider: `openai`, `anthropic`, `ollama`, `gemini` |
| `OPENAI_API_KEY` | For briefings/ACH | -- | OpenAI API key |
| `OSINT_OPENAI_MODEL` | No | `gpt-4o-mini` | OpenAI model name |
| `ANTHROPIC_API_KEY` | No | -- | Anthropic API key (alternative LLM) |
| `OSINT_OLLAMA_BASE_URL` | No | -- | Ollama base URL for local LLM |
| `GOOGLE_API_KEY` | No | -- | Google Gemini API key |
| `TWITTER_BEARER_TOKEN` | No | -- | Twitter API v2 (falls back to Nitter) |
| `TELEGRAM_API_ID` | No | -- | Telegram API ID |
| `TELEGRAM_API_HASH` | No | -- | Telegram API hash |
| `CONGRESS_API_KEY` | No | -- | Congress.gov legislation tracking |
| `FAA_NOTAM_KEY` | No | -- | FAA airspace closure data |
| `NASA_FIRMS_KEY` | No | -- | NASA thermal anomaly detection |
| `NVD_API_KEY` | No | -- | NVD vulnerability feed (increases rate limit) |
| `SENTINEL_HUB_TOKEN` | No | -- | Copernicus satellite imagery |
| `COMTRADE_API_KEY` | No | -- | UN COMTRADE trade flow data |
| `OSINT_DB_URL` | No | `sqlite:///data/osint.db` | Database connection URL |
| `CELERY_BROKER_URL` | No | -- | Redis URL for Celery task queue |
| `CELERY_RESULT_BACKEND` | No | -- | Redis URL for Celery results |
| `OSINT_SPACY_MODEL` | No | `en_core_web_lg` | spaCy model for NER |
| `OSINT_API_HOST` | No | `0.0.0.0` | API server bind address |
| `OSINT_API_PORT` | No | `8000` | API server port |
| `OSINT_API_KEY` | No | -- | API key for `/api/` route authentication |

## Scaling

The default configuration uses SQLite and runs everything in-process. For production:

**PostgreSQL + pgvector** -- Switch to PostgreSQL for concurrent access and vector similarity search over embeddings. The provided `docker-compose.yml` starts `pgvector/pgvector:pg16`.

```bash
pip install -e ".[postgres]"
docker compose up -d postgres
# Set OSINT_DB_URL=postgresql://osint:osint_dev@localhost:5432/osint_monitor
```

**Celery + Redis** -- Offload collection and analysis tasks to background workers for parallel execution.

```bash
pip install -e ".[celery]"
docker compose up -d redis
# Set CELERY_BROKER_URL=redis://localhost:6379/0
```

**Docker Compose** -- The included `docker-compose.yml` provides PostgreSQL 16 with pgvector and Redis 7.

## CLI Commands

All commands are run via `python main.py <command>` or the installed `osint-monitor` entry point.

| Command | Description | Key Options |
|---------|-------------|-------------|
| `collect` | Run collection and processing pipeline | `--hours-back` (default: 24) |
| `briefing` | Generate intelligence briefing | `--type daily\|flash`, `--hours-back`, `--provider`, `--output` |
| `serve` | Start web dashboard and API server | `--host`, `--port`, `--reload` |
| `daemon` | Run background scheduler daemon | -- |
| `migrate` | Initialize or update database schema | -- |
| `seed` | Seed entities from `config/entities.yaml` | -- |
| `import` | Import legacy `archive.json` data | `--file` |
| `alerts` | Check and display current alerts | `--hours-back` (default: 24) |

Running `python main.py` with no arguments defaults to `collect`.

## Project Structure

```
osint-monitor/
├── main.py                          # CLI entry point
├── pyproject.toml                   # Package metadata and dependencies
├── docker-compose.yml               # PostgreSQL + Redis services
├── .env.example                     # Environment variable template
├── config/
│   ├── sources.yaml                 # Source definitions and credibility scores
│   ├── entities.yaml                # Entity seeds (aliases, Wikidata IDs)
│   ├── alerts.yaml                  # Alert rules and channel configuration
│   └── indicators.yaml             # I&W scenario definitions
├── osint_monitor/
│   ├── cli.py                       # Argument parsing and command dispatch
│   ├── core/
│   │   ├── config.py                # YAML config loading and settings
│   │   ├── database.py              # SQLAlchemy models and session management
│   │   ├── models.py                # Pydantic data models
│   │   ├── scheduler.py             # APScheduler job definitions
│   │   ├── tasks.py                 # Celery task definitions
│   │   └── vector_search.py         # pgvector similarity search
│   ├── collectors/
│   │   ├── base.py                  # BaseCollector interface
│   │   ├── rss.py                   # RSS and Nitter collectors
│   │   ├── twitter.py               # Twitter API v2 collector
│   │   ├── telegram.py              # Telegram channel collector
│   │   ├── structured.py            # ACLED, GDELT, USGS, NASA FIRMS
│   │   ├── govint.py                # Congress, travel advisories, OONI, NOTAM
│   │   ├── sigint.py                # IAEA, NVD, currency, UNHCR, COMTRADE
│   │   ├── sanctions.py             # OFAC SDN, UN sanctions
│   │   ├── adsb.py                  # ADS-B military aircraft tracking
│   │   ├── ais.py                   # AIS maritime vessel tracking
│   │   └── custom.py                # Custom collector base
│   ├── processors/
│   │   ├── pipeline.py              # Pipeline orchestrator
│   │   ├── dedup.py                 # Content hash and semantic deduplication
│   │   ├── embeddings.py            # Sentence-transformer embedding generation
│   │   ├── nlp.py                   # spaCy NER and event triple extraction
│   │   ├── entity_resolver.py       # Alias matching and entity resolution
│   │   ├── clustering.py            # HDBSCAN event clustering
│   │   ├── corroboration.py         # Admiralty/NATO scoring
│   │   ├── scoring.py               # Composite severity scoring
│   │   ├── stance.py                # Claim extraction and stance classification
│   │   ├── relations.py             # Relation extraction (SPO triples)
│   │   ├── geocoding.py             # Location to coordinate resolution
│   │   ├── fulltext.py              # Article body fetching
│   │   ├── language.py              # Language detection and translation
│   │   ├── documents.py             # Document feed processing
│   │   └── imint.py                 # Image analysis (EXIF, OCR, manipulation)
│   ├── analysis/
│   │   ├── briefing.py              # Daily and flash briefing generation
│   │   ├── indicators.py            # I&W evaluation and escalation modeling
│   │   ├── ach.py                   # Analysis of Competing Hypotheses
│   │   ├── graph.py                 # Entity graph, communities, centrality
│   │   ├── coordination.py          # Coordinated posting and influence detection
│   │   ├── temporal.py              # Timelines and narrative propagation
│   │   ├── trends.py                # Entity mention trend analysis
│   │   ├── stix_export.py           # STIX 2.1 bundle generation
│   │   ├── export.py                # CSV/JSON export, CIR/IIR reports, webhooks
│   │   └── llm.py                   # Multi-provider LLM abstraction
│   ├── alerting/
│   │   ├── engine.py                # Alert rule evaluation
│   │   ├── channels.py              # Delivery channels (desktop, Slack, etc.)
│   │   └── fatigue.py               # Alert fatigue management and cooldowns
│   └── api/
│       ├── app.py                   # FastAPI application and page routes
│       ├── auth.py                  # API key authentication
│       ├── websocket.py             # Server-Sent Events for live updates
│       └── routes/
│           ├── events.py            # Event CRUD endpoints
│           ├── entities.py          # Entity CRUD and graph endpoints
│           ├── alerts.py            # Alert list and acknowledge endpoints
│           ├── briefings.py         # Briefing list, detail, and generation
│           ├── search.py            # Full-text search
│           └── intelligence.py      # STIX, ACH, I&W, coordination, graph, export
├── web/
│   ├── templates/                   # Jinja2 HTMX templates
│   └── static/                      # CSS, JS, assets
└── scripts/
    ├── import_archive.py            # Legacy data import
    ├── migrate.py                   # Database migration helper
    └── seed_entities.py             # Entity seeding helper
```

## License

MIT
