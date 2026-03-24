"""FastAPI application with HTMX dashboard."""

from __future__ import annotations

import logging
import os
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from osint_monitor.core.database import init_db
from osint_monitor.api.routes.events import router as events_router
from osint_monitor.api.routes.entities import router as entities_router
from osint_monitor.api.routes.alerts import router as alerts_router
from osint_monitor.api.routes.briefings import router as briefings_router
from osint_monitor.api.routes.search import router as search_router
from osint_monitor.api.websocket import router as sse_router
from osint_monitor.api.routes.intelligence import router as intel_router
from osint_monitor.api.routes.daemon import router as daemon_router
from osint_monitor.api.routes.ingest import router as ingest_router
from osint_monitor.api.auth import require_api_key

logger = logging.getLogger(__name__)

WEB_DIR = Path(__file__).parent.parent.parent / "web"
TEMPLATES_DIR = WEB_DIR / "templates"
STATIC_DIR = WEB_DIR / "static"

# Build global dependencies list: add API-key auth when OSINT_API_KEY is set.
_global_deps = []
if os.environ.get("OSINT_API_KEY"):
    _global_deps.append(Depends(require_api_key))

app = FastAPI(
    title="OSINT Monitor",
    description="Geopolitical Intelligence Analysis Platform",
    version="2.0.0",
    dependencies=_global_deps,
)

# CORS — allow browser collectors to POST from any origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files
STATIC_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Templates
TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# API routes
app.include_router(events_router, prefix="/api/events", tags=["events"])
app.include_router(entities_router, prefix="/api/entities", tags=["entities"])
app.include_router(alerts_router, prefix="/api/alerts", tags=["alerts"])
app.include_router(briefings_router, prefix="/api/briefings", tags=["briefings"])
app.include_router(search_router, prefix="/api/search", tags=["search"])
app.include_router(sse_router, prefix="/api", tags=["stream"])
app.include_router(intel_router, prefix="/api/intel", tags=["intelligence"])
app.include_router(daemon_router, prefix="/api/daemon", tags=["daemon"])
app.include_router(ingest_router, prefix="/api/ingest", tags=["ingest"])


@app.on_event("startup")
async def startup():
    init_db()
    logger.info("OSINT Monitor API started")


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/events", response_class=HTMLResponse)
async def events_page(request: Request):
    return templates.TemplateResponse("events.html", {"request": request})


@app.get("/events/{event_id}", response_class=HTMLResponse)
async def event_detail_page(request: Request, event_id: int):
    return templates.TemplateResponse("event_detail.html", {"request": request, "event_id": event_id})


@app.get("/entities", response_class=HTMLResponse)
async def entities_page(request: Request):
    return templates.TemplateResponse("entities.html", {"request": request})


@app.get("/entities/{entity_id}", response_class=HTMLResponse)
async def entity_detail_page(request: Request, entity_id: int):
    return templates.TemplateResponse("entity_detail.html", {"request": request, "entity_id": entity_id})


@app.get("/map", response_class=HTMLResponse)
async def map_page(request: Request):
    return templates.TemplateResponse("map.html", {"request": request})


@app.get("/graph", response_class=HTMLResponse)
async def graph_page(request: Request):
    return templates.TemplateResponse("graph.html", {"request": request})


@app.get("/briefings", response_class=HTMLResponse)
async def briefings_page(request: Request):
    return templates.TemplateResponse("briefings.html", {"request": request})


@app.get("/alerts", response_class=HTMLResponse)
async def alerts_page(request: Request):
    return templates.TemplateResponse("alerts.html", {"request": request})


@app.get("/indicators", response_class=HTMLResponse)
async def indicators_page(request: Request):
    return templates.TemplateResponse("indicators.html", {"request": request})


@app.get("/claims", response_class=HTMLResponse)
async def claims_page(request: Request):
    return templates.TemplateResponse("claims.html", {"request": request})


@app.get("/timeline", response_class=HTMLResponse)
async def timeline_page(request: Request):
    return templates.TemplateResponse("timeline.html", {"request": request})


@app.get("/stix", response_class=HTMLResponse)
async def stix_page(request: Request):
    return templates.TemplateResponse("stix.html", {"request": request})
