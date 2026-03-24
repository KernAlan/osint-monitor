"""Collectors for structured intelligence data APIs.

Provides collectors for:
- ACLED (Armed Conflict Location & Event Data)
- GDELT (Global Event Database)
- USGS Seismic (earthquake / nuclear test proxy)
- NASA FIRMS (fire / thermal anomaly detection)
"""

from __future__ import annotations

import hashlib
import logging
import math
import os
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import quote_plus

import requests

from osint_monitor.collectors.base import BaseCollector
from osint_monitor.core.models import RawItemModel

logger = logging.getLogger(__name__)

# Shared HTTP settings
_SESSION_HEADERS = {
    "User-Agent": "osint-monitor/1.0 (research; https://github.com/osint-monitor)",
}
_TIMEOUT = 15


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in km between two points (Haversine)."""
    R = 6371.0
    rlat1, rlat2 = math.radians(lat1), math.radians(lat2)
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2) ** 2 + math.cos(rlat1) * math.cos(rlat2) * math.sin(dlon / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


# ───────────────────────────────────────────────────────────────────────────
# 1. ACLED – Armed Conflict Location & Event Data
# ───────────────────────────────────────────────────────────────────────────

class ACLEDCollector(BaseCollector):
    """Collect armed-conflict events from the ACLED REST API.

    ACLED migrated to OAuth token-based auth at ``https://acleddata.com/api/``.
    Set env vars ``ACLED_EMAIL`` and ``ACLED_PASSWORD`` (your acleddata.com
    login credentials).  Register free at https://acleddata.com/register/.
    """

    BASE_URL = "https://acleddata.com/api/acled/read"
    TOKEN_URL = "https://acleddata.com/oauth/token"

    RELEVANT_EVENT_TYPES = frozenset([
        "Battles",
        "Explosions/Remote violence",
        "Violence against civilians",
        "Protests",
        "Riots",
        "Strategic developments",
    ])

    def __init__(
        self,
        region: Optional[int] = None,
        country: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 100,
        days_back: int = 7,
        **kwargs,
    ):
        super().__init__(
            name="ACLED",
            source_type="structured_api",
            url=self.BASE_URL,
            **kwargs,
        )
        self.region = region
        self.country = country
        self.event_type = event_type
        self.limit = limit
        self.days_back = days_back

    def _get_token(self) -> str | None:
        """Exchange ACLED credentials for an OAuth access token."""
        email = os.environ.get("ACLED_EMAIL", "")
        password = os.environ.get("ACLED_PASSWORD", "")
        if not email or not password:
            return None
        try:
            resp = requests.post(self.TOKEN_URL, data={
                "username": email,
                "password": password,
                "grant_type": "password",
                "client_id": "acled",
            }, headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=15)
            resp.raise_for_status()
            token = resp.json().get("access_token")
            if token:
                logger.info("ACLED OAuth token obtained")
            return token
        except Exception as exc:
            logger.warning("ACLED token request failed: %s", exc)
            return None

    def collect(self) -> list[RawItemModel]:
        """Fetch recent ACLED events and return as RawItemModels."""
        token = self._get_token()
        if not token:
            email = os.environ.get("ACLED_EMAIL", "")
            if not email:
                print("  [err] ACLED: Set ACLED_EMAIL and ACLED_PASSWORD. Register free at https://acleddata.com/register/")
            else:
                print("  [err] ACLED: Token request failed (check credentials)")
            return []

        start_date = (datetime.now(timezone.utc) - timedelta(days=self.days_back)).strftime("%Y-%m-%d")

        params: dict = {
            "_format": "json",
            "limit": self.limit,
            "event_date": f"{start_date}|",
            "event_date_where": "BETWEEN",
        }
        if self.region is not None:
            params["region"] = self.region
        if self.country:
            params["country"] = self.country
        if self.event_type:
            params["event_type"] = self.event_type

        headers = {
            **_SESSION_HEADERS,
            "Authorization": f"Bearer {token}",
        }

        payload = None
        try:
            resp = requests.get(
                self.BASE_URL,
                params=params,
                headers=headers,
                timeout=_TIMEOUT,
            )
            resp.raise_for_status()
            payload = resp.json()
        except Exception as exc:
            logger.warning("ACLED request failed: %s", exc)
            print(f"  [err] ACLED: {exc}")
            return []

        data = payload.get("data", [])
        if not isinstance(data, list):
            logger.warning("ACLED returned unexpected data format")
            return []

        items: list[RawItemModel] = []
        for event in data:
            evt_type = event.get("event_type", "")
            if evt_type not in self.RELEVANT_EVENT_TYPES:
                continue

            actor1 = event.get("actor1", "")
            actor2 = event.get("actor2", "")
            location = event.get("location", "Unknown")

            if actor2:
                title = f"{evt_type}: {actor1} vs {actor2} in {location}"
            else:
                title = f"{evt_type} in {location}"

            lat = event.get("latitude", "")
            lon = event.get("longitude", "")
            fatalities = event.get("fatalities", "0")
            notes = event.get("notes", "")
            content = f"Location: {lat},{lon} | Fatalities: {fatalities}\n{notes}"

            # Parse event_date
            published_at = None
            raw_date = event.get("event_date", "")
            if raw_date:
                try:
                    published_at = datetime.strptime(raw_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                except ValueError:
                    pass

            items.append(RawItemModel(
                title=title,
                content=content.strip(),
                url=event.get("source_url", ""),
                source_name="ACLED",
                external_id=f"acled_{event.get('data_id', '')}",
                published_at=published_at,
            ))

        logger.info("ACLED collected %d items from %d raw events", len(items), len(data))
        return items[: self.max_items]


# ───────────────────────────────────────────────────────────────────────────
# 2. GDELT – Global Event Database
# ───────────────────────────────────────────────────────────────────────────

class GDELTCollector(BaseCollector):
    """Collect articles from the GDELT API.

    Completely free, no API key required.  Uses the Context API as primary
    (more reliable) and falls back to the DOC API.  Both enforce a
    rate limit of one request per 5 seconds.
    """

    CONTEXT_API = "https://api.gdeltproject.org/api/v2/context/context"
    DOC_API = "https://api.gdeltproject.org/api/v2/doc/doc"
    GEO_API = "https://api.gdeltproject.org/api/v2/geo/geo"

    _BACKOFF_DELAYS = (3, 6)  # seconds for retry attempts
    _last_request_ts: float = 0.0  # class-level: last successful request epoch
    _MIN_REQUEST_GAP = 6.0  # seconds between requests to avoid 429s

    def __init__(
        self,
        query: str = "military OR conflict OR sanctions",
        timespan: str = "24h",
        max_records: int = 50,
        **kwargs,
    ):
        super().__init__(
            name="GDELT",
            source_type="structured_api",
            url=self.DOC_API,
            **kwargs,
        )
        self.query = query
        self.timespan = timespan
        self.max_records = max_records

    def collect(self) -> list[RawItemModel]:
        """Fetch GDELT article list matching the query.

        Tries the Context API first (more reliable), falls back to DOC API.
        GDELT enforces a 5-second rate limit per IP; uses exponential backoff
        (3s, 6s) and tracks last successful request to avoid hammering.
        """
        import time

        # Respect minimum gap between requests across all GDELTCollector instances
        since_last = time.time() - GDELTCollector._last_request_ts
        if since_last < self._MIN_REQUEST_GAP:
            wait = self._MIN_REQUEST_GAP - since_last
            logger.debug("GDELT: waiting %.1fs to respect rate limit", wait)
            time.sleep(wait)

        params = {
            "query": self.query,
            "mode": "ArtList",
            "maxrecords": self.max_records,
            "format": "json",
            "timespan": self.timespan,
        }

        payload = None
        for api_url, api_name in [
            (self.CONTEXT_API, "Context"),
            (self.DOC_API, "DOC"),
        ]:
            try:
                resp = requests.get(
                    api_url,
                    params=params,
                    headers=_SESSION_HEADERS,
                    timeout=_TIMEOUT,
                )
                # GDELT returns 429 as plain text, not JSON — exponential backoff
                if resp.status_code == 429:
                    for attempt, delay in enumerate(self._BACKOFF_DELAYS, 1):
                        logger.info(
                            "GDELT %s rate-limited, backoff attempt %d/%d (waiting %ds)...",
                            api_name, attempt, len(self._BACKOFF_DELAYS), delay,
                        )
                        time.sleep(delay)
                        resp = requests.get(
                            api_url,
                            params=params,
                            headers=_SESSION_HEADERS,
                            timeout=_TIMEOUT,
                        )
                        if resp.status_code != 429:
                            break
                    if resp.status_code == 429:
                        logger.debug("GDELT %s still rate-limited after retries, trying next endpoint", api_name)
                        continue

                resp.raise_for_status()
                GDELTCollector._last_request_ts = time.time()

                # GDELT sometimes returns HTML or plain text on error
                content_type = resp.headers.get("content-type", "")
                if "json" not in content_type and "javascript" not in content_type:
                    # Try parsing anyway — GDELT sometimes omits content-type
                    try:
                        payload = resp.json()
                    except Exception:
                        logger.debug("GDELT %s returned non-JSON: %s", api_name, resp.text[:100])
                        continue
                else:
                    payload = resp.json()

                if payload and payload.get("articles"):
                    break
            except Exception as exc:
                logger.debug("GDELT %s request failed: %s", api_name, exc)
                time.sleep(2)
                continue

        if payload is None:
            logger.warning("GDELT: all endpoints failed or rate-limited")
            return []

        articles = payload.get("articles", [])
        if not isinstance(articles, list):
            logger.warning("GDELT returned unexpected data format")
            return []

        items: list[RawItemModel] = []
        for art in articles:
            title = art.get("title", "")
            if not title:
                continue

            # Parse seendate  (GDELT format: "20240315T120000Z")
            published_at = None
            seen = art.get("seendate", "")
            if seen:
                try:
                    published_at = datetime.strptime(seen, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
                except ValueError:
                    pass

            domain = art.get("domain", "")
            language = art.get("language", "")
            source_country = art.get("sourcecountry", "")
            content = f"Domain: {domain} | Language: {language} | Source country: {source_country}"

            items.append(RawItemModel(
                title=title,
                content=content,
                url=art.get("url", ""),
                source_name="GDELT",
                external_id=f"gdelt_{hashlib.md5((art.get('url', '') or title).encode()).hexdigest()[:12]}",
                published_at=published_at,
            ))

        logger.info("GDELT collected %d articles", len(items))
        return items[: self.max_items]

    def get_event_counts(self, query: str, timespan: str = "24h") -> dict:
        """Hit the GDELT GEO API and return geocoded event points (GeoJSON).

        Useful for map overlays.  Returns the raw GeoJSON dict or an empty
        dict on failure.
        """
        params = {
            "query": query,
            "mode": "PointData",
            "format": "GeoJSON",
            "timespan": timespan,
        }
        try:
            resp = requests.get(
                self.GEO_API,
                params=params,
                headers=_SESSION_HEADERS,
                timeout=_TIMEOUT,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            logger.warning("GDELT GEO request failed: %s", exc)
            return {}


# ───────────────────────────────────────────────────────────────────────────
# 3. USGS Seismic – earthquake / nuclear-test proxy
# ───────────────────────────────────────────────────────────────────────────

class USGSSeismicCollector(BaseCollector):
    """Collect seismic events from the USGS Earthquake Hazards API.

    Flags events near known nuclear test sites as high-priority.
    """

    BASE_URL = "https://earthquake.usgs.gov/fdsnws/event/1/query"

    # Known nuclear test sites: (name, lat, lon, radius_km)
    NUCLEAR_TEST_SITES: list[tuple[str, float, float, float]] = [
        ("Punggye-ri, DPRK", 41.28, 129.08, 50),
        ("Novaya Zemlya, Russia", 73.37, 54.97, 100),
        ("Lop Nur, China", 41.75, 88.35, 100),
        ("Semipalatinsk, Kazakhstan", 50.07, 78.43, 50),
        ("Nevada Test Site, US", 37.12, -116.06, 50),
    ]

    SIGNIFICANT_MAGNITUDE = 5.0

    def __init__(
        self,
        min_magnitude: float = 2.0,
        days_back: int = 7,
        **kwargs,
    ):
        super().__init__(
            name="USGS Seismic",
            source_type="structured_api",
            url=self.BASE_URL,
            **kwargs,
        )
        self.min_magnitude = min_magnitude
        self.days_back = days_back

    # Try to import the project's own Haversine helper; fall back to local one.
    @staticmethod
    def _check_geofence(lat: float, lon: float, fence_lat: float, fence_lon: float, radius_km: float) -> bool:
        try:
            from osint_monitor.processors.geocoding import check_geofence
            return check_geofence(lat, lon, fence_lat, fence_lon, radius_km)
        except ImportError:
            return _haversine_km(lat, lon, fence_lat, fence_lon) <= radius_km

    def _near_test_site(self, lat: float, lon: float) -> Optional[str]:
        """Return the name of the nuclear test site if (lat, lon) is nearby, else None."""
        for site_name, s_lat, s_lon, radius in self.NUCLEAR_TEST_SITES:
            if self._check_geofence(lat, lon, s_lat, s_lon, radius):
                return site_name
        return None

    def collect(self) -> list[RawItemModel]:
        """Fetch seismic events from USGS and flag those near nuclear test sites."""
        start_time = (datetime.now(timezone.utc) - timedelta(days=self.days_back)).strftime("%Y-%m-%dT%H:%M:%S")

        params = {
            "format": "geojson",
            "starttime": start_time,
            "minmagnitude": self.min_magnitude,
        }

        try:
            resp = requests.get(
                self.BASE_URL,
                params=params,
                headers=_SESSION_HEADERS,
                timeout=_TIMEOUT,
            )
            resp.raise_for_status()
            payload = resp.json()
        except Exception as exc:
            logger.warning("USGS seismic request failed: %s", exc)
            return []

        features = payload.get("features", [])
        items: list[RawItemModel] = []

        for feature in features:
            props = feature.get("properties", {})
            coords = feature.get("geometry", {}).get("coordinates", [])
            if len(coords) < 3:
                continue

            lon, lat, depth_km = coords[0], coords[1], coords[2]
            magnitude = props.get("mag", 0) or 0
            place = props.get("place", "Unknown")
            event_url = props.get("url", "")
            event_id = props.get("ids", "").strip(",")

            # Parse origin time (milliseconds since epoch)
            published_at = None
            epoch_ms = props.get("time")
            if epoch_ms is not None:
                try:
                    published_at = datetime.fromtimestamp(epoch_ms / 1000.0, tz=timezone.utc)
                except (ValueError, OSError):
                    pass

            depth_note = "shallow" if depth_km < 10 else "deep"
            content = (
                f"Magnitude: {magnitude} | Depth: {depth_km:.1f} km ({depth_note}) | "
                f"Location: {lat},{lon} | Place: {place}"
            )

            site_name = self._near_test_site(lat, lon)

            if site_name:
                suspicious = " [SHALLOW - suspicious]" if depth_km < 10 else ""
                title = f"Seismic event near {site_name}: M{magnitude}{suspicious}"
                items.append(RawItemModel(
                    title=title,
                    content=content,
                    url=event_url,
                    source_name="USGS Seismic",
                    external_id=f"usgs_{event_id}" if event_id else None,
                    published_at=published_at,
                ))
            elif magnitude >= self.SIGNIFICANT_MAGNITUDE:
                title = f"Earthquake M{magnitude} - {place}"
                items.append(RawItemModel(
                    title=title,
                    content=content,
                    url=event_url,
                    source_name="USGS Seismic",
                    external_id=f"usgs_{event_id}" if event_id else None,
                    published_at=published_at,
                ))

        logger.info(
            "USGS collected %d relevant items from %d total seismic events",
            len(items), len(features),
        )
        return items[: self.max_items]


# ───────────────────────────────────────────────────────────────────────────
# 4. NASA FIRMS – Fire / Thermal Anomaly Detection
# ───────────────────────────────────────────────────────────────────────────

class NASAFIRMSCollector(BaseCollector):
    """Collect active fire / thermal anomaly data from NASA FIRMS.

    Uses the area API when a MAP_KEY is available (env ``NASA_FIRMS_KEY``),
    otherwise falls back to the public VIIRS active-fire CSV endpoint.
    """

    AREA_API = "https://firms.modaps.eosdis.nasa.gov/api/area/csv/{map_key}/{source}/{area}/{days}"
    # The public open-data CSV contains global VIIRS detections for the last 24h
    FALLBACK_CSV = "https://firms.modaps.eosdis.nasa.gov/data/active_fire/suomi-npp-viirs-c2/csv/SUOMI_VIIRS_C2_Global_24h.csv"

    # Predefined conflict-zone bounding boxes (south_lat,west_lon,north_lat,east_lon)
    CONFLICT_ZONES: dict[str, str] = {
        "ukraine": "44,22,53,40",
        "iran": "25,44,40,64",
        "gaza": "31.2,34.2,31.6,34.6",
        "yemen": "12,42,19,54",
    }

    CLUSTER_RADIUS_KM = 1.0  # fires within this distance are grouped

    def __init__(
        self,
        zones: Optional[list[str]] = None,
        source: str = "VIIRS_SNPP_NRT",
        days: int = 1,
        fallback_country: str = "world",
        **kwargs,
    ):
        super().__init__(
            name="NASA FIRMS",
            source_type="structured_api",
            url="https://firms.modaps.eosdis.nasa.gov",
            **kwargs,
        )
        self.map_key = os.environ.get("NASA_FIRMS_KEY", "")
        self.zones = zones or list(self.CONFLICT_ZONES.keys())
        self.source = source
        self.days = days
        self.fallback_country = fallback_country

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_firms_csv(text: str) -> list[dict]:
        """Parse FIRMS CSV text into a list of dicts."""
        lines = text.strip().splitlines()
        if len(lines) < 2:
            return []
        headers = [h.strip() for h in lines[0].split(",")]
        rows: list[dict] = []
        for line in lines[1:]:
            values = line.split(",")
            if len(values) != len(headers):
                continue
            rows.append(dict(zip(headers, [v.strip() for v in values])))
        return rows

    @staticmethod
    def _cluster_fires(fires: list[dict], radius_km: float) -> list[list[dict]]:
        """Group fire detections that are within *radius_km* of each other.

        Simple greedy clustering: assign each fire to the first cluster
        whose centroid is within *radius_km*, or start a new cluster.
        """
        clusters: list[list[dict]] = []
        centroids: list[tuple[float, float]] = []

        for fire in fires:
            try:
                flat = float(fire.get("latitude", 0))
                flon = float(fire.get("longitude", 0))
            except (ValueError, TypeError):
                continue

            assigned = False
            for idx, (clat, clon) in enumerate(centroids):
                if _haversine_km(flat, flon, clat, clon) <= radius_km:
                    clusters[idx].append(fire)
                    # Update centroid (running mean)
                    n = len(clusters[idx])
                    centroids[idx] = (
                        clat + (flat - clat) / n,
                        clon + (flon - clon) / n,
                    )
                    assigned = True
                    break

            if not assigned:
                clusters.append([fire])
                centroids.append((flat, flon))

        return clusters

    @staticmethod
    def _zone_label(lat: float, lon: float, zones: dict[str, str]) -> str:
        """Return the zone name that contains (lat, lon), or 'unknown'."""
        for name, bbox in zones.items():
            parts = [float(p) for p in bbox.split(",")]
            s_lat, w_lon, n_lat, e_lon = parts
            if s_lat <= lat <= n_lat and w_lon <= lon <= e_lon:
                return name
        return "unknown"

    # ------------------------------------------------------------------
    # Data fetching
    # ------------------------------------------------------------------

    def _fetch_area_api(self, zone_name: str, bbox: str) -> list[dict]:
        """Fetch fires from the authenticated FIRMS area API."""
        url = self.AREA_API.format(
            map_key=self.map_key,
            source=self.source,
            area=bbox,
            days=self.days,
        )
        try:
            resp = requests.get(url, headers=_SESSION_HEADERS, timeout=_TIMEOUT)
            resp.raise_for_status()
            return self._parse_firms_csv(resp.text)
        except Exception as exc:
            logger.warning("FIRMS area API failed for zone '%s': %s", zone_name, exc)
            return []

    def _fetch_fallback(self) -> list[dict]:
        """Fetch fires from the public VIIRS active-fire open-data CSV.

        This is a large file (~50-100 MB for global 24h data).  We stream
        it and stop after reading enough rows to fill our conflict zones.
        """
        try:
            resp = requests.get(
                self.FALLBACK_CSV,
                headers=_SESSION_HEADERS,
                timeout=60,
                stream=True,
            )
            resp.raise_for_status()

            # Read in chunks to avoid loading the entire global dataset
            # We only need fires within our conflict zone bounding boxes
            lines: list[str] = []
            header_line: str = ""
            max_lines = 500_000  # safety cap
            line_count = 0

            for chunk in resp.iter_content(chunk_size=65536, decode_unicode=True):
                if chunk is None:
                    continue
                for line in chunk.splitlines():
                    if not header_line:
                        header_line = line
                        lines.append(line)
                        continue
                    line_count += 1
                    if line_count > max_lines:
                        break
                    # Quick pre-filter: parse lat/lon and check bounding boxes
                    parts = line.split(",")
                    if len(parts) < 2:
                        continue
                    try:
                        lat = float(parts[0])
                        lon = float(parts[1])
                    except (ValueError, IndexError):
                        continue
                    # Check if this fire falls in any conflict zone
                    for bbox_str in self.CONFLICT_ZONES.values():
                        bp = [float(p) for p in bbox_str.split(",")]
                        if bp[0] <= lat <= bp[2] and bp[1] <= lon <= bp[3]:
                            lines.append(line)
                            break
                if line_count > max_lines:
                    break

            resp.close()
            logger.info(
                "FIRMS fallback: scanned %d rows, kept %d in conflict zones",
                line_count, len(lines) - 1,
            )
            if len(lines) < 2:
                return []

            csv_text = "\n".join(lines)
            return self._parse_firms_csv(csv_text)

        except Exception as exc:
            logger.warning("FIRMS fallback CSV request failed: %s", exc)
            return []

    # ------------------------------------------------------------------
    # collect
    # ------------------------------------------------------------------

    def collect(self) -> list[RawItemModel]:
        """Fetch thermal anomaly data and return clustered fire detections."""
        all_fires: list[dict] = []

        if self.map_key:
            for zone_name in self.zones:
                bbox = self.CONFLICT_ZONES.get(zone_name)
                if not bbox:
                    logger.warning("Unknown FIRMS zone: %s", zone_name)
                    continue
                fires = self._fetch_area_api(zone_name, bbox)
                # Tag each fire with its zone for later labelling
                for f in fires:
                    f["_zone"] = zone_name
                all_fires.extend(fires)
        else:
            logger.info("NASA_FIRMS_KEY not set; using public VIIRS fallback")
            raw_fires = self._fetch_fallback()
            # Keep only fires that fall inside a predefined conflict zone
            for f in raw_fires:
                try:
                    flat = float(f.get("latitude", 0))
                    flon = float(f.get("longitude", 0))
                except (ValueError, TypeError):
                    continue
                zone = self._zone_label(flat, flon, self.CONFLICT_ZONES)
                if zone != "unknown":
                    f["_zone"] = zone
                    all_fires.append(f)

        if not all_fires:
            logger.info("FIRMS: no fire detections in monitored zones")
            return []

        # Cluster nearby fires
        clusters = self._cluster_fires(all_fires, self.CLUSTER_RADIUS_KM)

        items: list[RawItemModel] = []
        for cluster in clusters:
            if not cluster:
                continue

            # Compute cluster centroid
            lats = []
            lons = []
            brightnesses = []
            confidences = []
            satellites = set()
            zone_name = cluster[0].get("_zone", "unknown")

            for fire in cluster:
                try:
                    lats.append(float(fire.get("latitude", 0)))
                    lons.append(float(fire.get("longitude", 0)))
                except (ValueError, TypeError):
                    continue
                try:
                    brightnesses.append(float(fire.get("bright_ti4", fire.get("brightness", 0))))
                except (ValueError, TypeError):
                    pass
                confidences.append(fire.get("confidence", ""))
                satellites.add(fire.get("satellite", fire.get("instrument", "")))

            if not lats:
                continue

            avg_lat = sum(lats) / len(lats)
            avg_lon = sum(lons) / len(lons)
            max_brightness = max(brightnesses) if brightnesses else 0
            sat_str = ", ".join(s for s in satellites if s)

            title = f"Thermal anomaly detected: {avg_lat:.4f},{avg_lon:.4f} ({zone_name})"
            content = (
                f"Fire detections in cluster: {len(cluster)} | "
                f"Max brightness: {max_brightness} | "
                f"Confidence values: {', '.join(str(c) for c in confidences[:5])} | "
                f"Satellite: {sat_str}"
            )

            # Use the first fire's acquisition date if available
            published_at = None
            acq_date = cluster[0].get("acq_date", "")
            acq_time = cluster[0].get("acq_time", "0000")
            if acq_date:
                try:
                    published_at = datetime.strptime(
                        f"{acq_date} {acq_time}", "%Y-%m-%d %H%M"
                    ).replace(tzinfo=timezone.utc)
                except ValueError:
                    pass

            items.append(RawItemModel(
                title=title,
                content=content,
                url="https://firms.modaps.eosdis.nasa.gov/map/",
                source_name="NASA FIRMS",
                external_id=f"firms_{hashlib.md5(f'{avg_lat:.4f}_{avg_lon:.4f}_{acq_date}_{acq_time}'.encode()).hexdigest()[:12]}",
                published_at=published_at,
            ))

        logger.info(
            "FIRMS collected %d clusters from %d fire detections",
            len(items), len(all_fires),
        )
        return items[: self.max_items]
