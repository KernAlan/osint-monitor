"""Infrastructure intelligence collectors: BGP routing, DNS health, GNSS interference.

These produce pre-narrative signals — raw measurements of the physical/digital
world that reveal events before anyone reports on them.
"""

from __future__ import annotations

import logging
import os
import socket
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import requests

from osint_monitor.collectors.base import BaseCollector
from osint_monitor.core.models import RawItemModel

logger = logging.getLogger(__name__)

_TIMEOUT = 20


# ───────────────────────────────────────────────────────────────────────────
# 1. BGP Route Monitor — detect infrastructure damage from routing changes
# ───────────────────────────────────────────────────────────────────────────

# Key Iranian ASNs and their operators
WATCHED_ASNS: dict[str, dict[str, Any]] = {
    "AS12880": {"name": "DCI (Iran Telecom)", "country": "IR", "critical": True},
    "AS58224": {"name": "TIC (Iran)", "country": "IR", "critical": True},
    "AS44244": {"name": "IRANCELL", "country": "IR", "critical": True},
    "AS197207": {"name": "MCCI (Iran Mobile)", "country": "IR", "critical": True},
    "AS48159": {"name": "TeleCommunication Infrastructure Co", "country": "IR", "critical": True},
    "AS6736": {"name": "ROSTELECOM", "country": "RU", "critical": False},
    "AS4134": {"name": "CHINANET", "country": "CN", "critical": False},
    "AS8452": {"name": "TE Egypt", "country": "EG", "critical": False},
    "AS9121": {"name": "Turk Telekom", "country": "TR", "critical": False},
}

# RIPE RIS REST API for BGP updates
RIPE_RIS_API = "https://stat.ripe.net/data/bgp-updates/data.json"
RIPE_ROUTING_STATUS = "https://stat.ripe.net/data/routing-status/data.json"
RIPE_VISIBILITY = "https://stat.ripe.net/data/visibility/data.json"


class BGPMonitor(BaseCollector):
    """Monitor BGP routing changes for watched Autonomous Systems.

    Detects route withdrawals, visibility drops, and path changes that
    indicate infrastructure damage, deliberate isolation, or cable cuts.
    Free API, no key required (RIPE Stat).
    """

    def __init__(self, **kwargs):
        super().__init__(
            name="BGP Infrastructure Monitor",
            source_type="infrastructure",
            url=RIPE_RIS_API,
            **kwargs,
        )
        self.watched_asns = kwargs.get("watched_asns", WATCHED_ASNS)

    def _check_routing_status(self, asn: str) -> dict | None:
        """Get current routing status for an ASN."""
        try:
            resp = requests.get(RIPE_ROUTING_STATUS, params={
                "resource": asn,
            }, timeout=_TIMEOUT)
            resp.raise_for_status()
            data = resp.json().get("data", {})
            return {
                "announced_prefixes": data.get("announced_space", {}).get("v4", {}).get("prefixes", 0),
                "visibility_v4": data.get("visibility", {}).get("v4", {}).get("total_ris_peers", 0),
            }
        except Exception as exc:
            logger.debug("Routing status check failed for %s: %s", asn, exc)
            return None

    def _check_bgp_updates(self, asn: str, hours_back: int = 6) -> dict:
        """Check recent BGP updates (announcements vs withdrawals)."""
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=hours_back)

        try:
            resp = requests.get(RIPE_RIS_API, params={
                "resource": asn,
                "starttime": start.strftime("%Y-%m-%dT%H:%M"),
                "endtime": now.strftime("%Y-%m-%dT%H:%M"),
            }, timeout=_TIMEOUT)
            resp.raise_for_status()
            data = resp.json().get("data", {})
            updates = data.get("updates", [])

            announcements = sum(1 for u in updates if u.get("type") == "A")
            withdrawals = sum(1 for u in updates if u.get("type") == "W")

            return {
                "total_updates": len(updates),
                "announcements": announcements,
                "withdrawals": withdrawals,
                "withdrawal_ratio": withdrawals / max(len(updates), 1),
            }
        except Exception as exc:
            logger.debug("BGP updates check failed for %s: %s", asn, exc)
            return {"total_updates": 0, "announcements": 0, "withdrawals": 0, "withdrawal_ratio": 0}

    def collect(self) -> list[RawItemModel]:
        items: list[RawItemModel] = []

        for asn, info in self.watched_asns.items():
            name = info["name"]
            country = info["country"]

            # Check routing status
            status = self._check_routing_status(asn)
            updates = self._check_bgp_updates(asn, hours_back=6)

            if status is None and updates["total_updates"] == 0:
                continue

            # Detect anomalies
            is_anomalous = False
            severity_notes: list[str] = []

            if updates["withdrawal_ratio"] > 0.5 and updates["total_updates"] > 10:
                is_anomalous = True
                severity_notes.append(
                    f"HIGH withdrawal ratio: {updates['withdrawal_ratio']:.0%} "
                    f"({updates['withdrawals']}/{updates['total_updates']} updates)"
                )

            if updates["withdrawals"] > 50:
                is_anomalous = True
                severity_notes.append(f"Mass withdrawal: {updates['withdrawals']} routes withdrawn in 6h")

            if status and status["announced_prefixes"] == 0:
                is_anomalous = True
                severity_notes.append("CRITICAL: Zero announced prefixes — AS appears completely offline")

            if status and status["visibility_v4"] < 5:
                is_anomalous = True
                severity_notes.append(f"Low visibility: only {status['visibility_v4']} RIS peers see this AS")

            # Always report critical ASNs; only report non-critical if anomalous
            if not is_anomalous and not info.get("critical"):
                continue

            if is_anomalous:
                title = f"BGP ANOMALY: {asn} ({name}, {country}) — routing disruption detected"
            else:
                title = f"BGP status: {asn} ({name}, {country}) — normal"

            content_parts = [
                f"ASN: {asn} ({name})",
                f"Country: {country}",
                f"Updates (6h): {updates['total_updates']} total, {updates['announcements']} announcements, {updates['withdrawals']} withdrawals",
                f"Withdrawal ratio: {updates['withdrawal_ratio']:.1%}",
            ]
            if status:
                content_parts.append(f"Announced prefixes: {status['announced_prefixes']}")
                content_parts.append(f"RIS peer visibility: {status['visibility_v4']}")
            if severity_notes:
                content_parts.append(f"SIGNALS: {'; '.join(severity_notes)}")

            items.append(RawItemModel(
                title=title,
                content="\n".join(content_parts),
                url=f"https://stat.ripe.net/{asn}",
                source_name=self.name,
                external_id=f"bgp_{asn}_{datetime.now(timezone.utc).strftime('%Y%m%d%H')}",
                published_at=datetime.now(timezone.utc),
                fetched_at=datetime.now(timezone.utc),
            ))

            # Rate limit RIPE Stat
            time.sleep(1)

        anomaly_count = sum(1 for i in items if "ANOMALY" in (i.title or ""))
        print(f"  [ok] {self.name}: {len(items)} ASNs checked, {anomaly_count} anomalies")
        return items[:self.max_items]


# ───────────────────────────────────────────────────────────────────────────
# 2. DNS Health Monitor — track government/military domain availability
# ───────────────────────────────────────────────────────────────────────────

WATCHED_DOMAINS: dict[str, dict[str, str]] = {
    # Iranian government
    "president.ir": {"country": "IR", "type": "government", "desc": "Iranian Presidency"},
    "leader.ir": {"country": "IR", "type": "government", "desc": "Supreme Leader office"},
    "dolat.ir": {"country": "IR", "type": "government", "desc": "Iranian government portal"},
    "iribnews.ir": {"country": "IR", "type": "media", "desc": "IRIB state broadcaster"},
    "irna.ir": {"country": "IR", "type": "media", "desc": "IRNA state news agency"},
    "tasnimnews.com": {"country": "IR", "type": "media", "desc": "Tasnim News (IRGC-linked)"},
    "farsnews.ir": {"country": "IR", "type": "media", "desc": "Fars News (IRGC-linked)"},
    "modafl.ir": {"country": "IR", "type": "military", "desc": "Iran Ministry of Defense"},
    # Russian key domains
    "kremlin.ru": {"country": "RU", "type": "government", "desc": "Kremlin"},
    "mil.ru": {"country": "RU", "type": "military", "desc": "Russian MoD"},
    "tass.com": {"country": "RU", "type": "media", "desc": "TASS state agency"},
    # Chinese key domains
    "mod.gov.cn": {"country": "CN", "type": "military", "desc": "China MoD"},
    "xinhuanet.com": {"country": "CN", "type": "media", "desc": "Xinhua state agency"},
    # North Korea
    "kcna.kp": {"country": "KP", "type": "media", "desc": "KCNA state media"},
    "rodong.rep.kp": {"country": "KP", "type": "media", "desc": "Rodong Sinmun"},
}


class DNSHealthMonitor(BaseCollector):
    """Monitor DNS resolution and HTTP reachability of government/military domains.

    Domain unreachability = infrastructure damage, censorship, or deliberate isolation.
    No API needed — pure DNS lookups + HTTP HEAD requests.
    """

    def __init__(self, **kwargs):
        super().__init__(
            name="DNS Health Monitor",
            source_type="infrastructure",
            url="",
            **kwargs,
        )
        self.domains = kwargs.get("domains", WATCHED_DOMAINS)

    @staticmethod
    def _check_dns(domain: str) -> dict:
        """Check if a domain resolves via DNS."""
        try:
            ips = socket.getaddrinfo(domain, 443, socket.AF_INET)
            ip_list = list({addr[4][0] for addr in ips})
            return {"resolves": True, "ips": ip_list}
        except socket.gaierror:
            return {"resolves": False, "ips": []}
        except Exception:
            return {"resolves": False, "ips": []}

    # Domains with known SSL certificate issues (e.g. Chinese government sites
    # with cert mismatches).  We still monitor them -- detecting when they go
    # *actually* offline matters -- but we skip SSL verification to avoid
    # wasting ~10s per domain on expected cert failures.
    _SSL_SKIP_TLDS: set[str] = {".cn", ".kp"}

    @staticmethod
    def _check_http(domain: str) -> dict:
        """Check HTTP(S) reachability with a HEAD request.

        For domains in TLDs known to have chronic certificate issues
        (.cn, .kp) we disable SSL verification so the check completes
        in seconds instead of timing out.
        """
        import urllib3
        skip_ssl = any(domain.endswith(tld) for tld in DNSHealthMonitor._SSL_SKIP_TLDS)
        for scheme in ["https", "http"]:
            try:
                # Suppress the InsecureRequestWarning when we intentionally
                # skip verification for known-bad-cert domains.
                if skip_ssl:
                    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                resp = requests.head(
                    f"{scheme}://{domain}",
                    timeout=10,
                    allow_redirects=True,
                    headers={"User-Agent": "osint-monitor/1.0"},
                    verify=not skip_ssl,
                )
                return {
                    "reachable": True,
                    "status_code": resp.status_code,
                    "response_time_ms": int(resp.elapsed.total_seconds() * 1000),
                    "scheme": scheme,
                }
            except Exception:
                continue
        return {"reachable": False, "status_code": 0, "response_time_ms": 0, "scheme": ""}

    def collect(self) -> list[RawItemModel]:
        items: list[RawItemModel] = []
        down_count = 0

        for domain, info in self.domains.items():
            dns = self._check_dns(domain)
            http = self._check_http(domain) if dns["resolves"] else {
                "reachable": False, "status_code": 0, "response_time_ms": 0, "scheme": ""
            }

            is_down = not dns["resolves"] or not http["reachable"]

            if is_down:
                down_count += 1
                title = f"DOMAIN DOWN: {domain} ({info['desc']}, {info['country']}) — unreachable"
            else:
                title = f"Domain OK: {domain} ({info['desc']}, {info['country']})"

            content_parts = [
                f"Domain: {domain}",
                f"Description: {info['desc']}",
                f"Country: {info['country']}",
                f"Type: {info['type']}",
                f"DNS resolves: {dns['resolves']}",
                f"IPs: {', '.join(dns['ips']) if dns['ips'] else 'none'}",
                f"HTTP reachable: {http['reachable']}",
                f"Status code: {http['status_code']}",
                f"Response time: {http['response_time_ms']}ms",
            ]

            # Only create items for DOWN domains or critical government sites
            if is_down or info["type"] in ("government", "military"):
                items.append(RawItemModel(
                    title=title,
                    content="\n".join(content_parts),
                    url=f"https://{domain}",
                    source_name=self.name,
                    external_id=f"dns_{domain}_{datetime.now(timezone.utc).strftime('%Y%m%d%H')}",
                    published_at=datetime.now(timezone.utc),
                    fetched_at=datetime.now(timezone.utc),
                ))

            time.sleep(0.5)  # Don't hammer

        print(f"  [ok] {self.name}: {len(self.domains)} domains checked, {down_count} unreachable")
        return items[:self.max_items]


# ───────────────────────────────────────────────────────────────────────────
# 3. Flight Route Anomaly Detector — infer no-fly zones from avoidance
# ───────────────────────────────────────────────────────────────────────────

class FlightRouteMonitor(BaseCollector):
    """Detect commercial flight rerouting around conflict zones.

    Uses OpenSky Network to find flights near conflict zones and detect
    unusual routing patterns (diversions, avoidance corridors).
    """

    OPENSKY_URL = "https://opensky-network.org/api/states/all"

    # Regions where commercial traffic avoidance is a signal
    WATCH_ZONES: dict[str, dict[str, Any]] = {
        "persian_gulf": {
            "bbox": (23.0, 47.0, 30.0, 57.0),
            "desc": "Persian Gulf / Strait of Hormuz",
            "normal_traffic_floor": 30,  # expect at least this many commercial flights normally
        },
        "eastern_med": {
            "bbox": (33.0, 33.0, 37.0, 37.0),
            "desc": "Eastern Mediterranean / Lebanon-Syria",
            "normal_traffic_floor": 20,
        },
        "black_sea": {
            "bbox": (41.0, 27.0, 47.0, 42.0),
            "desc": "Black Sea",
            "normal_traffic_floor": 15,
        },
    }

    def __init__(self, **kwargs):
        super().__init__(
            name="Flight Route Monitor",
            source_type="infrastructure",
            url=self.OPENSKY_URL,
            **kwargs,
        )

    def _count_commercial_traffic(self, bbox: tuple) -> dict:
        """Count aircraft in a bounding box, separating military from commercial."""
        from osint_monitor.collectors.adsb import MILITARY_CALLSIGN_PREFIXES

        lat_min, lon_min, lat_max, lon_max = bbox
        try:
            resp = requests.get(self.OPENSKY_URL, params={
                "lamin": lat_min, "lamax": lat_max,
                "lomin": lon_min, "lomax": lon_max,
            }, timeout=30)
            resp.raise_for_status()
            states = resp.json().get("states", []) or []
        except Exception as exc:
            logger.debug("OpenSky query failed: %s", exc)
            return {"total": 0, "commercial": 0, "military": 0, "origins": {}}

        commercial = 0
        military = 0
        origins: dict[str, int] = {}

        for state in states:
            callsign = (state[1] or "").strip().upper()
            origin = state[2] or "Unknown"
            origins[origin] = origins.get(origin, 0) + 1

            is_mil = any(callsign.startswith(p) for p in MILITARY_CALLSIGN_PREFIXES)
            if is_mil:
                military += 1
            else:
                commercial += 1

        return {
            "total": len(states),
            "commercial": commercial,
            "military": military,
            "origins": dict(sorted(origins.items(), key=lambda x: x[1], reverse=True)[:10]),
        }

    def collect(self) -> list[RawItemModel]:
        items: list[RawItemModel] = []

        for zone_key, zone in self.WATCH_ZONES.items():
            traffic = self._count_commercial_traffic(zone["bbox"])

            is_anomalous = traffic["commercial"] < zone["normal_traffic_floor"]
            mil_presence = traffic["military"] > 0

            if is_anomalous:
                title = (
                    f"FLIGHT AVOIDANCE: {zone['desc']} — only {traffic['commercial']} commercial "
                    f"flights (normal: {zone['normal_traffic_floor']}+)"
                )
            elif mil_presence:
                title = (
                    f"Airspace activity: {zone['desc']} — {traffic['commercial']} commercial, "
                    f"{traffic['military']} military aircraft"
                )
            else:
                title = f"Airspace normal: {zone['desc']} — {traffic['commercial']} commercial flights"

            top_origins = ", ".join(f"{k}: {v}" for k, v in list(traffic["origins"].items())[:5])
            content = (
                f"Zone: {zone['desc']}\n"
                f"Total aircraft: {traffic['total']}\n"
                f"Commercial: {traffic['commercial']} (normal floor: {zone['normal_traffic_floor']})\n"
                f"Military: {traffic['military']}\n"
                f"Top origin countries: {top_origins}\n"
                f"Commercial avoidance detected: {is_anomalous}"
            )

            if is_anomalous or mil_presence:
                items.append(RawItemModel(
                    title=title,
                    content=content,
                    url="https://opensky-network.org/",
                    source_name=self.name,
                    external_id=f"flight_{zone_key}_{datetime.now(timezone.utc).strftime('%Y%m%d%H')}",
                    published_at=datetime.now(timezone.utc),
                    fetched_at=datetime.now(timezone.utc),
                ))

            time.sleep(11)  # OpenSky rate limit: 1 req / 10s

        anomalies = sum(1 for i in items if "AVOIDANCE" in (i.title or ""))
        print(f"  [ok] {self.name}: {len(self.WATCH_ZONES)} zones checked, {anomalies} avoidance patterns")
        return items[:self.max_items]


# ───────────────────────────────────────────────────────────────────────────
# 4. Seismic Explosion Discriminator — enhance USGS with explosion detection
# ───────────────────────────────────────────────────────────────────────────

# Known military/strategic facilities where shallow seismic = possible strike
STRATEGIC_FACILITIES: list[dict[str, Any]] = [
    {"name": "Natanz nuclear facility", "lat": 33.72, "lon": 51.72, "radius_km": 20, "country": "IR"},
    {"name": "Fordow enrichment plant", "lat": 34.88, "lon": 51.99, "radius_km": 15, "country": "IR"},
    {"name": "Isfahan nuclear complex", "lat": 32.65, "lon": 51.68, "radius_km": 20, "country": "IR"},
    {"name": "Bushehr nuclear plant", "lat": 28.83, "lon": 50.88, "radius_km": 15, "country": "IR"},
    {"name": "Parchin military complex", "lat": 35.52, "lon": 51.77, "radius_km": 15, "country": "IR"},
    {"name": "Bandar Abbas naval base", "lat": 27.15, "lon": 56.28, "radius_km": 20, "country": "IR"},
    {"name": "Chabahar port", "lat": 25.30, "lon": 60.62, "radius_km": 15, "country": "IR"},
    {"name": "Kharg Island oil terminal", "lat": 29.24, "lon": 50.31, "radius_km": 10, "country": "IR"},
    {"name": "Abadan refinery", "lat": 30.34, "lon": 48.30, "radius_km": 10, "country": "IR"},
    {"name": "Tehran", "lat": 35.69, "lon": 51.39, "radius_km": 30, "country": "IR"},
    {"name": "Zaporizhzhia NPP", "lat": 47.51, "lon": 34.59, "radius_km": 15, "country": "UA"},
    {"name": "Sevastopol naval base", "lat": 44.62, "lon": 33.53, "radius_km": 20, "country": "RU"},
    {"name": "Tartus naval facility", "lat": 34.89, "lon": 35.89, "radius_km": 10, "country": "SY"},
]


class SeismicExplosionDetector(BaseCollector):
    """Detect possible large explosions from seismic data characteristics.

    Explosion signatures differ from earthquakes:
    - Shallow depth (< 5 km, often < 1 km)
    - No aftershock sequence
    - Proximity to known military/strategic facilities
    - Characteristic magnitude range (M2-M4 for large conventional weapons)

    Uses the same USGS API but with different analysis logic.
    """

    BASE_URL = "https://earthquake.usgs.gov/fdsnws/event/1/query"

    def __init__(self, **kwargs):
        super().__init__(
            name="Seismic Explosion Detector",
            source_type="infrastructure",
            url=self.BASE_URL,
            **kwargs,
        )
        self.facilities = kwargs.get("facilities", STRATEGIC_FACILITIES)

    @staticmethod
    def _haversine(lat1, lon1, lat2, lon2):
        import math
        R = 6371.0
        rlat1, rlat2 = math.radians(lat1), math.radians(lat2)
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)
        a = math.sin(dlat / 2) ** 2 + math.cos(rlat1) * math.cos(rlat2) * math.sin(dlon / 2) ** 2
        return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    def _near_facility(self, lat: float, lon: float) -> dict | None:
        for fac in self.facilities:
            dist = self._haversine(lat, lon, fac["lat"], fac["lon"])
            if dist <= fac["radius_km"]:
                return {**fac, "distance_km": round(dist, 1)}
        return None

    @staticmethod
    def _explosion_likelihood(depth_km: float, magnitude: float, near_facility: bool) -> tuple[str, float]:
        """Score how likely a seismic event is an explosion vs natural earthquake."""
        score = 0.0
        reasons: list[str] = []

        if depth_km <= 1.0:
            score += 0.4
            reasons.append("surface-level depth")
        elif depth_km <= 5.0:
            score += 0.25
            reasons.append("very shallow")
        elif depth_km <= 10.0:
            score += 0.1
            reasons.append("shallow")

        if 1.5 <= magnitude <= 4.5:
            score += 0.2
            reasons.append("magnitude consistent with large explosion")

        if near_facility:
            score += 0.3
            reasons.append("near known strategic facility")

        if depth_km == 0.0:
            score += 0.1
            reasons.append("zero depth (surface event)")

        assessment = "LOW"
        if score >= 0.6:
            assessment = "HIGH"
        elif score >= 0.35:
            assessment = "MODERATE"

        return assessment, score

    def collect(self) -> list[RawItemModel]:
        items: list[RawItemModel] = []

        # Query shallow events near strategic regions
        start_time = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime(
            "%Y-%m-%dT%H:%M:%S"
        )

        params = {
            "format": "geojson",
            "starttime": start_time,
            "minmagnitude": 1.5,
            "maxdepth": 10,  # Only shallow events
        }

        try:
            resp = requests.get(self.BASE_URL, params=params, timeout=_TIMEOUT)
            resp.raise_for_status()
            features = resp.json().get("features", [])
        except Exception as exc:
            logger.warning("Seismic explosion detector query failed: %s", exc)
            print(f"  [err] {self.name}: {exc}")
            return []

        for feature in features:
            props = feature.get("properties", {})
            coords = feature.get("geometry", {}).get("coordinates", [])
            if len(coords) < 3:
                continue

            lon, lat, depth_km = coords[0], coords[1], coords[2]
            magnitude = props.get("mag", 0) or 0
            place = props.get("place", "Unknown")

            facility = self._near_facility(lat, lon)
            assessment, score = self._explosion_likelihood(
                depth_km, magnitude, facility is not None
            )

            if assessment == "LOW" and facility is None:
                continue

            published_at = None
            epoch_ms = props.get("time")
            if epoch_ms is not None:
                try:
                    published_at = datetime.fromtimestamp(epoch_ms / 1000.0, tz=timezone.utc)
                except (ValueError, OSError):
                    pass

            if facility:
                title = (
                    f"SEISMIC NEAR FACILITY: M{magnitude} depth={depth_km}km near "
                    f"{facility['name']} ({facility['distance_km']}km away) — "
                    f"explosion likelihood: {assessment}"
                )
            else:
                title = (
                    f"Shallow seismic: M{magnitude} depth={depth_km}km at {place} — "
                    f"explosion likelihood: {assessment}"
                )

            content = (
                f"Magnitude: {magnitude}\n"
                f"Depth: {depth_km} km\n"
                f"Location: {lat}, {lon}\n"
                f"Place: {place}\n"
                f"Explosion likelihood: {assessment} (score: {score:.2f})\n"
            )
            if facility:
                content += (
                    f"Nearest facility: {facility['name']} ({facility['country']})\n"
                    f"Distance: {facility['distance_km']} km\n"
                )

            items.append(RawItemModel(
                title=title,
                content=content,
                url=props.get("url", ""),
                source_name=self.name,
                external_id=f"seis_exp_{props.get('ids', '').strip(',')}",
                published_at=published_at,
                fetched_at=datetime.now(timezone.utc),
            ))

        facility_hits = sum(1 for i in items if "FACILITY" in (i.title or ""))
        print(f"  [ok] {self.name}: {len(features)} shallow events, {len(items)} flagged, {facility_hits} near facilities")
        return items[:self.max_items]
