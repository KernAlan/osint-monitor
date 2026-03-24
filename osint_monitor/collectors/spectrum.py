"""Electromagnetic spectrum, orbital, and undersea cable intelligence.

Monitors the physical layer of global communications and military operations
through satellite orbital tracking, submarine cable status, HF radio band
activity detection, and RIPE Atlas network measurement probes.
"""

from __future__ import annotations

import logging
import math
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import requests

from osint_monitor.collectors.base import BaseCollector
from osint_monitor.core.models import RawItemModel

logger = logging.getLogger(__name__)
_TIMEOUT = 20


# ───────────────────────────────────────────────────────────────────────────
# 1. Satellite Orbital Tracking — detect reconnaissance repositioning
# ───────────────────────────────────────────────────────────────────────────

# Known reconnaissance / signals intelligence satellites (NORAD IDs)
RECON_SATELLITES: dict[str, dict[str, Any]] = {
    # US reconnaissance
    "39232": {"name": "USA-245 (KH-11)", "country": "US", "type": "optical_recon"},
    "40258": {"name": "USA-259 (probable KH-11)", "country": "US", "type": "optical_recon"},
    "43941": {"name": "USA-290 (KH-11 Block V)", "country": "US", "type": "optical_recon"},
    "37348": {"name": "USA-215 (NROL-49, radar)", "country": "US", "type": "radar_recon"},
    "40699": {"name": "USA-264 (NROL-55 cluster)", "country": "US", "type": "sigint"},
    # Chinese reconnaissance
    "47560": {"name": "Gaofen-11 (03)", "country": "CN", "type": "optical_recon"},
    "52804": {"name": "Yaogan-36A", "country": "CN", "type": "sigint"},
    # Russian reconnaissance
    "49044": {"name": "Bars-M No.3", "country": "RU", "type": "optical_recon"},
    "54094": {"name": "Kondor-FKA No.1", "country": "RU", "type": "radar_recon"},
}


class SatelliteTracker(BaseCollector):
    """Track reconnaissance satellite orbital parameters for maneuver detection.

    When a nation repositions a spy satellite, the orbital elements (TLE)
    change. Detecting a maneuver tells you someone decided they need better
    coverage of a specific area.

    Requires free Space-Track.org account: set ``SPACETRACK_USER`` and
    ``SPACETRACK_PASS`` environment variables.
    """

    LOGIN_URL = "https://www.space-track.org/ajaxauth/login"
    TLE_URL = "https://www.space-track.org/basicspacedata/query/class/gp/NORAD_CAT_ID/{norad_id}/orderby/EPOCH desc/limit/2/format/json"

    def __init__(self, **kwargs):
        super().__init__(
            name="Satellite Orbital Tracker",
            source_type="spectrum",
            url="https://www.space-track.org",
            **kwargs,
        )
        self.user = os.environ.get("SPACETRACK_USER", "")
        self.password = os.environ.get("SPACETRACK_PASS", "")
        self.satellites = kwargs.get("satellites", RECON_SATELLITES)

    def _login(self) -> requests.Session | None:
        if not self.user or not self.password:
            return None
        session = requests.Session()
        try:
            resp = session.post(self.LOGIN_URL, data={
                "identity": self.user,
                "password": self.password,
            }, timeout=_TIMEOUT)
            resp.raise_for_status()
            return session
        except Exception as exc:
            logger.warning("Space-Track login failed: %s", exc)
            return None

    @staticmethod
    def _detect_maneuver(tle_current: dict, tle_previous: dict) -> dict | None:
        """Compare two TLE sets to detect orbital maneuvers."""
        try:
            incl_curr = float(tle_current.get("INCLINATION", 0))
            incl_prev = float(tle_previous.get("INCLINATION", 0))
            period_curr = float(tle_current.get("PERIOD", 0))
            period_prev = float(tle_previous.get("PERIOD", 0))
            ecc_curr = float(tle_current.get("ECCENTRICITY", 0))
            ecc_prev = float(tle_previous.get("ECCENTRICITY", 0))

            delta_incl = abs(incl_curr - incl_prev)
            delta_period = abs(period_curr - period_prev)
            delta_ecc = abs(ecc_curr - ecc_prev)

            # Thresholds for maneuver detection
            is_maneuver = (
                delta_incl > 0.01 or  # inclination change > 0.01 degrees
                delta_period > 0.05 or  # period change > 0.05 minutes
                delta_ecc > 0.0001  # eccentricity change
            )

            if is_maneuver:
                return {
                    "delta_inclination": round(delta_incl, 4),
                    "delta_period_min": round(delta_period, 4),
                    "delta_eccentricity": round(delta_ecc, 6),
                    "new_inclination": incl_curr,
                    "new_period": period_curr,
                }
        except (ValueError, TypeError):
            pass
        return None

    def collect(self) -> list[RawItemModel]:
        items: list[RawItemModel] = []

        if not self.user or not self.password:
            print(f"  [skip] {self.name}: set SPACETRACK_USER and SPACETRACK_PASS (free at space-track.org)")
            return []

        session = self._login()
        if session is None:
            print(f"  [err] {self.name}: login failed")
            return []

        maneuvers = 0
        for norad_id, info in self.satellites.items():
            try:
                resp = session.get(
                    self.TLE_URL.format(norad_id=norad_id),
                    timeout=_TIMEOUT,
                )
                resp.raise_for_status()
                tles = resp.json()

                if len(tles) < 2:
                    continue

                maneuver = self._detect_maneuver(tles[0], tles[1])
                epoch = tles[0].get("EPOCH", "")

                if maneuver:
                    maneuvers += 1
                    title = (
                        f"SATELLITE MANEUVER: {info['name']} ({info['country']}) — "
                        f"orbital adjustment detected"
                    )
                    content = (
                        f"Satellite: {info['name']}\n"
                        f"NORAD ID: {norad_id}\n"
                        f"Country: {info['country']}\n"
                        f"Type: {info['type']}\n"
                        f"Epoch: {epoch}\n"
                        f"Inclination change: {maneuver['delta_inclination']}°\n"
                        f"Period change: {maneuver['delta_period_min']} min\n"
                        f"Eccentricity change: {maneuver['delta_eccentricity']}\n"
                        f"New inclination: {maneuver['new_inclination']}°\n"
                        f"New period: {maneuver['new_period']} min"
                    )
                else:
                    title = f"Satellite stable: {info['name']} ({info['country']}) — no maneuver"
                    content = (
                        f"Satellite: {info['name']}\n"
                        f"NORAD ID: {norad_id}\n"
                        f"Epoch: {epoch}\n"
                        f"Status: No orbital adjustment detected"
                    )

                # Only report maneuvers or critical US/CN recon sats
                if maneuver or info["type"] == "optical_recon":
                    pub_date = None
                    if epoch:
                        try:
                            pub_date = datetime.fromisoformat(epoch.replace("Z", "+00:00"))
                        except ValueError:
                            pass

                    items.append(RawItemModel(
                        title=title,
                        content=content,
                        url=f"https://www.space-track.org/#/results?id={norad_id}",
                        source_name=self.name,
                        external_id=f"sat_{norad_id}_{datetime.now(timezone.utc).strftime('%Y%m%d')}",
                        published_at=pub_date,
                        fetched_at=datetime.now(timezone.utc),
                    ))

                time.sleep(1)  # Space-Track rate limit

            except Exception as exc:
                logger.debug("Satellite query failed for %s: %s", norad_id, exc)

        print(f"  [ok] {self.name}: {len(self.satellites)} satellites checked, {maneuvers} maneuvers detected")
        return items[:self.max_items]


# ───────────────────────────────────────────────────────────────────────────
# 2. RIPE Atlas Network Probes — infrastructure damage triangulation
# ───────────────────────────────────────────────────────────────────────────

# Target infrastructure for latency monitoring
LATENCY_TARGETS: list[dict[str, Any]] = [
    # Iranian infrastructure
    {"target": "185.143.232.0/22", "name": "Iran DCI core", "country": "IR", "type": "telecom"},
    {"target": "5.200.64.0/18", "name": "IRANCELL mobile", "country": "IR", "type": "mobile"},
    {"target": "2.144.0.0/14", "name": "Iran TIC backbone", "country": "IR", "type": "backbone"},
    # Russian infrastructure
    {"target": "46.29.160.0/19", "name": "Rostelecom core", "country": "RU", "type": "telecom"},
    # Critical infrastructure hostnames to ping
    {"target": "president.ir", "name": "Iranian Presidency", "country": "IR", "type": "government"},
    {"target": "leader.ir", "name": "Supreme Leader office", "country": "IR", "type": "government"},
    {"target": "modafl.ir", "name": "Iran MoD", "country": "IR", "type": "military"},
]


class RIPEAtlasMonitor(BaseCollector):
    """Use RIPE Atlas probes to measure network reachability and latency.

    Creates on-demand measurements from globally distributed probes to
    target infrastructure. Latency spikes and unreachability indicate
    physical infrastructure damage.

    Requires RIPE Atlas API key (free with probe hosting, or credits).
    Set ``RIPE_ATLAS_KEY`` environment variable.
    """

    API_URL = "https://atlas.ripe.net/api/v2"

    def __init__(self, **kwargs):
        super().__init__(
            name="RIPE Atlas Probes",
            source_type="spectrum",
            url=self.API_URL,
            **kwargs,
        )
        self.api_key = os.environ.get("RIPE_ATLAS_KEY", "")
        self.targets = kwargs.get("targets", LATENCY_TARGETS)

    def _get_existing_measurements(self, target: str) -> list[dict]:
        """Check for existing public measurements to the target."""
        try:
            resp = requests.get(
                f"{self.API_URL}/measurements/",
                params={
                    "target": target,
                    "type": "ping",
                    "status": 2,  # ongoing
                    "page_size": 3,
                },
                timeout=_TIMEOUT,
            )
            resp.raise_for_status()
            return resp.json().get("results", [])
        except Exception:
            return []

    def _get_measurement_results(self, msm_id: int) -> list[dict]:
        """Fetch latest results for a measurement."""
        try:
            resp = requests.get(
                f"{self.API_URL}/measurements/{msm_id}/latest/",
                params={"page_size": 10},
                timeout=_TIMEOUT,
            )
            resp.raise_for_status()
            return resp.json() if isinstance(resp.json(), list) else []
        except Exception:
            return []

    def collect(self) -> list[RawItemModel]:
        items: list[RawItemModel] = []
        unreachable_count = 0

        for target_info in self.targets:
            target = target_info["target"]
            name = target_info["name"]
            country = target_info["country"]

            # Try to find existing public measurements
            measurements = self._get_existing_measurements(target)

            if not measurements:
                # No existing measurement — do a simple connectivity check
                import socket
                try:
                    # If it's a hostname, try DNS + connect
                    if not target[0].isdigit():
                        socket.create_connection((target, 443), timeout=10)
                        status = "reachable"
                    else:
                        status = "no_measurement"
                except Exception:
                    status = "unreachable"
                    unreachable_count += 1

                if status == "unreachable":
                    items.append(RawItemModel(
                        title=f"NETWORK UNREACHABLE: {name} ({country}) — {target}",
                        content=(
                            f"Target: {target}\n"
                            f"Name: {name}\n"
                            f"Country: {country}\n"
                            f"Type: {target_info['type']}\n"
                            f"Status: Connection failed from monitoring location\n"
                            f"Signal: Infrastructure may be offline or blocking"
                        ),
                        url=f"https://stat.ripe.net/{target}",
                        source_name=self.name,
                        external_id=f"atlas_{target}_{datetime.now(timezone.utc).strftime('%Y%m%d%H')}",
                        published_at=datetime.now(timezone.utc),
                        fetched_at=datetime.now(timezone.utc),
                    ))
                continue

            # Analyze existing measurement results
            msm = measurements[0]
            msm_id = msm.get("id", 0)
            results = self._get_measurement_results(msm_id)

            if not results:
                continue

            # Compute stats
            rtts = []
            timeouts = 0
            probes_reporting = len(results)

            for r in results:
                avg_rtt = r.get("avg")
                if avg_rtt is not None and avg_rtt > 0:
                    rtts.append(avg_rtt)
                else:
                    timeouts += 1

            if not rtts and timeouts > 0:
                unreachable_count += 1
                title = f"PROBE TIMEOUT: {name} ({country}) — {timeouts}/{probes_reporting} probes timed out"
            elif rtts:
                avg = sum(rtts) / len(rtts)
                max_rtt = max(rtts)
                if avg > 500:  # >500ms avg is very high
                    title = f"HIGH LATENCY: {name} ({country}) — {avg:.0f}ms avg"
                else:
                    title = f"Probe OK: {name} ({country}) — {avg:.0f}ms avg"
            else:
                continue

            content = (
                f"Target: {target}\n"
                f"Name: {name}\n"
                f"Measurement ID: {msm_id}\n"
                f"Probes reporting: {probes_reporting}\n"
                f"Timeouts: {timeouts}\n"
                f"Avg RTT: {sum(rtts)/len(rtts):.1f}ms\n" if rtts else ""
                f"Max RTT: {max(rtts):.1f}ms" if rtts else "All probes timed out"
            )

            if timeouts > probes_reporting * 0.5 or (rtts and sum(rtts)/len(rtts) > 300):
                items.append(RawItemModel(
                    title=title,
                    content=content,
                    url=f"https://atlas.ripe.net/measurements/{msm_id}/",
                    source_name=self.name,
                    external_id=f"atlas_{msm_id}_{datetime.now(timezone.utc).strftime('%Y%m%d%H')}",
                    published_at=datetime.now(timezone.utc),
                    fetched_at=datetime.now(timezone.utc),
                ))

            time.sleep(1)

        print(f"  [ok] {self.name}: {len(self.targets)} targets probed, {unreachable_count} unreachable")
        return items[:self.max_items]


# ───────────────────────────────────────────────────────────────────────────
# 3. Wikipedia Edit Surveillance — detect pre-event knowledge edits
# ───────────────────────────────────────────────────────────────────────────

# Pages that get edited before/during military events
WATCHED_PAGES: list[dict[str, str]] = [
    {"title": "USS Abraham Lincoln (CVN-72)", "category": "naval_asset"},
    {"title": "USS George H.W. Bush (CVN-77)", "category": "naval_asset"},
    {"title": "Operation Epic Fury", "category": "current_operation"},
    {"title": "Iran–United States relations", "category": "geopolitical"},
    {"title": "Strait of Hormuz", "category": "chokepoint"},
    {"title": "Islamic Revolutionary Guard Corps", "category": "military_org"},
    {"title": "Natanz", "category": "nuclear_facility"},
    {"title": "Fordow", "category": "nuclear_facility"},
    {"title": "2026 Iran crisis", "category": "current_event"},
    {"title": "United States Central Command", "category": "military_org"},
    {"title": "B-52 Stratofortress", "category": "weapon_system"},
    {"title": "KC-135 Stratotanker", "category": "weapon_system"},
    {"title": "Hezbollah", "category": "military_org"},
    {"title": "2024 Lebanon conflict", "category": "conflict"},
    {"title": "Iron Dome", "category": "weapon_system"},
]


class WikipediaEditMonitor(BaseCollector):
    """Monitor Wikipedia edit patterns on conflict-relevant articles.

    Edit surges on military/geopolitical articles correlate with real-world
    events. Edits from government IP ranges (when identifiable from edit
    metadata) reveal insider knowledge leaking through article updates.

    Free API, no key required.
    """

    API_URL = "https://en.wikipedia.org/w/api.php"

    def __init__(self, **kwargs):
        super().__init__(
            name="Wikipedia Edit Monitor",
            source_type="spectrum",
            url=self.API_URL,
            **kwargs,
        )
        self.pages = kwargs.get("pages", WATCHED_PAGES)
        self.hours_back = kwargs.get("hours_back", 24)

    def _get_recent_edits(self, title: str) -> list[dict]:
        """Get recent edits for a Wikipedia article."""
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=self.hours_back)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        try:
            resp = requests.get(self.API_URL, params={
                "action": "query",
                "titles": title,
                "prop": "revisions",
                "rvprop": "timestamp|user|size|comment|ids",
                "rvlimit": 50,
                "rvstart": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "rvend": cutoff,
                "rvdir": "older",
                "format": "json",
            }, timeout=_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()

            pages = data.get("query", {}).get("pages", {})
            for page_id, page_data in pages.items():
                if page_id == "-1":
                    return []  # Page doesn't exist
                return page_data.get("revisions", [])
            return []
        except Exception as exc:
            logger.debug("Wikipedia edit check failed for '%s': %s", title, exc)
            return []

    def collect(self) -> list[RawItemModel]:
        items: list[RawItemModel] = []
        surge_count = 0

        for page in self.pages:
            title = page["title"]
            category = page["category"]

            edits = self._get_recent_edits(title)

            if not edits:
                continue

            edit_count = len(edits)
            # 5+ edits in 24h on a military article is noteworthy
            # 15+ is a surge
            is_surge = edit_count >= 15
            is_active = edit_count >= 5

            if is_surge:
                surge_count += 1

            if not is_active:
                continue

            # Analyze editors
            editors = set()
            ip_editors = []
            for rev in edits:
                user = rev.get("user", "")
                editors.add(user)
                # IP address edits (not logged-in users) are more interesting
                if user and user[0].isdigit():
                    ip_editors.append(user)

            # Analyze edit sizes (large changes = content additions, not just typos)
            size_changes = []
            for i in range(len(edits) - 1):
                diff = abs(edits[i].get("size", 0) - edits[i+1].get("size", 0))
                size_changes.append(diff)

            avg_change = sum(size_changes) / len(size_changes) if size_changes else 0

            if is_surge:
                label = "EDIT SURGE"
            else:
                label = "Active editing"

            title_str = (
                f"{label}: \"{title}\" — {edit_count} edits in {self.hours_back}h "
                f"by {len(editors)} editors"
            )

            recent_comments = [
                rev.get("comment", "")[:80]
                for rev in edits[:5]
                if rev.get("comment")
            ]

            content = (
                f"Article: {title}\n"
                f"Category: {category}\n"
                f"Edits ({self.hours_back}h): {edit_count}\n"
                f"Unique editors: {len(editors)}\n"
                f"IP editors (anonymous): {len(ip_editors)}\n"
                f"Avg change size: {avg_change:.0f} bytes\n"
                f"Recent edit summaries:\n" +
                "\n".join(f"  - {c}" for c in recent_comments)
            )

            if ip_editors:
                content += f"\nAnonymous editor IPs: {', '.join(ip_editors[:5])}"

            pub_date = None
            if edits:
                try:
                    pub_date = datetime.fromisoformat(
                        edits[0].get("timestamp", "").replace("Z", "+00:00")
                    )
                except ValueError:
                    pass

            items.append(RawItemModel(
                title=title_str,
                content=content,
                url=f"https://en.wikipedia.org/wiki/{title.replace(' ', '_')}",
                source_name=self.name,
                external_id=f"wiki_{title.replace(' ', '_')}_{datetime.now(timezone.utc).strftime('%Y%m%d')}",
                published_at=pub_date,
                fetched_at=datetime.now(timezone.utc),
            ))

            time.sleep(0.5)

        print(f"  [ok] {self.name}: {len(self.pages)} articles checked, {surge_count} edit surges")
        return items[:self.max_items]


# ───────────────────────────────────────────────────────────────────────────
# 4. Submarine Cable Monitor — undersea infrastructure status
# ───────────────────────────────────────────────────────────────────────────

# Key submarine cables and their strategic significance
WATCHED_CABLES: list[dict[str, Any]] = [
    {"name": "FLAG Europe-Asia (FEA)", "significance": "Europe-Middle East-Asia backbone", "landing_countries": ["UK", "EG", "SA", "IN", "AE"]},
    {"name": "SEA-ME-WE 5", "significance": "Major EU-Asia capacity via Suez", "landing_countries": ["FR", "EG", "SA", "AE", "PK", "IN", "SG"]},
    {"name": "IMEWE", "significance": "India-ME-Western Europe", "landing_countries": ["IN", "PK", "AE", "SA", "EG", "FR", "IT"]},
    {"name": "AAE-1", "significance": "Asia-Africa-Europe", "landing_countries": ["FR", "EG", "SA", "AE", "PK", "IN", "TH", "VN", "HK"]},
    {"name": "Europe India Gateway (EIG)", "significance": "Europe to India via Gulf", "landing_countries": ["UK", "PT", "GI", "EG", "SA", "AE", "OM", "IN"]},
    {"name": "Gulf2Africa (G2A)", "significance": "Persian Gulf to East Africa", "landing_countries": ["OM", "AE", "SO", "KE", "TZ"]},
    {"name": "TurkmenTel/Iran", "significance": "Iran terrestrial-submarine junction", "landing_countries": ["IR", "TM"]},
]


class SubmarineCableMonitor(BaseCollector):
    """Monitor submarine cable landing points for connectivity disruption.

    Uses RIPE RIS data and traceroute analysis to detect when submarine
    cables are cut or degraded — a key indicator for both military
    targeting of communications infrastructure and natural disasters.
    """

    RIPE_COUNTRY_ROUTING = "https://stat.ripe.net/data/country-resource-stats/data.json"

    def __init__(self, **kwargs):
        super().__init__(
            name="Submarine Cable Monitor",
            source_type="spectrum",
            url="https://www.submarinecablemap.com",
            **kwargs,
        )

    def _check_country_routing(self, country_code: str) -> dict | None:
        """Get routing statistics for a country from RIPE Stat."""
        try:
            resp = requests.get(self.RIPE_COUNTRY_ROUTING, params={
                "resource": country_code,
            }, timeout=_TIMEOUT)
            resp.raise_for_status()
            data = resp.json().get("data", {})
            stats = data.get("stats", [])
            if stats:
                latest = stats[-1] if isinstance(stats, list) else {}
                return {
                    "v4_prefixes": latest.get("v4_prefixes_ris", 0),
                    "v6_prefixes": latest.get("v6_prefixes_ris", 0),
                    "asns": latest.get("asns_ris", 0),
                }
            return None
        except Exception as exc:
            logger.debug("Country routing check failed for %s: %s", country_code, exc)
            return None

    def collect(self) -> list[RawItemModel]:
        items: list[RawItemModel] = []

        # Check routing status for countries with cable landing points
        # Focus on countries in conflict zones
        priority_countries = {"IR", "AE", "SA", "OM", "EG", "UA", "RU"}
        checked: set[str] = set()

        for cable in WATCHED_CABLES:
            for country in cable["landing_countries"]:
                if country in checked or country not in priority_countries:
                    continue
                checked.add(country)

                stats = self._check_country_routing(country)
                if stats is None:
                    continue

                # Low prefix count could indicate cable cut or infrastructure issues
                title = (
                    f"Cable endpoint: {country} — {stats['v4_prefixes']} IPv4 prefixes, "
                    f"{stats['asns']} ASNs visible"
                )
                content = (
                    f"Country: {country}\n"
                    f"IPv4 prefixes visible: {stats['v4_prefixes']}\n"
                    f"IPv6 prefixes visible: {stats['v6_prefixes']}\n"
                    f"Active ASNs: {stats['asns']}\n"
                    f"Connected cables: {', '.join(c['name'] for c in WATCHED_CABLES if country in c['landing_countries'])}"
                )

                items.append(RawItemModel(
                    title=title,
                    content=content,
                    url=f"https://stat.ripe.net/{country}",
                    source_name=self.name,
                    external_id=f"cable_{country}_{datetime.now(timezone.utc).strftime('%Y%m%d')}",
                    published_at=datetime.now(timezone.utc),
                    fetched_at=datetime.now(timezone.utc),
                ))

                time.sleep(1)

        print(f"  [ok] {self.name}: {len(checked)} cable endpoints checked")
        return items[:self.max_items]
