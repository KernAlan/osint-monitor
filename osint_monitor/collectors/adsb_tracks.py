"""ADS-B flight track intelligence via ADSB.lol free API.

Provides military aircraft tracking with route analysis, tanker orbit
detection, ISR dwell patterns, and cargo surge identification.

Uses https://api.adsb.lol/v2/mil — free, no API key, no rate limit,
unfiltered military aircraft data globally.
"""

from __future__ import annotations

import json
import logging
import math
import os
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from osint_monitor.collectors.base import BaseCollector
from osint_monitor.core.models import RawItemModel

logger = logging.getLogger(__name__)

_TIMEOUT = 20
_DATA_DIR = Path(__file__).parent.parent.parent / "data"

# ADSB.lol API
ADSB_LOL_MIL = "https://api.adsb.lol/v2/mil"

# Regions of interest
WATCH_REGIONS: dict[str, dict[str, Any]] = {
    "persian_gulf": {
        "desc": "Persian Gulf / Iran Theater",
        "bbox": (23, 44, 40, 63),
        "significance": "Operation Epic Fury theater, Hormuz, Iranian airspace",
    },
    "eastern_med": {
        "desc": "Eastern Mediterranean",
        "bbox": (30, 25, 40, 37),
        "significance": "Lebanon front, Suez approach, bomber transit route",
    },
    "red_sea": {
        "desc": "Red Sea / Bab el-Mandeb",
        "bbox": (12, 38, 22, 50),
        "significance": "Houthi anti-ship zone, Yemen theater",
    },
    "western_europe": {
        "desc": "Western Europe (bomber staging)",
        "bbox": (45, -10, 60, 15),
        "significance": "RAF Fairford (B-1B/B-52 base), bomber departure routes",
    },
    "black_sea": {
        "desc": "Black Sea",
        "bbox": (41, 27, 47, 42),
        "significance": "Russia-Ukraine ISR, NATO patrol",
    },
    "taiwan_strait": {
        "desc": "Taiwan Strait",
        "bbox": (22, 117, 26, 121),
        "significance": "China-Taiwan flashpoint",
    },
}

# Aircraft type classification
TANKERS = {"KC135", "K35R", "K35E", "KC10", "KC46", "A330", "A332", "A339", "MRTT"}
ISR_RECON = {"GLHK", "RQ4", "P8", "P3", "E3", "E6", "E8", "RC135", "RC12", "EP3", "U2", "GLEX", "GLF5", "GLF6", "CL60", "CL35"}
BOMBERS = {"B1", "B1B", "B52", "B52H", "B2", "B21", "B2A"}
CARGO = {"C17", "C5", "C5M", "C130", "C30J", "A400", "C2"}
FIGHTERS = {"F15", "F16", "F18", "F22", "F35", "F35A", "F35B", "F35C", "FA18", "EUFI", "GROB", "RFLY", "TYPH"}

def _classify_aircraft(ac_type: str) -> str:
    """Classify an aircraft type into a role."""
    t = (ac_type or "").upper().replace("-", "")
    for tanker in TANKERS:
        if tanker in t:
            return "tanker"
    for isr in ISR_RECON:
        if isr in t:
            return "isr_recon"
    for bomber in BOMBERS:
        if bomber in t:
            return "bomber"
    for cargo in CARGO:
        if cargo in t:
            return "cargo"
    for fighter in FIGHTERS:
        if fighter in t:
            return "fighter"
    return "other_military"


# Known base locations for route analysis
KNOWN_BASES: dict[str, tuple[float, float, str]] = {
    "RAF Fairford": (51.68, -1.79, "UK — B-1B/B-52 forward base"),
    "RAF Lakenheath": (52.41, 0.56, "UK — F-15E base"),
    "Al Udeid": (25.12, 51.31, "Qatar — CENTCOM forward HQ"),
    "Al Dhafra": (24.25, 54.55, "UAE — USAF tanker/ISR hub"),
    "Prince Sultan AB": (24.06, 47.58, "Saudi — USAF Patriot/fighter"),
    "Incirlik": (37.00, 35.43, "Turkey — NATO base"),
    "Souda Bay": (35.49, 24.12, "Crete — US/NATO naval air"),
    "Sigonella": (37.40, 14.92, "Sicily — P-8/Global Hawk hub"),
    "Ramstein": (49.44, 7.60, "Germany — USAF HQ Europe"),
    "Diego Garcia": (-7.31, 72.41, "Indian Ocean — B-52/B-2 staging"),
}

def _nearest_base(lat: float, lon: float) -> tuple[str, float] | None:
    """Find the nearest known military base."""
    best = None
    best_dist = float("inf")
    for name, (blat, blon, _) in KNOWN_BASES.items():
        dlat = math.radians(blat - lat)
        dlon = math.radians(blon - lon)
        a = math.sin(dlat/2)**2 + math.cos(math.radians(lat)) * math.cos(math.radians(blat)) * math.sin(dlon/2)**2
        dist_km = 6371 * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
        if dist_km < best_dist:
            best_dist = dist_km
            best = name
    if best and best_dist < 500:  # within 500km
        return best, round(best_dist, 1)
    return None


class ADSBTrackCollector(BaseCollector):
    """Collect military aircraft positions and analyze patterns.

    Signals extracted:
    - Tanker orbits (active refueling = strike packages cycling)
    - ISR dwell (persistent surveillance = something being watched)
    - Bomber presence (active strike missions)
    - Cargo surge (force buildup or evacuation)
    - Route analysis (which airspace is being avoided)
    - Regional force concentration anomalies

    Free API, no key, no rate limit.
    """

    def __init__(self, **kwargs):
        super().__init__(
            name="ADSB Military Tracks",
            source_type="adsb",
            url=ADSB_LOL_MIL,
            **kwargs,
        )
        self.regions = kwargs.get("regions", WATCH_REGIONS)
        self._history_path = _DATA_DIR / "adsb_history.json"

    def _load_history(self) -> dict:
        try:
            if self._history_path.exists():
                return json.loads(self._history_path.read_text())
        except Exception:
            pass
        return {"snapshots": []}

    def _save_history(self, history: dict) -> None:
        try:
            _DATA_DIR.mkdir(parents=True, exist_ok=True)
            # Keep last 96 snapshots (~24h at 15min intervals)
            history["snapshots"] = history["snapshots"][-96:]
            self._history_path.write_text(json.dumps(history, indent=2))
        except Exception as exc:
            logger.debug("ADS-B history save failed: %s", exc)

    def _fetch_military(self) -> list[dict]:
        """Fetch all military aircraft globally from ADSB.lol."""
        try:
            resp = requests.get(ADSB_LOL_MIL, timeout=_TIMEOUT, headers={
                "User-Agent": "osint-monitor/1.0",
            })
            resp.raise_for_status()
            data = resp.json()
            return data.get("ac", [])
        except Exception as exc:
            logger.warning("ADSB.lol fetch failed: %s", exc)
            return []

    def _filter_to_region(self, aircraft: list[dict], bbox: tuple) -> list[dict]:
        """Filter aircraft to a bounding box."""
        lat_min, lon_min, lat_max, lon_max = bbox
        result = []
        for ac in aircraft:
            lat = ac.get("lat")
            lon = ac.get("lon")
            if lat is None or lon is None:
                continue
            if lat_min <= lat <= lat_max and lon_min <= lon <= lon_max:
                result.append(ac)
        return result

    def _analyze_region(self, region_name: str, region: dict, aircraft: list[dict]) -> list[dict]:
        """Analyze military aircraft in a region and produce intelligence items."""
        in_region = self._filter_to_region(aircraft, region["bbox"])

        if not in_region:
            return []

        # Classify by role
        by_role: dict[str, list[dict]] = defaultdict(list)
        for ac in in_region:
            role = _classify_aircraft(ac.get("t", ""))
            by_role[role].append(ac)

        signals: list[dict] = []

        # Tanker presence = active refueling operations
        tankers = by_role.get("tanker", [])
        if tankers:
            details = []
            for t in tankers:
                callsign = (t.get("flight") or "").strip()
                actype = t.get("t", "?")
                alt = t.get("alt_baro", "?")
                details.append(f"{callsign} ({actype}) at {alt}ft")
            signals.append({
                "type": "tanker_orbit",
                "priority": "HIGH",
                "title": f"TANKER ACTIVITY: {len(tankers)} tanker(s) over {region['desc']} — active refueling operations",
                "detail": f"Tankers: {'; '.join(details)}\nSignificance: Tanker orbits indicate active strike packages cycling through the area",
            })

        # ISR presence = persistent surveillance
        isr = by_role.get("isr_recon", [])
        if isr:
            details = []
            for i in isr:
                callsign = (i.get("flight") or "").strip()
                actype = i.get("t", "?")
                alt = i.get("alt_baro", "?")
                lat = i.get("lat", "?")
                lon = i.get("lon", "?")
                details.append(f"{callsign} ({actype}) at {alt}ft pos=({lat},{lon})")
            signals.append({
                "type": "isr_dwell",
                "priority": "HIGH",
                "title": f"ISR ACTIVITY: {len(isr)} reconnaissance aircraft over {region['desc']}",
                "detail": f"ISR assets: {'; '.join(details)}\nSignificance: Persistent ISR = something specific is being watched or a target is being developed",
            })

        # Bomber presence = active strike missions
        bombers = by_role.get("bomber", [])
        if bombers:
            details = []
            for b in bombers:
                callsign = (b.get("flight") or "").strip()
                actype = b.get("t", "?")
                alt = b.get("alt_baro", "?")
                heading = b.get("true_heading", "?")
                reg = b.get("r", "?")
                details.append(f"{callsign} ({actype}, reg={reg}) at {alt}ft hdg={heading}")

                # Check nearest base for route analysis
                lat = b.get("lat")
                lon = b.get("lon")
                if lat and lon:
                    base = _nearest_base(lat, lon)
                    if base:
                        details.append(f"  -> Nearest base: {base[0]} ({base[1]}km)")

            signals.append({
                "type": "bomber_track",
                "priority": "CRITICAL",
                "title": f"BOMBER ACTIVITY: {len(bombers)} bomber(s) over {region['desc']} — active strike mission",
                "detail": f"Bombers: {'; '.join(details)}\nSignificance: Bomber presence over/near theater = active long-range strike operations",
            })

        # Cargo surge = force movement
        cargo = by_role.get("cargo", [])
        if len(cargo) >= 3:
            details = []
            for c in cargo:
                callsign = (c.get("flight") or "").strip()
                actype = c.get("t", "?")
                details.append(f"{callsign} ({actype})")
            signals.append({
                "type": "cargo_surge",
                "priority": "MODERATE",
                "title": f"CARGO MOVEMENT: {len(cargo)} military transport aircraft over {region['desc']}",
                "detail": f"Transports: {'; '.join(details)}\nSignificance: Multiple cargo aircraft = force buildup, resupply, or evacuation",
            })

        # Overall force concentration
        total = len(in_region)
        if total >= 5:
            role_summary = ", ".join(f"{len(v)} {k}" for k, v in sorted(by_role.items(), key=lambda x: len(x[1]), reverse=True) if v)
            signals.append({
                "type": "force_concentration",
                "priority": "MODERATE",
                "title": f"MILITARY CONCENTRATION: {total} aircraft over {region['desc']}",
                "detail": f"Breakdown: {role_summary}\nRegion: {region['significance']}",
            })

        return signals

    def collect(self) -> list[RawItemModel]:
        """Fetch global military aircraft and analyze by region."""
        items: list[RawItemModel] = []

        aircraft = self._fetch_military()
        if not aircraft:
            print(f"  [err] {self.name}: no data from ADSB.lol")
            return []

        total_global = len(aircraft)

        # Save snapshot for historical comparison
        history = self._load_history()
        snapshot = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_global": total_global,
            "by_region": {},
        }

        all_signals: list[dict] = []
        region_counts: dict[str, int] = {}

        for region_name, region in self.regions.items():
            in_region = self._filter_to_region(aircraft, region["bbox"])
            region_counts[region_name] = len(in_region)
            snapshot["by_region"][region_name] = len(in_region)

            signals = self._analyze_region(region_name, region, aircraft)
            all_signals.extend(signals)

        history["snapshots"].append(snapshot)

        # Detect historical anomalies (compare to previous snapshots)
        if len(history["snapshots"]) >= 3:
            for region_name in self.regions:
                recent_counts = [
                    s["by_region"].get(region_name, 0)
                    for s in history["snapshots"][-10:]
                ]
                current = region_counts.get(region_name, 0)
                if len(recent_counts) >= 3:
                    avg = sum(recent_counts[:-1]) / len(recent_counts[:-1])
                    if avg > 0 and current > avg * 2:
                        all_signals.append({
                            "type": "surge_anomaly",
                            "priority": "HIGH",
                            "title": f"SURGE: {region_name} has {current} aircraft vs {avg:.0f} average — unusual concentration",
                            "detail": f"Current: {current}, Historical avg: {avg:.1f}, Ratio: {current/avg:.1f}x",
                        })

        self._save_history(history)

        # Convert signals to RawItemModel
        for sig in all_signals:
            items.append(RawItemModel(
                title=sig["title"],
                content=sig["detail"],
                url="https://globe.adsbexchange.com/",
                source_name=self.name,
                external_id=f"adsb_{sig['type']}_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M')}",
                published_at=datetime.now(timezone.utc),
                fetched_at=datetime.now(timezone.utc),
            ))

        # Summary item
        region_summary = ", ".join(f"{name}: {count}" for name, count in region_counts.items() if count > 0)
        if region_summary:
            items.insert(0, RawItemModel(
                title=f"Military aircraft snapshot: {total_global} globally | {region_summary}",
                content=f"Global military aircraft tracked: {total_global}\nBy region: {region_summary}",
                url="https://api.adsb.lol/v2/mil",
                source_name=self.name,
                external_id=f"adsb_snapshot_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M')}",
                published_at=datetime.now(timezone.utc),
                fetched_at=datetime.now(timezone.utc),
            ))

        signal_count = len([s for s in all_signals if s["priority"] in ("CRITICAL", "HIGH")])
        print(f"  [ok] {self.name}: {total_global} mil aircraft globally, {sum(region_counts.values())} in watched regions, {signal_count} high-priority signals")
        return items[:self.max_items]
