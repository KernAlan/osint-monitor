"""ADS-B flight tracking collector using OpenSky Network API."""

import logging
import time
from datetime import datetime

import requests

from osint_monitor.collectors.base import BaseCollector
from osint_monitor.core.models import RawItemModel

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Predefined regions of interest: (lat_min, lat_max, lon_min, lon_max)
# ---------------------------------------------------------------------------
REGIONS_OF_INTEREST: dict[str, tuple[float, float, float, float]] = {
    "persian_gulf": (23.0, 30.0, 47.0, 57.0),
    "black_sea": (41.0, 47.0, 27.0, 42.0),
    "south_china_sea": (5.0, 23.0, 105.0, 121.0),
    "taiwan_strait": (22.0, 26.0, 117.0, 121.0),
    "baltic": (53.0, 60.0, 13.0, 30.0),
}

# Military callsign prefixes and their descriptions
MILITARY_CALLSIGN_PREFIXES: dict[str, str] = {
    "RCH": "USAF cargo (AMC)",
    "DUKE": "USAF tanker",
    "EVIL": "USAF fighter",
    "FORTE": "RQ-4 Global Hawk",
    "JAKE": "P-8 Poseidon",
    "HOMER": "USAF E-3 Sentry AWACS",
    "NCHO": "USAF RC-135 Rivet Joint",
    "RRR": "Royal Air Force",
    "CNV": "French Air Force",
    "GAF": "German Air Force",
    "IAM": "Italian Air Force",
    "SUI": "Swiss Air Force",
    "PLF": "Polish Air Force",
    "SVF": "Swedish Air Force",
    "BAF": "Belgian Air Force",
    "NAF": "Royal Netherlands Air Force",
    "HRZ": "Croatian Air Force",
    "CASA": "Spanish Air Force (CASA transport)",
}

# OpenSky Network API endpoint
OPENSKY_API_URL = "https://opensky-network.org/api/states/all"

# Free tier: 1 request per 10 seconds
RATE_LIMIT_SECONDS = 10


class ADSBCollector(BaseCollector):
    """Collects military aircraft positions via OpenSky Network ADS-B data."""

    _last_request_time: float = 0.0

    def __init__(
        self,
        region_name: str,
        bbox: tuple[float, float, float, float] | None = None,
        military_only: bool = True,
        **kwargs,
    ):
        self.region_name = region_name
        self.military_only = military_only

        if bbox is not None:
            self.bbox = bbox
        elif region_name in REGIONS_OF_INTEREST:
            self.bbox = REGIONS_OF_INTEREST[region_name]
        else:
            raise ValueError(
                f"Unknown region {region_name!r}. Provide a bbox or use one of: "
                f"{', '.join(REGIONS_OF_INTEREST)}"
            )

        super().__init__(
            name=f"adsb_{region_name}",
            source_type="adsb",
            url=OPENSKY_API_URL,
            **kwargs,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _respect_rate_limit(self) -> None:
        """Block until the OpenSky free-tier rate limit window has passed."""
        elapsed = time.time() - ADSBCollector._last_request_time
        if elapsed < RATE_LIMIT_SECONDS:
            time.sleep(RATE_LIMIT_SECONDS - elapsed)
        ADSBCollector._last_request_time = time.time()

    def _fetch_states(self) -> list[list]:
        """Fetch aircraft state vectors from OpenSky for the configured bbox."""
        lat_min, lat_max, lon_min, lon_max = self.bbox
        params = {
            "lamin": lat_min,
            "lamax": lat_max,
            "lomin": lon_min,
            "lomax": lon_max,
        }

        self._respect_rate_limit()

        resp = requests.get(OPENSKY_API_URL, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        return data.get("states") or []

    @staticmethod
    def _is_military_callsign(callsign: str | None) -> str | None:
        """Return the description if callsign matches a military prefix, else None."""
        if not callsign:
            return None
        cs = callsign.strip().upper()
        for prefix, description in MILITARY_CALLSIGN_PREFIXES.items():
            if cs.startswith(prefix):
                return description
        return None

    @staticmethod
    def _parse_state(state: list) -> dict:
        """Parse an OpenSky state vector into a readable dict.

        OpenSky state vector indices:
        0  icao24          6  baro_altitude   12 on_ground
        1  callsign        7  true_track      13 velocity_source
        2  origin_country  8  velocity         14 category
        3  time_position   9  vertical_rate
        4  last_contact   10  sensors
        5  longitude      11  geo_altitude
        """
        return {
            "icao24": state[0],
            "callsign": (state[1] or "").strip(),
            "origin_country": state[2],
            "longitude": state[5],
            "latitude": state[6] if len(state) > 6 else None,
            "baro_altitude_m": state[7] if len(state) > 7 else None,
            "heading": state[10] if len(state) > 10 else None,
            "velocity_ms": state[9] if len(state) > 9 else None,
            "vertical_rate": state[11] if len(state) > 11 else None,
            "on_ground": state[8] if len(state) > 8 else None,
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def collect(self) -> list[RawItemModel]:
        """Collect military aircraft detections over the configured region."""
        items: list[RawItemModel] = []
        try:
            raw_states = self._fetch_states()
            logger.info(
                "%s: received %d total aircraft states", self.name, len(raw_states)
            )

            for state_vec in raw_states:
                parsed = self._parse_state(state_vec)
                callsign = parsed["callsign"]

                if self.military_only:
                    mil_desc = self._is_military_callsign(callsign)
                    if mil_desc is None:
                        continue
                else:
                    mil_desc = self._is_military_callsign(callsign) or "civilian"

                # Build human-readable content
                alt_ft = (
                    f"{int(parsed['baro_altitude_m'] * 3.281):,} ft"
                    if parsed["baro_altitude_m"] is not None
                    else "unknown altitude"
                )
                speed_kts = (
                    f"{int(parsed['velocity_ms'] * 1.944)} kts"
                    if parsed["velocity_ms"] is not None
                    else "unknown speed"
                )
                heading = (
                    f"{int(parsed['heading'])}\u00b0"
                    if parsed["heading"] is not None
                    else "unknown heading"
                )

                content = (
                    f"Military aircraft detected: {callsign} ({mil_desc})\n"
                    f"Origin country: {parsed['origin_country']}\n"
                    f"Altitude: {alt_ft}\n"
                    f"Speed: {speed_kts}\n"
                    f"Heading: {heading}\n"
                    f"Position: {parsed['latitude']}, {parsed['longitude']}\n"
                    f"ICAO24: {parsed['icao24']}"
                )

                adsbx_url = (
                    f"https://globe.adsbexchange.com/?icao={parsed['icao24']}"
                )

                items.append(
                    RawItemModel(
                        title=(
                            f"Military aircraft {callsign} detected over "
                            f"{self.region_name}"
                        ),
                        content=content,
                        url=adsbx_url,
                        published_at=datetime.utcnow(),
                        source_name=self.name,
                        external_id=f"adsb_{parsed['icao24']}_{int(time.time())}",
                        fetched_at=datetime.utcnow(),
                    )
                )

            items = items[: self.max_items]
            print(f"  [ok] {self.name}: {len(items)} military aircraft detected")

        except requests.exceptions.RequestException as exc:
            print(f"  [err] {self.name}: HTTP error - {exc}")
            logger.error("%s: request failed: %s", self.name, exc)
        except Exception as exc:
            print(f"  [err] {self.name}: {exc}")
            logger.error("%s: unexpected error: %s", self.name, exc, exc_info=True)

        return items

    @staticmethod
    def detect_unusual_activity(
        current_states: list, historical_avg: int
    ) -> bool:
        """Flag when the number of military aircraft significantly exceeds
        the historical average for a region.

        Uses a simple threshold of 2x the historical average, or at least
        5 aircraft above the average, whichever is greater.
        """
        mil_count = sum(
            1
            for s in current_states
            if ADSBCollector._is_military_callsign(
                (s[1] or "").strip() if isinstance(s, list) else None
            )
            is not None
        )

        excess_threshold = max(historical_avg * 2, historical_avg + 5)
        is_unusual = mil_count >= excess_threshold

        if is_unusual:
            logger.warning(
                "Unusual military air activity: %d aircraft vs historical avg %d",
                mil_count,
                historical_avg,
            )

        return is_unusual
