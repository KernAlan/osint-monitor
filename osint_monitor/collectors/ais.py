"""AIS ship tracking collector for naval vessel monitoring."""

import hashlib
import logging
import re
from datetime import datetime

from osint_monitor.collectors.base import BaseCollector
from osint_monitor.core.models import RawItemModel

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Chokepoints of strategic interest
# ---------------------------------------------------------------------------
CHOKEPOINTS: dict[str, dict] = {
    "strait_of_hormuz": {
        "description": "Strait of Hormuz",
        "bbox": (25.5, 27.0, 55.5, 57.5),
        "significance": "~21% of global oil transit",
    },
    "bab_el_mandeb": {
        "description": "Bab el-Mandeb",
        "bbox": (12.3, 13.0, 43.0, 43.7),
        "significance": "Red Sea / Gulf of Aden gateway",
    },
    "strait_of_malacca": {
        "description": "Strait of Malacca",
        "bbox": (1.0, 4.0, 100.0, 104.5),
        "significance": "Primary Pacific-Indian Ocean shipping lane",
    },
    "suez_canal": {
        "description": "Suez Canal",
        "bbox": (29.8, 31.3, 32.2, 32.6),
        "significance": "Mediterranean-Red Sea transit",
    },
    "taiwan_strait": {
        "description": "Taiwan Strait",
        "bbox": (22.0, 26.0, 117.0, 121.0),
        "significance": "Strategic flashpoint, major shipping lane",
    },
}

# ---------------------------------------------------------------------------
# Vessel identification patterns
# ---------------------------------------------------------------------------

# Named warship prefixes: prefix -> navy
WARSHIP_PREFIXES: dict[str, str] = {
    "USS": "United States Navy",
    "HMS": "Royal Navy",
    "HMCS": "Royal Canadian Navy",
    "HMAS": "Royal Australian Navy",
    "INS": "Indian Navy",
    "KRI": "Indonesian Navy",
    "ROKS": "Republic of Korea Navy",
    "JS": "Japan Maritime Self-Defense Force",
    "TCG": "Turkish Navy",
    "FS": "French Navy",
    "FGS": "German Navy",
    "ITS": "Italian Navy",
    "ESPS": "Spanish Navy",
    "HNLMS": "Royal Netherlands Navy",
    "BRP": "Philippine Navy",
}

# Hull number patterns: type code -> description
HULL_TYPE_CODES: dict[str, str] = {
    "CVN": "Nuclear aircraft carrier",
    "CV": "Aircraft carrier",
    "DDG": "Guided-missile destroyer",
    "DD": "Destroyer",
    "CG": "Guided-missile cruiser",
    "FFG": "Guided-missile frigate",
    "FF": "Frigate",
    "LHD": "Amphibious assault ship",
    "LHA": "Amphibious assault ship",
    "LPD": "Amphibious transport dock",
    "LSD": "Dock landing ship",
    "SSN": "Nuclear attack submarine",
    "SSBN": "Nuclear ballistic missile submarine",
    "SSK": "Diesel-electric submarine",
    "SSGN": "Nuclear guided-missile submarine",
    "MCM": "Mine countermeasures ship",
    "PC": "Patrol coastal",
    "AS": "Submarine tender",
    "AOE": "Fast combat support ship",
    "T-AO": "Fleet oiler",
    "T-AKE": "Dry cargo/ammunition ship",
}

# Regex patterns (compiled at module level for performance)
_SHIP_NAME_PATTERN = re.compile(
    r"\b("
    + "|".join(re.escape(p) for p in WARSHIP_PREFIXES)
    + r")\s+([A-Z][A-Za-z\s\-']+?)(?:\s*\(|[,.\s]|$)",
    re.IGNORECASE,
)

_HULL_NUMBER_PATTERN = re.compile(
    r"\b("
    + "|".join(re.escape(h) for h in HULL_TYPE_CODES)
    + r")[\s\-]?(\d{1,4})\b",
    re.IGNORECASE,
)

_IMO_PATTERN = re.compile(r"\bIMO[\s\-]?(\d{7})\b", re.IGNORECASE)

_MMSI_PATTERN = re.compile(r"\bMMSI[\s:\-]?\s*(\d{9})\b", re.IGNORECASE)


def parse_vessel_mention(text: str) -> dict | None:
    """Extract vessel identification information from free text.

    Returns a dict with any identified vessel details, or None if nothing
    vessel-related was found.

    Possible keys: ship_name, ship_prefix, navy, hull_type, hull_number,
    hull_description, imo, mmsi.
    """
    result: dict = {}

    # Ship names (USS Enterprise, HMS Queen Elizabeth, etc.)
    ship_match = _SHIP_NAME_PATTERN.search(text)
    if ship_match:
        prefix = ship_match.group(1).upper()
        name = ship_match.group(2).strip().rstrip(",.")
        result["ship_prefix"] = prefix
        result["ship_name"] = f"{prefix} {name}"
        result["navy"] = WARSHIP_PREFIXES.get(prefix, "Unknown")

    # Hull numbers (CVN-78, DDG-51, SSN-774, etc.)
    hull_match = _HULL_NUMBER_PATTERN.search(text)
    if hull_match:
        hull_type = hull_match.group(1).upper()
        hull_num = hull_match.group(2)
        result["hull_type"] = hull_type
        result["hull_number"] = f"{hull_type}-{hull_num}"
        result["hull_description"] = HULL_TYPE_CODES.get(hull_type, "Unknown type")

    # IMO numbers (IMO 1234567)
    imo_match = _IMO_PATTERN.search(text)
    if imo_match:
        result["imo"] = imo_match.group(1)

    # MMSI numbers (9-digit)
    mmsi_match = _MMSI_PATTERN.search(text)
    if mmsi_match:
        result["mmsi"] = mmsi_match.group(1)

    return result if result else None


class AISCollector(BaseCollector):
    """AIS-based naval vessel monitoring collector.

    Since free real-time AIS APIs are limited, this collector is implemented
    as a stub that other collectors (RSS, Twitter, Telegram) can feed vessel
    mentions into via ``parse_vessel_mention``.  The ``collect()`` method
    currently returns an empty list; integrate with a paid AIS API provider
    (MarineTraffic, VesselFinder, etc.) to enable direct collection.
    """

    DEFAULT_VESSEL_TYPES = ["military", "tanker", "lng_carrier"]

    def __init__(
        self,
        region_name: str,
        vessel_types_of_interest: list[str] | None = None,
        **kwargs,
    ):
        self.region_name = region_name
        self.vessel_types_of_interest = (
            vessel_types_of_interest or self.DEFAULT_VESSEL_TYPES
        )

        super().__init__(
            name=f"ais_{region_name}",
            source_type="ais",
            url="",  # No default public API endpoint
            **kwargs,
        )

    def collect(self) -> list[RawItemModel]:
        """Collect vessel tracking items.

        Currently a stub -- returns an empty list.  To activate, integrate a
        paid AIS data provider or point ``self.url`` at a compatible API.
        """
        logger.info(
            "%s: AIS collector is a stub; configure an AIS API provider to "
            "enable direct collection.  Use parse_vessel_mention() to extract "
            "vessel data from other collectors' items.",
            self.name,
        )
        print(
            f"  [info] {self.name}: AIS requires API configuration -- "
            f"returning empty. Use parse_vessel_mention() for text extraction."
        )
        return []

    def process_text_for_vessels(self, text: str, source_url: str = "") -> RawItemModel | None:
        """Convenience wrapper: parse text and return a RawItemModel if a
        vessel mention is found."""
        vessel = parse_vessel_mention(text)
        if vessel is None:
            return None

        ship_label = vessel.get("ship_name") or vessel.get("hull_number") or "Unknown vessel"

        content_parts = []
        if "ship_name" in vessel:
            content_parts.append(f"Vessel: {vessel['ship_name']}")
        if "navy" in vessel:
            content_parts.append(f"Navy: {vessel['navy']}")
        if "hull_number" in vessel:
            content_parts.append(
                f"Hull: {vessel['hull_number']} ({vessel.get('hull_description', '')})"
            )
        if "imo" in vessel:
            content_parts.append(f"IMO: {vessel['imo']}")
        if "mmsi" in vessel:
            content_parts.append(f"MMSI: {vessel['mmsi']}")
        content_parts.append(f"\nSource text excerpt:\n{text[:500]}")

        return RawItemModel(
            title=f"Naval vessel mention: {ship_label} ({self.region_name})",
            content="\n".join(content_parts),
            url=source_url,
            published_at=datetime.utcnow(),
            source_name=self.name,
            external_id=f"ais_{hashlib.md5(f'{ship_label}_{source_url}'.encode()).hexdigest()[:12]}",
            fetched_at=datetime.utcnow(),
        )
