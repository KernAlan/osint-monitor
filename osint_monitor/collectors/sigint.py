"""Signal intelligence and economic intelligence collectors.

Covers: refugee/displacement flows (UNHCR), vulnerability intelligence (NVD),
nuclear safeguards (IAEA), currency/economic signals, satellite imagery
change detection (Sentinel Hub), and trade flow analysis (UN COMTRADE).
"""

import json
import logging
import os
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import feedparser
import requests

from osint_monitor.collectors.base import BaseCollector
from osint_monitor.core.models import RawItemModel

logger = logging.getLogger(__name__)

_TIMEOUT = 15

# ---------------------------------------------------------------------------
# 1. UNHCR - Refugee / Displacement Flows
# ---------------------------------------------------------------------------

class UNHCRCollector(BaseCollector):
    """Collect refugee and displacement data from the UNHCR Population API.

    Large-scale displacement surges (>10 000 people) serve as conflict
    escalation signals.  Free API, no key required.
    """

    # The /unrsd/ endpoint was removed; use /demographics/ which returns
    # refugee population by country-of-origin and country-of-asylum.
    BASE_URL = "https://api.unhcr.org/population/v1/demographics/"

    # Countries of origin relevant for conflict monitoring
    PRIORITY_ORIGINS = [
        "SYR", "UKR", "AFG", "SOM", "SSD", "MMR", "COD", "SDN",
        "YEM", "ERI", "IRQ", "PSE",
    ]

    def __init__(self, **kwargs):
        super().__init__(
            name="UNHCR Displacement",
            source_type="sigint_displacement",
            url=self.BASE_URL,
            **kwargs,
        )
        self.threshold = kwargs.get("threshold", 100_000)

    def collect(self) -> list[RawItemModel]:
        items: list[RawItemModel] = []

        # Query the most recent available year (UNHCR data lags ~1 year)
        for year_offset in range(0, 3):
            query_year = datetime.utcnow().year - year_offset
            params = {
                "limit": 100,
                "yearFrom": query_year,
                "yearTo": query_year,
            }

            try:
                resp = requests.get(self.BASE_URL, params=params, timeout=_TIMEOUT)
                resp.raise_for_status()
                data = resp.json()
            except Exception as exc:
                logger.debug("UNHCR fetch for year %d failed: %s", query_year, exc)
                continue

            records = data.get("items", [])
            if not records:
                continue

            # Aggregate by country-of-origin
            origin_totals: dict[str, dict] = {}
            for rec in records:
                coo_iso = rec.get("coo_iso", "")
                coa_name = rec.get("coa_name", "Unknown")
                total = int(rec.get("total", 0) or 0)
                if not coo_iso or total == 0:
                    continue

                if coo_iso not in origin_totals:
                    origin_totals[coo_iso] = {
                        "name": rec.get("coo_name", coo_iso),
                        "total": 0,
                        "destinations": [],
                    }
                origin_totals[coo_iso]["total"] += total
                origin_totals[coo_iso]["destinations"].append(
                    f"{coa_name}: {total:,}"
                )

            for coo_iso, info in sorted(
                origin_totals.items(),
                key=lambda x: x[1]["total"],
                reverse=True,
            ):
                if info["total"] < self.threshold:
                    continue

                title = f"Displacement: {info['total']:,} from {info['name']} ({query_year})"
                top_dest = "; ".join(info["destinations"][:5])
                content = (
                    f"Population: {info['total']:,}\n"
                    f"Origin: {info['name']} ({coo_iso})\n"
                    f"Year: {query_year}\n"
                    f"Top destinations: {top_dest}\n"
                    f"Source: UNHCR Population Statistics"
                )

                items.append(RawItemModel(
                    title=title,
                    content=content,
                    url="https://www.unhcr.org/refugee-statistics/",
                    published_at=datetime(query_year, 1, 1),
                    source_name=self.name,
                    external_id=f"unhcr-{coo_iso}-{query_year}-{info['total']}",
                    fetched_at=datetime.utcnow(),
                ))

                if len(items) >= self.max_items:
                    break

            if items:
                break  # Got data for this year, don't query older years

        print(f"  [ok] {self.name}: {len(items)} displacement records")
        return items


# ---------------------------------------------------------------------------
# 2. NVD - Vulnerability Intelligence
# ---------------------------------------------------------------------------

_ICS_KEYWORDS = [
    "SCADA", "ICS", "PLC",
    "Siemens", "Schneider Electric", "ABB", "Honeywell",
    "Rockwell", "Emerson",
    "power grid", "water treatment", "nuclear", "energy",
]

_ICS_PATTERN = re.compile("|".join(re.escape(k) for k in _ICS_KEYWORDS), re.IGNORECASE)


class NVDCollector(BaseCollector):
    """Collect critical-infrastructure-relevant CVEs from the NVD API.

    Filters for ICS/SCADA keywords and any CVSS >= 9.0.  Optionally uses
    NVD_API_KEY for higher rate limits.
    """

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self, **kwargs):
        super().__init__(
            name="NVD CVE Intelligence",
            source_type="sigint_vuln",
            url=self.BASE_URL,
            **kwargs,
        )
        self.api_key: str | None = os.environ.get("NVD_API_KEY")
        self.cvss_threshold = kwargs.get("cvss_threshold", 9.0)

    # -- helpers --

    @staticmethod
    def _extract_cvss(metrics: dict) -> float:
        """Return highest CVSS base score found in metrics block."""
        best = 0.0
        for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(version_key, [])
            for entry in entries:
                score = entry.get("cvssData", {}).get("baseScore", 0.0)
                if score > best:
                    best = score
        return best

    @staticmethod
    def _extract_cvss_vector(metrics: dict) -> str:
        for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(version_key, [])
            for entry in entries:
                vec = entry.get("cvssData", {}).get("vectorString")
                if vec:
                    return vec
        return ""

    @staticmethod
    def _extract_cwe(weaknesses: list) -> str:
        cwe_ids = []
        for w in weaknesses:
            for desc in w.get("description", []):
                val = desc.get("value", "")
                if val.startswith("CWE-"):
                    cwe_ids.append(val)
        return ", ".join(cwe_ids) if cwe_ids else "N/A"

    def _fetch_kev_ids(self) -> set[str]:
        """Fetch CISA Known Exploited Vulnerabilities catalog CVE IDs."""
        try:
            resp = requests.get(self.CISA_KEV_URL, timeout=_TIMEOUT)
            resp.raise_for_status()
            vulns = resp.json().get("vulnerabilities", [])
            return {v.get("cveID", "") for v in vulns}
        except Exception as exc:
            logger.warning("CISA KEV fetch failed (non-fatal): %s", exc)
            return set()

    # -- collect --

    def collect(self) -> list[RawItemModel]:
        items: list[RawItemModel] = []
        now = datetime.utcnow()
        # NVD API requires ISO 8601 with timezone offset and both start+end dates
        start = (now - timedelta(days=7)).strftime("%Y-%m-%dT00:00:00.000+00:00")
        end = now.strftime("%Y-%m-%dT23:59:59.999+00:00")
        params: dict[str, Any] = {
            "lastModStartDate": start,
            "lastModEndDate": end,
            "resultsPerPage": 50,
        }
        headers: dict[str, str] = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            resp = requests.get(
                self.BASE_URL, params=params, headers=headers, timeout=_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            logger.error("NVD fetch failed: %s", exc)
            print(f"  [err] {self.name}: {exc}")
            return items

        kev_ids = self._fetch_kev_ids()

        vulnerabilities = data.get("vulnerabilities", [])
        for vuln_wrapper in vulnerabilities:
            cve = vuln_wrapper.get("cve", {})
            cve_id = cve.get("id", "UNKNOWN")
            descriptions = cve.get("descriptions", [])
            desc_en = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                descriptions[0]["value"] if descriptions else "",
            )

            metrics = cve.get("metrics", {})
            score = self._extract_cvss(metrics)
            vector = self._extract_cvss_vector(metrics)
            cwe = self._extract_cwe(cve.get("weaknesses", []))

            is_ics = bool(_ICS_PATTERN.search(desc_en))
            is_critical = score >= self.cvss_threshold
            is_kev = cve_id in kev_ids

            if not (is_ics or is_critical):
                continue

            tags = []
            if is_ics:
                tags.append("ICS/SCADA")
            if is_critical:
                tags.append(f"CVSS {score}")
            if is_kev:
                tags.append("CISA-KEV ACTIVE EXPLOITATION")

            # Affected products (configurations)
            configs = cve.get("configurations", [])
            affected: list[str] = []
            for node_group in configs:
                for node in node_group.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        if match.get("vulnerable"):
                            affected.append(match.get("criteria", ""))

            title = f"{cve_id}: {desc_en[:100]} (CVSS: {score})"
            content = (
                f"Description: {desc_en}\n"
                f"CVSS Score: {score}\n"
                f"CVSS Vector: {vector}\n"
                f"CWE: {cwe}\n"
                f"Tags: {', '.join(tags)}\n"
                f"Affected Products: {'; '.join(affected[:10]) or 'N/A'}\n"
                f"In CISA KEV: {'YES - actively exploited' if is_kev else 'No'}"
            )

            items.append(RawItemModel(
                title=title,
                content=content,
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                published_at=_parse_iso(cve.get("published")),
                source_name=self.name,
                external_id=cve_id,
                fetched_at=datetime.utcnow(),
            ))

            if len(items) >= self.max_items:
                break

        print(f"  [ok] {self.name}: {len(items)} items")
        return items


# ---------------------------------------------------------------------------
# 3. IAEA - Nuclear Safeguards
# ---------------------------------------------------------------------------

_IAEA_KEYWORDS = re.compile(
    r"safeguards|verification|Iran|DPRK|enrichment|nuclear material|inspection",
    re.IGNORECASE,
)

_COUNTRY_TAGS = {
    "Iran": "IRN",
    "DPRK": "PRK",
    "North Korea": "PRK",
    "Syria": "SYR",
    "Libya": "LBY",
    "Ukraine": "UKR",
    "Russia": "RUS",
    "China": "CHN",
    "Pakistan": "PAK",
    "India": "IND",
}


class IAEACollector(BaseCollector):
    """Collect nuclear safeguards news from IAEA RSS feed.

    Primary source for nuclear proliferation assessment.  Filters for
    safeguards/verification keywords and tags items mentioning specific
    countries for indications & warning (I&W) cross-reference.
    """

    FEED_URL = "https://www.iaea.org/feeds/topnews"

    def __init__(self, **kwargs):
        super().__init__(
            name="IAEA Nuclear Safeguards",
            source_type="sigint_nuclear",
            url=self.FEED_URL,
            **kwargs,
        )

    @staticmethod
    def _clean_html(text: str) -> str:
        return re.sub(r"<[^>]+>", "", text).strip()

    def collect(self) -> list[RawItemModel]:
        items: list[RawItemModel] = []
        try:
            feed = feedparser.parse(self.FEED_URL)
        except Exception as exc:
            logger.error("IAEA RSS fetch failed: %s", exc)
            print(f"  [err] {self.name}: {exc}")
            return items

        for entry in feed.entries[: self.max_items * 2]:
            title = entry.get("title", "")
            description = self._clean_html(
                getattr(entry, "description", "") or ""
            )
            combined = f"{title} {description}"

            if not _IAEA_KEYWORDS.search(combined):
                continue

            # Tag countries mentioned
            country_tags: list[str] = []
            for country, iso in _COUNTRY_TAGS.items():
                if country.lower() in combined.lower():
                    country_tags.append(f"{country} ({iso})")

            pub_date = self._parse_feed_date(entry)

            content = description
            if country_tags:
                content += f"\n\nCountry tags for I&W: {', '.join(country_tags)}"

            items.append(RawItemModel(
                title=title,
                content=content[:5000],
                url=entry.get("link", ""),
                published_at=pub_date,
                source_name=self.name,
                external_id=entry.get("id") or entry.get("link", ""),
                fetched_at=datetime.utcnow(),
            ))

            if len(items) >= self.max_items:
                break

        print(f"  [ok] {self.name}: {len(items)} items")
        return items

    @staticmethod
    def _parse_feed_date(entry) -> datetime | None:
        for attr in ("published_parsed", "updated_parsed"):
            parsed = getattr(entry, attr, None)
            if parsed:
                try:
                    return datetime(*parsed[:6])
                except Exception:
                    pass
        return None


# ---------------------------------------------------------------------------
# 4. Currency / Economic Signal Intelligence
# ---------------------------------------------------------------------------

_WATCHLIST_CURRENCIES = [
    "RUB", "IRR", "TRY", "CNY", "KPW", "UAH", "ILS", "SAR", "TWD",
]

_CACHE_DIR = Path(__file__).resolve().parents[2] / "data"
_CURRENCY_CACHE = _CACHE_DIR / "currency_cache.json"


class CurrencyCollector(BaseCollector):
    """Monitor exchange-rate moves for watchlist currencies.

    Uses the free open.er-api.com endpoint.  Maintains a rolling JSON cache
    of previous rates at ``data/currency_cache.json`` to compute 30-day
    moving averages and flag significant moves (>5 % notable, >10 % significant,
    >20 % crisis).
    """

    BASE_URL = "https://open.er-api.com/v6/latest/USD"

    def __init__(self, **kwargs):
        super().__init__(
            name="Currency SIGINT",
            source_type="sigint_econ",
            url=self.BASE_URL,
            **kwargs,
        )
        self.watchlist: list[str] = kwargs.get("watchlist", _WATCHLIST_CURRENCIES)

    # -- cache helpers --

    @staticmethod
    def _load_cache() -> dict:
        if _CURRENCY_CACHE.exists():
            try:
                return json.loads(_CURRENCY_CACHE.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {}

    @staticmethod
    def _save_cache(cache: dict) -> None:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _CURRENCY_CACHE.write_text(
            json.dumps(cache, indent=2), encoding="utf-8",
        )

    @staticmethod
    def _avg(values: list[float]) -> float:
        return sum(values) / len(values) if values else 0.0

    # -- collect --

    def collect(self) -> list[RawItemModel]:
        items: list[RawItemModel] = []

        try:
            resp = requests.get(self.BASE_URL, timeout=_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            logger.error("Currency API fetch failed: %s", exc)
            print(f"  [err] {self.name}: {exc}")
            return items

        rates: dict[str, float] = data.get("rates", {})
        today = datetime.utcnow().strftime("%Y-%m-%d")

        cache = self._load_cache()

        for ccy in self.watchlist:
            current_rate = rates.get(ccy)
            if current_rate is None:
                continue

            # Update rolling history
            history: list[dict] = cache.get(ccy, [])
            history.append({"date": today, "rate": current_rate})
            # Keep last 30 entries
            history = history[-30:]
            cache[ccy] = history

            historical_rates = [h["rate"] for h in history[:-1]]
            if not historical_rates:
                continue

            avg_30d = self._avg(historical_rates)
            if avg_30d == 0:
                continue

            pct_change = ((current_rate - avg_30d) / avg_30d) * 100
            abs_change = abs(pct_change)

            if abs_change < 5.0:
                continue

            direction = "weakened" if pct_change > 0 else "strengthened"
            # For USD-quoted pairs, higher number = weaker local currency

            if abs_change >= 20:
                severity = "CRISIS"
            elif abs_change >= 10:
                severity = "SIGNIFICANT"
            else:
                severity = "NOTABLE"

            title = f"Currency alert: {ccy} {direction} {abs_change:.1f}% vs USD [{severity}]"
            content = (
                f"Currency: {ccy}\n"
                f"Current rate: {current_rate:.4f} per USD\n"
                f"30-day average: {avg_30d:.4f} per USD\n"
                f"Change: {pct_change:+.2f}%\n"
                f"Direction: {direction} ({severity})\n"
                f"Data points in window: {len(historical_rates)}\n"
                f"Date: {today}"
            )

            items.append(RawItemModel(
                title=title,
                content=content,
                url=self.BASE_URL,
                published_at=datetime.utcnow(),
                source_name=self.name,
                external_id=f"ccy-{ccy}-{today}",
                fetched_at=datetime.utcnow(),
            ))

        self._save_cache(cache)
        print(f"  [ok] {self.name}: {len(items)} alerts")
        return items


# ---------------------------------------------------------------------------
# 5. Sentinel - Satellite Imagery Change Detection
# ---------------------------------------------------------------------------

_AREAS_OF_INTEREST: list[dict[str, Any]] = [
    {
        "name": "Natanz Nuclear Facility, Iran",
        "lat": 33.72,
        "lon": 51.72,
        "radius_km": 2,
    },
    {
        "name": "Zaporizhzhia NPP, Ukraine",
        "lat": 47.51,
        "lon": 34.59,
        "radius_km": 5,
    },
    {
        "name": "Punggye-ri Test Site, DPRK",
        "lat": 41.28,
        "lon": 129.08,
        "radius_km": 3,
    },
    {
        "name": "Ras Tanura Oil Terminal, Saudi Arabia",
        "lat": 26.64,
        "lon": 50.15,
        "radius_km": 3,
    },
    {
        "name": "Yokosuka Naval Base, Japan",
        "lat": 35.28,
        "lon": 139.67,
        "radius_km": 3,
    },
]


class SentinelCollector(BaseCollector):
    """Check Sentinel Hub for new satellite imagery over predefined AOIs.

    Authentication: set ``SENTINEL_CLIENT_ID`` and ``SENTINEL_CLIENT_SECRET``
    (from Copernicus Data Space OAuth).  The collector auto-refreshes the
    access token on each collection run.  Legacy ``SENTINEL_HUB_TOKEN`` is
    also accepted as a static fallback.

    Note: actual change detection requires image analysis (see
    ``processors/imint.py``).  This collector only flags new imagery
    availability.
    """

    # Copernicus Data Space catalog (NOT the old services.sentinel-hub.com)
    CATALOG_URL = "https://sh.dataspace.copernicus.eu/api/v1/catalog/1.0.0/search"
    TOKEN_URL = "https://identity.dataspace.copernicus.eu/auth/realms/CDSE/protocol/openid-connect/token"

    def __init__(self, **kwargs):
        super().__init__(
            name="Sentinel Imagery",
            source_type="sigint_imint",
            url=self.CATALOG_URL,
            **kwargs,
        )
        self.client_id = os.environ.get("SENTINEL_CLIENT_ID", "")
        self.client_secret = os.environ.get("SENTINEL_CLIENT_SECRET", "")
        self.token: str | None = os.environ.get("SENTINEL_HUB_TOKEN")
        self.aois: list[dict[str, Any]] = kwargs.get("aois", _AREAS_OF_INTEREST)

    def _refresh_token(self) -> str | None:
        """Exchange client credentials for an access token."""
        if not self.client_id or not self.client_secret:
            return None
        try:
            resp = requests.post(self.TOKEN_URL, data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            }, timeout=15)
            resp.raise_for_status()
            token = resp.json().get("access_token")
            if token:
                logger.info("Sentinel OAuth token refreshed")
            return token
        except Exception as exc:
            logger.warning("Sentinel token refresh failed: %s", exc)
            return None

    @staticmethod
    def _bbox(lat: float, lon: float, radius_km: float) -> list[float]:
        """Approximate bounding box from centre + radius (degrees)."""
        # ~111 km per degree latitude, longitude varies with cos(lat)
        import math

        dlat = radius_km / 111.0
        dlon = radius_km / (111.0 * math.cos(math.radians(lat)))
        return [lon - dlon, lat - dlat, lon + dlon, lat + dlat]

    def collect(self) -> list[RawItemModel]:
        items: list[RawItemModel] = []

        # Auto-refresh token from client credentials if available
        if self.client_id and self.client_secret:
            refreshed = self._refresh_token()
            if refreshed:
                self.token = refreshed

        if not self.token:
            msg = (
                "Sentinel credentials not set. Set SENTINEL_CLIENT_ID and "
                "SENTINEL_CLIENT_SECRET from Copernicus Data Space OAuth."
            )
            logger.warning(msg)
            print(f"  [skip] {self.name}: no credentials configured")
            return items

        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

        date_to = datetime.utcnow()
        date_from = date_to - timedelta(days=7)
        time_range = (
            f"{date_from.strftime('%Y-%m-%dT00:00:00Z')}/"
            f"{date_to.strftime('%Y-%m-%dT23:59:59Z')}"
        )

        for aoi in self.aois:
            bbox = self._bbox(aoi["lat"], aoi["lon"], aoi["radius_km"])

            payload = {
                "bbox": bbox,
                "datetime": time_range,
                "collections": ["sentinel-2-l2a"],
                "limit": 5,
            }

            try:
                resp = requests.post(
                    self.CATALOG_URL,
                    json=payload,
                    headers=headers,
                    timeout=_TIMEOUT,
                )
                resp.raise_for_status()
                data = resp.json()
            except Exception as exc:
                logger.warning("Sentinel query failed for %s: %s", aoi["name"], exc)
                continue

            features = data.get("features", [])
            for feat in features:
                props = feat.get("properties", {})
                acq_date = props.get("datetime", "unknown")
                cloud = props.get("eo:cloud_cover", "N/A")

                title = f"New satellite imagery: {aoi['name']} ({acq_date[:10]})"
                content = (
                    f"AOI: {aoi['name']}\n"
                    f"Centre: ({aoi['lat']}, {aoi['lon']})\n"
                    f"Radius: {aoi['radius_km']} km\n"
                    f"Acquisition date: {acq_date}\n"
                    f"Cloud cover: {cloud}%\n"
                    f"Collection: sentinel-2-l2a\n"
                    f"Note: image requires analysis via processors/imint.py"
                )

                items.append(RawItemModel(
                    title=title,
                    content=content,
                    url=self.CATALOG_URL,
                    published_at=_parse_iso(acq_date),
                    source_name=self.name,
                    external_id=feat.get("id", f"sentinel-{aoi['name']}-{acq_date}"),
                    fetched_at=datetime.utcnow(),
                ))

            if len(items) >= self.max_items:
                break

        print(f"  [ok] {self.name}: {len(items)} new images across {len(self.aois)} AOIs")
        return items


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _parse_iso(value: str | None) -> datetime | None:
    """Best-effort ISO-8601 parse."""
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value.rstrip("Z"), fmt)
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# UN COMTRADE — trade flow analysis for sanctions evasion / dual-use procurement
# ---------------------------------------------------------------------------

# HS commodity codes of intelligence interest
_DUAL_USE_HS_CODES: dict[str, str] = {
    "8401": "Nuclear reactors, fuel elements",
    "8471": "Computing machinery",
    "8525": "Radar, radio navigation",
    "8526": "Radar apparatus",
    "8541": "Semiconductor devices",
    "8542": "Integrated circuits",
    "2844": "Radioactive elements/isotopes",
    "2845": "Heavy water / deuterium",
    "3602": "Prepared explosives",
    "3603": "Detonators / fuses",
    "8802": "Aircraft / spacecraft",
    "8906": "Warships",
    "9013": "Lasers / optical devices",
    "9014": "Direction finding / navigation",
    "9305": "Arms / ammunition parts",
    "8710": "Tanks / armored vehicles",
}

# Countries under sanctions or watchlist (ISO-3)
_WATCHLIST_COUNTRIES = {
    "IRN", "RUS", "PRK", "SYR", "CUB", "VEN", "MMR", "BLR", "CHN",
}


class COMTRADECollector(BaseCollector):
    """UN COMTRADE trade flow collector for sanctions evasion detection.

    API: https://comtradeapi.un.org/data/v1/get/C/A/HS
    Requires: COMTRADE_API_KEY env var (free, apply at comtradeapi.un.org).
    """

    def __init__(self, **kwargs):
        self.api_key = os.environ.get("COMTRADE_API_KEY", "")
        super().__init__(
            name="UN COMTRADE",
            source_type="sigint_trade",
            url="https://comtradeapi.un.org/data/v1/get/C/A/HS",
            **kwargs,
        )

    def collect(self) -> list[RawItemModel]:
        if not self.api_key:
            logger.debug(
                "COMTRADE_API_KEY not set. Apply free at https://comtradeapi.un.org/ "
                "to enable trade flow monitoring."
            )
            return []

        items: list[RawItemModel] = []
        now = datetime.utcnow()
        # COMTRADE data has ~2 month lag; query most recent available year
        year = now.year - 1

        for hs_code, description in _DUAL_USE_HS_CODES.items():
            try:
                batch = self._query_hs_code(hs_code, description, year)
                items.extend(batch)
            except Exception as exc:
                logger.warning("COMTRADE query failed for HS %s: %s", hs_code, exc)

        print(f"  [ok] {self.name}: {len(items)} trade anomalies")
        return items[: self.max_items]

    def _query_hs_code(
        self, hs_code: str, description: str, year: int
    ) -> list[RawItemModel]:
        """Query a single HS code and flag suspicious flows."""
        params = {
            "subscription-key": self.api_key,
            "cmdCode": hs_code,
            "flowCode": "M",  # imports
            "period": str(year),
            "reporterCode": ",".join(
                _iso3_to_comtrade.get(c, "") for c in _WATCHLIST_COUNTRIES
                if _iso3_to_comtrade.get(c)
            ),
            "maxRecords": "500",
        }

        resp = requests.get(self.url, params=params, timeout=30, headers=_HEADERS)
        resp.raise_for_status()
        data = resp.json()

        items: list[RawItemModel] = []
        for record in data.get("data", []):
            reporter = record.get("reporterDesc", "Unknown")
            partner = record.get("partnerDesc", "Unknown")
            value_usd = record.get("primaryValue", 0)
            qty = record.get("qty", 0)
            flow = record.get("flowDesc", "Import")

            # Flag: sanctioned country importing dual-use goods
            if value_usd and value_usd > 1_000_000:
                items.append(RawItemModel(
                    title=(
                        f"Trade flow: {reporter} imported ${value_usd:,.0f} of "
                        f"{description} (HS {hs_code}) from {partner}"
                    ),
                    content=(
                        f"Commodity: {description} (HS {hs_code})\n"
                        f"Reporter: {reporter}\nPartner: {partner}\n"
                        f"Flow: {flow}\nValue: ${value_usd:,.0f}\n"
                        f"Quantity: {qty}\nPeriod: {record.get('period', year)}"
                    ),
                    url=f"https://comtradeplus.un.org/TradeFlow?Frequency=A&Flows=M&CommodityCodes={hs_code}",
                    source_name=self.name,
                    external_id=f"comtrade_{hs_code}_{reporter}_{partner}_{year}",
                    fetched_at=datetime.utcnow(),
                ))

        return items


# ISO-3 to COMTRADE numeric reporter codes (subset)
_iso3_to_comtrade: dict[str, str] = {
    "IRN": "364", "RUS": "643", "PRK": "408", "SYR": "760",
    "CUB": "192", "VEN": "862", "MMR": "104", "BLR": "112", "CHN": "156",
}

_HEADERS = {"User-Agent": "OSINT-Monitor/2.0 (research)"}
