"""Government and infrastructure intelligence collectors.

Covers US Congressional activity, airspace NOTAMs, State Dept travel
advisories, and OONI internet-shutdown detection.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from datetime import datetime, timedelta

import feedparser
import requests

from osint_monitor.collectors.base import BaseCollector
from osint_monitor.core.models import RawItemModel

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_REQUEST_TIMEOUT = 15

_DEFENSE_KEYWORDS = [
    "defense", "military", "sanctions", "arms", "nuclear",
    "intelligence", "foreign", "security",
    "iran", "china", "russia", "ukraine", "taiwan",
]


def _clean_html(text: str) -> str:
    return re.sub(r"<[^>]+>", "", text).strip()


# ---------------------------------------------------------------------------
# 1. CongressCollector – US Congressional Activity
# ---------------------------------------------------------------------------

class CongressCollector(BaseCollector):
    """Monitors US Congress for defense/foreign-affairs bills via congress.gov API."""

    API_URL = "https://api.congress.gov/v3/bill?format=json&limit=50&sort=updateDate+desc"

    STAGE_MAP = {
        "introduced": "introduced",
        "referred to committee": "committee",
        "reported by committee": "committee",
        "passed house": "floor",
        "passed senate": "floor",
        "resolving differences": "floor",
        "passed": "passed",
        "to president": "passed",
        "became public law": "signed",
        "signed by president": "signed",
        "vetoed": "passed",
    }

    def __init__(self, **kwargs):
        super().__init__(
            name="US Congress",
            source_type="government",
            url=self.API_URL,
            **kwargs,
        )
        self.api_key = os.environ.get("CONGRESS_API_KEY", "")

    # ------------------------------------------------------------------

    def collect(self) -> list[RawItemModel]:
        if not self.api_key:
            logger.warning(
                "CONGRESS_API_KEY not set – skipping CongressCollector. "
                "Get a free key at https://api.congress.gov/sign-up/"
            )
            return []

        try:
            resp = requests.get(
                self.API_URL,
                params={"api_key": self.api_key},
                timeout=_REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            logger.error("CongressCollector fetch error: %s", e)
            return []

        items: list[RawItemModel] = []
        for bill in data.get("bills", []):
            title = bill.get("title", "")
            if not self._matches_keywords(title):
                continue

            bill_type = bill.get("type", "")
            bill_number = bill.get("number", "")
            latest_action = bill.get("latestAction", {})
            action_text = latest_action.get("text", "")
            action_date = latest_action.get("actionDate", "")
            stage = self._detect_stage(action_text)

            sponsors_text = ""
            sponsor = bill.get("sponsors", [])
            if isinstance(sponsor, list):
                sponsors_text = ", ".join(
                    s.get("name", s.get("fullName", "")) for s in sponsor
                )

            committees_text = ""
            committees = bill.get("committees", {})
            if isinstance(committees, dict):
                committees_text = committees.get("url", "")
            elif isinstance(committees, list):
                committees_text = ", ".join(
                    c.get("name", "") for c in committees
                )

            content_parts = [
                f"Stage: {stage}",
                f"Latest action ({action_date}): {action_text}",
            ]
            if sponsors_text:
                content_parts.append(f"Sponsors: {sponsors_text}")
            if committees_text:
                content_parts.append(f"Committees: {committees_text}")

            pub_date = None
            if action_date:
                try:
                    pub_date = datetime.strptime(action_date, "%Y-%m-%d")
                except ValueError:
                    pass

            item_title = f"{bill_type} {bill_number}: {title}"
            items.append(RawItemModel(
                title=item_title[:300],
                content="\n".join(content_parts),
                url=bill.get("url", f"https://www.congress.gov/bill/{bill.get('congress', '')}"),
                published_at=pub_date,
                source_name=self.name,
                external_id=f"congress_{bill_type}{bill_number}_{bill.get('congress', '')}",
                fetched_at=datetime.utcnow(),
            ))

        items = items[: self.max_items]
        print(f"  [ok] {self.name}: {len(items)} items")
        return items

    # ------------------------------------------------------------------

    @staticmethod
    def _matches_keywords(title: str) -> bool:
        lower = title.lower()
        return any(kw in lower for kw in _DEFENSE_KEYWORDS)

    @classmethod
    def _detect_stage(cls, action_text: str) -> str:
        lower = action_text.lower()
        for phrase, stage in cls.STAGE_MAP.items():
            if phrase in lower:
                return stage
        return "introduced"


# ---------------------------------------------------------------------------
# 2. NOTAMCollector – Airspace Closure Monitoring
# ---------------------------------------------------------------------------

class NOTAMCollector(BaseCollector):
    """Monitors NOTAMs for TFRs and military airspace activations in
    geopolitically significant FIRs."""

    FAA_API_URL = "https://external-api.faa.gov/notamapi/v1/notams"

    # Flight Information Regions of interest
    FIRS_OF_INTEREST = {
        # Persian Gulf
        "OIIX": "Tehran FIR",
        "ORBB": "Baghdad FIR",
        "OMAE": "UAE FIR",
        # Ukraine
        "UKBV": "Kyiv FIR",
        "UKLV": "Lviv FIR",
        # Taiwan Strait
        "RCTP": "Taipei FIR",
        "ZSHA": "Shanghai FIR",
        # Pacific / Russia Far East
        "UEEE": "Russia Far East FIR",
    }

    GPS_KEYWORDS = ["GPS", "GNSS", "JAMMING", "INTERFERENCE"]

    def __init__(self, **kwargs):
        super().__init__(
            name="NOTAMs",
            source_type="aviation",
            url=self.FAA_API_URL,
            **kwargs,
        )
        self.api_key = os.environ.get("FAA_NOTAM_KEY", "")

    # ------------------------------------------------------------------

    def collect(self) -> list[RawItemModel]:
        if not self.api_key:
            logger.warning(
                "FAA_NOTAM_KEY not set – skipping NOTAMCollector. "
                "Register for a free key at https://api.faa.gov/"
            )
            return []

        items: list[RawItemModel] = []
        for fir_code, fir_name in self.FIRS_OF_INTEREST.items():
            try:
                fetched = self._fetch_notams_for_fir(fir_code, fir_name)
                items.extend(fetched)
            except Exception as e:
                logger.error("NOTAM fetch error for %s: %s", fir_code, e)

        items = items[: self.max_items]
        print(f"  [ok] {self.name}: {len(items)} items")
        return items

    def _fetch_notams_for_fir(
        self, fir_code: str, fir_name: str
    ) -> list[RawItemModel]:
        headers = {"client_id": self.api_key}
        params = {
            "domesticLocation": fir_code,
            "notamType": "N",
            "sortBy": "effectiveStartDate",
            "sortOrder": "DESC",
            "pageSize": 25,
        }

        resp = requests.get(
            self.FAA_API_URL,
            headers=headers,
            params=params,
            timeout=_REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()

        results: list[RawItemModel] = []
        for item in data.get("items", []):
            properties = item.get("properties", {})
            core = properties.get("coreNOTAMData", {}).get("notam", {})
            text = core.get("text", "")
            classification = core.get("classification", "")
            location = core.get("location", fir_code)
            notam_id = core.get("id", "")
            effective = core.get("effectiveStart", "")
            expire = core.get("effectiveEnd", "")

            is_tfr = "TFR" in text.upper() or classification.upper() in ("TFR", "FDC")
            is_military = any(
                kw in text.upper()
                for kw in ["MILITARY", "MIL EXERCISE", "LIVE FIRING", "RESTRICTED AREA"]
            )
            is_gps = any(kw in text.upper() for kw in self.GPS_KEYWORDS)

            if not (is_tfr or is_military or is_gps):
                continue

            notam_type = (
                "GPS/GNSS interference" if is_gps
                else "TFR" if is_tfr
                else "Military airspace"
            )

            pub_date = None
            if effective:
                try:
                    pub_date = datetime.fromisoformat(effective.replace("Z", "+00:00"))
                except ValueError:
                    pass

            content_parts = [
                f"Type: {notam_type}",
                f"FIR: {fir_code} ({fir_name})",
                f"Location: {location}",
                f"Effective: {effective} to {expire}",
                f"Full text: {text[:1000]}",
            ]
            if is_gps:
                content_parts.append("** GPS/GNSS interference – high significance **")

            results.append(RawItemModel(
                title=f"NOTAM: {notam_type} - {location} ({fir_code})",
                content="\n".join(content_parts),
                url=f"https://www.notams.faa.gov/dinsQueryWeb/queryRetrievalMapAction.do?reportType=Report&retrieveLocId={fir_code}",
                published_at=pub_date,
                source_name=self.name,
                external_id=f"notam_{notam_id}" if notam_id else f"notam_{hashlib.md5(f'{fir_code}_{location}_{effective}'.encode()).hexdigest()[:12]}",
                fetched_at=datetime.utcnow(),
            ))

        return results


# ---------------------------------------------------------------------------
# 3. TravelAdvisoryCollector – Embassy Security Levels
# ---------------------------------------------------------------------------

class TravelAdvisoryCollector(BaseCollector):
    """Monitors US State Department travel advisories via RSS."""

    # The main RSS URL is behind a CAPTCHA wall; use the TAsTWs.xml feed instead
    RSS_URL = "https://travel.state.gov/_res/rss/TAsTWs.xml"
    HTML_URL = "https://travel.state.gov/content/travel/en/traveladvisories/traveladvisories.html"

    LEVEL_LABELS = {
        1: "Exercise Normal Precautions",
        2: "Exercise Increased Caution",
        3: "Reconsider Travel",
        4: "Do Not Travel",
    }

    # Regex to pull advisory level from titles like "Country - Level 3: Reconsider Travel"
    _LEVEL_RE = re.compile(r"Level\s+(\d)", re.IGNORECASE)
    # Country typically comes before the dash
    _COUNTRY_RE = re.compile(r"^(.+?)\s*[-–—]")

    def __init__(self, **kwargs):
        super().__init__(
            name="Travel Advisories",
            source_type="government",
            url=self.RSS_URL,
            **kwargs,
        )

    # ------------------------------------------------------------------

    def collect(self) -> list[RawItemModel]:
        items = self._collect_rss()
        if not items:
            logger.info("RSS feed returned nothing; travel advisory collection empty.")
        return items

    def _collect_rss(self) -> list[RawItemModel]:
        try:
            feed = feedparser.parse(self.RSS_URL)
        except Exception as e:
            logger.error("TravelAdvisoryCollector RSS error: %s", e)
            return []

        items: list[RawItemModel] = []
        for entry in feed.entries[: self.max_items]:
            raw_title = entry.get("title", "")
            description = _clean_html(entry.get("description", "") or "")
            link = entry.get("link", "")

            level = self._extract_level(raw_title + " " + description)
            country = self._extract_country(raw_title)

            if level:
                display_title = f"Travel Advisory [{level}]: {country}"
            else:
                display_title = f"Travel Advisory: {country}"

            content_parts = [
                f"Level: {level} – {self.LEVEL_LABELS.get(level, 'Unknown')}" if level else "Level: unknown",
                f"Country: {country}",
                f"Details: {description[:2000]}",
            ]
            if level and level >= 3:
                content_parts.append("** HIGH SIGNAL – Level 3+ advisory **")

            pub_date = self._parse_date(entry)

            items.append(RawItemModel(
                title=display_title,
                content="\n".join(content_parts),
                url=link,
                published_at=pub_date,
                source_name=self.name,
                external_id=entry.get("id") or link,
                fetched_at=datetime.utcnow(),
            ))

        print(f"  [ok] {self.name}: {len(items)} items")
        return items

    # ------------------------------------------------------------------

    def _extract_level(self, text: str) -> int | None:
        m = self._LEVEL_RE.search(text)
        if m:
            val = int(m.group(1))
            if 1 <= val <= 4:
                return val
        return None

    def _extract_country(self, title: str) -> str:
        m = self._COUNTRY_RE.match(title)
        if m:
            return m.group(1).strip()
        return title.strip()

    @staticmethod
    def _parse_date(entry) -> datetime | None:
        for attr in ("published_parsed", "updated_parsed"):
            parsed = getattr(entry, attr, None)
            if parsed:
                try:
                    return datetime(*parsed[:6])
                except Exception:
                    pass
        return None


# ---------------------------------------------------------------------------
# 4. OONICollector – Internet Shutdown Detection
# ---------------------------------------------------------------------------

class OONICollector(BaseCollector):
    """Detects internet shutdowns and censorship events via OONI API."""

    INCIDENTS_URL = "https://api.ooni.io/api/v1/incidents/search"
    MEASUREMENTS_URL = "https://api.ooni.io/api/v1/measurements"

    # Countries of primary interest (ISO alpha-2)
    PRIORITY_COUNTRIES = {
        "IR", "RU", "CN", "UA", "IQ", "SY", "YE", "MM", "BY", "VE",
        "ET", "SD", "KP", "CU", "TW",
    }

    def __init__(self, **kwargs):
        super().__init__(
            name="OONI Internet Monitor",
            source_type="infrastructure",
            url=self.INCIDENTS_URL,
            **kwargs,
        )

    # ------------------------------------------------------------------

    def collect(self) -> list[RawItemModel]:
        items: list[RawItemModel] = []
        items.extend(self._collect_incidents())
        items.extend(self._collect_anomalous_measurements())
        items = items[: self.max_items]
        print(f"  [ok] {self.name}: {len(items)} items")
        return items

    def _collect_incidents(self) -> list[RawItemModel]:
        try:
            resp = requests.get(
                self.INCIDENTS_URL,
                params={"limit": 20, "status": "ongoing"},
                timeout=_REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            logger.error("OONI incidents fetch error: %s", e)
            return []

        items: list[RawItemModel] = []
        for inc in data.get("incidents", []):
            country = inc.get("CCs", inc.get("probe_cc", ""))
            if isinstance(country, list):
                country = ", ".join(country)
            title_text = inc.get("title", "Internet disruption")
            start_date = inc.get("start_time", "")
            short_desc = inc.get("short_description", "")
            event_type = inc.get("test_name", inc.get("event_type", ""))
            asns = inc.get("ASNs", [])
            if isinstance(asns, list):
                asns_text = ", ".join(str(a) for a in asns)
            else:
                asns_text = str(asns)

            pub_date = None
            if start_date:
                try:
                    pub_date = datetime.fromisoformat(start_date.replace("Z", "+00:00"))
                except ValueError:
                    pass

            content_parts = [
                f"Country: {country}",
                f"Start: {start_date}",
                f"Type: {event_type}",
                f"ASNs affected: {asns_text}" if asns_text else "",
                f"Description: {short_desc[:1500]}",
            ]

            is_priority = False
            if isinstance(country, str):
                for cc in self.PRIORITY_COUNTRIES:
                    if cc in country.upper():
                        is_priority = True
                        break
            if is_priority:
                content_parts.append("** Priority country – possible leading indicator of military/political action **")

            items.append(RawItemModel(
                title=f"Internet disruption: {country} - {title_text}",
                content="\n".join(p for p in content_parts if p),
                url=inc.get("explorer_url", "https://explorer.ooni.org/"),
                published_at=pub_date,
                source_name=self.name,
                external_id=f"ooni_inc_{inc.get('incident_id', inc.get('id', ''))}",
                fetched_at=datetime.utcnow(),
            ))

        return items

    def _collect_anomalous_measurements(self) -> list[RawItemModel]:
        since = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%d")
        try:
            resp = requests.get(
                self.MEASUREMENTS_URL,
                params={
                    "limit": 50,
                    "since": since,
                    "test_name": "web_connectivity",
                    "anomaly": "true",
                },
                timeout=_REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            logger.error("OONI measurements fetch error: %s", e)
            return []

        # Group by country to avoid flooding with individual measurements
        country_anomalies: dict[str, list[dict]] = {}
        for result in data.get("results", []):
            cc = result.get("probe_cc", "??")
            country_anomalies.setdefault(cc, []).append(result)

        items: list[RawItemModel] = []
        for cc, measurements in country_anomalies.items():
            if cc not in self.PRIORITY_COUNTRIES:
                continue

            count = len(measurements)
            sample = measurements[0]
            input_url = sample.get("input", "")
            test_date = sample.get("measurement_start_time", "")
            probe_asn = sample.get("probe_asn", "")

            pub_date = None
            if test_date:
                try:
                    pub_date = datetime.fromisoformat(test_date.replace("Z", "+00:00"))
                except ValueError:
                    pass

            blocked_urls = list({m.get("input", "") for m in measurements if m.get("input")})

            content_parts = [
                f"Country: {cc}",
                f"Anomalous measurements in last 7 days: {count}",
                f"Sample ASN: {probe_asn}",
                f"Blocked/anomalous URLs ({min(count, 10)} of {count}):",
            ]
            for u in blocked_urls[:10]:
                content_parts.append(f"  - {u}")
            content_parts.append(
                "** Internet censorship anomaly in priority country – "
                "possible indicator of military ops, protests, or election manipulation **"
            )

            items.append(RawItemModel(
                title=f"Internet disruption: {cc} - {count} anomalous web tests",
                content="\n".join(content_parts),
                url=f"https://explorer.ooni.org/search?probe_cc={cc}&test_name=web_connectivity&since={since}&only=anomalies",
                published_at=pub_date,
                source_name=self.name,
                external_id=f"ooni_anomaly_{cc}_{since}",
                fetched_at=datetime.utcnow(),
            ))

        return items
