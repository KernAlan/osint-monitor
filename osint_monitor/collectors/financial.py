"""Financial intelligence collectors: commodity prices, defense stocks, SEC filings.

Financial signals move before narratives — traders have sources, and money
doesn't lie. These collectors detect pre-narrative market movements that
correlate with geopolitical events.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests

from osint_monitor.collectors.base import BaseCollector
from osint_monitor.core.models import RawItemModel

logger = logging.getLogger(__name__)

_TIMEOUT = 15
_DATA_DIR = Path(__file__).parent.parent.parent / "data"


# ───────────────────────────────────────────────────────────────────────────
# 1. Commodity Price Monitor — oil, gold, defense-relevant commodities
# ───────────────────────────────────────────────────────────────────────────

class CommodityMonitor(BaseCollector):
    """Track commodity price movements that signal geopolitical events.

    Oil price spikes precede conflict reporting. Gold spikes signal
    risk-off sentiment. Uranium movements correlate with nuclear tensions.

    Uses Yahoo Finance v8 API (free, no key).
    """

    YAHOO_QUOTE_URL = "https://query1.finance.yahoo.com/v8/finance/chart/{symbol}"

    # Commodities to watch with significance thresholds
    COMMODITIES: dict[str, dict[str, Any]] = {
        "CL=F": {
            "name": "WTI Crude Oil",
            "significance": "Energy supply disruption, Gulf conflict intensity",
            "spike_pct": 3.0,
            "crash_pct": -3.0,
        },
        "BZ=F": {
            "name": "Brent Crude Oil",
            "significance": "International oil benchmark, Hormuz transit risk",
            "spike_pct": 3.0,
            "crash_pct": -3.0,
        },
        "GC=F": {
            "name": "Gold",
            "significance": "Risk-off sentiment, geopolitical uncertainty",
            "spike_pct": 2.0,
            "crash_pct": -2.0,
        },
        "NG=F": {
            "name": "Natural Gas",
            "significance": "Energy infrastructure targeting, pipeline disruption",
            "spike_pct": 5.0,
            "crash_pct": -5.0,
        },
        "UX=F": {
            "name": "Uranium (UxC)",
            "significance": "Nuclear escalation sentiment",
            "spike_pct": 3.0,
            "crash_pct": -3.0,
        },
    }

    def __init__(self, **kwargs):
        super().__init__(
            name="Commodity SIGINT",
            source_type="financial",
            url="https://finance.yahoo.com",
            **kwargs,
        )
        self._cache_path = _DATA_DIR / "commodity_cache.json"

    def _load_cache(self) -> dict:
        try:
            if self._cache_path.exists():
                return json.loads(self._cache_path.read_text())
        except Exception:
            pass
        return {}

    def _save_cache(self, cache: dict) -> None:
        try:
            _DATA_DIR.mkdir(parents=True, exist_ok=True)
            self._cache_path.write_text(json.dumps(cache, indent=2))
        except Exception as exc:
            logger.debug("Cache save failed: %s", exc)

    def _fetch_quote(self, symbol: str) -> dict | None:
        """Fetch current price and recent history from Yahoo Finance."""
        try:
            resp = requests.get(
                self.YAHOO_QUOTE_URL.format(symbol=symbol),
                params={"interval": "1d", "range": "5d"},
                headers={"User-Agent": "osint-monitor/1.0"},
                timeout=_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()

            result = data.get("chart", {}).get("result", [])
            if not result:
                return None

            meta = result[0].get("meta", {})
            indicators = result[0].get("indicators", {}).get("quote", [{}])[0]
            closes = indicators.get("close", [])
            timestamps = result[0].get("timestamp", [])

            current = meta.get("regularMarketPrice", 0)
            prev_close = meta.get("previousClose", meta.get("chartPreviousClose", 0))

            # Build price history
            history: list[dict] = []
            for ts, close in zip(timestamps, closes):
                if close is not None:
                    history.append({
                        "date": datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d"),
                        "close": round(close, 2),
                    })

            return {
                "current": round(current, 2),
                "prev_close": round(prev_close, 2),
                "change_pct": round((current - prev_close) / prev_close * 100, 2) if prev_close else 0,
                "currency": meta.get("currency", "USD"),
                "history": history,
            }
        except Exception as exc:
            logger.debug("Yahoo Finance fetch failed for %s: %s", symbol, exc)
            return None

    def collect(self) -> list[RawItemModel]:
        items: list[RawItemModel] = []
        cache = self._load_cache()
        alerts = 0

        for symbol, info in self.COMMODITIES.items():
            quote = self._fetch_quote(symbol)
            if quote is None:
                continue

            change_pct = quote["change_pct"]
            is_spike = change_pct >= info["spike_pct"]
            is_crash = change_pct <= info["crash_pct"]

            # Check multi-day trend
            history = quote.get("history", [])
            five_day_change = 0.0
            if len(history) >= 2:
                first = history[0]["close"]
                last = history[-1]["close"]
                five_day_change = round((last - first) / first * 100, 2) if first else 0

            # Update cache
            cache[symbol] = {
                "price": quote["current"],
                "change_pct": change_pct,
                "five_day_pct": five_day_change,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            if is_spike or is_crash or abs(five_day_change) > info["spike_pct"] * 2:
                alerts += 1
                direction = "SPIKE" if change_pct > 0 else "DROP"
                title = (
                    f"COMMODITY {direction}: {info['name']} "
                    f"{'+'if change_pct>0 else ''}{change_pct}% "
                    f"(${quote['current']})"
                )
            else:
                title = (
                    f"Commodity: {info['name']} "
                    f"{'+'if change_pct>0 else ''}{change_pct}% "
                    f"(${quote['current']})"
                )

            history_str = " | ".join(f"{h['date']}: ${h['close']}" for h in history[-5:])
            content = (
                f"Commodity: {info['name']} ({symbol})\n"
                f"Current: ${quote['current']} {quote['currency']}\n"
                f"Daily change: {'+' if change_pct>0 else ''}{change_pct}%\n"
                f"5-day change: {'+' if five_day_change>0 else ''}{five_day_change}%\n"
                f"Previous close: ${quote['prev_close']}\n"
                f"Significance: {info['significance']}\n"
                f"History: {history_str}"
            )

            # Only emit alerts or significant movements
            if is_spike or is_crash or abs(five_day_change) > info["spike_pct"]:
                items.append(RawItemModel(
                    title=title,
                    content=content,
                    url=f"https://finance.yahoo.com/quote/{symbol}",
                    source_name=self.name,
                    external_id=f"commodity_{symbol}_{datetime.now(timezone.utc).strftime('%Y%m%d')}",
                    published_at=datetime.now(timezone.utc),
                    fetched_at=datetime.now(timezone.utc),
                ))

        self._save_cache(cache)
        print(f"  [ok] {self.name}: {len(self.COMMODITIES)} commodities checked, {alerts} alerts")
        return items[:self.max_items]


# ───────────────────────────────────────────────────────────────────────────
# 2. Defense Stock Monitor — procurement and mobilization signals
# ───────────────────────────────────────────────────────────────────────────

class DefenseStockMonitor(BaseCollector):
    """Track defense contractor stock movements as leading indicators.

    Defense stocks move before contract announcements because institutional
    investors have sources. Unusual moves correlate with procurement
    decisions, conflict escalation, and arms deals.
    """

    YAHOO_QUOTE_URL = "https://query1.finance.yahoo.com/v8/finance/chart/{symbol}"

    DEFENSE_TICKERS: dict[str, dict[str, str]] = {
        "LMT": {"name": "Lockheed Martin", "focus": "F-35, missiles, missile defense"},
        "RTX": {"name": "RTX (Raytheon)", "focus": "Patriot, air defense, missiles"},
        "NOC": {"name": "Northrop Grumman", "focus": "B-21, drones, cyber"},
        "GD": {"name": "General Dynamics", "focus": "Submarines, land systems, IT"},
        "BA": {"name": "Boeing", "focus": "F-15, tankers, bombers"},
        "LHX": {"name": "L3Harris", "focus": "ISR, EW, communications"},
        "HII": {"name": "Huntington Ingalls", "focus": "Carriers, submarines, shipbuilding"},
        "KTOS": {"name": "Kratos Defense", "focus": "Drones, target systems"},
        "AVAV": {"name": "AeroVironment", "focus": "Small UAS, Switchblade"},
        "PLTR": {"name": "Palantir", "focus": "Intelligence analytics, AI"},
    }

    SPIKE_THRESHOLD = 3.0  # percent daily change to flag

    def __init__(self, **kwargs):
        super().__init__(
            name="Defense Stock Monitor",
            source_type="financial",
            url="https://finance.yahoo.com",
            **kwargs,
        )

    def _fetch_quote(self, symbol: str) -> dict | None:
        try:
            resp = requests.get(
                self.YAHOO_QUOTE_URL.format(symbol=symbol),
                params={"interval": "1d", "range": "5d"},
                headers={"User-Agent": "osint-monitor/1.0"},
                timeout=_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
            result = data.get("chart", {}).get("result", [])
            if not result:
                return None

            meta = result[0].get("meta", {})
            current = meta.get("regularMarketPrice", 0)
            prev_close = meta.get("previousClose", meta.get("chartPreviousClose", 0))

            return {
                "current": round(current, 2),
                "prev_close": round(prev_close, 2),
                "change_pct": round((current - prev_close) / prev_close * 100, 2) if prev_close else 0,
            }
        except Exception as exc:
            logger.debug("Yahoo Finance failed for %s: %s", symbol, exc)
            return None

    def collect(self) -> list[RawItemModel]:
        items: list[RawItemModel] = []
        movers: list[tuple[str, float]] = []

        for symbol, info in self.DEFENSE_TICKERS.items():
            quote = self._fetch_quote(symbol)
            if quote is None:
                continue

            change = quote["change_pct"]
            if abs(change) >= self.SPIKE_THRESHOLD:
                movers.append((symbol, change))

                direction = "SURGE" if change > 0 else "DROP"
                title = (
                    f"DEFENSE STOCK {direction}: {info['name']} ({symbol}) "
                    f"{'+' if change>0 else ''}{change}% (${quote['current']})"
                )
                content = (
                    f"Company: {info['name']} ({symbol})\n"
                    f"Focus: {info['focus']}\n"
                    f"Current: ${quote['current']}\n"
                    f"Change: {'+' if change>0 else ''}{change}%\n"
                    f"Previous close: ${quote['prev_close']}"
                )

                items.append(RawItemModel(
                    title=title,
                    content=content,
                    url=f"https://finance.yahoo.com/quote/{symbol}",
                    source_name=self.name,
                    external_id=f"defense_{symbol}_{datetime.now(timezone.utc).strftime('%Y%m%d')}",
                    published_at=datetime.now(timezone.utc),
                    fetched_at=datetime.now(timezone.utc),
                ))

        # Sector-wide movement detection
        if len(movers) >= 3:
            avg_move = sum(m[1] for m in movers) / len(movers)
            if avg_move > 0:
                sector_title = f"DEFENSE SECTOR SURGE: {len(movers)} stocks moving +{avg_move:.1f}% avg"
            else:
                sector_title = f"DEFENSE SECTOR DROP: {len(movers)} stocks moving {avg_move:.1f}% avg"

            items.insert(0, RawItemModel(
                title=sector_title,
                content=f"Movers: {', '.join(f'{s} {c:+.1f}%' for s, c in movers)}",
                url="https://finance.yahoo.com",
                source_name=self.name,
                external_id=f"defense_sector_{datetime.now(timezone.utc).strftime('%Y%m%d')}",
                published_at=datetime.now(timezone.utc),
                fetched_at=datetime.now(timezone.utc),
            ))

        print(f"  [ok] {self.name}: {len(self.DEFENSE_TICKERS)} stocks checked, {len(movers)} significant movers")
        return items[:self.max_items]


# ───────────────────────────────────────────────────────────────────────────
# 3. SEC EDGAR Monitor — defense contract filings
# ───────────────────────────────────────────────────────────────────────────

class SECDefenseMonitor(BaseCollector):
    """Monitor SEC EDGAR for defense contractor material event filings.

    8-K filings from defense contractors often reveal material contracts
    (weapons orders, resupply) before DoD press releases.

    Free API, no key required.
    """

    EDGAR_FULLTEXT = "https://efts.sec.gov/LATEST/search-index"
    EDGAR_SUBMISSIONS = "https://data.sec.gov/submissions/CIK{cik}.json"

    # CIK numbers for major defense contractors
    DEFENSE_CIKS: dict[str, str] = {
        "0000936468": "LMT (Lockheed Martin)",
        "0000101829": "RTX (Raytheon)",
        "0001133421": "NOC (Northrop Grumman)",
        "0000040533": "GD (General Dynamics)",
        "0000012927": "BA (Boeing)",
        "0001047122": "LHX (L3Harris)",
        "0001501585": "HII (Huntington Ingalls)",
    }

    # Keywords that signal material defense contracts
    CONTRACT_KEYWORDS = [
        "material contract", "contract award", "defense contract",
        "government contract", "modification", "task order",
        "production contract", "sustainment", "missile",
        "munitions", "weapons system",
    ]

    def __init__(self, **kwargs):
        super().__init__(
            name="SEC Defense Filings",
            source_type="financial",
            url="https://www.sec.gov/cgi-bin/browse-edgar",
            **kwargs,
        )

    def _fetch_recent_filings(self, cik: str) -> list[dict]:
        """Fetch recent filings for a company from EDGAR."""
        try:
            resp = requests.get(
                self.EDGAR_SUBMISSIONS.format(cik=cik.lstrip("0").zfill(10)),
                headers={
                    "User-Agent": "osint-monitor research@example.com",
                    "Accept": "application/json",
                },
                timeout=_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()

            recent = data.get("filings", {}).get("recent", {})
            forms = recent.get("form", [])
            dates = recent.get("filingDate", [])
            descriptions = recent.get("primaryDocDescription", [])
            accessions = recent.get("accessionNumber", [])

            filings: list[dict] = []
            cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")

            for i in range(min(len(forms), 20)):
                if dates[i] < cutoff:
                    continue
                # Only 8-K (material events) and 10-Q/10-K with contract mentions
                if forms[i] in ("8-K", "8-K/A"):
                    filings.append({
                        "form": forms[i],
                        "date": dates[i],
                        "description": descriptions[i] if i < len(descriptions) else "",
                        "accession": accessions[i] if i < len(accessions) else "",
                    })

            return filings
        except Exception as exc:
            logger.debug("EDGAR fetch failed for CIK %s: %s", cik, exc)
            return []

    def collect(self) -> list[RawItemModel]:
        items: list[RawItemModel] = []
        import time

        for cik, company_name in self.DEFENSE_CIKS.items():
            filings = self._fetch_recent_filings(cik)

            for filing in filings:
                title = f"SEC Filing: {company_name} — {filing['form']} ({filing['date']})"
                content = (
                    f"Company: {company_name}\n"
                    f"Form: {filing['form']}\n"
                    f"Filing date: {filing['date']}\n"
                    f"Description: {filing['description']}\n"
                    f"Accession: {filing['accession']}"
                )

                # Parse date
                pub_date = None
                try:
                    pub_date = datetime.strptime(filing["date"], "%Y-%m-%d").replace(
                        tzinfo=timezone.utc
                    )
                except ValueError:
                    pass

                accession_clean = filing["accession"].replace("-", "")
                items.append(RawItemModel(
                    title=title,
                    content=content,
                    url=f"https://www.sec.gov/Archives/edgar/data/{cik.lstrip('0')}/{accession_clean}/",
                    source_name=self.name,
                    external_id=f"sec_{filing['accession']}",
                    published_at=pub_date,
                    fetched_at=datetime.now(timezone.utc),
                ))

            time.sleep(0.5)  # SEC rate limit: 10 req/sec

        print(f"  [ok] {self.name}: {len(items)} defense contractor filings (last 7 days)")
        return items[:self.max_items]


# ───────────────────────────────────────────────────────────────────────────
# 4. SAM.gov Contract Monitor — government procurement signals
# ───────────────────────────────────────────────────────────────────────────

class SAMContractMonitor(BaseCollector):
    """Monitor SAM.gov for defense contract awards and opportunities.

    Defense procurement signals precede operational capability by weeks/months.
    Surge procurement (ammunition, fuel, medical) indicates anticipated
    high-tempo operations.

    Uses the SAM.gov public API (free, key required — get at api.sam.gov).
    """

    API_URL = "https://api.sam.gov/opportunities/v2/search"

    DEFENSE_KEYWORDS = [
        "ammunition", "munitions", "missile", "fuel JP-8",
        "medical supplies combat", "body armor", "MRAP",
        "drone", "UAV", "counter-UAS", "radar",
        "C4ISR", "intelligence surveillance",
    ]

    def __init__(self, **kwargs):
        super().__init__(
            name="SAM.gov Procurement",
            source_type="financial",
            url=self.API_URL,
            **kwargs,
        )
        self.api_key = os.environ.get("SAM_GOV_API_KEY", "")

    def collect(self) -> list[RawItemModel]:
        if not self.api_key:
            logger.debug("SAM_GOV_API_KEY not set, skipping procurement monitor")
            print(f"  [skip] {self.name}: no API key (free at api.sam.gov)")
            return []

        items: list[RawItemModel] = []
        posted_from = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%m/%d/%Y")

        for keyword in self.DEFENSE_KEYWORDS[:5]:  # Limit queries
            try:
                resp = requests.get(self.API_URL, params={
                    "api_key": self.api_key,
                    "postedFrom": posted_from,
                    "q": keyword,
                    "limit": 5,
                }, timeout=_TIMEOUT)
                resp.raise_for_status()
                data = resp.json()

                for opp in data.get("opportunitiesData", []):
                    title = opp.get("title", "Untitled")
                    sol_number = opp.get("solicitationNumber", "")
                    agency = opp.get("fullParentPathName", "")
                    posted = opp.get("postedDate", "")

                    pub_date = None
                    if posted:
                        try:
                            pub_date = datetime.strptime(posted, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                        except ValueError:
                            pass

                    items.append(RawItemModel(
                        title=f"DOD Procurement: {title[:100]}",
                        content=f"Agency: {agency}\nSolicitation: {sol_number}\nKeyword match: {keyword}",
                        url=opp.get("uiLink", ""),
                        source_name=self.name,
                        external_id=f"sam_{sol_number}" if sol_number else f"sam_{hashlib.md5(f'{title}_{agency}_{posted}'.encode()).hexdigest()[:12]}",
                        published_at=pub_date,
                        fetched_at=datetime.now(timezone.utc),
                    ))

            except Exception as exc:
                logger.debug("SAM.gov query failed for '%s': %s", keyword, exc)

        print(f"  [ok] {self.name}: {len(items)} procurement opportunities")
        return items[:self.max_items]
