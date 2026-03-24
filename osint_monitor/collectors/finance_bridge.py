"""Bridge collector to the finance_agent (That's My Quant).

Runs the finance_agent to generate a fresh daily market report, then
extracts geopolitically relevant signals from the JSON output.

Requires the finance_agent repo at a known path with FRED_API_KEY and
TIINGO_API_KEY configured in its .env file.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from osint_monitor.collectors.base import BaseCollector
from osint_monitor.core.models import RawItemModel

logger = logging.getLogger(__name__)

# Default path to the finance_agent repo
_DEFAULT_FINANCE_AGENT_PATH = Path(os.environ.get(
    "FINANCE_AGENT_PATH",
    str(Path(__file__).parent.parent.parent.parent / "finance_agent"),
))


class FinanceBridgeCollector(BaseCollector):
    """Run the finance_agent and extract intelligence-relevant signals.

    1. Executes ``python run.py`` in the finance_agent repo
    2. Reads the generated daily JSON report
    3. Extracts signals: commodity spikes, VIX, defense sector rotation,
       currency stress, correlation breakdowns, COT positioning extremes,
       crypto fear/greed, and intermarket regime shifts

    Set ``FINANCE_AGENT_PATH`` env var if the repo isn't at the default
    sibling directory location.
    """

    def __init__(self, **kwargs):
        self.agent_path = Path(kwargs.pop("agent_path", _DEFAULT_FINANCE_AGENT_PATH))
        super().__init__(
            name="Financial Intelligence (Quant)",
            source_type="financial",
            url=str(self.agent_path),
            **kwargs,
        )

    # ------------------------------------------------------------------
    # Run the finance agent
    # ------------------------------------------------------------------

    def _run_agent(self) -> Path | None:
        """Execute the finance agent and return the path to the generated report."""
        run_script = self.agent_path / "run.py"
        if not run_script.exists():
            logger.warning("finance_agent not found at %s", self.agent_path)
            print(f"  [err] {self.name}: finance_agent not found at {self.agent_path}")
            return None

        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        expected_report = self.agent_path / "data" / f"daily_market_report_{today}.json"

        # Skip if today's report already exists (avoid redundant API calls)
        if expected_report.exists():
            logger.info("Today's finance report already exists: %s", expected_report)
            print(f"  [ok] {self.name}: using existing report for {today}")
            return expected_report

        # Run the agent
        print(f"  [..] {self.name}: running finance_agent (this may take 1-2 min)...")
        try:
            result = subprocess.run(
                [sys.executable, str(run_script)],
                cwd=str(self.agent_path),
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute max
                env={**os.environ},  # inherit env (API keys)
            )

            if result.returncode != 0:
                logger.error("finance_agent failed (rc=%d): %s", result.returncode, result.stderr[:500])
                print(f"  [err] {self.name}: agent failed — {result.stderr[:100]}")
                return None

            # Find the generated report
            if expected_report.exists():
                return expected_report

            # Fall back to most recent report
            data_dir = self.agent_path / "data"
            reports = sorted(data_dir.glob("daily_market_report_*.json"))
            if reports:
                return reports[-1]

            return None

        except subprocess.TimeoutExpired:
            print(f"  [err] {self.name}: agent timed out (5 min)")
            return None
        except Exception as exc:
            logger.error("finance_agent execution failed: %s", exc)
            print(f"  [err] {self.name}: {exc}")
            return None

    # ------------------------------------------------------------------
    # Extract signals from the report
    # ------------------------------------------------------------------

    def _extract_signals(self, report: dict) -> list[RawItemModel]:
        """Extract geopolitically relevant signals from the finance report."""
        items: list[RawItemModel] = []
        report_date = report.get("report_date", datetime.now(timezone.utc).strftime("%Y-%m-%d"))

        # 1. Key insights (top-level market narrative)
        insights = report.get("key_insights", [])
        if insights:
            items.append(RawItemModel(
                title=f"Market Intelligence Summary ({report_date})",
                content="\n".join(f"- {i}" for i in insights),
                url="",
                source_name=self.name,
                external_id=f"fintel_insights_{report_date}",
                published_at=datetime.now(timezone.utc),
                fetched_at=datetime.now(timezone.utc),
            ))

        # 2. Commodity/energy signals
        items.extend(self._extract_commodity_signals(report, report_date))

        # 3. VIX / volatility signals
        items.extend(self._extract_volatility_signals(report, report_date))

        # 4. Defense sector signals
        items.extend(self._extract_defense_signals(report, report_date))

        # 5. Currency / dollar signals
        items.extend(self._extract_currency_signals(report, report_date))

        # 6. COT positioning extremes
        items.extend(self._extract_cot_signals(report, report_date))

        # 7. Crypto fear/greed
        items.extend(self._extract_crypto_signals(report, report_date))

        # 8. Correlation breakdowns
        items.extend(self._extract_correlation_signals(report, report_date))

        # 9. Intermarket ratios
        items.extend(self._extract_ratio_signals(report, report_date))

        # 10. Macro regime signals
        items.extend(self._extract_macro_signals(report, report_date))

        return items

    def _extract_commodity_signals(self, report: dict, date: str) -> list[RawItemModel]:
        """Extract oil, gold, copper, energy signals."""
        items: list[RawItemModel] = []
        energy_tickers = {"USO", "GLD", "CPER"}
        commodity_names = {"USO": "Oil (WTI)", "GLD": "Gold", "CPER": "Copper"}

        for summary in report.get("market_data", []):
            ticker = summary.get("ticker", "")
            if ticker not in energy_tickers:
                continue

            name = commodity_names.get(ticker, summary.get("name", ticker))
            price = summary.get("current_price", 0)
            returns = summary.get("returns", {})
            daily_ret = returns.get("daily", 0)
            weekly_ret = returns.get("weekly", 0)
            monthly_ret = returns.get("monthly", 0)

            # Flag significant moves
            if abs(daily_ret) >= 2.0 or abs(weekly_ret) >= 5.0:
                direction = "SPIKE" if daily_ret > 0 else "DROP"
                title = f"COMMODITY {direction}: {name} daily={daily_ret:+.1f}% weekly={weekly_ret:+.1f}% (${price:.2f})"

                tech = summary.get("technical_indicators", {})
                content = (
                    f"Commodity: {name} ({ticker})\n"
                    f"Price: ${price:.2f}\n"
                    f"Returns: daily={daily_ret:+.2f}%, weekly={weekly_ret:+.2f}%, "
                    f"monthly={monthly_ret:+.2f}%\n"
                    f"RSI: {tech.get('RSI_14', 'n/a')}\n"
                    f"Trend: {summary.get('trend', 'n/a')}\n"
                    f"Volatility: {summary.get('volatility_annualized', {}).get('current', 'n/a')}"
                )

                items.append(RawItemModel(
                    title=title,
                    content=content,
                    url="",
                    source_name=self.name,
                    external_id=f"fintel_{ticker}_{date}",
                    published_at=datetime.now(timezone.utc),
                    fetched_at=datetime.now(timezone.utc),
                ))

        return items

    def _extract_volatility_signals(self, report: dict, date: str) -> list[RawItemModel]:
        """Extract VIX and volatility regime signals."""
        items: list[RawItemModel] = []

        for summary in report.get("macro_data", []):
            if summary.get("series_id") == "VIXCLS":
                vix = summary.get("current_value", 0)
                trend = summary.get("trend", "")

                if vix > 25:
                    level = "ELEVATED FEAR"
                elif vix > 30:
                    level = "HIGH FEAR"
                elif vix > 40:
                    level = "EXTREME FEAR"
                else:
                    level = "NORMAL"

                if vix > 25 or "Increasing" in str(trend):
                    items.append(RawItemModel(
                        title=f"VIX {level}: {vix:.1f} (trend: {trend})",
                        content=(
                            f"VIX (CBOE Volatility Index): {vix:.1f}\n"
                            f"Level: {level}\n"
                            f"Trend: {trend}\n"
                            f"Signal: Market fear {'elevated' if vix > 25 else 'rising'} — "
                            f"geopolitical risk pricing into options markets"
                        ),
                        url="",
                        source_name=self.name,
                        external_id=f"fintel_vix_{date}",
                        published_at=datetime.now(timezone.utc),
                        fetched_at=datetime.now(timezone.utc),
                    ))
                break

        return items

    def _extract_defense_signals(self, report: dict, date: str) -> list[RawItemModel]:
        """Extract defense sector and military-industrial signals."""
        items: list[RawItemModel] = []
        defense_tickers = {"XLE", "XLK", "XLU"}  # Energy, tech, utilities as war proxies

        # Check momentum ranking for defense-relevant sectors
        momentum = report.get("momentum_ranking", [])
        if momentum:
            top_3 = [m.get("ticker", "") for m in momentum[:3]]
            bottom_3 = [m.get("ticker", "") for m in momentum[-3:]]

            if "XLE" in top_3:
                items.append(RawItemModel(
                    title=f"Energy sector leading market — war economy signal",
                    content=f"XLE (Energy) in top 3 momentum. Full ranking: {json.dumps(momentum[:5], default=str)}",
                    url="",
                    source_name=self.name,
                    external_id=f"fintel_sector_energy_{date}",
                    published_at=datetime.now(timezone.utc),
                    fetched_at=datetime.now(timezone.utc),
                ))

            if "XLU" in top_3:
                items.append(RawItemModel(
                    title=f"Utilities sector leading — defensive rotation (risk-off)",
                    content=f"XLU (Utilities) in top 3 momentum. Investors seeking safety.",
                    url="",
                    source_name=self.name,
                    external_id=f"fintel_sector_defensive_{date}",
                    published_at=datetime.now(timezone.utc),
                    fetched_at=datetime.now(timezone.utc),
                ))

        return items

    def _extract_currency_signals(self, report: dict, date: str) -> list[RawItemModel]:
        """Extract USD strength and currency stress signals."""
        items: list[RawItemModel] = []

        for summary in report.get("market_data", []):
            if summary.get("ticker") == "UUP":
                returns = summary.get("returns", {})
                weekly = returns.get("weekly", 0)
                monthly = returns.get("monthly", 0)

                if abs(weekly) >= 1.0 or abs(monthly) >= 3.0:
                    direction = "STRENGTHENING" if weekly > 0 else "WEAKENING"
                    items.append(RawItemModel(
                        title=f"USD {direction}: weekly={weekly:+.1f}% monthly={monthly:+.1f}%",
                        content=(
                            f"US Dollar Index (UUP): weekly={weekly:+.2f}%, monthly={monthly:+.2f}%\n"
                            f"Signal: Dollar {'strength = flight to safety' if weekly > 0 else 'weakness = risk appetite or Fed concerns'}"
                        ),
                        url="",
                        source_name=self.name,
                        external_id=f"fintel_usd_{date}",
                        published_at=datetime.now(timezone.utc),
                        fetched_at=datetime.now(timezone.utc),
                    ))
                break

        return items

    def _extract_cot_signals(self, report: dict, date: str) -> list[RawItemModel]:
        """Extract CFTC Commitment of Traders positioning extremes."""
        items: list[RawItemModel] = []

        for cot in report.get("cot_positioning", []):
            signal = cot.get("signal", "")
            if "Crowded" in signal:
                name = cot.get("name", "")
                percentile = cot.get("percentile", 0)
                net_position = cot.get("net_long", 0)

                items.append(RawItemModel(
                    title=f"COT {signal}: {name} (percentile: {percentile})",
                    content=(
                        f"Contract: {name}\n"
                        f"Signal: {signal}\n"
                        f"Net position: {net_position:,}\n"
                        f"Percentile: {percentile}\n"
                        f"Significance: Crowded positioning often precedes reversals"
                    ),
                    url="",
                    source_name=self.name,
                    external_id=f"fintel_cot_{name.replace(' ', '_')}_{date}",
                    published_at=datetime.now(timezone.utc),
                    fetched_at=datetime.now(timezone.utc),
                ))

        return items

    def _extract_crypto_signals(self, report: dict, date: str) -> list[RawItemModel]:
        """Extract crypto fear/greed and sanctions evasion signals."""
        items: list[RawItemModel] = []

        for crypto in report.get("onchain_data", []):
            fg = crypto.get("fear_greed_value", 50)
            if fg is not None and (fg <= 20 or fg >= 80):
                level = "EXTREME FEAR" if fg <= 20 else "EXTREME GREED"
                btc_price = crypto.get("price", 0)
                items.append(RawItemModel(
                    title=f"Crypto {level}: Fear & Greed = {fg} (BTC ${btc_price:,.0f})",
                    content=(
                        f"Fear & Greed Index: {fg}\n"
                        f"BTC Price: ${btc_price:,.2f}\n"
                        f"BTC Dominance: {crypto.get('btc_dominance', 'n/a')}%\n"
                        f"Signal: {'Risk-off across all markets' if fg <= 20 else 'Speculative excess'}"
                    ),
                    url="",
                    source_name=self.name,
                    external_id=f"fintel_crypto_fg_{date}",
                    published_at=datetime.now(timezone.utc),
                    fetched_at=datetime.now(timezone.utc),
                ))
            break

        return items

    def _extract_correlation_signals(self, report: dict, date: str) -> list[RawItemModel]:
        """Extract correlation breakdown signals."""
        items: list[RawItemModel] = []

        for pair in report.get("correlation_key_pairs", []):
            change = pair.get("change", 0)
            if abs(change) >= 0.3:
                label = pair.get("label", "")
                current = pair.get("current", 0)
                items.append(RawItemModel(
                    title=f"CORRELATION BREAK: {label} shifted {change:+.2f} (now {current:.2f})",
                    content=(
                        f"Pair: {label}\n"
                        f"Current correlation: {current:.3f}\n"
                        f"Change: {change:+.3f}\n"
                        f"Signal: Major regime change in market structure"
                    ),
                    url="",
                    source_name=self.name,
                    external_id=f"fintel_corr_{label.replace('/', '_')}_{date}",
                    published_at=datetime.now(timezone.utc),
                    fetched_at=datetime.now(timezone.utc),
                ))

        return items

    def _extract_ratio_signals(self, report: dict, date: str) -> list[RawItemModel]:
        """Extract intermarket ratio signals."""
        items: list[RawItemModel] = []

        ratios_data = report.get("intermarket_ratios", {})
        ratios = ratios_data if isinstance(ratios_data, list) else ratios_data.get("ratios", [])

        for ratio in ratios:
            signal = ratio.get("signal", "")
            if signal and "outperforming" in signal.lower():
                label = ratio.get("label", "")
                current = ratio.get("current", 0)
                items.append(RawItemModel(
                    title=f"Intermarket: {label} — {signal}",
                    content=f"Ratio: {label}\nCurrent: {current:.4f}\nSignal: {signal}",
                    url="",
                    source_name=self.name,
                    external_id=f"fintel_ratio_{label.replace('/', '_')}_{date}",
                    published_at=datetime.now(timezone.utc),
                    fetched_at=datetime.now(timezone.utc),
                ))

        return items

    def _extract_macro_signals(self, report: dict, date: str) -> list[RawItemModel]:
        """Extract critical macro regime signals."""
        items: list[RawItemModel] = []

        # Yield curve inversion (recession signal)
        for macro in report.get("macro_data", []):
            if macro.get("series_id") == "T10Y2Y":
                spread = macro.get("current_value", 0)
                if spread is not None and spread < 0:
                    items.append(RawItemModel(
                        title=f"YIELD CURVE INVERTED: 10Y-2Y spread = {spread:.2f}%",
                        content=(
                            f"10Y-2Y Treasury Spread: {spread:.3f}%\n"
                            f"Signal: Inverted yield curve — historically precedes recession\n"
                            f"War spending may be masking underlying economic weakness"
                        ),
                        url="",
                        source_name=self.name,
                        external_id=f"fintel_yield_curve_{date}",
                        published_at=datetime.now(timezone.utc),
                        fetched_at=datetime.now(timezone.utc),
                    ))

            # Credit spreads widening (financial stress)
            if macro.get("series_id") in ("BAMLH0A0HYM2", "BAA10Y"):
                spread = macro.get("current_value", 0)
                name = macro.get("name", "Credit Spread")
                if spread is not None and spread > 5.0:
                    items.append(RawItemModel(
                        title=f"CREDIT STRESS: {name} = {spread:.2f}%",
                        content=(
                            f"{name}: {spread:.3f}%\n"
                            f"Signal: Elevated credit spreads — financial system under stress\n"
                            f"War-related uncertainty hitting corporate bond markets"
                        ),
                        url="",
                        source_name=self.name,
                        external_id=f"fintel_credit_{date}",
                        published_at=datetime.now(timezone.utc),
                        fetched_at=datetime.now(timezone.utc),
                    ))

        return items

    # ------------------------------------------------------------------
    # collect()
    # ------------------------------------------------------------------

    def collect(self) -> list[RawItemModel]:
        """Run the finance agent and extract intelligence signals."""
        report_path = self._run_agent()

        if report_path is None:
            return []

        try:
            report = json.loads(report_path.read_text())
        except Exception as exc:
            logger.error("Failed to read finance report: %s", exc)
            print(f"  [err] {self.name}: failed to parse report — {exc}")
            return []

        items = self._extract_signals(report)

        print(f"  [ok] {self.name}: {len(items)} intelligence signals extracted from {report_path.name}")
        return items[:self.max_items]
