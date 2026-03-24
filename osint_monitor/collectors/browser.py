"""Browser-based collector using Playwright.

Collects from X/Twitter For You feed by connecting to the user's already-running
Chrome instance via Chrome DevTools Protocol (CDP). This avoids profile locking
issues and uses the existing logged-in session.

Key discoveries from testing:
- window.scrollBy() does NOT trigger X's infinite scroll — must use mouse wheel
- X virtualizes the DOM — only ~5 articles exist at once
- A polling harvester on each scroll captures tweets before they get recycled
- Detect ads by looking for "Ad"/"Promoted" span text, NOT placementTracking div

Setup: Chrome must be launched with --remote-debugging-port=9222
  Add to Chrome shortcut target: --remote-debugging-port=9222
  Or set CHROME_CDP_URL env var to an existing CDP endpoint.
"""

import logging
import os
import subprocess
from datetime import datetime, timezone

from osint_monitor.collectors.base import BaseCollector
from osint_monitor.core.models import RawItemModel

logger = logging.getLogger(__name__)

CHROME_CDP_URL = os.environ.get("CHROME_CDP_URL", "http://localhost:9222")

# JS to inject into X page — harvests tweets from the DOM
HARVESTER_JS = """
() => {
    const seen = new Set();
    const results = [];

    for (const tweet of document.querySelectorAll('article[data-testid="tweet"]')) {
        const textEl = tweet.querySelector('[data-testid="tweetText"]');
        const text = textEl ? textEl.textContent.trim() : '';
        if (!text || seen.has(text)) continue;

        // Skip ads
        let isAd = false;
        for (const s of tweet.querySelectorAll('span')) {
            const t = s.textContent.trim();
            if (t === 'Ad' || t === 'Promoted') { isAd = true; break; }
        }
        if (isAd) continue;

        seen.add(text);
        const userEl = tweet.querySelector('[data-testid="User-Name"]');
        const timeEl = tweet.querySelector('time');
        let tweetUrl = '', tweetId = '';
        for (const a of tweet.querySelectorAll('a[href*="/status/"]')) {
            const m = a.href.match(/\\/status\\/(\\d+)$/);
            if (m) { tweetUrl = a.href; tweetId = m[1]; break; }
        }
        let username = '', displayName = '';
        if (userEl) {
            for (const s of userEl.querySelectorAll('span')) {
                if (s.textContent.startsWith('@')) { username = s.textContent; break; }
            }
            const first = userEl.querySelector('span');
            displayName = first ? first.textContent : '';
        }
        results.push({
            title: (displayName + ' (' + username + '): ' + text.substring(0, 150)),
            content: text,
            url: tweetUrl,
            published_at: timeEl ? timeEl.getAttribute('datetime') : null,
            external_id: tweetId,
        });
    }
    return results;
}
"""


def _ensure_chrome_cdp() -> bool:
    """Check if Chrome is running with CDP enabled."""
    import urllib.request
    try:
        urllib.request.urlopen(f"{CHROME_CDP_URL}/json/version", timeout=2)
        return True
    except Exception:
        return False


def _item_data_to_model(item_data: dict, seen_ids: set) -> RawItemModel | None:
    """Convert a raw JS item dict to a RawItemModel, deduping by ID."""
    eid = item_data.get("external_id", "")
    if not eid or eid in seen_ids:
        return None
    seen_ids.add(eid)

    pub_at = None
    if item_data.get("published_at"):
        try:
            pub_at = datetime.fromisoformat(
                item_data["published_at"].replace("Z", "+00:00")
            )
        except ValueError:
            pass

    return RawItemModel(
        title=item_data.get("title", "")[:200],
        content=item_data.get("content", "")[:5000],
        url=item_data.get("url", ""),
        published_at=pub_at,
        source_name="X-ForYou",
        external_id=eid,
        fetched_at=datetime.now(timezone.utc),
    )


class XForYouCollector(BaseCollector):
    """Collects tweets from X/Twitter For You feed via Playwright + CDP."""

    def __init__(self, scroll_rounds: int = 15, **kwargs):
        super().__init__(
            name="X-ForYou",
            source_type="browser",
            url="https://x.com/home",
            **kwargs,
        )
        self.scroll_rounds = scroll_rounds

    def collect(self) -> list[RawItemModel]:
        items = []
        try:
            if not _ensure_chrome_cdp():
                print(f"  [skip] {self.name}: Chrome CDP not available at {CHROME_CDP_URL}")
                logger.warning(
                    "Chrome CDP not available. Start Chrome with "
                    "--remote-debugging-port=9222 or set CHROME_CDP_URL."
                )
                return []
            items = self._collect_via_cdp()
            print(f"  [ok] {self.name}: {len(items)} items")
        except Exception as e:
            logger.error(f"X browser collector failed: {e}")
            print(f"  [err] {self.name}: {e}")
        return items

    def _collect_via_cdp(self) -> list[RawItemModel]:
        from playwright.sync_api import sync_playwright

        seen_ids: set[str] = set()
        all_items: list[RawItemModel] = []

        with sync_playwright() as p:
            # Connect to existing Chrome instance via CDP
            browser = p.chromium.connect_over_cdp(CHROME_CDP_URL)

            try:
                # Create a new context and page within the existing browser
                # This inherits the user's cookies and logged-in session
                context = browser.contexts[0] if browser.contexts else browser.new_context()
                page = context.new_page()
                page.goto("https://x.com/home", wait_until="domcontentloaded")
                page.wait_for_timeout(4000)  # let feed render

                # Scroll and harvest
                for i in range(self.scroll_rounds):
                    batch = page.evaluate(HARVESTER_JS)
                    for item_data in batch:
                        model = _item_data_to_model(item_data, seen_ids)
                        if model:
                            all_items.append(model)

                    # Mouse wheel scroll — triggers X's infinite loader
                    page.mouse.wheel(0, 3000)
                    page.wait_for_timeout(1200)

                # Final harvest
                batch = page.evaluate(HARVESTER_JS)
                for item_data in batch:
                    model = _item_data_to_model(item_data, seen_ids)
                    if model:
                        all_items.append(model)

                page.close()
            finally:
                browser.close()

        return all_items

    def health_check(self) -> bool:
        """Check if Chrome CDP is reachable."""
        return _ensure_chrome_cdp()
