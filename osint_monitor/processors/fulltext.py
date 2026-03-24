"""Full-text article extraction for enriching items beyond RSS summaries.

Uses requests + beautifulsoup4 to fetch and extract main article text,
stripping boilerplate navigation, footers, sidebars, and ads.
"""

from __future__ import annotations

import json
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup, Tag
from sqlalchemy import func
from sqlalchemy.orm import Session

from osint_monitor.core.database import RawItem, Source

logger = logging.getLogger(__name__)

USER_AGENT = "OSINT-Monitor/2.0 (research tool)"
REQUEST_TIMEOUT = 10  # seconds
MAX_CONTENT_LENGTH = 10000  # chars

# Playwright headless browser fallback for JS-rendered sites (BBC, Al Jazeera, etc.)
PLAYWRIGHT_FALLBACK_ENABLED = True
PLAYWRIGHT_TIMEOUT = 15000  # ms — max time to wait for page load
_playwright_browser = None  # singleton browser instance

# Domains that have repeatedly failed extraction; populated at runtime.
_domain_blocklist: dict[str, int] = {}
_BLOCKLIST_THRESHOLD = 3  # failures before blocking a domain
_BLOCKLIST_EXPIRY = 3600  # seconds before retrying a blocked domain
_domain_block_times: dict[str, float] = {}


# ---------------------------------------------------------------------------
# Boilerplate tag/class removal
# ---------------------------------------------------------------------------

_STRIP_TAGS = {"nav", "footer", "header", "aside", "script", "style", "noscript", "svg"}

_STRIP_CLASSES = {
    "sidebar", "side-bar", "nav", "navbar", "navigation",
    "footer", "ad", "ads", "advertisement", "promo", "promotion",
    "related", "related-articles", "related-posts", "recommended",
    "social", "share", "sharing", "comments", "comment-section",
    "newsletter", "signup", "subscribe", "cookie", "banner",
    "menu", "breadcrumb", "pagination",
}

_STRIP_IDS = {
    "sidebar", "nav", "navbar", "footer", "comments", "ad",
    "related", "newsletter", "cookie-banner",
}


def _strip_boilerplate(soup: BeautifulSoup) -> None:
    """Remove boilerplate elements from the parsed HTML in-place."""
    for tag_name in _STRIP_TAGS:
        for el in soup.find_all(tag_name):
            el.decompose()

    for el in soup.find_all(True):
        if not isinstance(el, Tag):
            continue
        # After decompose() calls, remaining elements in the list may be
        # detached from the tree.  Skip them to avoid attribute errors.
        if el.parent is None:
            continue
        classes = el.get("class") or []
        if isinstance(classes, list):
            class_str = " ".join(classes).lower()
        else:
            class_str = str(classes).lower()

        el_id = (el.get("id") or "").lower()

        if any(c in class_str for c in _STRIP_CLASSES):
            el.decompose()
            continue
        if el_id in _STRIP_IDS:
            el.decompose()
            continue


def _get_domain(url: str) -> str:
    """Extract the domain from a URL for matching."""
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def _paragraphs_to_text(paragraphs: list[Tag], min_length: int = 0) -> str:
    """Join paragraph tags into text, filtering by minimum length."""
    parts = []
    for p in paragraphs:
        if p is None or not isinstance(p, Tag):
            continue
        t = p.get_text(strip=True)
        if t and len(t) > min_length:
            parts.append(t)
    return "\n\n".join(parts)


# ---------------------------------------------------------------------------
# JSON-LD structured data extraction
# ---------------------------------------------------------------------------

def extract_article_from_json_ld(soup: BeautifulSoup) -> str | None:
    """Parse JSON-LD structured data to extract articleBody text.

    Works on almost every modern news site regardless of HTML structure.
    Returns the article body text or None if not found.
    """
    scripts = soup.find_all("script", type="application/ld+json")
    for script in scripts:
        if script is None or not script.string:
            continue
        try:
            data = json.loads(script.string)
        except (json.JSONDecodeError, TypeError):
            continue

        # JSON-LD can be a single object or an array
        items = data if isinstance(data, list) else [data]

        for item in items:
            if not isinstance(item, dict):
                continue

            try:
                # Check @graph arrays (common in WordPress, BBC, etc.)
                if "@graph" in item and isinstance(item.get("@graph"), list):
                    items.extend(item["@graph"])
                    continue

                item_type = item.get("@type", "")
                if isinstance(item_type, list):
                    item_type = " ".join(str(t) for t in item_type)
                elif not isinstance(item_type, str):
                    item_type = str(item_type)

                # Look for article-like types
                is_article = any(
                    t in item_type
                    for t in ("Article", "NewsArticle", "ReportageNewsArticle",
                              "BlogPosting", "WebPage")
                )

                body = item.get("articleBody") or item.get("text") or ""
                if is_article and isinstance(body, str) and len(body) > 100:
                    return body.strip()
            except (AttributeError, TypeError):
                continue

    return None


def _extract_og_description(soup: BeautifulSoup) -> str | None:
    """Extract og:description meta tag as a last-resort summary."""
    try:
        meta = soup.find("meta", property="og:description")
        if meta is not None and isinstance(meta, Tag):
            content = meta.get("content")
            if content and isinstance(content, str) and len(content) > 30:
                return content.strip()
    except (AttributeError, TypeError):
        pass

    # Also try meta name="description"
    try:
        meta = soup.find("meta", attrs={"name": "description"})
        if meta is not None and isinstance(meta, Tag):
            content = meta.get("content")
            if content and isinstance(content, str) and len(content) > 30:
                return content.strip()
    except (AttributeError, TypeError):
        pass

    return None


# ---------------------------------------------------------------------------
# Site-specific extractors
# ---------------------------------------------------------------------------

def _extract_bbc(soup: BeautifulSoup) -> str | None:
    """BBC-specific extractor.

    BBC uses React/JS rendering with data-component attributes and
    ssrcss-* class names.
    """
    # Strategy 1: data-component="text-block" divs
    blocks = soup.find_all("div", attrs={"data-component": "text-block"})
    if blocks:
        paragraphs = []
        for block in blocks:
            if block is not None and isinstance(block, Tag):
                paragraphs.extend(block.find_all("p"))
        text = _paragraphs_to_text(paragraphs)
        if len(text) > 100:
            return text

    # Strategy 2: BBC's React class name pattern
    containers = soup.find_all("div", class_=re.compile(r"ssrcss-.*RichTextComponentWrapper"))
    if containers:
        paragraphs = []
        for c in containers:
            if c is not None and isinstance(c, Tag):
                paragraphs.extend(c.find_all("p"))
        text = _paragraphs_to_text(paragraphs)
        if len(text) > 100:
            return text

    # Strategy 3: <article> tag
    article = soup.find("article")
    if article is not None and isinstance(article, Tag):
        paragraphs = article.find_all("p")
        text = _paragraphs_to_text(paragraphs)
        if len(text) > 100:
            return text

    # Strategy 4: main content area paragraphs
    main = soup.find("main") or soup.find("div", id="main-content")
    if main is not None and isinstance(main, Tag):
        paragraphs = main.find_all("p")
        text = _paragraphs_to_text(paragraphs, min_length=20)
        if len(text) > 100:
            return text

    return None


def _extract_aljazeera(soup: BeautifulSoup) -> str | None:
    """Al Jazeera-specific extractor."""
    selectors = [
        "div.wysiwyg",
        "div.article-p-wrapper",
        ".article__body-text",
        ".article__subhead",
        "div.main-article-body",
    ]
    for sel in selectors:
        container = soup.select_one(sel)
        if container is not None and isinstance(container, Tag):
            paragraphs = container.find_all("p")
            text = _paragraphs_to_text(paragraphs)
            if len(text) > 100:
                return text

    # Fallback: article tag
    article = soup.find("article")
    if article is not None and isinstance(article, Tag):
        paragraphs = article.find_all("p")
        text = _paragraphs_to_text(paragraphs, min_length=20)
        if len(text) > 100:
            return text

    return None


def _extract_scmp(soup: BeautifulSoup) -> str | None:
    """South China Morning Post extractor."""
    selectors = [
        "div[data-qa='article-body']",
        "div.article-body",
        "div.article-body-content",
        ".body-output",
    ]
    for sel in selectors:
        container = soup.select_one(sel)
        if container is not None and isinstance(container, Tag):
            paragraphs = container.find_all("p")
            text = _paragraphs_to_text(paragraphs)
            if len(text) > 100:
                return text
    return None


def _extract_reuters(soup: BeautifulSoup) -> str | None:
    """Reuters extractor."""
    selectors = [
        "div.article-body__content",
        "div.article-body__content__17Yit",
        "[data-testid='paragraph']",
        "div.article-body",
    ]
    for sel in selectors:
        container = soup.select_one(sel)
        if container is not None and isinstance(container, Tag):
            paragraphs = container.find_all("p")
            text = _paragraphs_to_text(paragraphs)
            if len(text) > 100:
                return text

    # Reuters uses multiple paragraph divs with data-testid
    test_paras = soup.find_all(attrs={"data-testid": re.compile(r"paragraph")})
    if test_paras:
        text = _paragraphs_to_text(test_paras)
        if len(text) > 100:
            return text

    return None


def _extract_defense_military(soup: BeautifulSoup) -> str | None:
    """Extractor for Defense News, Breaking Defense, and similar military/defense sites."""
    selectors = [
        "div.article-body",
        "div.entry-content",
        "div.article__body",
        "div.post-content",
        ".article-content",
    ]
    for sel in selectors:
        container = soup.select_one(sel)
        if container is not None and isinstance(container, Tag):
            paragraphs = container.find_all("p")
            text = _paragraphs_to_text(paragraphs)
            if len(text) > 100:
                return text
    return None


def _extract_war_on_rocks(soup: BeautifulSoup) -> str | None:
    """War on the Rocks extractor."""
    container = soup.select_one("div.entry-content")
    if container is not None and isinstance(container, Tag):
        paragraphs = container.find_all("p")
        text = _paragraphs_to_text(paragraphs)
        if len(text) > 100:
            return text
    return None


# Map domain substrings to site-specific extractors
_SITE_EXTRACTORS: list[tuple[list[str], callable]] = [
    (["bbc.co.uk", "bbc.com"], _extract_bbc),
    (["aljazeera.com", "aljazeera.net"], _extract_aljazeera),
    (["scmp.com"], _extract_scmp),
    (["reuters.com"], _extract_reuters),
    (["defensenews.com", "breakingdefense.com"], _extract_defense_military),
    (["warontherocks.com"], _extract_war_on_rocks),
]


def _get_site_extractor(domain: str) -> callable | None:
    """Return the site-specific extractor for a domain, or None."""
    for domain_patterns, extractor in _SITE_EXTRACTORS:
        if any(pat in domain for pat in domain_patterns):
            return extractor
    return None


# ---------------------------------------------------------------------------
# Generic extraction strategies
# ---------------------------------------------------------------------------

def _strategy_article_tag(soup: BeautifulSoup) -> str | None:
    """Strategy A: Look for <article> tag."""
    article = soup.find("article")
    if article is not None and isinstance(article, Tag):
        paragraphs = article.find_all("p")
        text = _paragraphs_to_text(paragraphs)
        if len(text) > 100:
            return text
    return None


def _strategy_common_selectors(soup: BeautifulSoup) -> str | None:
    """Strategy B: Look for common article container CSS selectors."""
    selectors = [
        ".article-body",
        ".story-body",
        ".entry-content",
        "#article-body",
        "[itemprop='articleBody']",
        ".post-content",
        ".article-content",
        ".story-content",
        ".article__body",
        ".article-text",
        ".field-body",
    ]
    for selector in selectors:
        container = soup.select_one(selector)
        if container is not None and isinstance(container, Tag):
            paragraphs = container.find_all("p")
            text = _paragraphs_to_text(paragraphs)
            if len(text) > 100:
                return text
    return None


def _strategy_paragraph_fallback(soup: BeautifulSoup) -> str | None:
    """Strategy C: Gather <p> tags from main/article/content divs."""
    try:
        containers = soup.find_all(
            ["main", "article", "div"],
            class_=lambda c: c and any(
                x in (c if isinstance(c, str) else " ".join(c)).lower()
                for x in ("content", "body", "main", "post", "story", "text")
            ),
        )
    except (AttributeError, TypeError):
        containers = []

    if not containers:
        body = soup.body if soup.body else soup
        containers = [body] if body is not None else []

    best_text = ""
    for container in containers:
        if container is None or not isinstance(container, Tag):
            continue
        paragraphs = container.find_all("p")
        text = _paragraphs_to_text(paragraphs, min_length=30)
        if len(text) > len(best_text):
            best_text = text

    return best_text if len(best_text) > 100 else None


def _strategy_generic_all_paragraphs(soup: BeautifulSoup) -> str | None:
    """Strategy D: Collect all <p> tags with >50 chars of text as last resort."""
    paragraphs = soup.find_all("p")
    text = _paragraphs_to_text(paragraphs, min_length=50)
    if len(text) > 100:
        return text
    return None


# ---------------------------------------------------------------------------
# Domain blocklist management
# ---------------------------------------------------------------------------

def _is_domain_blocked(domain: str) -> bool:
    """Check if a domain is temporarily blocked due to repeated failures."""
    if domain not in _domain_blocklist:
        return False
    if _domain_blocklist[domain] < _BLOCKLIST_THRESHOLD:
        return False
    # Check if the block has expired
    block_time = _domain_block_times.get(domain, 0)
    if time.time() - block_time > _BLOCKLIST_EXPIRY:
        # Reset and allow retry
        _domain_blocklist[domain] = 0
        return False
    return True


def _record_domain_failure(domain: str) -> None:
    """Record a failure for a domain; may cause it to be temporarily blocked."""
    _domain_blocklist[domain] = _domain_blocklist.get(domain, 0) + 1
    if _domain_blocklist[domain] >= _BLOCKLIST_THRESHOLD:
        _domain_block_times[domain] = time.time()
        logger.info(
            "Domain %s blocked for %ds after %d consecutive failures",
            domain, _BLOCKLIST_EXPIRY, _domain_blocklist[domain],
        )


def _record_domain_success(domain: str) -> None:
    """Reset failure counter on success."""
    _domain_blocklist.pop(domain, None)
    _domain_block_times.pop(domain, None)


# ---------------------------------------------------------------------------
# Playwright headless browser fallback
# ---------------------------------------------------------------------------

def _get_playwright_browser():
    """Return a singleton Playwright browser instance, launching if needed.

    Returns None if playwright is not installed or browser launch fails.
    """
    global _playwright_browser
    if _playwright_browser is not None:
        if _playwright_browser.is_connected():
            return _playwright_browser
        # Browser disconnected; reset so we re-launch.
        _playwright_browser = None

    try:
        from playwright.sync_api import sync_playwright  # noqa: F811

        # Keep the Playwright context manager alive via a module-level ref.
        # This is intentional — we want one browser for the process lifetime.
        pw = sync_playwright().start()
        _playwright_browser = pw.chromium.launch(headless=True)
        logger.info("Playwright headless Chromium launched for fulltext fallback")
        return _playwright_browser
    except ImportError:
        logger.debug("Playwright not installed — headless fallback unavailable")
        return None
    except Exception as exc:
        logger.warning("Failed to launch Playwright browser: %s", exc)
        return None


def _extract_with_playwright(url: str) -> str | None:
    """Fetch a URL with a headless browser and extract article text from the
    rendered DOM.  Returns extracted text or None on failure.
    """
    browser = _get_playwright_browser()
    if browser is None:
        return None

    page = None
    try:
        page = browser.new_page(
            user_agent=USER_AGENT,
            java_script_enabled=True,
        )
        page.goto(url, wait_until="domcontentloaded", timeout=PLAYWRIGHT_TIMEOUT)

        # Wait for article content to appear — try a few common selectors,
        # fall back to a fixed delay if none match.
        selectors_to_try = ["article", "main", "[data-component='text-block']", ".wysiwyg"]
        rendered = False
        for sel in selectors_to_try:
            try:
                page.wait_for_selector(sel, timeout=3000)
                rendered = True
                break
            except Exception:
                continue
        if not rendered:
            # No known selector matched; give JS 3 seconds to hydrate.
            page.wait_for_timeout(3000)

        html = page.content()
        page.close()
        page = None

        soup = BeautifulSoup(html, "html.parser")

        # Re-use existing extraction pipeline on the rendered HTML.
        json_ld_text = extract_article_from_json_ld(soup)
        _strip_boilerplate(soup)

        domain = _get_domain(url)
        text = None

        site_extractor = _get_site_extractor(domain)
        if site_extractor is not None:
            text = site_extractor(soup)

        if text is None:
            text = _strategy_article_tag(soup)
        if text is None:
            text = _strategy_common_selectors(soup)
        if text is None:
            text = _strategy_paragraph_fallback(soup)
        if text is None:
            text = _strategy_generic_all_paragraphs(soup)

        if text is None or len(text) < 200:
            if json_ld_text and (text is None or len(json_ld_text) > len(text)):
                text = json_ld_text

        if text and len(text) > 100:
            logger.info("Playwright fallback extracted %d chars from %s", len(text), url)
            return text

        return None

    except Exception as exc:
        logger.warning("Playwright extraction failed for %s: %s", url, exc)
        return None
    finally:
        if page is not None:
            try:
                page.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_article_text(url: str) -> str | None:
    """Fetch a URL and extract the main article text.

    Returns cleaned text (max 10000 chars) or None on failure.
    Uses site-specific extractors first, then generic strategies,
    then JSON-LD and meta tag fallbacks.
    """
    domain = _get_domain(url)

    # Check domain blocklist
    if _is_domain_blocked(domain):
        logger.debug("Skipping blocked domain %s for URL %s", domain, url)
        return None

    try:
        response = requests.get(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )
        response.raise_for_status()

        # Only process HTML content
        content_type = response.headers.get("Content-Type", "")
        if "html" not in content_type.lower() and "text" not in content_type.lower():
            logger.debug("Skipping non-HTML content at %s: %s", url, content_type)
            return None

        soup = BeautifulSoup(response.text, "html.parser")

        # Attempt JSON-LD extraction before stripping boilerplate (scripts get
        # removed by _strip_boilerplate, so we need to grab JSON-LD first).
        json_ld_text = extract_article_from_json_ld(soup)

        _strip_boilerplate(soup)

        text = None

        # 1. Try site-specific extractor
        site_extractor = _get_site_extractor(domain)
        if site_extractor is not None:
            text = site_extractor(soup)

        # 2. Try generic strategies
        if text is None:
            text = _strategy_article_tag(soup)
        if text is None:
            text = _strategy_common_selectors(soup)
        if text is None:
            text = _strategy_paragraph_fallback(soup)
        if text is None:
            text = _strategy_generic_all_paragraphs(soup)

        # 3. Handle JavaScript-rendered / SPA sites
        #    If we got very little text from HTML, fall back to JSON-LD
        if text is None or len(text) < 200:
            if json_ld_text and (text is None or len(json_ld_text) > len(text)):
                text = json_ld_text

        # 4. Last resort: og:description meta tag (at least gives a summary)
        if text is None or len(text) < 200:
            og_desc = _extract_og_description(soup)
            if og_desc and (text is None or len(og_desc) > len(text)):
                text = og_desc

        # 5. Playwright headless browser fallback for JS-rendered sites
        #    (BBC, Al Jazeera, etc. that return a React shell to requests.get)
        if (text is None or len(text) < 200) and PLAYWRIGHT_FALLBACK_ENABLED:
            logger.debug("Trying Playwright fallback for %s", url)
            pw_text = _extract_with_playwright(url)
            if pw_text and (text is None or len(pw_text) > len(text)):
                text = pw_text

        if text is None:
            logger.debug("Could not extract article text from %s", url)
            _record_domain_failure(domain)
            return None

        # Clean up whitespace
        lines = [line.strip() for line in text.splitlines()]
        text = "\n\n".join(line for line in lines if line)

        # Truncate to max length
        if len(text) > MAX_CONTENT_LENGTH:
            text = text[:MAX_CONTENT_LENGTH].rsplit(" ", 1)[0] + "..."

        _record_domain_success(domain)
        return text

    except requests.RequestException as exc:
        logger.warning("Failed to fetch %s: %s", url, exc)
        # requests failed entirely — try Playwright before giving up
        if PLAYWRIGHT_FALLBACK_ENABLED and not _is_domain_blocked(domain):
            logger.debug("Trying Playwright fallback after request failure for %s", url)
            pw_text = _extract_with_playwright(url)
            if pw_text and len(pw_text) > 100:
                _record_domain_success(domain)
                # Clean up and truncate
                lines = [line.strip() for line in pw_text.splitlines()]
                pw_text = "\n\n".join(line for line in lines if line)
                if len(pw_text) > MAX_CONTENT_LENGTH:
                    pw_text = pw_text[:MAX_CONTENT_LENGTH].rsplit(" ", 1)[0] + "..."
                return pw_text
        _record_domain_failure(domain)
        return None
    except Exception as exc:
        logger.warning("Error extracting text from %s: %s", url, exc)
        _record_domain_failure(domain)
        return None


def enrich_item_content(session: Session, item_id: int) -> bool:
    """Enrich a single item by fetching full article text if content is short.

    If the item's content is under 200 characters and it has a URL, fetches
    the full article text and updates the content field.

    Returns True if the item was enriched, False otherwise.
    """
    item = session.query(RawItem).filter(RawItem.id == item_id).first()
    if item is None:
        logger.warning("Item %d not found for enrichment", item_id)
        return False

    current_content = item.content or ""
    if len(current_content) >= 200:
        logger.debug("Item %d already has sufficient content (%d chars)", item_id, len(current_content))
        return False

    if not item.url:
        logger.debug("Item %d has no URL for enrichment", item_id)
        return False

    # Skip if the domain is currently blocked
    domain = _get_domain(item.url)
    if _is_domain_blocked(domain):
        logger.debug(
            "Skipping item %d: domain %s is temporarily blocked",
            item_id, domain,
        )
        return False

    logger.info("Enriching item %d from %s", item_id, item.url)
    full_text = extract_article_text(item.url)

    if full_text and len(full_text) > len(current_content):
        item.content = full_text
        session.commit()
        logger.info(
            "Enriched item %d: %d -> %d chars",
            item_id, len(current_content), len(full_text),
        )
        return True

    return False


def _enrich_worker(item_id: int, item_url: str, use_playwright: bool = False) -> str:
    """Worker function for enrichment.

    Each call creates its own DB session to ensure thread safety.
    When use_playwright=False, Playwright fallback is temporarily disabled
    so it can safely run in a thread pool.
    Returns 'enriched', 'skipped', 'needs_playwright', or 'failed'.
    """
    from osint_monitor.core.database import get_session

    domain = _get_domain(item_url)
    if _is_domain_blocked(domain):
        logger.debug("Skipping item %d: domain %s blocked", item_id, domain)
        return "skipped"

    thread_session = get_session()
    try:
        if not use_playwright:
            # First pass: requests only, no Playwright (thread-safe)
            global PLAYWRIGHT_FALLBACK_ENABLED
            old_val = PLAYWRIGHT_FALLBACK_ENABLED
            PLAYWRIGHT_FALLBACK_ENABLED = False
            try:
                success = enrich_item_content(thread_session, item_id)
            finally:
                PLAYWRIGHT_FALLBACK_ENABLED = old_val
            if success:
                return "enriched"
            return "needs_playwright"
        else:
            # Second pass: Playwright enabled (must run on main thread)
            success = enrich_item_content(thread_session, item_id)
            if success:
                return "enriched"
            return "skipped"
    except Exception as exc:
        logger.error("Failed to enrich item %d: %s", item_id, exc)
        thread_session.rollback()
        return "failed"
    finally:
        thread_session.close()


def enrich_recent_items(
    session: Session, hours_back: int = 24, max_items: int = 50
) -> dict[str, int]:
    """Batch enrich recent items that have short content.

    Prioritizes items from high-credibility sources. Uses a thread pool
    (4 workers) to fetch and extract articles concurrently. Skips domains
    that have repeatedly failed extraction.

    Returns a summary dict with counts of processed/enriched/skipped/failed items.
    """
    cutoff = datetime.utcnow() - timedelta(hours=hours_back)

    # Query items with short content, prioritizing high-credibility sources
    items = (
        session.query(RawItem)
        .join(Source, RawItem.source_id == Source.id)
        .filter(
            RawItem.fetched_at >= cutoff,
            RawItem.url.isnot(None),
            RawItem.url != "",
            func.length(func.coalesce(RawItem.content, "")) < 200,
        )
        .order_by(Source.credibility_score.desc())
        .limit(max_items)
        .all()
    )

    # Collect item IDs and URLs before entering the thread pool — avoid
    # passing ORM objects across threads (they're bound to the caller's session).
    work_items = [(item.id, item.url or "") for item in items]

    stats = {
        "total_candidates": len(work_items),
        "enriched": 0,
        "skipped": 0,
        "failed": 0,
    }

    logger.info(
        "Found %d items to enrich (last %d hours, max %d)",
        len(work_items), hours_back, max_items,
    )

    if not work_items:
        return stats

    # Pass 1: parallel requests-based extraction (no Playwright — thread-safe)
    playwright_queue: list[tuple[int, str]] = []
    with ThreadPoolExecutor(max_workers=6) as executor:
        future_to_item = {
            executor.submit(_enrich_worker, item_id, item_url, False): (item_id, item_url)
            for item_id, item_url in work_items
        }
        for future in as_completed(future_to_item):
            item_id, item_url = future_to_item[future]
            try:
                result = future.result()
                if result == "needs_playwright":
                    playwright_queue.append((item_id, item_url))
                else:
                    stats[result] += 1
            except Exception as exc:
                logger.error("Unexpected error enriching item %d: %s", item_id, exc)
                stats["failed"] += 1

    # Pass 2: Playwright fallback on main thread (not thread-safe)
    if playwright_queue and PLAYWRIGHT_FALLBACK_ENABLED:
        for item_id, item_url in playwright_queue:
            result = _enrich_worker(item_id, item_url, use_playwright=True)
            stats[result] += 1

    logger.info(
        "Enrichment complete: %d enriched, %d skipped, %d failed out of %d",
        stats["enriched"], stats["skipped"], stats["failed"], stats["total_candidates"],
    )

    return stats
