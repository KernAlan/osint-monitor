"""Generic web scraper collector for custom sources."""

from __future__ import annotations

import logging
import re
from datetime import datetime

import requests
from bs4 import BeautifulSoup

from osint_monitor.collectors.base import BaseCollector
from osint_monitor.core.models import RawItemModel

logger = logging.getLogger(__name__)


class CustomWebCollector(BaseCollector):
    """Generic web page scraper with CSS selectors."""

    def __init__(
        self,
        name: str,
        url: str,
        article_selector: str = "article",
        title_selector: str = "h2",
        link_selector: str = "a",
        content_selector: str = "p",
        **kwargs,
    ):
        super().__init__(name=name, source_type="custom", url=url, **kwargs)
        self.article_selector = article_selector
        self.title_selector = title_selector
        self.link_selector = link_selector
        self.content_selector = content_selector

    def collect(self) -> list[RawItemModel]:
        items = []
        try:
            resp = requests.get(self.url, timeout=30, headers={
                "User-Agent": "OSINT-Monitor/2.0 (research tool)",
            })
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, "html.parser")

            for article in soup.select(self.article_selector)[:self.max_items]:
                title_el = article.select_one(self.title_selector)
                link_el = article.select_one(self.link_selector)
                content_el = article.select_one(self.content_selector)

                title = title_el.get_text(strip=True) if title_el else ""
                link = link_el.get("href", "") if link_el else ""
                content = content_el.get_text(strip=True) if content_el else ""

                if not title:
                    continue

                # Resolve relative URLs
                if link and not link.startswith("http"):
                    from urllib.parse import urljoin
                    link = urljoin(self.url, link)

                items.append(RawItemModel(
                    title=title,
                    content=content[:5000],
                    url=link,
                    source_name=self.name,
                    external_id=link or title[:100],
                    fetched_at=datetime.utcnow(),
                ))

            print(f"  [ok] {self.name}: {len(items)} items")
        except Exception as e:
            print(f"  [err] {self.name}: {e}")

        return items
