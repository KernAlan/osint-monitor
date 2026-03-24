"""RSS/Atom feed collector."""

import re
from datetime import datetime

import feedparser
import requests as _requests

from osint_monitor.collectors.base import BaseCollector
from osint_monitor.core.models import RawItemModel

_RSS_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; OSINT-Monitor/2.0; +research)",
    "Accept": "application/rss+xml, application/xml, text/xml, */*",
}


class RSSCollector(BaseCollector):
    """Collects items from RSS/Atom feeds."""

    def __init__(self, name: str, url: str, **kwargs):
        super().__init__(name=name, source_type="rss", url=url, **kwargs)

    def collect(self) -> list[RawItemModel]:
        items = []
        try:
            try:
                resp = _requests.get(self.url, timeout=10, headers=_RSS_HEADERS)
                resp.raise_for_status()
                feed = feedparser.parse(resp.text)
            except _requests.RequestException:
                # Fallback to feedparser's own fetcher (different UA, handles redirects)
                feed = feedparser.parse(self.url)
            for entry in feed.entries[:self.max_items]:
                pub_date = self._parse_date(entry)
                description = self._clean_html(
                    getattr(entry, "description", "") or ""
                )
                content = self._get_full_content(entry) or description

                items.append(RawItemModel(
                    title=entry.get("title", "No title"),
                    content=content[:5000],
                    url=entry.get("link", ""),
                    published_at=pub_date,
                    source_name=self.name,
                    external_id=entry.get("id") or entry.get("link", ""),
                    fetched_at=datetime.utcnow(),
                ))
            print(f"  [ok] {self.name}: {len(items)} items")
        except Exception as e:
            print(f"  [err] {self.name}: {e}")
        return items

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

    @staticmethod
    def _clean_html(text: str) -> str:
        return re.sub(r"<[^>]+>", "", text).strip()

    @staticmethod
    def _get_full_content(entry) -> str | None:
        content_list = getattr(entry, "content", None)
        if content_list and isinstance(content_list, list):
            raw = content_list[0].get("value", "")
            return re.sub(r"<[^>]+>", "", raw).strip()
        return None


class NitterCollector(RSSCollector):
    """Collects Twitter/X via Nitter RSS proxy.

    Tries each Nitter instance in order as a fallback chain.
    Only logs a single result line to avoid duplicate output per account.
    """

    def __init__(self, username: str, instances: list[str] | None = None, **kwargs):
        self.username = username.lstrip("@")
        self.instances = instances or ["https://nitter.net"]
        super().__init__(
            name=f"@{self.username}",
            url=f"{self.instances[0]}/{self.username}/rss",
            **kwargs,
        )
        self.source_type = "twitter_nitter"

    def collect(self) -> list[RawItemModel]:
        last_error = None
        for instance in self.instances:
            self.url = f"{instance}/{self.username}/rss"
            try:
                resp = _requests.get(self.url, timeout=10, headers=_RSS_HEADERS)
                resp.raise_for_status()
                feed = feedparser.parse(resp.text)
                items = []
                for entry in feed.entries[:self.max_items]:
                    pub_date = self._parse_date(entry)
                    description = self._clean_html(
                        getattr(entry, "description", "") or ""
                    )
                    content = self._get_full_content(entry) or description

                    items.append(RawItemModel(
                        title=entry.get("title", "No title"),
                        content=content[:5000],
                        url=entry.get("link", ""),
                        published_at=pub_date,
                        source_name=self.name,
                        external_id=entry.get("id") or entry.get("link", ""),
                        fetched_at=datetime.utcnow(),
                    ))
                if items:
                    print(f"  [ok] {self.name}: {len(items)} items (via {instance})")
                    return items
            except Exception as e:
                last_error = e
                continue

        # All instances exhausted — log once
        if last_error:
            print(f"  [err] {self.name}: all Nitter instances failed (last: {last_error})")
        else:
            print(f"  [--] {self.name}: 0 items (tried {len(self.instances)} instances)")
        return []
