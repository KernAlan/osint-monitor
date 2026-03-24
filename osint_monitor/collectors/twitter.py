"""Twitter/X collector via API v2 (tweepy) with Nitter RSS fallback."""

from __future__ import annotations

import logging
import os
from datetime import datetime

from osint_monitor.collectors.base import BaseCollector
from osint_monitor.collectors.rss import NitterCollector
from osint_monitor.core.models import RawItemModel

logger = logging.getLogger(__name__)


class TwitterAPICollector(BaseCollector):
    """Collects from Twitter/X via API v2 using tweepy.

    Requires TWITTER_BEARER_TOKEN env var.
    Free tier: 10k tweets/month.
    """

    def __init__(self, username: str, nitter_instances: list[str] | None = None, **kwargs):
        self.username = username
        self.bearer_token = os.environ.get("TWITTER_BEARER_TOKEN")
        self._nitter_fallback = NitterCollector(
            username=username,
            instances=nitter_instances,
            **kwargs,
        )
        super().__init__(
            name=f"@{username}",
            source_type="twitter",
            url=f"https://twitter.com/{username}",
            **kwargs,
        )

    def collect(self) -> list[RawItemModel]:
        if self.bearer_token:
            try:
                return self._collect_via_api()
            except Exception as e:
                logger.warning(f"Twitter API failed for @{self.username}: {e}, trying Nitter")

        return self._nitter_fallback.collect()

    def _collect_via_api(self) -> list[RawItemModel]:
        import tweepy

        client = tweepy.Client(bearer_token=self.bearer_token)

        # Get user ID
        user = client.get_user(username=self.username)
        if not user.data:
            return []

        # Get recent tweets
        tweets = client.get_users_tweets(
            user.data.id,
            max_results=min(self.max_items, 100),
            tweet_fields=["created_at", "text", "id"],
        )

        items = []
        if tweets.data:
            for tweet in tweets.data:
                items.append(RawItemModel(
                    title=tweet.text[:200],
                    content=tweet.text,
                    url=f"https://twitter.com/{self.username}/status/{tweet.id}",
                    published_at=tweet.created_at,
                    source_name=f"@{self.username}",
                    external_id=str(tweet.id),
                    fetched_at=datetime.utcnow(),
                ))
            print(f"  [ok] @{self.username} (API): {len(items)} tweets")

        return items
