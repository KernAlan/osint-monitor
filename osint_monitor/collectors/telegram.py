"""Telegram channel collector via Telethon."""

from __future__ import annotations

import logging
import os
from datetime import datetime

from osint_monitor.collectors.base import BaseCollector
from osint_monitor.core.models import RawItemModel

logger = logging.getLogger(__name__)


class TelegramCollector(BaseCollector):
    """Collects from Telegram channels via Telethon.

    Requires:
    - TELEGRAM_API_ID env var
    - TELEGRAM_API_HASH env var
    - First run requires interactive auth (session saved for reuse)
    """

    def __init__(self, channel: str, **kwargs):
        self.channel = channel
        self.api_id = os.environ.get("TELEGRAM_API_ID")
        self.api_hash = os.environ.get("TELEGRAM_API_HASH")
        super().__init__(
            name=f"tg:{channel}",
            source_type="telegram",
            url=f"https://t.me/{channel}",
            **kwargs,
        )

    def collect(self) -> list[RawItemModel]:
        if not self.api_id or not self.api_hash:
            logger.debug(f"Telegram credentials not set, skipping {self.channel}")
            return []

        try:
            return self._collect_async()
        except Exception as e:
            logger.error(f"Telegram collection failed for {self.channel}: {e}")
            return []

    def _collect_async(self) -> list[RawItemModel]:
        import asyncio
        from telethon.sync import TelegramClient

        items = []
        session_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "data", "telegram_session"
        )

        with TelegramClient(session_path, int(self.api_id), self.api_hash) as client:
            for message in client.iter_messages(self.channel, limit=self.max_items):
                if not message.text:
                    continue
                items.append(RawItemModel(
                    title=message.text[:200],
                    content=message.text,
                    url=f"https://t.me/{self.channel}/{message.id}",
                    published_at=message.date.replace(tzinfo=None) if message.date else None,
                    source_name=f"tg:{self.channel}",
                    external_id=f"tg_{self.channel}_{message.id}",
                    fetched_at=datetime.utcnow(),
                ))

        print(f"  [ok] tg:{self.channel}: {len(items)} messages")
        return items

    def health_check(self) -> bool:
        return bool(self.api_id and self.api_hash)
