"""Alert delivery channels: email, Slack, Discord, webhook, desktop."""

from __future__ import annotations

import json
import logging
import smtplib
from abc import ABC, abstractmethod
from email.mime.text import MIMEText

import requests

from osint_monitor.core.database import Alert

logger = logging.getLogger(__name__)


class AlertChannel(ABC):
    """Abstract alert delivery channel."""

    @abstractmethod
    def send(self, alert: Alert) -> bool:
        """Send an alert. Returns True on success."""
        ...

    def format_alert(self, alert: Alert) -> str:
        severity_map = {1.0: "CRITICAL", 0.75: "HIGH", 0.5: "MEDIUM"}
        level = severity_map.get(alert.severity, f"SEV-{alert.severity:.1f}")
        return f"[{level}] {alert.title}\n{alert.detail or ''}"


class DesktopChannel(AlertChannel):
    """Desktop notification via plyer."""

    def send(self, alert: Alert) -> bool:
        try:
            from plyer import notification
            notification.notify(
                title=f"OSINT Alert: {alert.title[:50]}",
                message=alert.detail[:200] if alert.detail else alert.title,
                app_name="OSINT Monitor",
                timeout=10,
            )
            return True
        except ImportError:
            logger.debug("plyer not installed, skipping desktop notification")
            return False
        except Exception as e:
            logger.error(f"Desktop notification failed: {e}")
            return False


class SlackChannel(AlertChannel):
    """Slack webhook channel."""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send(self, alert: Alert) -> bool:
        try:
            emoji = ":rotating_light:" if alert.severity >= 0.9 else ":warning:"
            payload = {
                "text": f"{emoji} *{alert.title}*\n{alert.detail or ''}",
                "unfurl_links": False,
            }
            resp = requests.post(self.webhook_url, json=payload, timeout=10)
            return resp.status_code == 200
        except Exception as e:
            logger.error(f"Slack delivery failed: {e}")
            return False


class DiscordChannel(AlertChannel):
    """Discord webhook channel."""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send(self, alert: Alert) -> bool:
        try:
            color = 0xFF0000 if alert.severity >= 0.9 else 0xFF8C00
            payload = {
                "embeds": [{
                    "title": alert.title[:256],
                    "description": (alert.detail or "")[:4096],
                    "color": color,
                    "footer": {"text": f"OSINT Monitor | Severity: {alert.severity:.2f}"},
                }]
            }
            resp = requests.post(self.webhook_url, json=payload, timeout=10)
            return resp.status_code in (200, 204)
        except Exception as e:
            logger.error(f"Discord delivery failed: {e}")
            return False


class WebhookChannel(AlertChannel):
    """Generic webhook channel."""

    def __init__(self, url: str, headers: dict | None = None):
        self.url = url
        self.headers = headers or {"Content-Type": "application/json"}

    def send(self, alert: Alert) -> bool:
        try:
            payload = {
                "alert_type": alert.alert_type,
                "severity": alert.severity,
                "title": alert.title,
                "detail": alert.detail,
                "timestamp": alert.created_at.isoformat() if alert.created_at else None,
            }
            resp = requests.post(self.url, json=payload, headers=self.headers, timeout=10)
            return resp.status_code < 400
        except Exception as e:
            logger.error(f"Webhook delivery failed: {e}")
            return False


class EmailChannel(AlertChannel):
    """SMTP email channel."""

    def __init__(self, smtp_host: str, smtp_port: int, username: str, password: str,
                 from_addr: str, to_addrs: list[str], use_tls: bool = True):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_addr = from_addr
        self.to_addrs = to_addrs
        self.use_tls = use_tls

    def send(self, alert: Alert) -> bool:
        try:
            msg = MIMEText(self.format_alert(alert))
            msg["Subject"] = f"OSINT Alert: {alert.title[:78]}"
            msg["From"] = self.from_addr
            msg["To"] = ", ".join(self.to_addrs)

            if self.use_tls:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port)
                server.starttls()
            else:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port)

            server.login(self.username, self.password)
            server.sendmail(self.from_addr, self.to_addrs, msg.as_string())
            server.quit()
            return True
        except Exception as e:
            logger.error(f"Email delivery failed: {e}")
            return False


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def build_channels(config_list: list[dict]) -> list[AlertChannel]:
    """Build channel instances from alerts.yaml config."""
    channels = []
    for cfg in config_list:
        ch_type = cfg.get("type", "")
        ch_config = cfg.get("config", {})

        if not cfg.get("enabled", True):
            continue

        if ch_type == "desktop":
            channels.append(DesktopChannel())
        elif ch_type == "slack":
            channels.append(SlackChannel(ch_config["webhook_url"]))
        elif ch_type == "discord":
            channels.append(DiscordChannel(ch_config["webhook_url"]))
        elif ch_type == "webhook":
            channels.append(WebhookChannel(ch_config["url"], ch_config.get("headers")))
        elif ch_type == "email":
            channels.append(EmailChannel(**ch_config))
        else:
            logger.warning(f"Unknown channel type: {ch_type}")

    return channels


def dispatch_alerts(alerts: list[Alert], channels: list[AlertChannel]):
    """Send alerts through all configured channels."""
    for alert in alerts:
        delivered = []
        for channel in channels:
            try:
                if channel.send(alert):
                    delivered.append(channel.__class__.__name__)
            except Exception as e:
                logger.error(f"Channel {channel.__class__.__name__} failed: {e}")

        if delivered:
            alert.delivered_via = ", ".join(delivered)
            logger.info(f"Alert delivered: {alert.title} via {alert.delivered_via}")
