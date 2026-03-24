"""Configuration loading and validation."""

import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


BASE_DIR = Path(__file__).parent.parent.parent
CONFIG_DIR = BASE_DIR / "config"
DATA_DIR = BASE_DIR / "data"


class SourceConfig(BaseModel):
    name: str
    url: str
    type: str = "rss"
    category: str = "general"
    credibility_score: float = 0.5
    priority: int = 2
    poll_interval: int = 900
    enabled: bool = True


class TwitterAccountConfig(BaseModel):
    username: str
    focus: str = "general"
    credibility_score: float = 0.4


class RegionConfig(BaseModel):
    keywords: list[str] = Field(default_factory=list)
    priority: int = 2


class AlertKeywordsConfig(BaseModel):
    critical: list[str] = Field(default_factory=list)
    high: list[str] = Field(default_factory=list)


class AlertRuleConfig(BaseModel):
    name: str
    type: str = "keyword"  # keyword, anomaly, trend, threshold, compound
    conditions: dict = Field(default_factory=dict)
    severity: float = 0.5
    cooldown_minutes: int = 240
    channels: list[str] = Field(default_factory=lambda: ["desktop"])


class AlertChannelConfig(BaseModel):
    type: str  # email, slack, discord, webhook, desktop
    enabled: bool = True
    config: dict = Field(default_factory=dict)


class AlertsConfig(BaseModel):
    rules: list[AlertRuleConfig] = Field(default_factory=list)
    channels: list[AlertChannelConfig] = Field(default_factory=list)
    quiet_hours: dict = Field(default_factory=dict)  # {"start": "22:00", "end": "07:00"}
    default_cooldown_minutes: int = 240


class EntitySeedConfig(BaseModel):
    canonical_name: str
    entity_type: str
    aliases: list[str] = Field(default_factory=list)
    wikidata_id: Optional[str] = None


class TierConfig(BaseModel):
    hot_interval_seconds: int = 150    # 2.5 min
    warm_interval_seconds: int = 600   # 10 min
    cold_interval_seconds: int = 3600  # 60 min


class SourcesFileConfig(BaseModel):
    rss_feeds: list[SourceConfig] = Field(default_factory=list)
    twitter_accounts: list[TwitterAccountConfig] = Field(default_factory=list)
    nitter_instances: list[str] = Field(default_factory=list)
    alert_keywords: AlertKeywordsConfig = Field(default_factory=AlertKeywordsConfig)
    regions: dict[str, RegionConfig] = Field(default_factory=dict)
    tiers: TierConfig = Field(default_factory=TierConfig)


class AppSettings(BaseSettings):
    """App-level settings from environment variables."""
    db_url: str = f"sqlite:///{DATA_DIR / 'osint.db'}"
    openai_api_key: Optional[str] = None
    openai_model: str = "gpt-4o-mini"
    anthropic_api_key: Optional[str] = None
    ollama_base_url: str = "http://localhost:11434"
    default_llm_provider: str = "openai"
    spacy_model: str = "en_core_web_lg"
    embedding_model: str = "all-MiniLM-L6-v2"
    log_level: str = "INFO"
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    model_config = {"env_prefix": "OSINT_", "env_file": str(BASE_DIR / ".env"), "extra": "ignore"}


def load_sources_config(path: Path | None = None) -> SourcesFileConfig:
    """Load and validate sources.yaml."""
    path = path or CONFIG_DIR / "sources.yaml"
    with open(path) as f:
        raw = yaml.safe_load(f)
    return SourcesFileConfig(**raw)


def load_entities_config(path: Path | None = None) -> list[EntitySeedConfig]:
    """Load and validate entities.yaml."""
    path = path or CONFIG_DIR / "entities.yaml"
    if not path.exists():
        return []
    with open(path) as f:
        raw = yaml.safe_load(f)
    return [EntitySeedConfig(**e) for e in raw.get("entities", [])]


def load_alerts_config(path: Path | None = None) -> AlertsConfig:
    """Load and validate alerts.yaml."""
    path = path or CONFIG_DIR / "alerts.yaml"
    if not path.exists():
        return AlertsConfig()
    with open(path) as f:
        raw = yaml.safe_load(f)
    return AlertsConfig(**raw)


def get_settings() -> AppSettings:
    """Get application settings."""
    return AppSettings()
