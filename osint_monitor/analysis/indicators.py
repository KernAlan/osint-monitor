"""Indicators & Warnings (I&W) framework for geopolitical scenario monitoring.

Scans recent OSINT items against predefined indicator sets to assess
threat levels for specific geopolitical scenarios.

Features:
- Entity-aware indicator matching (entity+keyword co-occurrence)
- Temporal decay weighting (recent evidence weighted higher)
- Historical baseline comparison
- Escalation probability modeling (logistic)
- YAML-configurable scenarios
- Red Team / Devil's Advocate counter-assessment via LLM
"""

from __future__ import annotations

import logging
import math
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import func
from sqlalchemy.orm import Session

from osint_monitor.core.database import (
    Entity,
    ItemEntity,
    RawItem,
    Source,
    TrendSnapshot,
)

logger = logging.getLogger(__name__)

# Default path for YAML scenario config
_DEFAULT_YAML_PATH = Path(__file__).parent.parent.parent / "config" / "indicators.yaml"


# ---------------------------------------------------------------------------
# Indicator & Warning Scenario Definitions (hardcoded defaults)
# ---------------------------------------------------------------------------

IW_SCENARIOS: dict[str, dict[str, Any]] = {
    "iran_nuclear_breakout": {
        "description": "Iran moves toward nuclear weapon capability",
        "indicators": [
            {
                "name": "IAEA inspector expulsion",
                "weight": 0.9,
                "keywords": ["IAEA", "inspector", "expel", "access denied"],
                "entities": ["IAEA", "Iran"],
            },
            {
                "name": "Enrichment above 60%",
                "weight": 0.95,
                "keywords": ["enrichment", "90%", "weapons-grade", "HEU"],
                "entities": ["IRGC", "Iran"],
            },
            {
                "name": "Fordow/Natanz expansion",
                "weight": 0.7,
                "keywords": ["Fordow", "Natanz", "centrifuge", "cascade"],
                "entities": ["Iran"],
            },
            {
                "name": "Arak reactor restart",
                "weight": 0.6,
                "keywords": ["Arak", "heavy water", "plutonium"],
                "entities": ["Iran"],
            },
        ],
    },
    "china_taiwan_invasion": {
        "description": "China military action against Taiwan",
        "indicators": [
            {
                "name": "PLA amphibious exercise surge",
                "weight": 0.8,
                "keywords": ["amphibious", "exercise", "Fujian", "landing"],
                "entities": ["PLA", "China"],
            },
            {
                "name": "PLAN carrier group deployment",
                "weight": 0.7,
                "keywords": ["carrier", "Shandong", "Fujian", "Taiwan Strait"],
                "entities": ["PLAN", "China"],
            },
            {
                "name": "Civilian vessel requisition",
                "weight": 0.9,
                "keywords": ["civilian", "requisition", "ferry", "ro-ro"],
                "entities": ["China"],
            },
            {
                "name": "Embassy evacuation advisory",
                "weight": 0.95,
                "keywords": ["embassy", "evacuate", "Taiwan", "departure"],
                "entities": ["Taiwan"],
            },
            {
                "name": "Cyber attacks on Taiwan",
                "weight": 0.6,
                "keywords": ["cyber", "Taiwan", "attack", "infrastructure"],
                "entities": ["Taiwan", "China"],
            },
        ],
    },
    "russia_nato_escalation": {
        "description": "Russia-NATO direct military confrontation",
        "indicators": [
            {
                "name": "Nuclear posture change",
                "weight": 0.95,
                "keywords": ["nuclear", "posture", "strategic forces", "SSBN", "surge"],
                "entities": ["Russia"],
            },
            {
                "name": "GPS jamming in NATO space",
                "weight": 0.7,
                "keywords": ["GPS", "jamming", "Baltic", "Nordic"],
                "entities": ["Russia", "NATO"],
            },
            {
                "name": "Article 5 discussion",
                "weight": 0.8,
                "keywords": ["Article 5", "invoke", "collective defense"],
                "entities": ["NATO"],
            },
            {
                "name": "Submarine surge",
                "weight": 0.75,
                "keywords": ["submarine", "GIUK gap", "North Atlantic", "patrol"],
                "entities": ["Russia"],
            },
            {
                "name": "Baltic/Nordic airspace violation",
                "weight": 0.6,
                "keywords": ["airspace", "violation", "intercept", "scramble"],
                "entities": ["Russia", "NATO"],
            },
        ],
    },
    "middle_east_regional_war": {
        "description": "Multi-state Middle East conflict escalation",
        "indicators": [
            {
                "name": "Hezbollah rocket barrage",
                "weight": 0.8,
                "keywords": ["Hezbollah", "rocket", "barrage", "northern Israel"],
                "entities": ["Hezbollah", "Israel"],
            },
            {
                "name": "Strait of Hormuz closure",
                "weight": 0.9,
                "keywords": ["Hormuz", "closure", "blockade", "mining"],
                "entities": ["Iran"],
            },
            {
                "name": "Houthi anti-ship escalation",
                "weight": 0.7,
                "keywords": ["Houthi", "ship", "Red Sea", "Bab el-Mandeb"],
                "entities": ["Houthi"],
            },
            {
                "name": "US carrier group redeployment",
                "weight": 0.6,
                "keywords": ["carrier", "CENTCOM", "deployment", "Persian Gulf"],
                "entities": ["United States"],
            },
        ],
    },
}


# ---------------------------------------------------------------------------
# YAML scenario loading
# ---------------------------------------------------------------------------

def load_iw_scenarios_from_yaml(path: Path | None = None) -> dict[str, dict[str, Any]]:
    """Load I&W scenarios from a YAML configuration file.

    Falls back to the hardcoded IW_SCENARIOS if the file doesn't exist or
    cannot be parsed.

    Args:
        path: Path to the YAML file.  Defaults to config/indicators.yaml.

    Returns:
        dict mapping scenario keys to scenario definitions.
    """
    yaml_path = path or _DEFAULT_YAML_PATH

    if not yaml_path.exists():
        logger.info(
            "YAML scenario file not found at %s; using hardcoded defaults", yaml_path
        )
        return IW_SCENARIOS

    try:
        with open(yaml_path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, dict):
            raise ValueError("Top-level YAML must be a mapping of scenario keys")
        logger.info("Loaded %d I&W scenarios from %s", len(data), yaml_path)
        return data
    except Exception as exc:
        logger.error("Failed to load YAML scenarios from %s: %s", yaml_path, exc)
        return IW_SCENARIOS


def _get_active_scenarios() -> dict[str, dict[str, Any]]:
    """Return the active scenario set (YAML if available, else hardcoded)."""
    return load_iw_scenarios_from_yaml()


# ---------------------------------------------------------------------------
# Keyword matching helpers
# ---------------------------------------------------------------------------

def _item_matches_keywords(item: RawItem, keywords: list[str]) -> bool:
    """Check if any keyword appears in the item's title or content (case-insensitive)."""
    text = f"{item.title or ''} {item.content or ''}".lower()
    for kw in keywords:
        if kw.lower() in text:
            return True
    return False


def _build_keyword_pattern(keywords: list[str]) -> re.Pattern:
    """Build a compiled regex that matches any of the keywords (case-insensitive)."""
    escaped = [re.escape(kw) for kw in keywords]
    return re.compile("|".join(escaped), re.IGNORECASE)


# ---------------------------------------------------------------------------
# Entity-aware matching
# ---------------------------------------------------------------------------

def _item_has_entity(
    session: Session,
    item: RawItem,
    entity_names: list[str],
    _cache: dict[int, set[str]] | None = None,
) -> bool:
    """Check whether an item is linked to at least one of the given entities
    via the ItemEntity table.

    Uses canonical_name or alias matching (case-insensitive).  An optional
    ``_cache`` dict (item_id -> set of lowercase entity names) avoids
    repeated DB round-trips when evaluating multiple indicators against the
    same item set.
    """
    if _cache is not None and item.id in _cache:
        item_entities = _cache[item.id]
    else:
        # Query entities linked to this item
        rows = (
            session.query(Entity.canonical_name, Entity.aliases)
            .join(ItemEntity, ItemEntity.entity_id == Entity.id)
            .filter(ItemEntity.item_id == item.id)
            .all()
        )
        item_entity_names: set[str] = set()
        for canonical, aliases in rows:
            item_entity_names.add(canonical.lower())
            if aliases:
                # aliases is stored as a JSON list of strings
                alias_list = aliases if isinstance(aliases, list) else []
                for a in alias_list:
                    item_entity_names.add(a.lower())
        if _cache is not None:
            _cache[item.id] = item_entity_names
        item_entities = item_entity_names

    target_names = {n.lower() for n in entity_names}
    return bool(item_entities & target_names)


def _item_matches_indicator(
    session: Session,
    item: RawItem,
    indicator: dict[str, Any],
    entity_cache: dict[int, set[str]] | None = None,
) -> bool:
    """Check if an item matches an indicator.

    If the indicator defines ``entities``, BOTH a keyword match AND an entity
    co-occurrence are required.  Otherwise, keyword-only matching is used
    (backward compatible).
    """
    if not _item_matches_keywords(item, indicator["keywords"]):
        return False

    entity_names = indicator.get("entities")
    if entity_names:
        return _item_has_entity(session, item, entity_names, _cache=entity_cache)

    return True


# ---------------------------------------------------------------------------
# LLM-scored indicator evaluation
# ---------------------------------------------------------------------------

def evaluate_indicators_llm(
    session: Session,
    hours_back: int = 24,
    provider: str | None = None,
) -> list[dict[str, Any]]:
    """Evaluate I&W scenarios using LLM relevance scoring instead of keywords.

    For each scenario, sends a batch of recent item titles to the LLM and asks
    it to score each item's relevance to each indicator on a 0-10 scale.
    Much more accurate than keyword matching but costs ~$0.01-0.02 per run.

    Falls back to keyword-based evaluate_indicators() if LLM is unavailable.
    """
    try:
        from osint_monitor.analysis.llm import get_llm
        llm = get_llm(provider)
    except Exception as e:
        logger.warning("LLM unavailable for I&W scoring, falling back to keywords: %s", e)
        return evaluate_indicators(session, hours_back)

    scenarios = _get_active_scenarios()
    cutoff = datetime.utcnow() - timedelta(hours=hours_back)
    recent_items = (
        session.query(RawItem)
        .filter(RawItem.fetched_at >= cutoff)
        .all()
    )

    if not recent_items:
        return [_baseline_result(key, sc) for key, sc in scenarios.items()]

    # Build item summaries (batch to avoid token explosion)
    item_summaries = []
    for item in recent_items[:100]:  # cap at 100 for cost control
        title = (item.title or "")[:150]
        source = item.source.name if item.source else "Unknown"
        item_summaries.append({"id": item.id, "text": f"[{source}] {title}", "item": item})

    results = []
    for scenario_key, scenario in scenarios.items():
        result = _evaluate_scenario_llm(llm, scenario_key, scenario, item_summaries)
        results.append(result)

    results.sort(key=lambda r: r["threat_score"], reverse=True)
    return results


def _evaluate_scenario_llm(
    llm,
    scenario_key: str,
    scenario: dict[str, Any],
    item_summaries: list[dict],
) -> dict[str, Any]:
    """Evaluate one scenario against items using LLM scoring."""
    indicators = scenario["indicators"]
    indicator_names = [ind["name"] for ind in indicators]

    # Build prompt
    items_text = "\n".join(f"{i+1}. {s['text']}" for i, s in enumerate(item_summaries))
    indicators_text = "\n".join(f"- {name}" for name in indicator_names)

    prompt = f"""You are an intelligence analyst evaluating Indicators & Warnings.

SCENARIO: {scenario['description']}

INDICATORS TO EVALUATE:
{indicators_text}

RECENT INTELLIGENCE ITEMS:
{items_text}

For each indicator, list which item numbers (if any) are GENUINELY relevant evidence for that specific indicator. Be strict -- an item about "Arctic military exercises" is NOT evidence for "PLA amphibious exercise surge" even though both mention exercises.

Respond as JSON:
{{
  "indicator_name_1": [item_numbers],
  "indicator_name_2": [item_numbers],
  ...
}}

Only include item numbers that are genuinely relevant. Empty list [] if no items match."""

    try:
        import json
        response = llm.generate(prompt, system="You are a strict intelligence analyst. Only mark items as relevant if they directly provide evidence for the specific indicator. No false positives.", temperature=0.1)

        # Parse response
        text = response.strip()
        if text.startswith("```"):
            text = "\n".join(l for l in text.split("\n") if not l.strip().startswith("```"))
        scores = json.loads(text)
    except Exception as e:
        logger.warning("LLM scoring failed for %s: %s, falling back", scenario_key, e)
        return _baseline_result(scenario_key, scenario)

    # Build result from LLM scores
    triggered = []
    total_weight = sum(ind["weight"] for ind in indicators)
    triggered_weight = 0.0
    total_evidence_count = 0

    for indicator in indicators:
        name = indicator["name"]
        matched_nums = scores.get(name, [])
        if not isinstance(matched_nums, list):
            matched_nums = []

        matching_items = []
        for num in matched_nums:
            idx = num - 1  # 1-indexed to 0-indexed
            if 0 <= idx < len(item_summaries):
                s = item_summaries[idx]
                item = s["item"]
                tw = compute_temporal_weight(item.published_at or item.fetched_at)
                matching_items.append({
                    "item_id": item.id,
                    "title": item.title,
                    "url": item.url,
                    "published_at": item.published_at.isoformat() if item.published_at else None,
                    "source_id": item.source_id,
                    "temporal_weight": round(tw, 4),
                })

        if matching_items:
            mean_tw = sum(m["temporal_weight"] for m in matching_items) / len(matching_items)
            triggered_weight += indicator["weight"] * mean_tw
            total_evidence_count += len(matching_items)
            triggered.append({
                "name": name,
                "weight": indicator["weight"],
                "evidence_count": len(matching_items),
                "mean_temporal_weight": round(mean_tw, 4),
                "evidence_items": matching_items[:10],
            })

    threat_score = triggered_weight / total_weight if total_weight > 0 else 0.0
    status = _score_to_status(threat_score)

    return {
        "scenario_key": scenario_key,
        "description": scenario["description"],
        "status": status,
        "threat_score": round(threat_score, 4),
        "triggered_indicators": triggered,
        "untriggered_indicators": [
            {"name": ind["name"], "weight": ind["weight"]}
            for ind in indicators
            if ind["name"] not in {t["name"] for t in triggered}
        ],
        "total_indicators": len(indicators),
        "triggered_count": len(triggered),
        "total_evidence_count": total_evidence_count,
        "scoring_method": "llm",
    }


# ---------------------------------------------------------------------------
# Temporal decay
# ---------------------------------------------------------------------------

def compute_temporal_weight(
    published_at: datetime | None,
    half_life_hours: float = 24.0,
) -> float:
    """Compute a temporal decay weight for an evidence item.

    Uses exponential decay: w = 2^(-age_hours / half_life_hours)

    Examples (half_life_hours=24):
        - 0 hours ago  -> 1.0
        - 6 hours ago  -> ~0.84
        - 24 hours ago -> 0.5
        - 48 hours ago -> 0.25

    Args:
        published_at: Item publish/fetch timestamp.  If None, returns 1.0.
        half_life_hours: Hours for weight to halve.

    Returns:
        Weight in (0.0, 1.0].
    """
    if published_at is None:
        return 1.0

    age_hours = (datetime.utcnow() - published_at).total_seconds() / 3600.0
    if age_hours < 0:
        age_hours = 0.0

    return math.pow(2, -age_hours / half_life_hours)


# ---------------------------------------------------------------------------
# Core evaluation
# ---------------------------------------------------------------------------

def evaluate_indicators(
    session: Session, hours_back: int = 24
) -> list[dict[str, Any]]:
    """Scan recent items against all I&W scenario indicator sets.

    Returns a list of scenario assessment dicts, one per scenario, containing:
        - scenario_key: str
        - description: str
        - status: "ELEVATED" | "WARNING" | "WATCH" | "BASELINE"
        - threat_score: float (0.0 - 1.0)
        - triggered_indicators: list of triggered indicator dicts
        - total_evidence_count: int
    """
    scenarios = _get_active_scenarios()

    cutoff = datetime.utcnow() - timedelta(hours=hours_back)
    recent_items = (
        session.query(RawItem)
        .filter(RawItem.fetched_at >= cutoff)
        .all()
    )

    if not recent_items:
        logger.info("No items in the last %d hours for I&W evaluation", hours_back)
        return [
            _baseline_result(key, scenario)
            for key, scenario in scenarios.items()
        ]

    results: list[dict[str, Any]] = []

    for scenario_key, scenario in scenarios.items():
        result = _evaluate_scenario(session, scenario_key, scenario, recent_items)
        results.append(result)

    # Sort by threat score descending
    results.sort(key=lambda r: r["threat_score"], reverse=True)
    return results


def _evaluate_scenario(
    session: Session,
    scenario_key: str,
    scenario: dict[str, Any],
    items: list[RawItem],
) -> dict[str, Any]:
    """Evaluate a single scenario against a set of items.

    Uses entity-aware matching and temporal decay weighting.
    """
    indicators = scenario["indicators"]
    triggered: list[dict[str, Any]] = []
    total_weight = sum(ind["weight"] for ind in indicators)
    triggered_weight = 0.0
    total_evidence_count = 0

    # Shared entity cache across indicators for this evaluation pass
    entity_cache: dict[int, set[str]] = {}

    for indicator in indicators:
        matching_items: list[dict[str, Any]] = []
        temporal_weight_sum = 0.0

        for item in items:
            if _item_matches_indicator(session, item, indicator, entity_cache):
                tw = compute_temporal_weight(item.published_at or item.fetched_at)
                temporal_weight_sum += tw
                matching_items.append({
                    "item_id": item.id,
                    "title": item.title,
                    "url": item.url,
                    "published_at": (
                        item.published_at.isoformat() if item.published_at else None
                    ),
                    "source_id": item.source_id,
                    "temporal_weight": round(tw, 4),
                })

        if matching_items:
            # Indicator contribution is its weight scaled by the mean temporal
            # weight of its evidence items (so stale-only evidence counts less).
            mean_tw = temporal_weight_sum / len(matching_items)
            triggered_weight += indicator["weight"] * mean_tw
            total_evidence_count += len(matching_items)
            triggered.append({
                "name": indicator["name"],
                "weight": indicator["weight"],
                "evidence_count": len(matching_items),
                "mean_temporal_weight": round(mean_tw, 4),
                "evidence_items": matching_items[:10],  # cap for readability
            })

    threat_score = triggered_weight / total_weight if total_weight > 0 else 0.0
    status = _score_to_status(threat_score)

    return {
        "scenario_key": scenario_key,
        "description": scenario["description"],
        "status": status,
        "threat_score": round(threat_score, 4),
        "triggered_indicators": triggered,
        "total_indicators": len(indicators),
        "triggered_count": len(triggered),
        "total_evidence_count": total_evidence_count,
    }


def _score_to_status(score: float) -> str:
    """Map a threat score to a human-readable status level."""
    if score > 0.5:
        return "ELEVATED"
    if score > 0.3:
        return "WARNING"
    if score > 0.1:
        return "WATCH"
    return "BASELINE"


def _baseline_result(
    scenario_key: str, scenario: dict[str, Any]
) -> dict[str, Any]:
    """Return a BASELINE result for a scenario (no data)."""
    return {
        "scenario_key": scenario_key,
        "description": scenario["description"],
        "status": "BASELINE",
        "threat_score": 0.0,
        "triggered_indicators": [],
        "total_indicators": len(scenario["indicators"]),
        "triggered_count": 0,
        "total_evidence_count": 0,
    }


# ---------------------------------------------------------------------------
# Detailed single-scenario status
# ---------------------------------------------------------------------------

def get_scenario_status(
    session: Session, scenario_key: str, hours_back: int = 72
) -> dict[str, Any]:
    """Get detailed status for one I&W scenario with full evidence chain.

    Returns a dict with:
        - scenario_key, description, status, threat_score
        - triggered_indicators with full evidence item details
        - timeline: evidence items sorted by publish date
        - source_breakdown: count of evidence items per source
    """
    scenarios = _get_active_scenarios()

    if scenario_key not in scenarios:
        logger.warning("Unknown I&W scenario: %s", scenario_key)
        return {
            "error": f"Unknown scenario: {scenario_key}",
            "available_scenarios": list(scenarios.keys()),
        }

    scenario = scenarios[scenario_key]
    cutoff = datetime.utcnow() - timedelta(hours=hours_back)

    recent_items = (
        session.query(RawItem)
        .join(Source, RawItem.source_id == Source.id)
        .filter(RawItem.fetched_at >= cutoff)
        .all()
    )

    # Base evaluation
    result = _evaluate_scenario(session, scenario_key, scenario, recent_items)

    # Enrich with timeline and source breakdown
    all_evidence_items: list[dict[str, Any]] = []
    source_counts: dict[str, int] = {}

    for trig in result["triggered_indicators"]:
        for ev in trig["evidence_items"]:
            all_evidence_items.append({
                **ev,
                "indicator_name": trig["name"],
                "indicator_weight": trig["weight"],
            })
            # Count by source
            src_id = ev.get("source_id")
            if src_id is not None:
                source = session.query(Source).filter(Source.id == src_id).first()
                src_name = source.name if source else f"source-{src_id}"
                source_counts[src_name] = source_counts.get(src_name, 0) + 1

    # Sort timeline by published_at
    all_evidence_items.sort(
        key=lambda x: x.get("published_at") or "9999",
        reverse=True,
    )

    result["timeline"] = all_evidence_items
    result["source_breakdown"] = source_counts
    result["hours_back"] = hours_back
    result["evaluated_at"] = datetime.utcnow().isoformat()

    return result


# ---------------------------------------------------------------------------
# Historical baseline comparison
# ---------------------------------------------------------------------------

def compare_to_baseline(
    session: Session,
    scenario_key: str,
    current_score: float,
    baseline_days: int = 30,
) -> dict[str, Any]:
    """Compare the current indicator score against a historical baseline.

    Queries TrendSnapshot records tagged with the scenario's metric name to
    build a rolling average.  If no snapshot history exists it falls back to
    re-evaluating indicators over daily slices of the baseline window.

    Args:
        session: SQLAlchemy session.
        scenario_key: I&W scenario key.
        current_score: The current threat_score for this scenario.
        baseline_days: Number of days of history to consider.

    Returns:
        dict with keys: current, baseline_avg, sigma_above, is_elevated.
    """
    metric_name = f"iw_{scenario_key}"
    cutoff = datetime.utcnow() - timedelta(days=baseline_days)

    # Attempt to pull historical scores from TrendSnapshot
    snapshots = (
        session.query(TrendSnapshot.metric_value)
        .filter(
            TrendSnapshot.metric_name == metric_name,
            TrendSnapshot.window_end >= cutoff,
        )
        .all()
    )

    historical_values = [row.metric_value for row in snapshots]

    if len(historical_values) < 3:
        # Not enough snapshot history -- re-evaluate daily slices
        scenarios = _get_active_scenarios()
        scenario = scenarios.get(scenario_key)
        if scenario:
            historical_values = _compute_daily_scores(
                session, scenario_key, scenario, baseline_days
            )

    if not historical_values:
        return {
            "current": current_score,
            "baseline_avg": 0.0,
            "sigma_above": 0.0,
            "is_elevated": False,
        }

    import numpy as np

    baseline_avg = float(np.mean(historical_values))
    std = float(np.std(historical_values))
    sigma_above = (current_score - baseline_avg) / std if std > 0 else 0.0

    return {
        "current": round(current_score, 4),
        "baseline_avg": round(baseline_avg, 4),
        "sigma_above": round(sigma_above, 2),
        "is_elevated": sigma_above >= 2.0,
    }


def _compute_daily_scores(
    session: Session,
    scenario_key: str,
    scenario: dict[str, Any],
    days: int,
) -> list[float]:
    """Re-evaluate a scenario for each of the last *days* 24-hour windows."""
    scores: list[float] = []
    now = datetime.utcnow()

    for d in range(1, days + 1):
        window_end = now - timedelta(days=d - 1)
        window_start = now - timedelta(days=d)
        items = (
            session.query(RawItem)
            .filter(
                RawItem.fetched_at >= window_start,
                RawItem.fetched_at < window_end,
            )
            .all()
        )
        if items:
            result = _evaluate_scenario(session, scenario_key, scenario, items)
            scores.append(result["threat_score"])
        else:
            scores.append(0.0)

    return scores


# ---------------------------------------------------------------------------
# Escalation probability modeling
# ---------------------------------------------------------------------------

def _sigmoid(x: float) -> float:
    """Numerically stable sigmoid function."""
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    exp_x = math.exp(x)
    return exp_x / (1.0 + exp_x)


def estimate_escalation_probability(
    session: Session,
    scenario_key: str,
    hours_forward: int = 168,
) -> dict[str, Any]:
    """Estimate probability of escalation using a simple logistic model.

    P(escalation) = sigmoid(w1 * threat_score + w2 * trend_velocity
                            + w3 * source_count - bias)

    trend_velocity = (current_score - score_7d_ago) / 7

    Args:
        session: SQLAlchemy session.
        scenario_key: I&W scenario key.
        hours_forward: Forecast horizon in hours (default 168 = 7 days).

    Returns:
        dict with probability, factors, confidence_interval, assessment.
    """
    scenarios = _get_active_scenarios()
    scenario = scenarios.get(scenario_key)
    if scenario is None:
        return {
            "error": f"Unknown scenario: {scenario_key}",
            "available_scenarios": list(scenarios.keys()),
        }

    # Current evaluation
    cutoff_now = datetime.utcnow() - timedelta(hours=72)
    current_items = (
        session.query(RawItem).filter(RawItem.fetched_at >= cutoff_now).all()
    )
    current_result = _evaluate_scenario(session, scenario_key, scenario, current_items)
    threat_score = current_result["threat_score"]

    # Score from 7 days ago (use items from 7-10 days ago as proxy)
    cutoff_7d_start = datetime.utcnow() - timedelta(days=10)
    cutoff_7d_end = datetime.utcnow() - timedelta(days=7)
    old_items = (
        session.query(RawItem)
        .filter(
            RawItem.fetched_at >= cutoff_7d_start,
            RawItem.fetched_at < cutoff_7d_end,
        )
        .all()
    )
    old_result = _evaluate_scenario(session, scenario_key, scenario, old_items)
    score_7d_ago = old_result["threat_score"]

    trend_velocity = (threat_score - score_7d_ago) / 7.0

    # Count distinct sources in current evidence
    source_ids: set[int] = set()
    for trig in current_result["triggered_indicators"]:
        for ev in trig["evidence_items"]:
            sid = ev.get("source_id")
            if sid is not None:
                source_ids.add(sid)
    source_count = len(source_ids)

    # Logistic model coefficients
    # threat_score 0-1, trend_velocity typically -0.1 to +0.1, source_count 0-20
    # evidence_count is a strong signal - many items matching = higher probability
    evidence_count = current_result.get("total_evidence_count", 0)
    evidence_factor = min(evidence_count / 10.0, 2.0)  # caps at 2.0 for 20+ items

    w1 = 4.0    # weight for threat_score
    w2 = 3.0    # weight for trend_velocity
    w3 = 0.12   # weight per distinct source
    w4 = 1.5    # weight for evidence density
    bias = 2.0  # lower bias so active conflicts score higher

    logit = w1 * threat_score + w2 * trend_velocity + w3 * source_count + w4 * evidence_factor - bias
    probability = _sigmoid(logit)

    # Confidence interval (heuristic: wider when less data)
    uncertainty = max(0.05, 0.25 - 0.01 * min(evidence_count, 20))
    ci_low = max(0.0, probability - uncertainty)
    ci_high = min(1.0, probability + uncertainty)

    # Assessment label
    if probability > 0.7:
        assessment = "LIKELY"
    elif probability >= 0.4:
        assessment = "POSSIBLE"
    else:
        assessment = "UNLIKELY"

    return {
        "scenario_key": scenario_key,
        "hours_forward": hours_forward,
        "probability": round(probability, 4),
        "factors": {
            "threat_score": round(threat_score, 4),
            "score_7d_ago": round(score_7d_ago, 4),
            "trend_velocity": round(trend_velocity, 4),
            "source_count": source_count,
            "evidence_count": evidence_count,
        },
        "confidence_interval": [round(ci_low, 4), round(ci_high, 4)],
        "assessment": assessment,
    }


# ---------------------------------------------------------------------------
# Red Team / Devil's Advocate counter-assessment
# ---------------------------------------------------------------------------

def generate_counter_assessment(
    session: Session,
    scenario_key: str,
    provider: str | None = None,
) -> str:
    """Generate a Red Team counter-assessment for a scenario.

    Feeds the current I&W assessment to an LLM with a devil's-advocate system
    prompt to challenge assumptions and surface alternative explanations.

    Args:
        session: SQLAlchemy session.
        scenario_key: I&W scenario key.
        provider: LLM provider override (e.g. "openai", "anthropic").

    Returns:
        The counter-assessment text.
    """
    from osint_monitor.analysis.llm import get_llm

    # Build the current assessment snapshot
    status = get_scenario_status(session, scenario_key, hours_back=72)
    if "error" in status:
        return f"Cannot generate counter-assessment: {status['error']}"

    escalation = estimate_escalation_probability(session, scenario_key)
    baseline = compare_to_baseline(
        session, scenario_key, status["threat_score"]
    )

    # Format the assessment for the LLM
    assessment_text = (
        f"SCENARIO: {status['description']}\n"
        f"STATUS: {status['status']}  |  THREAT SCORE: {status['threat_score']}\n"
        f"ESCALATION PROBABILITY: {escalation.get('probability', 'N/A')} "
        f"({escalation.get('assessment', 'N/A')})\n"
        f"BASELINE COMPARISON: current={baseline['current']}, "
        f"avg={baseline['baseline_avg']}, "
        f"sigma_above={baseline['sigma_above']}, "
        f"elevated={baseline['is_elevated']}\n\n"
        f"TRIGGERED INDICATORS ({status['triggered_count']}/{status['total_indicators']}):\n"
    )
    for trig in status["triggered_indicators"]:
        assessment_text += (
            f"  - {trig['name']} (weight={trig['weight']}, "
            f"evidence={trig['evidence_count']})\n"
        )
        for ev in trig.get("evidence_items", [])[:3]:
            assessment_text += f"      * {ev.get('title', 'N/A')}\n"

    system_prompt = (
        "You are a Red Team analyst specializing in intelligence assessment. "
        "Your role is to challenge every assumption in the assessment presented "
        "to you. For each triggered indicator, consider:\n"
        "1. What alternative, benign explanations exist for this evidence?\n"
        "2. What biases (confirmation, availability, anchoring) might be "
        "inflating the threat assessment?\n"
        "3. What key evidence is MISSING that would be expected if the "
        "hypothesis were true?\n"
        "4. What evidence would definitively disprove the main hypothesis?\n"
        "5. Are there deception indicators -- could an adversary be deliberately "
        "seeding misleading signals?\n\n"
        "Be specific, cite the indicators by name, and provide a structured "
        "counter-assessment with an alternative threat rating."
    )

    user_prompt = (
        f"Provide a Red Team / Devil's Advocate counter-assessment for the "
        f"following I&W evaluation:\n\n{assessment_text}"
    )

    try:
        llm = get_llm(provider=provider)
        return llm.generate(user_prompt, system=system_prompt, temperature=0.5)
    except Exception as exc:
        logger.error("LLM counter-assessment failed: %s", exc)
        return f"Counter-assessment generation failed: {exc}"
