"""State-transition alert engine.

Alerts fire when something CHANGES, not when something EXISTS.
Four tiers:
  1. Analytical Shift   — I&W thresholds crossed, corroboration changed, fusion convergence
  2. Novel Signal       — new event clusters, source silence breaks, entity emergence
  3. Environmental      — signal gaps opened/closed, source failures, infra anomalies
  4. First Report       — genuinely new, high-credibility first sighting (very limited)
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from osint_monitor.core.config import load_alerts_config, load_sources_config
from osint_monitor.core.database import Alert, Entity, Event, EventItem, ItemEntity, RawItem, Source
from osint_monitor.core.models import AlertType
from osint_monitor.alerting.fatigue import FatigueManager
from osint_monitor.alerting.state import StateTracker

logger = logging.getLogger(__name__)

# I&W tier boundaries
IW_TIERS = [
    (0.5, "ELEVATED"),
    (0.3, "WARNING"),
    (0.1, "WATCH"),
    (0.0, "BASELINE"),
]


def _iw_tier(score: float) -> str:
    for threshold, label in IW_TIERS:
        if score >= threshold:
            return label
    return "BASELINE"


class AlertEngine:
    """Evaluates state transitions and generates alerts."""

    def __init__(self, session: Session):
        self.session = session
        self.fatigue = FatigueManager(session)
        self.state = StateTracker(session)
        self._sources_config = load_sources_config()

    def evaluate_all(self, hours_back: int = 1) -> list[Alert]:
        """Run all alert tiers and return newly fired alerts."""
        candidates: list[Alert] = []

        # Tier 1: Analytical Shift
        candidates.extend(self._tier1_iw_thresholds(hours_back))
        candidates.extend(self._tier1_corroboration_changes())
        candidates.extend(self._tier1_fusion_convergence(hours_back))

        # Tier 2: Novel Signal
        candidates.extend(self._tier2_new_event_clusters())
        candidates.extend(self._tier2_source_silence_break())

        # Tier 3: Environmental Change
        candidates.extend(self._tier3_signal_gaps(hours_back))

        # Tier 4: First Report
        candidates.extend(self._tier4_first_report(hours_back))

        # Filter through dedup
        fired = []
        for alert in candidates:
            if self.fatigue.should_fire(alert):
                self.session.add(alert)
                self.session.flush()
                fired.append(alert)
            else:
                logger.debug(f"Alert deduped: {alert.trigger_key}")

        self.session.commit()
        if fired:
            logger.info(f"Fired {len(fired)} alerts ({len(candidates) - len(fired)} deduped)")
        return fired

    # ------------------------------------------------------------------
    # Tier 1: Analytical Shift
    # ------------------------------------------------------------------

    def _tier1_iw_thresholds(self, hours_back: int) -> list[Alert]:
        """Detect I&W scenario tier transitions."""
        try:
            from osint_monitor.analysis.indicators import evaluate_indicators
            current_results = evaluate_indicators(self.session, hours_back=24)
        except Exception as e:
            logger.debug(f"I&W evaluation unavailable: {e}")
            return []

        previous = self.state.get_or_default("iw_scores", {})
        alerts = []

        current_state = {}
        for scenario in current_results:
            key = scenario.get("scenario_key", "")
            score = scenario.get("threat_score", 0)
            current_tier = _iw_tier(score)
            previous_tier = previous.get(key, {}).get("tier", "BASELINE")
            previous_score = previous.get(key, {}).get("score", 0)

            current_state[key] = {"tier": current_tier, "score": score}

            if current_tier != previous_tier:
                # Direction matters
                tier_order = ["BASELINE", "WATCH", "WARNING", "ELEVATED"]
                cur_idx = tier_order.index(current_tier) if current_tier in tier_order else 0
                prev_idx = tier_order.index(previous_tier) if previous_tier in tier_order else 0
                direction = "escalated" if cur_idx > prev_idx else "de-escalated"

                # Build evidence summary
                triggered = scenario.get("triggered_indicators", [])
                evidence_summary = ", ".join(
                    f"{ind['name']} ({ind['evidence_count']} items)"
                    for ind in triggered[:5]
                )

                severity = 0.9 if current_tier == "ELEVATED" else 0.7 if current_tier == "WARNING" else 0.4

                alerts.append(Alert(
                    alert_type=AlertType.IW_THRESHOLD.value,
                    severity=severity,
                    title=f"I&W {direction}: {key} {previous_tier} → {current_tier} ({score:.0%})",
                    detail=(
                        f"Scenario: {scenario.get('description', key)}\n"
                        f"Score: {previous_score:.0%} → {score:.0%}\n"
                        f"Evidence: {evidence_summary}"
                    ),
                    trigger_key=f"iw:{key}:{previous_tier}→{current_tier}",
                ))

        self.state.set("iw_scores", current_state)
        return alerts

    def _tier1_corroboration_changes(self) -> list[Alert]:
        """Detect when an event's corroboration status changes."""
        previous = self.state.get_or_default("corroboration", {})
        events = self.session.query(Event).all()
        alerts = []

        current_state = {}
        for ev in events:
            eid = str(ev.id)
            current_level = ev.corroboration_level or "UNVERIFIED"
            current_contradictions = ev.has_contradictions or False
            prev = previous.get(eid, {})
            prev_level = prev.get("level", "UNVERIFIED")
            prev_contradictions = prev.get("contradictions", False)

            current_state[eid] = {"level": current_level, "contradictions": current_contradictions}

            # Level upgrade (POSSIBLE → CONFIRMED is more interesting than the reverse)
            level_order = ["UNVERIFIED", "DOUBTFUL", "POSSIBLE", "PROBABLE", "CONFIRMED"]
            cur_idx = level_order.index(current_level) if current_level in level_order else 0
            prev_idx = level_order.index(prev_level) if prev_level in level_order else 0

            if cur_idx > prev_idx and cur_idx >= 3:  # Only alert on PROBABLE or CONFIRMED upgrades
                alerts.append(Alert(
                    event_id=ev.id,
                    alert_type=AlertType.CORROBORATION_CHANGE.value,
                    severity=0.6,
                    title=f"Corroboration upgrade: '{ev.summary[:80]}' {prev_level} → {current_level}",
                    detail=(
                        f"Event now {ev.admiralty_rating or ''} {current_level} "
                        f"with {ev.source_count or 0} independent sources."
                    ),
                    trigger_key=f"corr:{ev.id}:{prev_level}→{current_level}",
                ))

            # New contradictions appeared
            if current_contradictions and not prev_contradictions:
                alerts.append(Alert(
                    event_id=ev.id,
                    alert_type=AlertType.ASSESSMENT_CONTRADICTION.value,
                    severity=0.7,
                    title=f"Contradictions detected: '{ev.summary[:80]}'",
                    detail=f"Sources now disagree on this event. Review source stance.",
                    trigger_key=f"contradiction:{ev.id}",
                ))

        self.state.set("corroboration", current_state)
        return alerts

    def _tier1_fusion_convergence(self, hours_back: int) -> list[Alert]:
        """Detect new cross-modal fusion convergences."""
        try:
            from osint_monitor.analysis.fusion import fuse_signals
            current_correlations = fuse_signals(self.session, hours_back=24)
        except Exception as e:
            logger.debug(f"Fusion unavailable: {e}")
            return []

        previous_keys = set(self.state.get_or_default("fusion_keys", {}).get("keys", []))
        alerts = []

        current_keys = set()
        for corr in current_correlations:
            # Key by pattern + time bucket
            key = f"{corr['pattern']}@{corr['time_bucket']}"
            current_keys.add(key)

            if key not in previous_keys and corr["confidence"] >= 0.7:
                modalities = ", ".join(corr["modalities_matched"])
                alerts.append(Alert(
                    alert_type=AlertType.FUSION_CONVERGENCE.value,
                    severity=corr["confidence"],
                    title=f"Fusion convergence: {corr['pattern']} ({corr['confidence']:.0%})",
                    detail=(
                        f"Modalities: {modalities}\n"
                        f"Time: {corr['time_bucket']}\n"
                        f"Sources: {corr['source_count']}, Items: {corr['item_count']}"
                    ),
                    trigger_key=f"fusion:{key}",
                ))

        self.state.set("fusion_keys", {"keys": list(current_keys)})
        return alerts

    # ------------------------------------------------------------------
    # Tier 2: Novel Signal
    # ------------------------------------------------------------------

    def _tier2_new_event_clusters(self) -> list[Alert]:
        """Alert on new event clusters that formed since last check."""
        previous_ids = set(self.state.get_or_default("event_ids", {}).get("ids", []))
        current_events = self.session.query(Event).all()
        alerts = []

        current_ids = set()
        for ev in current_events:
            current_ids.add(ev.id)

            if ev.id not in previous_ids:
                # New event — only alert if it has substance
                source_count = ev.source_count or 0
                if source_count >= 3:
                    alerts.append(Alert(
                        event_id=ev.id,
                        alert_type=AlertType.NEW_EVENT_CLUSTER.value,
                        severity=min(0.5 + (source_count * 0.05), 0.9),
                        title=f"New event: '{ev.summary[:100]}' ({source_count} sources)",
                        detail=(
                            f"Region: {ev.region or 'unknown'}\n"
                            f"Corroboration: {ev.admiralty_rating or '?'} {ev.corroboration_level or 'UNVERIFIED'}"
                        ),
                        trigger_key=f"new_event:{ev.id}",
                    ))

        self.state.set("event_ids", {"ids": list(current_ids)})
        return alerts

    def _tier2_source_silence_break(self) -> list[Alert]:
        """Alert when a source that's been quiet for >24h suddenly posts."""
        previous = self.state.get_or_default("source_last_seen", {})
        alerts = []

        sources = self.session.query(Source).all()
        current_state = {}
        now = datetime.utcnow()

        for src in sources:
            latest_item = (
                self.session.query(RawItem)
                .filter_by(source_id=src.id)
                .order_by(RawItem.fetched_at.desc())
                .first()
            )
            if not latest_item:
                continue

            last_seen_str = previous.get(str(src.id))
            current_state[str(src.id)] = latest_item.fetched_at.isoformat()

            if last_seen_str:
                try:
                    last_seen = datetime.fromisoformat(last_seen_str)
                except ValueError:
                    continue

                gap = (latest_item.fetched_at - last_seen).total_seconds()
                # Item is fresh (within last hour) but previous was >24h ago
                if gap > 86400 and (now - latest_item.fetched_at).total_seconds() < 3600:
                    gap_hours = gap / 3600
                    alerts.append(Alert(
                        item_id=latest_item.id,
                        alert_type=AlertType.SOURCE_SILENCE_BREAK.value,
                        severity=0.6,
                        title=f"Source resumed: {src.name} (silent {gap_hours:.0f}h)",
                        detail=f"Latest: {latest_item.title[:200]}",
                        trigger_key=f"silence_break:{src.id}:{latest_item.fetched_at.date().isoformat()}",
                    ))

        self.state.set("source_last_seen", current_state)
        return alerts

    # ------------------------------------------------------------------
    # Tier 3: Environmental Change
    # ------------------------------------------------------------------

    def _tier3_signal_gaps(self, hours_back: int) -> list[Alert]:
        """Alert when signal gaps open or close."""
        try:
            from osint_monitor.analysis.fusion import detect_signal_gaps
            current_gaps = detect_signal_gaps(self.session, hours_back=24)
        except Exception as e:
            logger.debug(f"Signal gap detection unavailable: {e}")
            return []

        previous_gap_types = set(self.state.get_or_default("signal_gaps", {}).get("types", []))
        alerts = []

        current_gap_types = set()
        for gap in current_gaps:
            gap_id = f"{gap['gap_type']}:{gap['modality']}"
            current_gap_types.add(gap_id)

            # New gap opened
            if gap_id not in previous_gap_types:
                alerts.append(Alert(
                    alert_type=AlertType.SIGNAL_GAP_OPENED.value,
                    severity=0.5,
                    title=f"Signal gap: {gap['modality']} went dark",
                    detail=f"{gap['description']}\nSignificance: {gap.get('significance', 'unknown')}",
                    trigger_key=f"gap_opened:{gap_id}",
                ))

        # Gaps that closed
        for prev_gap in previous_gap_types:
            if prev_gap not in current_gap_types:
                modality = prev_gap.split(":", 1)[-1] if ":" in prev_gap else prev_gap
                alerts.append(Alert(
                    alert_type=AlertType.SIGNAL_GAP_CLOSED.value,
                    severity=0.4,
                    title=f"Signal restored: {modality} reporting again",
                    detail=f"Previously missing modality '{modality}' is now present in the data.",
                    trigger_key=f"gap_closed:{prev_gap}",
                ))

        self.state.set("signal_gaps", {"types": list(current_gap_types)})
        return alerts

    # ------------------------------------------------------------------
    # Tier 4: First Report (very limited keyword matching)
    # ------------------------------------------------------------------

    # Only truly binary events — things where the keyword IS the event
    FIRST_REPORT_TERMS = [
        "DEFCON",
        "nuclear detonation",
        "Article 5 invoked",
        "declaration of war",
        "nuclear test detected",
    ]

    def _tier4_first_report(self, hours_back: int) -> list[Alert]:
        """Alert on genuinely new, high-credibility first sightings of binary events."""
        cutoff = datetime.utcnow() - timedelta(hours=hours_back)

        # Only items not already alerted on, from credible sources
        already_alerted = set(
            row[0] for row in
            self.session.query(Alert.item_id)
            .filter(Alert.item_id.isnot(None))
            .all()
        )

        items = (
            self.session.query(RawItem)
            .join(Source)
            .filter(
                RawItem.fetched_at >= cutoff,
                Source.credibility_score >= 0.7,
            )
            .all()
        )

        alerts = []
        for item in items:
            if item.id in already_alerted:
                continue

            text = f"{item.title} {item.content or ''}".lower()
            for term in self.FIRST_REPORT_TERMS:
                if term.lower() in text:
                    alerts.append(Alert(
                        item_id=item.id,
                        alert_type=AlertType.FIRST_REPORT.value,
                        severity=1.0,
                        title=f"First report: '{term}' — {item.source.name}",
                        detail=f"Title: {item.title}\nURL: {item.url}",
                        trigger_key=f"first_report:{item.id}:{term}",
                    ))
                    break  # One alert per item

        return alerts

    # ------------------------------------------------------------------
    # Legacy compat
    # ------------------------------------------------------------------

    def escalate_unacknowledged(self, minutes: int = 30):
        """No-op. Artificial escalation removed — severity reflects reality, not neglect."""
        pass
