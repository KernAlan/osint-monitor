"""Structured Analysis of Competing Hypotheses (ACH).

Provides a rigorous, matrix-based framework for evaluating hypotheses
against evidence, with optional LLM-assisted generation and rating.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Optional

from sqlalchemy.orm import Session

from osint_monitor.core.database import Event, EventItem, RawItem, Source

logger = logging.getLogger(__name__)

# Rating scale: consistency of evidence with hypothesis
RATING_WEIGHTS: dict[str, float] = {
    "++": 2.0,   # Strongly consistent
    "+": 1.0,    # Consistent
    "0": 0.0,    # Neutral / not applicable
    "-": -1.0,   # Inconsistent
    "--": -2.0,  # Strongly inconsistent
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Hypothesis:
    id: str
    description: str
    prior_probability: float = 0.5


@dataclass
class Evidence:
    id: str
    description: str
    source: str
    credibility: float  # 0-1
    item_id: int | None = None


@dataclass
class ACHMatrix:
    """Analysis of Competing Hypotheses matrix.

    ``ratings`` maps (hypothesis_id, evidence_id) to a rating string
    from {"++", "+", "0", "-", "--"}.
    """

    hypotheses: list[Hypothesis] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    ratings: dict[tuple[str, str], str] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def compute_scores(self) -> dict[str, float]:
        """Weighted consistency score for each hypothesis.

        For every (hypothesis, evidence) pair the numeric rating is
        multiplied by the evidence credibility.  Scores are then
        normalised to [0, 1] across hypotheses.
        """
        if not self.hypotheses or not self.evidence:
            return {h.id: 0.0 for h in self.hypotheses}

        raw_scores: dict[str, float] = {}
        for hyp in self.hypotheses:
            total = 0.0
            for ev in self.evidence:
                rating_str = self.ratings.get((hyp.id, ev.id), "0")
                weight = RATING_WEIGHTS.get(rating_str, 0.0)
                total += weight * ev.credibility
            raw_scores[hyp.id] = total

        # Normalise to 0-1
        min_s = min(raw_scores.values())
        max_s = max(raw_scores.values())
        spread = max_s - min_s
        if spread == 0:
            return {h_id: 0.5 for h_id in raw_scores}

        return {
            h_id: round((score - min_s) / spread, 4)
            for h_id, score in raw_scores.items()
        }

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def identify_diagnostics(self) -> list[str]:
        """Return IDs of evidence items that discriminate between hypotheses.

        Diagnostic evidence is rated differently (positive for some
        hypotheses and negative for others).
        """
        diagnostics: list[str] = []
        for ev in self.evidence:
            ratings_for_ev = [
                RATING_WEIGHTS.get(self.ratings.get((h.id, ev.id), "0"), 0.0)
                for h in self.hypotheses
            ]
            if not ratings_for_ev:
                continue
            has_positive = any(r > 0 for r in ratings_for_ev)
            has_negative = any(r < 0 for r in ratings_for_ev)
            if has_positive and has_negative:
                diagnostics.append(ev.id)
        return diagnostics

    # ------------------------------------------------------------------
    # Bayesian update
    # ------------------------------------------------------------------

    def bayesian_update(
        self, new_evidence: Evidence, ratings: dict[str, str]
    ) -> dict[str, float]:
        """Update posterior probabilities given new evidence.

        Uses a simplified likelihood model where the rating determines
        how much the prior is shifted.

        Args:
            new_evidence: the new piece of evidence.
            ratings: mapping of hypothesis_id -> rating string for
                the new evidence.

        Returns:
            Updated posterior probabilities for each hypothesis,
            normalised to sum to 1.
        """
        # Store the evidence and ratings in the matrix
        if new_evidence not in self.evidence:
            self.evidence.append(new_evidence)
        for hyp_id, rating in ratings.items():
            self.ratings[(hyp_id, new_evidence.id)] = rating

        # Likelihood multipliers based on rating and credibility
        likelihood_map = {
            "++": 4.0,
            "+": 2.0,
            "0": 1.0,
            "-": 0.5,
            "--": 0.25,
        }

        posteriors: dict[str, float] = {}
        for hyp in self.hypotheses:
            rating_str = ratings.get(hyp.id, "0")
            base_likelihood = likelihood_map.get(rating_str, 1.0)
            # Blend towards 1.0 for low-credibility evidence
            likelihood = 1.0 + (base_likelihood - 1.0) * new_evidence.credibility
            posteriors[hyp.id] = hyp.prior_probability * likelihood

        # Normalise
        total = sum(posteriors.values())
        if total > 0:
            posteriors = {k: round(v / total, 4) for k, v in posteriors.items()}
        else:
            n = len(posteriors)
            posteriors = {k: round(1.0 / n, 4) for k in posteriors}

        # Update priors for future incremental updates
        for hyp in self.hypotheses:
            hyp.prior_probability = posteriors.get(hyp.id, hyp.prior_probability)

        return posteriors


# ---------------------------------------------------------------------------
# LLM-assisted ACH construction
# ---------------------------------------------------------------------------

def build_ach_from_event(
    session: Session,
    event_id: int,
    llm_provider: str | None = None,
) -> ACHMatrix:
    """Build an ACH matrix for an event, optionally using an LLM.

    1. Gather all items linked to the event.
    2. If an LLM is available, generate hypotheses and rate evidence.
    3. Otherwise return a matrix with evidence only (no hypotheses/ratings).
    """
    # Collect evidence from event items
    rows = (
        session.query(RawItem, Source.name, Source.credibility_score)
        .join(EventItem, EventItem.item_id == RawItem.id)
        .join(Source, Source.id == RawItem.source_id)
        .filter(EventItem.event_id == event_id)
        .order_by(RawItem.published_at.asc())
        .all()
    )

    evidence_list: list[Evidence] = []
    for idx, (item, source_name, credibility) in enumerate(rows):
        snippet = (item.title or "") + " " + (item.content or "")
        snippet = snippet[:500].strip()
        evidence_list.append(
            Evidence(
                id=f"E{idx + 1}",
                description=snippet,
                source=source_name,
                credibility=credibility,
                item_id=item.id,
            )
        )

    matrix = ACHMatrix(evidence=evidence_list)

    if not evidence_list:
        return matrix

    # Attempt LLM-assisted hypothesis generation and rating
    if llm_provider is not None:
        try:
            matrix = _llm_generate_ach(matrix, llm_provider)
        except Exception:
            logger.warning(
                "LLM-assisted ACH generation failed; returning evidence-only matrix.",
                exc_info=True,
            )

    return matrix


def _llm_generate_ach(matrix: ACHMatrix, provider_name: str) -> ACHMatrix:
    """Use an LLM to generate hypotheses and rate evidence."""
    from osint_monitor.analysis.llm import get_llm

    llm = get_llm(provider=provider_name)

    evidence_text = "\n".join(
        f"- [{ev.id}] (source: {ev.source}, credibility: {ev.credibility:.1f}) "
        f"{ev.description}"
        for ev in matrix.evidence
    )

    # Step 1: generate hypotheses
    hyp_prompt = (
        "You are an intelligence analyst. Given the following evidence items "
        "about a developing event, generate 3 to 5 competing hypotheses that "
        "could explain the situation.\n\n"
        f"Evidence:\n{evidence_text}\n\n"
        "Respond with a JSON array of objects, each with keys "
        '"id" (H1, H2, ...), "description" (one sentence), and '
        '"prior_probability" (your initial estimate, all summing to ~1.0).'
    )

    hyp_data = llm.generate_json(hyp_prompt, system="You are a geopolitical intelligence analyst.")
    if isinstance(hyp_data, list):
        hypotheses_raw = hyp_data
    elif isinstance(hyp_data, dict) and "hypotheses" in hyp_data:
        hypotheses_raw = hyp_data["hypotheses"]
    else:
        hypotheses_raw = hyp_data if isinstance(hyp_data, list) else []

    hypotheses = [
        Hypothesis(
            id=h.get("id", f"H{i + 1}"),
            description=h.get("description", ""),
            prior_probability=float(h.get("prior_probability", 0.5)),
        )
        for i, h in enumerate(hypotheses_raw)
    ]

    if not hypotheses:
        return matrix

    matrix.hypotheses = hypotheses

    # Step 2: rate each evidence item against each hypothesis
    hyp_desc = "\n".join(f"- {h.id}: {h.description}" for h in hypotheses)
    rating_prompt = (
        "You are rating evidence consistency for an ACH (Analysis of Competing "
        "Hypotheses) matrix.\n\n"
        f"Hypotheses:\n{hyp_desc}\n\n"
        f"Evidence:\n{evidence_text}\n\n"
        "For each (hypothesis, evidence) pair, rate consistency as one of: "
        '"++", "+", "0", "-", "--".\n\n'
        "Respond with a JSON object where keys are hypothesis IDs and values "
        "are objects mapping evidence IDs to rating strings. Example:\n"
        '{"H1": {"E1": "+", "E2": "--"}, "H2": {"E1": "-", "E2": "+"}}'
    )

    rating_data = llm.generate_json(
        rating_prompt, system="You are a geopolitical intelligence analyst."
    )

    if isinstance(rating_data, dict):
        for hyp_id, ev_ratings in rating_data.items():
            if not isinstance(ev_ratings, dict):
                continue
            for ev_id, rating in ev_ratings.items():
                if rating in RATING_WEIGHTS:
                    matrix.ratings[(hyp_id, ev_id)] = rating

    return matrix


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------

def ach_to_markdown(matrix: ACHMatrix) -> str:
    """Render an ACH matrix as a readable markdown table."""
    if not matrix.hypotheses and not matrix.evidence:
        return "_No data available for ACH analysis._"

    scores = matrix.compute_scores() if matrix.hypotheses else {}
    diagnostics = set(matrix.identify_diagnostics()) if matrix.hypotheses else set()

    lines: list[str] = ["## Analysis of Competing Hypotheses", ""]

    # Header row
    hyp_headers = " | ".join(
        f"**{h.id}** ({scores.get(h.id, 0.0):.2f})" for h in matrix.hypotheses
    )
    header = f"| Evidence | {hyp_headers} |" if matrix.hypotheses else "| Evidence |"
    sep_parts = ["---"] + [":---:"] * len(matrix.hypotheses)
    separator = "| " + " | ".join(sep_parts) + " |"

    lines.append(header)
    lines.append(separator)

    # Evidence rows
    for ev in matrix.evidence:
        diag_marker = " **[D]**" if ev.id in diagnostics else ""
        label = f"{ev.id}: {ev.description[:80]}...{diag_marker}" if len(ev.description) > 80 else f"{ev.id}: {ev.description}{diag_marker}"
        cells = [label]
        for hyp in matrix.hypotheses:
            rating = matrix.ratings.get((hyp.id, ev.id), "0")
            cells.append(rating)
        lines.append("| " + " | ".join(cells) + " |")

    lines.append("")

    # Hypothesis descriptions
    lines.append("### Hypotheses")
    for hyp in matrix.hypotheses:
        score_str = f" -- score: {scores.get(hyp.id, 0.0):.2f}"
        lines.append(f"- **{hyp.id}**: {hyp.description}{score_str}")

    if diagnostics:
        lines.append("")
        lines.append("### Diagnostic Evidence")
        lines.append(
            "Items marked **[D]** discriminate between hypotheses "
            "(rated positively for some, negatively for others)."
        )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Key Assumptions Check
# ---------------------------------------------------------------------------

def key_assumptions_check(hypotheses: list[Hypothesis]) -> list[dict]:
    """Identify key assumptions underlying each hypothesis.

    This uses heuristic decomposition rather than an LLM.  Each
    hypothesis description is broken into its constituent claims,
    which are treated as assumptions.

    Returns:
        List of dicts with keys: hypothesis, assumptions, vulnerability.
    """
    results: list[dict] = []

    for hyp in hypotheses:
        desc = hyp.description
        # Simple heuristic: split on conjunctions and commas for sub-claims
        parts = desc.replace(" and ", " | ").replace(" because ", " | ").replace(
            " therefore ", " | "
        ).replace(", ", " | ").split(" | ")
        assumptions = [p.strip() for p in parts if len(p.strip()) > 10]

        if not assumptions:
            assumptions = [desc]

        # Vulnerability assessment based on probability
        if hyp.prior_probability < 0.2:
            vulnerability = "HIGH - low prior probability; small evidence shifts could eliminate"
        elif hyp.prior_probability < 0.4:
            vulnerability = "MODERATE - below-average prior; sensitive to disconfirming evidence"
        elif hyp.prior_probability > 0.8:
            vulnerability = "LOW prior vulnerability but HIGH confirmation bias risk"
        else:
            vulnerability = "MODERATE - standard prior; evaluate evidence carefully"

        results.append({
            "hypothesis": f"{hyp.id}: {hyp.description}",
            "assumptions": assumptions,
            "vulnerability": vulnerability,
        })

    return results
