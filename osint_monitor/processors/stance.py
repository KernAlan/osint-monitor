"""Claim-level stance detection between sources.

Goes beyond embedding similarity (corroboration.py's ``detect_source_disagreement``)
to determine *what* each source is actually asserting and whether those assertions
agree, disagree, or are unrelated.

Three detection approaches used in cascade:
  1. NLI via cross-encoder/nli-deberta-v3-base (best quality)
  2. Heuristic negation / contradictory-verb detection (no GPU, no download)
  3. LLM fallback via the project's multi-provider abstraction
"""

from __future__ import annotations

import logging
from itertools import product
from typing import TYPE_CHECKING

from osint_monitor.core.database import Claim, EventItem, RawItem, Source

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Contradictory verb pairs (bidirectional)
# ---------------------------------------------------------------------------

CONTRADICTORY_VERB_PAIRS: dict[str, str] = {
    "confirmed": "denied",
    "attacked": "defended",
    "advanced": "retreated",
    "destroyed": "survived",
    "killed": "rescued",
    "won": "lost",
    "increased": "decreased",
    "succeeded": "failed",
    "allowed": "blocked",
    "accepted": "rejected",
    "supported": "opposed",
    "claimed": "denied",
}

# Build a reverse map so lookups work in both directions
_VERB_CONTRADICTION_LOOKUP: dict[str, str] = {}
for _v1, _v2 in CONTRADICTORY_VERB_PAIRS.items():
    _VERB_CONTRADICTION_LOOKUP[_v1] = _v2
    _VERB_CONTRADICTION_LOOKUP[_v2] = _v1

# Negation cues
_NEGATION_WORDS = frozenset({
    "not", "no", "never", "neither", "nobody", "nothing", "nowhere",
    "nor", "denied", "rejected", "false", "untrue", "unlikely",
    "refuted", "disproved", "disputed", "incorrect", "wrong",
    "failed", "unable", "impossible",
})

# ---------------------------------------------------------------------------
# Lazy-loaded NLI model singleton
# ---------------------------------------------------------------------------

_nli_model = None
_nli_available: bool | None = None


def _get_nli_model():
    """Lazily load the cross-encoder NLI model.  Returns *None* if unavailable."""
    global _nli_model, _nli_available

    if _nli_available is False:
        return None
    if _nli_model is not None:
        return _nli_model

    try:
        from sentence_transformers import CrossEncoder
        _nli_model = CrossEncoder("cross-encoder/nli-deberta-v3-base")
        _nli_available = True
        logger.info("Loaded NLI cross-encoder model")
        return _nli_model
    except Exception as exc:
        logger.info("NLI model unavailable (%s), will use heuristic/LLM fallback", exc)
        _nli_available = False
        return None


# ---------------------------------------------------------------------------
# 1. Claim extraction
# ---------------------------------------------------------------------------

def extract_claims(text: str) -> list[dict]:
    """Extract factual claims from *text* via spaCy dependency parsing.

    Returns a list of dicts::

        {"claim": str, "subject": str, "verb": str, "object": str, "sentence": str}

    Only declarative sentences are considered (questions and nested quotes
    are skipped).
    """
    from osint_monitor.processors.nlp import get_nlp

    nlp = get_nlp()
    doc = nlp(text[:10_000])

    claims: list[dict] = []

    for sent in doc.sents:
        sent_text = sent.text.strip()

        # Skip questions
        if sent_text.endswith("?"):
            continue

        # Skip sentences that are entirely within quotation marks (quote-
        # within-quote noise).  A simple heuristic: if the sentence starts
        # and ends with quotes, skip.
        if (
            len(sent_text) > 2
            and sent_text[0] in ('"', "\u201c", "'", "\u2018")
            and sent_text[-1] in ('"', "\u201d", "'", "\u2019")
        ):
            continue

        # Walk tokens looking for main-clause ROOT verbs
        for token in sent:
            if token.dep_ != "ROOT" or token.pos_ != "VERB":
                continue

            subj_text: str | None = None
            obj_text: str | None = None

            for child in token.children:
                if child.dep_ in ("nsubj", "nsubjpass"):
                    # Prefer the full subtree span for compound subjects
                    subj_text = _subtree_text(child)
                elif child.dep_ in ("dobj", "attr", "oprd"):
                    obj_text = _subtree_text(child)
                elif child.dep_ == "prep":
                    # Prepositional objects can serve as the claim object
                    for pobj in child.children:
                        if pobj.dep_ == "pobj" and obj_text is None:
                            obj_text = _subtree_text(pobj)

            if subj_text and (obj_text or token.lemma_.lower()):
                claim_str = f"{subj_text} {token.lemma_} {obj_text or ''}".strip()
                claims.append({
                    "claim": claim_str,
                    "subject": subj_text,
                    "verb": token.lemma_.lower(),
                    "object": obj_text or "",
                    "sentence": sent_text,
                })

    return claims


def _subtree_text(token) -> str:
    """Return the text spanned by *token* and its syntactic subtree."""
    subtree = sorted(token.subtree, key=lambda t: t.i)
    return " ".join(t.text for t in subtree)


# ---------------------------------------------------------------------------
# 2. Pair-wise stance detection
# ---------------------------------------------------------------------------

def detect_stance_pair(claim_a: str, claim_b: str) -> dict:
    """Determine whether *claim_a* and *claim_b* agree, disagree, or are unrelated.

    Tries three approaches in order:
      1. NLI cross-encoder (highest quality)
      2. Heuristic negation / verb-contradiction
      3. LLM prompt

    Returns::

        {"stance": "AGREE"|"DISAGREE"|"UNRELATED", "confidence": float, "method": str}
    """
    # --- Approach 1: NLI cross-encoder ------------------------------------
    result = _detect_stance_nli(claim_a, claim_b)
    if result is not None:
        return result

    # --- Approach 2: Heuristic --------------------------------------------
    result = _detect_stance_heuristic(claim_a, claim_b)
    if result is not None:
        return result

    # --- Approach 3: LLM fallback -----------------------------------------
    result = _detect_stance_llm(claim_a, claim_b)
    if result is not None:
        return result

    # If everything failed, return UNRELATED with zero confidence
    return {"stance": "UNRELATED", "confidence": 0.0, "method": "none"}


# -- NLI ------------------------------------------------------------------

def _detect_stance_nli(claim_a: str, claim_b: str) -> dict | None:
    """Use NLI cross-encoder. Returns *None* if model unavailable."""
    model = _get_nli_model()
    if model is None:
        return None

    try:
        # NLI convention: [premise, hypothesis]
        scores = model.predict([(claim_a, claim_b)])
        # scores shape: (1, 3) – [contradiction, entailment, neutral]
        if hasattr(scores, "tolist"):
            scores = scores.tolist()
        if isinstance(scores[0], (list, tuple)):
            scores = list(scores[0])
        else:
            scores = list(scores)

        label_map = {0: "DISAGREE", 1: "AGREE", 2: "UNRELATED"}
        best_idx = int(max(range(len(scores)), key=lambda i: scores[i]))
        confidence = float(scores[best_idx])

        # Softmax normalisation (scores may be logits)
        import math
        exp_scores = [math.exp(s) for s in scores]
        total = sum(exp_scores)
        confidence = exp_scores[best_idx] / total if total > 0 else 0.0

        return {
            "stance": label_map.get(best_idx, "UNRELATED"),
            "confidence": round(confidence, 4),
            "method": "nli_crossencoder",
        }
    except Exception as exc:
        logger.debug("NLI inference failed: %s", exc)
        return None


# -- Heuristic -------------------------------------------------------------

def _detect_stance_heuristic(claim_a: str, claim_b: str) -> dict | None:
    """Use negation words and contradictory verbs to detect stance.

    Returns *None* if the heuristic cannot make a determination (i.e. no
    signal found — we do not guess UNRELATED, we let the next approach try).
    """
    tokens_a = set(claim_a.lower().split())
    tokens_b = set(claim_b.lower().split())

    # --- Entity overlap check: if the claims share very few content words
    # they are probably about different topics.
    overlap = tokens_a & tokens_b
    # Remove very common words for overlap check
    _stop = {"the", "a", "an", "is", "was", "were", "are", "in", "on", "of", "to", "and", "that", "it"}
    content_overlap = overlap - _stop
    if len(content_overlap) == 0:
        return {"stance": "UNRELATED", "confidence": 0.5, "method": "heuristic_no_overlap"}

    # --- Negation asymmetry: one claim has negation words, the other doesn't
    neg_a = tokens_a & _NEGATION_WORDS
    neg_b = tokens_b & _NEGATION_WORDS

    if bool(neg_a) != bool(neg_b):
        # One side is negated, the other is not — likely disagreement
        return {"stance": "DISAGREE", "confidence": 0.65, "method": "heuristic_negation"}

    # --- Contradictory verbs
    for verb_a in tokens_a:
        opposite = _VERB_CONTRADICTION_LOOKUP.get(verb_a)
        if opposite and opposite in tokens_b:
            return {"stance": "DISAGREE", "confidence": 0.70, "method": "heuristic_verb_contradiction"}

    # --- Both negated or neither: if there is good overlap, they likely agree
    if len(content_overlap) >= 3:
        return {"stance": "AGREE", "confidence": 0.45, "method": "heuristic_overlap"}

    # Not enough signal for a determination
    return None


# -- LLM ------------------------------------------------------------------

def _detect_stance_llm(claim_a: str, claim_b: str) -> dict | None:
    """Ask an LLM to classify stance.  Returns *None* if no LLM is available."""
    try:
        from osint_monitor.analysis.llm import get_llm

        llm = get_llm()
        prompt = (
            "Do these two claims agree, disagree, or discuss different topics?\n\n"
            f"Claim A: {claim_a}\n"
            f"Claim B: {claim_b}\n\n"
            "Answer with one word: AGREE, DISAGREE, or UNRELATED"
        )
        raw = llm.generate(prompt, system="You are a factual claim comparison assistant.", temperature=0.0)
        answer = raw.strip().upper()

        for label in ("AGREE", "DISAGREE", "UNRELATED"):
            if label in answer:
                return {"stance": label, "confidence": 0.80, "method": "llm"}

        logger.debug("LLM stance response not parseable: %s", raw)
        return None
    except Exception as exc:
        logger.debug("LLM stance detection unavailable: %s", exc)
        return None


# ---------------------------------------------------------------------------
# 2b. Claim extraction + classification into DB
# ---------------------------------------------------------------------------

_CLAIM_TYPE_KEYWORDS: dict[str, list[str]] = {
    "denial": ["denied", "rejected", "refuted"],
    "accusation": ["accused", "alleged", "blamed"],
    "threat": ["threatened", "warned", "vowed"],
    "confirmation": ["confirmed", "verified", "acknowledged"],
}


def _classify_claim_type(claim_text: str) -> str:
    """Classify a claim's type using keyword heuristics."""
    text_lower = claim_text.lower()
    for claim_type, keywords in _CLAIM_TYPE_KEYWORDS.items():
        for kw in keywords:
            if kw in text_lower:
                return claim_type
    return "assertion"


def extract_and_classify_claims(session: "Session", item_id: int) -> list[Claim]:
    """Extract claims from a RawItem, classify each, and persist to the DB.

    Steps:
      1. Load the RawItem
      2. Call ``extract_claims()`` on its text
      3. Classify each claim's type via keyword heuristics
      4. Create ``Claim`` records in the database
      5. Return the list of created Claim objects
    """
    item = session.get(RawItem, item_id)
    if not item:
        logger.warning("extract_and_classify_claims: item %d not found", item_id)
        return []

    text = f"{item.title or ''} {item.content or ''}".strip()
    if not text:
        return []

    raw_claims = extract_claims(text)
    if not raw_claims:
        return []

    source_name = ""
    if item.source:
        source_name = item.source.name
    elif item.source_id:
        src = session.get(Source, item.source_id)
        source_name = src.name if src else ""

    created: list[Claim] = []
    for rc in raw_claims:
        claim_type = _classify_claim_type(rc.get("sentence", rc.get("claim", "")))
        claim = Claim(
            item_id=item_id,
            subject=rc.get("subject", "")[:500],
            verb=rc.get("verb", "")[:200],
            object=rc.get("object", "")[:500] if rc.get("object") else None,
            claim_text=rc.get("sentence", rc.get("claim", "")),
            claim_type=claim_type,
            source_name=source_name,
        )
        session.add(claim)
        created.append(claim)

    session.flush()
    return created


# ---------------------------------------------------------------------------
# 3. Event-level source stance analysis
# ---------------------------------------------------------------------------

def detect_source_stance(session: "Session", event_id: int) -> list[dict]:
    """Compare claims across different sources for a single event.

    For every item in the event, extract claims, then compare each claim
    pair from *different* sources.

    Returns a list of dicts::

        {
            "source_a": str,
            "claim_a": str,
            "source_b": str,
            "claim_b": str,
            "stance": str,
            "confidence": float,
        }
    """
    event_items = (
        session.query(EventItem)
        .filter(EventItem.event_id == event_id)
        .all()
    )
    if not event_items:
        return []

    item_ids = [ei.item_id for ei in event_items]
    items = session.query(RawItem).filter(RawItem.id.in_(item_ids)).all()

    if len(items) < 2:
        return []

    # Build source name lookup
    source_cache: dict[int, str] = {}

    def _source_name(item: RawItem) -> str:
        if item.source_id not in source_cache:
            src = session.get(Source, item.source_id)
            source_cache[item.source_id] = src.name if src else f"source_{item.source_id}"
        return source_cache[item.source_id]

    # Extract claims per item, keyed by source
    # List of (source_name, source_id, claim_dict)
    all_claims: list[tuple[str, int, dict]] = []

    for item in items:
        text = f"{item.title or ''} {item.content or ''}".strip()
        if not text:
            continue
        try:
            claims = extract_claims(text)
        except Exception as exc:
            logger.debug("Claim extraction failed for item %d: %s", item.id, exc)
            continue
        sname = _source_name(item)
        for claim in claims:
            all_claims.append((sname, item.source_id, claim))

    if len(all_claims) < 2:
        return []

    # Compare claims from *different* sources
    results: list[dict] = []
    seen_pairs: set[tuple[str, str]] = set()

    for (src_a, sid_a, cl_a), (src_b, sid_b, cl_b) in product(all_claims, repeat=2):
        # Only cross-source comparisons
        if sid_a == sid_b:
            continue

        # Deduplicate symmetric pairs
        pair_key = (
            min(cl_a["claim"], cl_b["claim"]),
            max(cl_a["claim"], cl_b["claim"]),
        )
        if pair_key in seen_pairs:
            continue
        seen_pairs.add(pair_key)

        stance = detect_stance_pair(cl_a["claim"], cl_b["claim"])

        # Only report non-UNRELATED stances (or UNRELATED with high confidence)
        if stance["stance"] == "UNRELATED" and stance["confidence"] < 0.7:
            continue

        results.append({
            "source_a": src_a,
            "claim_a": cl_a["claim"],
            "source_b": src_b,
            "claim_b": cl_b["claim"],
            "stance": stance["stance"],
            "confidence": stance["confidence"],
        })

    # Sort: disagreements first, then by confidence descending
    _stance_order = {"DISAGREE": 0, "AGREE": 1, "UNRELATED": 2}
    results.sort(key=lambda r: (_stance_order.get(r["stance"], 3), -r["confidence"]))

    if results:
        disagree_count = sum(1 for r in results if r["stance"] == "DISAGREE")
        logger.info(
            "Event %d: %d stance pair(s) detected (%d disagreements)",
            event_id,
            len(results),
            disagree_count,
        )

    return results
