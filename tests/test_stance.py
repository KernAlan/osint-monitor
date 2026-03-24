"""Tests for osint_monitor.processors.stance (pure helpers, no NLP models)."""

from unittest.mock import patch, MagicMock

from osint_monitor.processors.stance import (
    CONTRADICTORY_VERB_PAIRS,
    extract_claims,
)


# ---------------------------------------------------------------------------
# Contradictory verb pairs
# ---------------------------------------------------------------------------

def test_contradictory_verbs():
    """'confirmed' and 'denied' should be a contradictory pair."""
    assert "confirmed" in CONTRADICTORY_VERB_PAIRS
    assert CONTRADICTORY_VERB_PAIRS["confirmed"] == "denied"


# ---------------------------------------------------------------------------
# Claim extraction (requires spaCy mock)
# ---------------------------------------------------------------------------

def test_claim_extraction():
    """extract_claims should return at least one claim with subject containing 'Russia'.

    We mock the spaCy pipeline so that no model download is required.
    """
    # Build a minimal mock that simulates spaCy's Doc / Token / Span interface
    mock_token_verb = MagicMock()
    mock_token_verb.dep_ = "ROOT"
    mock_token_verb.pos_ = "VERB"
    mock_token_verb.lemma_ = "attack"
    mock_token_verb.text = "attacked"

    mock_subj = MagicMock()
    mock_subj.dep_ = "nsubj"
    mock_subj.text = "Russia"
    mock_subj.i = 0
    # subtree returns itself (single-token subject)
    mock_subj.subtree = [mock_subj]

    mock_obj = MagicMock()
    mock_obj.dep_ = "dobj"
    mock_obj.text = "Ukraine"
    mock_obj.i = 2
    mock_obj.subtree = [mock_obj]

    mock_token_verb.children = [mock_subj, mock_obj]

    mock_sent = MagicMock()
    mock_sent.text = "Russia attacked Ukraine."
    mock_sent.__iter__ = lambda self: iter([mock_subj, mock_token_verb, mock_obj])

    mock_doc = MagicMock()
    mock_doc.sents = [mock_sent]

    mock_nlp = MagicMock(return_value=mock_doc)

    with patch("osint_monitor.processors.nlp.get_nlp", return_value=mock_nlp):
        claims = extract_claims("Russia attacked Ukraine.")

    assert len(claims) >= 1
    assert any("Russia" in c["subject"] for c in claims)
