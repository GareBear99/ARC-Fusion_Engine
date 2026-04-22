"""Explainable linear risk-scoring for events and entities.

The formula is deliberately simple so an analyst can trace exactly why a given
score landed where it did. See ``docs/ARCHITECTURE.md`` §5.3 for the full
specification and rationale.
"""
from __future__ import annotations
from math import log1p


def score_event(confidence: float, severity: int, watchlisted: bool, related_edges: int, event_count_7d: int) -> float:
    """Compute a risk score in ``[0, 100]`` for an event/entity.

    Components (all additive):

    * ``confidence * 50`` — 0-50 from the observer's confidence in the event.
    * ``severity * 4`` — 4-40 from the 1-10 severity scale on the event.
    * ``min(18, log1p(event_count_7d) * 6)`` — up to 18 extra points reflecting
      activity volume over the last 7 days (logarithmic so noise doesn't
      dominate).
    * ``min(12, related_edges * 1.5)`` — up to 12 extra points from the
      subject's existing graph connectivity.
    * ``+18`` flat if the subject is on any watchlist.

    The result is clamped to 100 and rounded to two decimals.
    """
    score = (confidence * 50.0) + (severity * 4.0) + min(18.0, log1p(event_count_7d) * 6.0) + min(12.0, related_edges * 1.5)
    if watchlisted:
        score += 18.0
    return round(min(100.0, score), 2)


def impact_band(score: float) -> str:
    """Map a numeric risk score to an impact label.

    Thresholds: ``>=80`` → ``"critical"``, ``>=60`` → ``"high"``, ``>=35`` →
    ``"medium"``, else ``"low"``. Used in proposal simulations and UI badges.
    """
    if score >= 80: return "critical"
    if score >= 60: return "high"
    if score >= 35: return "medium"
    return "low"
