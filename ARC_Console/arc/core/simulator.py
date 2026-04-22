"""Proposal dry-run engine.

Given an intended ``action`` against a ``target_id`` with a known live
``risk_score``, produces a structured preview of likely outcomes and caution
flags. Pure-Python and deterministic — no ML, no external calls. See
``docs/ARCHITECTURE.md`` §5.4.
"""
from __future__ import annotations
from arc.core.risk import impact_band


def simulate(action: str, target_id: str, risk_score: float, depth: int = 2) -> dict:
    """Return a dict describing the predicted impact of performing ``action``.

    ``action`` values of ``"observe" | "flag" | "escalate"`` contribute +10 to
    the projected score; anything else contributes +4. The projected score is
    then mapped to an ``impact_band`` and emitted alongside free-form
    ``likely_outcomes`` strings and ``caution_flags`` warnings. A ``depth``
    of 3+ adds a second-order-scrutiny outcome. Confidence rises with
    ``risk_score`` but saturates at 0.95.
    """
    score = min(100.0, risk_score + (10 if action.lower() in {"observe","flag","escalate"} else 4))
    outcomes = []
    flags = []
    if action.lower() == "observe":
        outcomes.extend([
            "Increased collection fidelity around target",
            "Higher analyst confidence if corroborating events continue",
        ])
    elif action.lower() == "flag":
        outcomes.extend([
            "Target appears in watch-driven triage views",
            "Future related events inherit heightened review priority",
        ])
    else:
        outcomes.extend([
            "Action enters operator review lane",
            "Downstream systems should remain approval-gated",
        ])
    if risk_score >= 60:
        flags.append("Target already elevated; false positives carry operator cost")
    if depth >= 3:
        outcomes.append("Second-order relationships may inherit temporary scrutiny")
    return {
        "target_id": target_id,
        "action": action,
        "impact_band": impact_band(score),
        "confidence": round(min(0.95, 0.55 + risk_score / 200.0), 2),
        "likely_outcomes": outcomes,
        "caution_flags": flags,
    }
