"""Analyst case management.

A case groups together events, notes, and later proposals into one
investigative unit. Events are attached via ``attach_event`` (idempotent —
case/event pair uniqueness is enforced at the DB layer).
"""
from __future__ import annotations
import sqlite3
from arc.core.db import connect
from arc.core.schemas import CaseIn, new_id, utcnow


def create_case(case: CaseIn) -> dict:
    """Create a new case row and return the canonical case dict."""
    case_id = new_id("case")
    with connect() as conn:
        conn.execute(
            "INSERT INTO cases (case_id, title, priority, status, summary, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (case_id, case.title, case.priority, case.status, case.summary, utcnow()),
        )
        conn.commit()
    return get_case(case_id)


def get_case(case_id: str) -> dict:
    """Return the case record plus all attached events, joined to ``events``.

    Raises ``KeyError(case_id)`` when the case does not exist, which the
    HTTP layer converts to 404.
    """
    with connect() as conn:
        row = conn.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
        if not row:
            raise KeyError(case_id)
        events = [dict(r) for r in conn.execute(
            "SELECT ce.case_event_id, ce.event_id, ce.attached_at, e.event_type, e.ts, e.subject, e.object, e.confidence, e.severity FROM case_events ce JOIN events e ON e.id = ce.event_id WHERE ce.case_id = ? ORDER BY e.ts DESC",
            (case_id,),
        ).fetchall()]
        return {**dict(row), "events": events}


def list_cases() -> list[dict]:
    """Return all cases newest-first, each annotated with ``event_count``."""
    with connect() as conn:
        return [
            {
                **dict(r),
                "event_count": conn.execute("SELECT COUNT(*) c FROM case_events WHERE case_id = ?", (r["case_id"],)).fetchone()["c"],
            }
            for r in conn.execute("SELECT * FROM cases ORDER BY created_at DESC").fetchall()
        ]


def attach_event(case_id: str, event_id: str) -> dict:
    """Attach ``event_id`` to ``case_id``, returning the updated case.

    Idempotent — re-attaching the same (case_id, event_id) is a no-op
    (``IntegrityError`` is swallowed). Raises ``KeyError`` if either the
    case or the event does not exist.
    """
    with connect() as conn:
        if not conn.execute("SELECT 1 FROM cases WHERE case_id = ?", (case_id,)).fetchone():
            raise KeyError(case_id)
        if not conn.execute("SELECT 1 FROM events WHERE id = ?", (event_id,)).fetchone():
            raise KeyError(event_id)
        try:
            conn.execute(
                "INSERT INTO case_events (case_event_id, case_id, event_id, attached_at) VALUES (?, ?, ?, ?)",
                (new_id("ce"), case_id, event_id, utcnow()),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            pass
    return get_case(case_id)
