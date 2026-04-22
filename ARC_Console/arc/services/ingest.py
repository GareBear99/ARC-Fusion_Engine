"""Event ingestion: the authoritative entry point for state-producing writes.

Every mutation that matters to downstream correctness flows through
``create_event``: entity resolution, fingerprint-based deduplication, risk
scoring, graph-edge accumulation, and receipt-chain appending all happen
here in a single transaction + post-commit receipt.

See ``docs/ARCHITECTURE.md`` §7.2 for the step-by-step spec.
"""
from __future__ import annotations
import json
from datetime import datetime, timedelta, timezone
from arc.core.db import connect
from arc.core.schemas import EventIn, EventOut, new_id
from arc.core.util import fingerprint
from arc.core.risk import score_event
from arc.services.resolver import resolve_entity
from arc.services.graph import upsert_edge
from arc.services.audit import append_receipt


def _event_count_7d(conn, subject_entity: str) -> int:
    """Return the count of events for ``subject_entity`` in the last 7 days.

    Used as one of the inputs to ``risk.score_event``. A sliding 7-day window
    keeps risk responsive to bursts without permanently inflating scores
    when activity cools down.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    row = conn.execute(
        "SELECT COUNT(*) AS c FROM events WHERE ts >= ? AND subject = ?",
        (cutoff, subject_entity),
    ).fetchone()
    return int(row["c"])


def create_event(data: EventIn) -> EventOut:
    """Ingest one event through the full ARC-Core pipeline.

    Pipeline:

    1. Resolve subject (and object if present) to canonical ``entity_id``.
    2. Compute the 24-char SHA-256 fingerprint from the canonicalized blob.
    3. If an event with this fingerprint already exists, return the existing
       ``EventOut`` (idempotent replay — this is why retries are safe).
    4. Compute risk inputs: watchlist status, graph connectivity, 7-day
       event count; pass them through ``risk.score_event``.
    5. Insert into ``events`` (payload canonically JSON-encoded).
    6. Monotonically raise the subject entity's ``risk_score`` via
       ``MAX(risk_score, new_score)``.
    7. Upsert a directed edge subject→object on ``event_type`` if the event
       has an object, reusing the ingest transaction.
    8. Commit.
    9. Outside the transaction, append a ``"event"`` receipt to the chain
       (post-commit so a receipt never exists for a rolled-back event).

    Returns the ``EventOut`` with the assigned ``id`` and ``fingerprint``.
    """
    subject_entity = resolve_entity(data.subject)
    object_entity = resolve_entity(data.object) if data.object else None
    fp = fingerprint(data.event_type, data.source, data.subject, data.object, data.location, data.payload)
    event_id = new_id("evt")
    with connect() as conn:
        existing = conn.execute("SELECT * FROM events WHERE fingerprint = ?", (fp,)).fetchone()
        if existing:
            payload = json.loads(existing["payload_json"])
            return EventOut(
                id=existing["id"],
                event_type=existing["event_type"],
                source=existing["source"],
                subject=data.subject,
                object=data.object,
                location=existing["location"],
                confidence=existing["confidence"],
                severity=existing["severity"],
                payload=payload,
                ts=existing["ts"],
                fingerprint=existing["fingerprint"],
            )
        watchlisted = conn.execute("SELECT 1 FROM watchlists WHERE entity_id = ? LIMIT 1", (subject_entity,)).fetchone() is not None
        edge_count = conn.execute("SELECT COUNT(*) AS c FROM edges WHERE src_entity = ? OR dst_entity = ?", (subject_entity, subject_entity)).fetchone()["c"]
        count7 = _event_count_7d(conn, subject_entity)
        risk_score = score_event(data.confidence, data.severity, watchlisted, int(edge_count), count7)
        conn.execute(
            "INSERT INTO events (id, ts, event_type, source, subject, object, location, confidence, severity, fingerprint, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (event_id, data.ts, data.event_type, data.source, subject_entity, object_entity, data.location, data.confidence, data.severity, fp, json.dumps(data.payload, sort_keys=True)),
        )
        conn.execute("UPDATE entities SET risk_score = MAX(risk_score, ?) WHERE entity_id = ?", (risk_score, subject_entity))
        if object_entity:
            upsert_edge(subject_entity, object_entity, data.event_type, increment=max(1.0, data.confidence * 2), conn=conn)
        conn.commit()
    append_receipt("event", event_id, "observer", {"fingerprint": fp, "subject": subject_entity, "object": object_entity, "source": data.source})
    return EventOut(id=event_id, fingerprint=fp, **data.model_dump())


def list_events(limit: int = 50, q: str | None = None) -> list[dict]:
    """Return the most recent events, optionally filtered by a free-text query.

    When ``q`` is provided, matches are case-insensitive LIKE searches across
    ``event_type``, ``source``, ``subject``, ``object``, ``location``, the
    serialized ``payload_json``, and the joined entity labels for subject
    and object. Results are always ordered by ``ts DESC`` and capped by
    ``limit`` (which the HTTP layer clamps to ``MAX_LIMIT``).

    No FTS index is used — this is a full table scan with LIKE predicates,
    which is fine up to ~10^6 events on commodity disks.
    """
    with connect() as conn:
        if q:
            token = f"%{q.lower()}%"
            rows = conn.execute(
                """
                SELECT e.*,
                       es.label AS subject_label,
                       eo.label AS object_label
                FROM events e
                LEFT JOIN entities es ON es.entity_id = e.subject
                LEFT JOIN entities eo ON eo.entity_id = e.object
                WHERE lower(e.event_type) LIKE ?
                   OR lower(e.source) LIKE ?
                   OR lower(e.subject) LIKE ?
                   OR lower(ifnull(e.object, '')) LIKE ?
                   OR lower(ifnull(e.location, '')) LIKE ?
                   OR lower(e.payload_json) LIKE ?
                   OR lower(ifnull(es.label, '')) LIKE ?
                   OR lower(ifnull(eo.label, '')) LIKE ?
                ORDER BY e.ts DESC LIMIT ?
                """,
                (token, token, token, token, token, token, token, token, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY ts DESC LIMIT ?",
                (limit,),
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item.pop("payload_json"))
            item.pop("subject_label", None)
            item.pop("object_label", None)
            result.append(item)
        return result
