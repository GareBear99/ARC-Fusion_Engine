"""Canonical entity-id minting and alias tracking.

Given a raw human-readable label, returns a stable ``ent_...`` identifier.
The mapping is deterministic: any whitespace/case variant of the same label
collapses to the same entity_id, so callers don't need to pre-normalize.

See ``docs/ARCHITECTURE.md`` §7.1.
"""
from __future__ import annotations
from arc.core.db import connect
from arc.core.schemas import utcnow
from arc.core.util import normalize_entity, guess_entity_type
import json


def resolve_entity(label: str) -> str:
    """Return the canonical ``entity_id`` for ``label``, creating it if new.

    The entity_id is ``"ent_" + normalize(label).replace(" ", "_")[:48]``.
    If the row already exists, ``label`` is appended to its aliases list
    (deduplicated, sorted) and ``last_seen`` is refreshed. Otherwise a new
    row is inserted with ``guess_entity_type(label)``, aliases ``[label]``,
    and ``risk_score=0``.
    """
    normalized = normalize_entity(label)
    entity_id = f"ent_{normalized.replace(' ', '_')[:48]}"
    now = utcnow()
    with connect() as conn:
        row = conn.execute("SELECT entity_id, aliases_json, first_seen FROM entities WHERE entity_id = ?", (entity_id,)).fetchone()
        if row:
            aliases = sorted(set(json.loads(row["aliases_json"]) + [label]))
            conn.execute(
                "UPDATE entities SET aliases_json = ?, last_seen = ? WHERE entity_id = ?",
                (json.dumps(aliases), now, entity_id),
            )
        else:
            conn.execute(
                "INSERT INTO entities (entity_id, label, entity_type, aliases_json, first_seen, last_seen, risk_score) VALUES (?, ?, ?, ?, ?, ?, 0)",
                (entity_id, label, guess_entity_type(label), json.dumps([label]), now, now),
            )
        conn.commit()
    return entity_id
