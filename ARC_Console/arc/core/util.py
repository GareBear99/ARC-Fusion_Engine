"""String-normalization and fingerprinting utilities for the ingest pipeline.

``fingerprint`` is the dedupe identity for events — a 24-hex-char SHA-256
prefix over a canonical JSON blob that normalizes entity strings and
sort-keys the payload so semantically-identical events produce identical
hashes regardless of whitespace or dict ordering.

See ``docs/ARCHITECTURE.md`` §5.2.
"""
from __future__ import annotations
import hashlib
import json
import re


def normalize_entity(text: str | None) -> str:
    """Collapse whitespace, trim, and lower-case an entity string.

    Returns an empty string for ``None``/empty input. This is the canonical
    form used wherever entity equality matters (resolver, fingerprint).
    """
    if not text:
        return ""
    value = re.sub(r"\s+", " ", text.strip().lower())
    return value


def guess_entity_type(value: str) -> str:
    """Lightweight heuristic classification for a raw entity label.

    Returns one of ``"location" | "device" | "org" | "person"`` based on
    simple substring rules. Intentionally dumb — analysts can override the
    type later via notes/proposals. Good enough for first-pass prioritization
    in the UI.
    """
    v = value.lower()
    if any(tok in v for tok in ["st", "ave", "road", "rd", "park", "mall", "airport"]):
        return "location"
    if any(ch.isdigit() for ch in v) and ("device" in v or "cam" in v or "node" in v):
        return "device"
    if "corp" in v or "inc" in v or "ltd" in v or "group" in v:
        return "org"
    return "person"


def fingerprint(event_type: str, source: str, subject: str, object_: str | None, location: str | None, payload: dict) -> str:
    """Compute the canonical 24-hex-char dedupe identity for an event.

    Subject/object/location are normalized via ``normalize_entity`` before
    hashing, and the payload is serialized with ``sort_keys=True`` so dict
    ordering cannot change the fingerprint. The resulting hex prefix is
    stored in ``events.fingerprint`` (UNIQUE index). Ingest uses this to
    short-circuit on replay: an event whose fingerprint already exists
    returns the existing row instead of inserting a duplicate.
    """
    blob = json.dumps({
        "event_type": event_type,
        "source": source,
        "subject": normalize_entity(subject),
        "object": normalize_entity(object_),
        "location": normalize_entity(location),
        "payload": payload,
    }, sort_keys=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:24]
