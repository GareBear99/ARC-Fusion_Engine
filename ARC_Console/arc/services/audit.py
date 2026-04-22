"""Audit log + tamper-evident receipt chain.

This module implements the heart of ARC-Core's integrity story:

* ``log(...)`` writes to ``audit_log`` — a simple debug/forensics trail used
  by every mutating API route. Not cryptographically chained.
* ``append_receipt(...)`` appends to ``receipt_chain`` — the SHA-256 +
  HMAC-signed chain that downstream consumers can verify end-to-end via
  ``verify_receipt_chain``. Every state-producing operation (events,
  structures, sensors, geofences, tracks, overlays, calibrations,
  incidents, auth users/sessions, notes, connectors, connector runs)
  appends one receipt.

Chain protocol: each row's ``hash = sha256(prev_hash|ts|type|id|role|payload)``
and ``signature = hmac_sha256(key, same_payload)``. Verification walks
rows in insertion order and re-derives both; any mismatch aborts with a
precise reason code.

See ``docs/ARCHITECTURE.md`` §8.
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import secrets
from pathlib import Path
from arc.core.config import KEY_DIR
from arc.core.db import connect
from arc.core.schemas import new_id, utcnow

#: On-disk path to the 32-byte HMAC signing key. Created on first use.
SIGNING_KEY_PATH = KEY_DIR / "receipt_signing.key"
#: Identifier recorded on every receipt row for future key-rotation support.
KEY_ID = "local-hmac-v1"


def _ensure_signing_key() -> bytes:
    """Return the HMAC signing key, minting one on first call.

    The key is 32 random bytes from ``secrets.token_bytes``. It's written to
    ``data/keys/receipt_signing.key`` with default file permissions; operators
    should tighten those (``chmod 600``) in production.
    """
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    if SIGNING_KEY_PATH.exists():
        return SIGNING_KEY_PATH.read_bytes()
    key = secrets.token_bytes(32)
    SIGNING_KEY_PATH.write_bytes(key)
    return key


def _encode_signature(payload: str) -> str:
    key = _ensure_signing_key()
    digest = hmac.new(key, payload.encode("utf-8"), hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")


def log(actor_role: str, action: str, target: str, detail: dict) -> None:
    """Write one row to ``audit_log``.

    Used by every mutating HTTP route for operator traceability. This is
    *not* cryptographically chained — for tamper-evidence, call
    ``append_receipt`` instead (or in addition).
    """
    with connect() as conn:
        conn.execute(
            "INSERT INTO audit_log (audit_id, ts, actor_role, action, target, detail_json) VALUES (?, ?, ?, ?, ?, ?)",
            (new_id("aud"), utcnow(), actor_role, action, target, json.dumps(detail, sort_keys=True)),
        )
        conn.commit()


def append_receipt(record_type: str, record_id: str, actor_role: str, payload: dict) -> dict:
    """Append one entry to the tamper-evident receipt chain.

    Reads the current tail hash (``"GENESIS"`` if the chain is empty),
    canonicalizes the payload via ``json.dumps(sort_keys=True)``, builds
    the chain payload string ``"{prev_hash}|{ts}|{type}|{id}|{role}|{payload_json}"``
    and stores both its SHA-256 hash and its base64-encoded HMAC-SHA256
    signature. Returns ``{receipt_id, hash, signature, key_id}`` for callers
    who want to surface the receipt fingerprint.
    """
    with connect() as conn:
        prev = conn.execute("SELECT hash FROM receipt_chain ORDER BY ts DESC, receipt_id DESC LIMIT 1").fetchone()
        prev_hash = prev["hash"] if prev else "GENESIS"
        ts = utcnow()
        payload_json = json.dumps(payload, sort_keys=True)
        chain_payload = f"{prev_hash}|{ts}|{record_type}|{record_id}|{actor_role}|{payload_json}"
        hash_value = hashlib.sha256(chain_payload.encode("utf-8")).hexdigest()
        signature = _encode_signature(chain_payload)
        receipt_id = new_id("rcp")
        conn.execute(
            "INSERT INTO receipt_chain (receipt_id, ts, record_type, record_id, actor_role, payload_json, prev_hash, hash, signature, key_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (receipt_id, ts, record_type, record_id, actor_role, payload_json, prev_hash, hash_value, signature, KEY_ID),
        )
        conn.commit()
    return {"receipt_id": receipt_id, "hash": hash_value, "signature": signature, "key_id": KEY_ID}


def list_receipts(limit: int = 100) -> list[dict]:
    """Return the most recent receipts, newest-first, with payload deserialized."""
    with connect() as conn:
        rows = conn.execute("SELECT * FROM receipt_chain ORDER BY ts DESC, receipt_id DESC LIMIT ?", (limit,)).fetchall()
        return [{**dict(r), "payload": json.loads(r["payload_json"])} for r in rows]


def verify_receipt_chain(limit: int | None = None) -> dict:
    """Walk the receipt chain in insertion order, re-deriving each hash + HMAC.

    Returns ``{ok: True, checked, tail, key_id}`` on success. On any
    mismatch returns ``{ok: False, checked, reason, receipt_id}`` where
    ``reason`` is one of ``prev_hash_mismatch``, ``hash_mismatch``,
    ``signature_mismatch``. ``limit`` caps how many rows to verify — the
    HTTP layer clamps this to ``RECEIPT_VERIFY_MAX``.
    """
    with connect() as conn:
        query = "SELECT * FROM receipt_chain ORDER BY ts ASC, receipt_id ASC"
        params = ()
        if limit:
            query += " LIMIT ?"
            params = (limit,)
        rows = conn.execute(query, params).fetchall()
    prev_hash = "GENESIS"
    checked = 0
    key = _ensure_signing_key()
    for row in rows:
        payload_json = row["payload_json"]
        chain_payload = f"{prev_hash}|{row['ts']}|{row['record_type']}|{row['record_id']}|{row['actor_role']}|{payload_json}"
        expected_hash = hashlib.sha256(chain_payload.encode("utf-8")).hexdigest()
        expected_sig = base64.b64encode(hmac.new(key, chain_payload.encode("utf-8"), hashlib.sha256).digest()).decode("ascii")
        if row["prev_hash"] != prev_hash:
            return {"ok": False, "checked": checked, "reason": "prev_hash_mismatch", "receipt_id": row["receipt_id"]}
        if row["hash"] != expected_hash:
            return {"ok": False, "checked": checked, "reason": "hash_mismatch", "receipt_id": row["receipt_id"]}
        if row["signature"] != expected_sig:
            return {"ok": False, "checked": checked, "reason": "signature_mismatch", "receipt_id": row["receipt_id"]}
        prev_hash = row["hash"]
        checked += 1
    return {"ok": True, "checked": checked, "tail": prev_hash, "key_id": KEY_ID}
