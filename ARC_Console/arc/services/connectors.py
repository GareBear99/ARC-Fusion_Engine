"""External-feed ingestion via connectors.

Currently only one connector type is implemented: ``filesystem_jsonl``,
which polls a directory for ``*.jsonl`` files and funnels each line through
``ingest.create_event``. The full connector lifecycle (sources, runs, cursor
watermark, receipts) is mapped out in ``docs/ARCHITECTURE.md`` §10.
"""
from __future__ import annotations
import json
from pathlib import Path
from arc.core.config import CONNECTOR_INBOX_DIR
from arc.core.db import connect
from arc.core.schemas import ConnectorIn, EventIn, new_id, utcnow
from arc.services.audit import append_receipt
from arc.services.ingest import create_event


def create_connector(item: ConnectorIn) -> dict:
    """Upsert a connector by ``name``, returning its canonical record.

    Keys an existing record on the name; if present, re-applies the type,
    config path, and enabled/disabled status. A ``connector`` receipt is
    appended either way.
    """
    now = utcnow()
    path = str(Path(item.path).expanduser())
    with connect() as conn:
        row = conn.execute("SELECT connector_id FROM connector_sources WHERE name = ?", (item.name,)).fetchone()
        if row:
            connector_id = row["connector_id"]
            conn.execute(
                "UPDATE connector_sources SET connector_type = ?, config_json = ?, status = ?, updated_at = ? WHERE connector_id = ?",
                (item.connector_type, json.dumps({"path": path}, sort_keys=True), "enabled" if item.enabled else "disabled", now, connector_id),
            )
        else:
            connector_id = new_id("con")
            conn.execute(
                "INSERT INTO connector_sources (connector_id, name, connector_type, config_json, status, cursor_value, last_polled_at, last_result_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)",
                (connector_id, item.name, item.connector_type, json.dumps({"path": path}, sort_keys=True), "enabled" if item.enabled else "disabled", "", json.dumps({}, sort_keys=True), now, now),
            )
        conn.commit()
    append_receipt("connector", item.name, "admin", {"path": path, "status": "enabled" if item.enabled else "disabled"})
    return get_connector_by_name(item.name)


def list_connectors() -> list[dict]:
    """Return all connectors with config and last_result JSON deserialized."""
    with connect() as conn:
        rows = conn.execute("SELECT * FROM connector_sources ORDER BY created_at ASC").fetchall()
        return [{**dict(r), "config": json.loads(r["config_json"]), "last_result": json.loads(r["last_result_json"])} for r in rows]


def get_connector(connector_id: str) -> dict:
    """Load one connector by id; raises ``KeyError`` if absent."""
    with connect() as conn:
        row = conn.execute("SELECT * FROM connector_sources WHERE connector_id = ?", (connector_id,)).fetchone()
        if not row:
            raise KeyError(connector_id)
        return {**dict(row), "config": json.loads(row["config_json"]), "last_result": json.loads(row["last_result_json"])}


def get_connector_by_name(name: str) -> dict:
    """Load one connector by its unique name; raises ``KeyError`` if absent."""
    with connect() as conn:
        row = conn.execute("SELECT connector_id FROM connector_sources WHERE name = ?", (name,)).fetchone()
        if not row:
            raise KeyError(name)
    return get_connector(row["connector_id"])


def _iter_jsonl(path: Path):
    """Yield parsed JSON objects one-per-line from a ``.jsonl`` file.

    Blank lines are skipped. Any line that fails ``json.loads`` raises,
    aborting the whole poll (the run is marked ``status=error``).
    """
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def poll_connector(connector_id: str) -> dict:
    """Run a single poll cycle for ``connector_id`` against its filesystem inbox.

    Iterates ``*.jsonl`` files whose name sorts after the stored cursor
    watermark, constructs an ``EventIn`` per line, and feeds it through
    ``ingest.create_event``. On completion, updates the cursor to the
    last-processed filename, writes a ``last_result`` JSON summary, closes
    the ``connector_runs`` row as ``ok``, and appends a ``connector_run``
    receipt. Any raised exception closes the run as ``error`` with the
    exception repr recorded, then re-raises.
    """
    connector = get_connector(connector_id)
    config = connector["config"]
    inbox = Path(config["path"]).expanduser()
    inbox.mkdir(parents=True, exist_ok=True)
    cursor = connector.get("cursor_value") or ""
    run_id = new_id("run")
    imported = 0
    imported_files = []
    detail = {"messages": []}
    with connect() as conn:
        conn.execute(
            "INSERT INTO connector_runs (run_id, connector_id, started_at, ended_at, status, imported_count, detail_json) VALUES (?, ?, ?, NULL, 'running', 0, ?)",
            (run_id, connector_id, utcnow(), json.dumps(detail, sort_keys=True)),
        )
        conn.commit()
    try:
        files = sorted(p for p in inbox.glob("*.jsonl") if p.name > cursor)
        for path in files:
            count_in_file = 0
            for raw in _iter_jsonl(path):
                evt = EventIn(
                    event_type=raw.get("event_type", "connector_event"),
                    source=raw.get("source", f"connector:{connector['name']}"),
                    subject=raw.get("subject", raw.get("entity", "Unknown Subject")),
                    object=raw.get("object"),
                    location=raw.get("location"),
                    confidence=float(raw.get("confidence", 0.7)),
                    severity=int(raw.get("severity", 4)),
                    payload={k: v for k, v in raw.items() if k not in {"event_type", "source", "subject", "entity", "object", "location", "confidence", "severity"}},
                    ts=raw.get("ts") or utcnow(),
                )
                create_event(evt)
                imported += 1
                count_in_file += 1
            imported_files.append({"file": path.name, "imported": count_in_file})
            cursor = path.name
        last_result = {"imported": imported, "files": imported_files}
        with connect() as conn:
            conn.execute(
                "UPDATE connector_sources SET cursor_value = ?, last_polled_at = ?, last_result_json = ?, updated_at = ? WHERE connector_id = ?",
                (cursor, utcnow(), json.dumps(last_result, sort_keys=True), utcnow(), connector_id),
            )
            conn.execute(
                "UPDATE connector_runs SET ended_at = ?, status = 'ok', imported_count = ?, detail_json = ? WHERE run_id = ?",
                (utcnow(), imported, json.dumps(last_result, sort_keys=True), run_id),
            )
            conn.commit()
        append_receipt("connector_run", run_id, "admin", {"connector_id": connector_id, "imported": imported})
        return {"connector_id": connector_id, "run_id": run_id, **last_result}
    except Exception as exc:
        with connect() as conn:
            conn.execute(
                "UPDATE connector_runs SET ended_at = ?, status = 'error', detail_json = ? WHERE run_id = ?",
                (utcnow(), json.dumps({"error": str(exc)}, sort_keys=True), run_id),
            )
            conn.commit()
        raise


def ensure_demo_connector() -> dict:
    """Seed + register the demo filesystem connector on a clean bootstrap.

    Writes two sample JSONL records (a presence event and a geo_ping event)
    to ``data/connectors/demo_feed/0001_seed.jsonl`` if missing, then
    upserts the connector record.
    """
    demo_path = CONNECTOR_INBOX_DIR / "demo_feed"
    demo_path.mkdir(parents=True, exist_ok=True)
    seed_file = demo_path / "0001_seed.jsonl"
    if not seed_file.exists():
        payload = [
            json.dumps({"event_type": "presence", "source": "filesystem-demo", "subject": "RG Sensor Mesh", "object": "Pine House", "location": "Williams Lake", "confidence": 0.84, "severity": 5, "note": "seeded connector event"}),
            json.dumps({"event_type": "geo_ping", "source": "filesystem-demo", "subject": "Demo Device", "location": "Pine House", "confidence": 0.78, "severity": 4, "floor": 1}),
        ]
        seed_file.write_text("\n".join(payload) + "\n", encoding="utf-8")
    return create_connector(ConnectorIn(name="demo-feed", connector_type="filesystem_jsonl", path=str(demo_path), enabled=True))
