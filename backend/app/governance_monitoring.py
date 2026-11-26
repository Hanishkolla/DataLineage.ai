"""M54 persistent scheduled governance monitoring.

Schedules store bounded metadata snapshots supplied by an authorized tenant admin.
A separate worker polls and executes due assessments. This is not a live source
connector: customers must refresh snapshots through the API when source metadata changes.
"""
from __future__ import annotations
import json, uuid
from datetime import datetime, timezone, timedelta
from .saas_store import db as _db
from .db_backend import configured_database_url
from .governance_risk import assess_governance_risk
from . import governance_repository as m52_governance
from . import audit_approvals

MIN_INTERVAL_MINUTES = 15
MAX_INTERVAL_MINUTES = 43200
MAX_SNAPSHOT_BYTES = 2 * 1024 * 1024


def _now():
    return datetime.now(timezone.utc)


def _iso(value):
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _schema(c):
    c.executescript("""
    CREATE TABLE IF NOT EXISTS governance_monitor_schedules (
      id TEXT PRIMARY KEY, org_id TEXT NOT NULL, name TEXT NOT NULL,
      interval_minutes INTEGER NOT NULL, snapshot_json TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1, next_run_at TEXT NOT NULL,
      last_run_at TEXT, last_status TEXT, last_error TEXT,
      created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ix_gov_monitor_due
      ON governance_monitor_schedules(enabled,next_run_at);
    CREATE TABLE IF NOT EXISTS governance_monitor_runs (
      id TEXT PRIMARY KEY, org_id TEXT NOT NULL, schedule_id TEXT NOT NULL,
      status TEXT NOT NULL, scan_id TEXT, risk_score INTEGER,
      finding_count INTEGER NOT NULL DEFAULT 0, error_code TEXT,
      started_at TEXT NOT NULL, finished_at TEXT
    );
    CREATE INDEX IF NOT EXISTS ix_gov_monitor_runs_org
      ON governance_monitor_runs(org_id,started_at DESC,id DESC);
    """)


def create_schedule(org_id: str, actor: str, payload: dict):
    if not org_id or not actor or not isinstance(payload, dict):
        raise ValueError("organization, actor and schedule are required")
    name = str(payload.get("name") or "").strip()
    if not name or len(name) > 160:
        raise ValueError("schedule name must be 1-160 characters")
    interval = payload.get("interval_minutes")
    if isinstance(interval, bool) or not isinstance(interval, int) or not MIN_INTERVAL_MINUTES <= interval <= MAX_INTERVAL_MINUTES:
        raise ValueError(f"interval_minutes must be between {MIN_INTERVAL_MINUTES} and {MAX_INTERVAL_MINUTES}")
    snapshot = {"metadata": payload.get("metadata"), "edges": payload.get("edges", []),
                "policies": payload.get("policies")}
    if not isinstance(snapshot["metadata"], dict) or not isinstance(snapshot["edges"], list):
        raise ValueError("metadata object and edges list are required")
    encoded = json.dumps(snapshot, separators=(",", ":"), ensure_ascii=False)
    if len(encoded.encode("utf-8")) > MAX_SNAPSHOT_BYTES:
        raise ValueError("governance snapshot exceeds 2 MiB")
    # Validate the snapshot before persisting a recurring job.
    assess_governance_risk(snapshot["metadata"], snapshot["edges"], snapshot["policies"])
    now = _now(); schedule_id = str(uuid.uuid4())
    with _db() as c:
        _schema(c)
        c.execute("INSERT INTO governance_monitor_schedules VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (schedule_id, org_id, name, interval, encoded, 1,
             _iso(now + timedelta(minutes=interval)), None, None, None,
             actor, _iso(now), _iso(now)))
    audit_approvals.append_event(org_id, actor, "governance.monitor.created",
        "governance_monitor_schedule", schedule_id, {"name": name, "interval_minutes": interval})
    return get_schedule(org_id, schedule_id)


def list_schedules(org_id: str, limit: int = 100):
    limit = max(1, min(int(limit), 300))
    with _db() as c:
        _schema(c)
        rows = c.execute("SELECT id,org_id,name,interval_minutes,enabled,next_run_at,last_run_at,last_status,last_error,created_by,created_at,updated_at FROM governance_monitor_schedules WHERE org_id=? ORDER BY created_at DESC,id DESC LIMIT ?", (org_id, limit)).fetchall()
        return [dict(r) | {"enabled": bool(r["enabled"])} for r in rows]


def get_schedule(org_id: str, schedule_id: str):
    with _db() as c:
        _schema(c)
        row = c.execute("SELECT id,org_id,name,interval_minutes,enabled,next_run_at,last_run_at,last_status,last_error,created_by,created_at,updated_at FROM governance_monitor_schedules WHERE org_id=? AND id=?", (org_id, schedule_id)).fetchone()
        return (dict(row) | {"enabled": bool(row["enabled"])}) if row else None


def set_enabled(org_id: str, schedule_id: str, enabled: bool, actor: str):
    if not isinstance(enabled, bool):
        raise ValueError("enabled must be a boolean")
    now = _now()
    with _db() as c:
        _schema(c)
        cur = c.execute("UPDATE governance_monitor_schedules SET enabled=?, next_run_at=?, updated_at=? WHERE org_id=? AND id=?",
            (1 if enabled else 0, _iso(now + timedelta(minutes=MIN_INTERVAL_MINUTES)), _iso(now), org_id, schedule_id))
        if cur.rowcount != 1:
            return None
    audit_approvals.append_event(org_id, actor, "governance.monitor.enabled" if enabled else "governance.monitor.disabled",
        "governance_monitor_schedule", schedule_id, {})
    return get_schedule(org_id, schedule_id)


def list_runs(org_id: str, schedule_id: str | None = None, limit: int = 100):
    limit = max(1, min(int(limit), 300))
    with _db() as c:
        _schema(c)
        if schedule_id:
            rows = c.execute("SELECT * FROM governance_monitor_runs WHERE org_id=? AND schedule_id=? ORDER BY started_at DESC,id DESC LIMIT ?", (org_id, schedule_id, limit)).fetchall()
        else:
            rows = c.execute("SELECT * FROM governance_monitor_runs WHERE org_id=? ORDER BY started_at DESC,id DESC LIMIT ?", (org_id, limit)).fetchall()
        return [dict(r) for r in rows]


def _claim_due(now: datetime):
    """Atomically advance due schedules and create run records before processing."""
    claimed = []
    with _db() as c:
        _schema(c)
        if configured_database_url():
            c.execute("SELECT pg_advisory_xact_lock(hashtext(?))", ("m54-monitor-claim",))
        else:
            c.execute("BEGIN IMMEDIATE")
        rows = c.execute("SELECT * FROM governance_monitor_schedules WHERE enabled=1 AND next_run_at<=? ORDER BY next_run_at,id LIMIT 25", (_iso(now),)).fetchall()
        for row in rows:
            run_id = str(uuid.uuid4()); started = _iso(now)
            next_at = _iso(now + timedelta(minutes=int(row["interval_minutes"])))
            cur = c.execute("UPDATE governance_monitor_schedules SET next_run_at=?,last_run_at=?,last_status='running',last_error=NULL,updated_at=? WHERE id=? AND enabled=1 AND next_run_at<=?",
                (next_at, started, started, row["id"], _iso(now)))
            if cur.rowcount != 1:
                continue
            c.execute("INSERT INTO governance_monitor_runs(id,org_id,schedule_id,status,started_at) VALUES(?,?,?,?,?)",
                (run_id, row["org_id"], row["id"], "running", started))
            claimed.append({"run_id": run_id, "schedule_id": row["id"], "org_id": row["org_id"],
                            "snapshot_json": row["snapshot_json"], "name": row["name"]})
    return claimed


def run_once(now: datetime | None = None):
    """Execute at most 25 due schedules; safe for multiple pollers via DB claim lock."""
    now = now or _now()
    claimed = _claim_due(now)
    completed = failed = 0
    for item in claimed:
        finished = _iso(_now())
        try:
            snapshot = json.loads(item["snapshot_json"])
            result = assess_governance_risk(snapshot["metadata"], snapshot["edges"], snapshot.get("policies"))
            persisted = m52_governance.save_scan(item["org_id"], result)
            with _db() as c:
                _schema(c)
                c.execute("UPDATE governance_monitor_runs SET status='completed',scan_id=?,risk_score=?,finding_count=?,finished_at=? WHERE id=? AND org_id=?",
                    (persisted["scan_id"], int(result["risk_score"]), int(result["finding_count"]), finished, item["run_id"], item["org_id"]))
                c.execute("UPDATE governance_monitor_schedules SET last_status='completed',last_error=NULL,updated_at=? WHERE id=? AND org_id=?",
                    (finished, item["schedule_id"], item["org_id"]))
            audit_approvals.append_event(item["org_id"], "governance_monitor_worker", "governance.monitor.completed",
                "governance_monitor_schedule", item["schedule_id"], {"run_id": item["run_id"], "scan_id": persisted["scan_id"], "risk_score": result["risk_score"]})
            completed += 1
        except Exception as exc:
            # Store only a stable error class; never persist snapshot contents or raw exception text.
            error_code = type(exc).__name__[:80]
            with _db() as c:
                _schema(c)
                c.execute("UPDATE governance_monitor_runs SET status='failed',error_code=?,finished_at=? WHERE id=? AND org_id=?",
                    (error_code, finished, item["run_id"], item["org_id"]))
                c.execute("UPDATE governance_monitor_schedules SET last_status='failed',last_error=?,updated_at=? WHERE id=? AND org_id=?",
                    (error_code, finished, item["schedule_id"], item["org_id"]))
            failed += 1
    return {"claimed": len(claimed), "completed": completed, "failed": failed}
