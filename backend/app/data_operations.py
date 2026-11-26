"""Milestone 39: evidence-based data operations, drift and quality intelligence.

This module analyzes supplied run events and metadata snapshots. It does not poll
cloud services, execute remediation, inspect customer data, or claim autonomous AI.
Incident persistence is tenant-scoped SQLite and uses parameterized SQL.
"""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

MAX_EVENTS = 10_000
MAX_INCIDENTS = 5_000
MAX_SNAPSHOT_TABLES = 20_000
MAX_COLUMNS_PER_TABLE = 10_000
MAX_INCIDENTS_PAGE = 500


def _s(value: Any, limit: int = 1000) -> str:
    return str(value or "").strip()[:limit]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _failure_triage(event: dict[str, Any]) -> dict[str, Any]:
    message = _s(event.get("message") or event.get("error") or event.get("failure_message"), 2000)
    low = message.casefold()
    checks = [
        (("permission", "access denied", "unauthorized", "forbidden", "iam", "credential"),
         "identity_or_permission", "Permission or identity failure", "high",
         "Verify workload identity, role assignments, token expiry and least-privilege access."),
        (("timeout", "timed out", "connection reset", "connection refused", "dns", "network"),
         "connectivity_or_timeout", "Connectivity or timeout", "medium",
         "Check endpoint health, DNS, network routes, connection pools and bounded retry policy."),
        (("schema", "column not found", "type mismatch", "incompatible type", "missing field"),
         "schema_contract", "Schema or data-contract mismatch", "high",
         "Compare recent source and target schemas; validate upstream changes and compatibility."),
        (("quota", "throttle", "rate limit", "too many requests"),
         "quota_or_throttling", "Quota or throttling", "medium",
         "Inspect service quotas and concurrency; apply exponential backoff with jitter."),
        (("out of memory", "oom", "memory limit", "executor lost"),
         "resource_exhaustion", "Compute resource exhaustion", "medium",
         "Review memory, worker sizing, skew and partition counts before increasing capacity."),
        (("duplicate", "unique constraint", "primary key"),
         "duplicate_or_constraint", "Duplicate or constraint violation", "medium",
         "Check source deduplication, merge keys and idempotency before replaying the run."),
    ]
    for tokens, code, cause, severity, recommendation in checks:
        if any(token in low for token in tokens):
            return {"cause_code": code, "probable_cause": cause, "severity": severity,
                    "recommendation": recommendation, "confidence": "heuristic"}
    return {"cause_code": "unclassified", "probable_cause": "Unclassified pipeline failure",
            "severity": "medium",
            "recommendation": "Inspect sanitized logs, recent deployments and upstream dependencies; avoid automatic replay until the cause is understood.",
            "confidence": "low"}


def analyze_runs(events: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(events, list) or len(events) > MAX_EVENTS or any(not isinstance(e, dict) for e in events):
        raise ValueError(f"events must be a list of at most {MAX_EVENTS} objects")
    results = []
    for event in events:
        status = _s(event.get("status")).casefold()
        if status not in {"failed", "failure", "error", "cancelled", "canceled", "timed_out", "timeout"}:
            continue
        triage = _failure_triage(event)
        event_id = _s(event.get("event_id") or event.get("run_id"), 200)
        pipeline = _s(event.get("pipeline") or event.get("job") or event.get("name") or "unknown", 300)
        results.append({
            "incident_id": str(uuid4()), "event_id": event_id or None,
            "pipeline": pipeline, "run_id": _s(event.get("run_id"), 200) or None,
            "status": status, "timestamp": _s(event.get("timestamp"), 80) or None,
            "cause_code": triage["cause_code"], "probable_cause": triage["probable_cause"],
            "severity": triage["severity"], "recommendation": triage["recommendation"],
            "confidence": triage["confidence"],
            # Evidence is truncated and should be sanitized by the caller before submission.
            "evidence": _s(event.get("message") or event.get("error"), 500),
            "source": _s(event.get("source") or event.get("platform"), 100) or None,
        })
    return {"event_count": len(events), "failure_count": len(results), "incidents": results,
            "analysis_mode": "deterministic_rule_based_triage",
            "limitations": ["Analyzes caller-supplied events only; it does not poll pipelines or access provider logs.",
                            "Root-cause labels are hypotheses based on message keywords, not verified diagnoses.",
                            "Recommendations are advisory; no automatic retry, deployment or remediation is performed."]}


def _snapshot_map(snapshot: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("tables", []), list):
        raise ValueError("snapshot must contain a tables list")
    tables = snapshot.get("tables", [])
    if len(tables) > MAX_SNAPSHOT_TABLES:
        raise ValueError("snapshot exceeds table safety limit")
    result = {}
    for table in tables:
        if not isinstance(table, dict):
            continue
        name = _s(table.get("name"), 500)
        schema = _s(table.get("schema"), 300)
        if not name:
            continue
        key = f"{schema}.{name}" if schema else name
        cols = table.get("columns", [])
        if not isinstance(cols, list) or len(cols) > MAX_COLUMNS_PER_TABLE:
            raise ValueError(f"invalid or oversized columns for table {key}")
        col_map = {}
        for col in cols:
            if isinstance(col, dict) and _s(col.get("name"), 300):
                col_name = _s(col.get("name"), 300)
                col_map[col_name.casefold()] = {"name": col_name, "type": _s(col.get("type"), 200) or "unknown"}
        result[key.casefold()] = {"name": key, "columns": col_map}
    return result


def detect_schema_drift(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    old, new = _snapshot_map(previous), _snapshot_map(current)
    changes = []
    for key in sorted(old.keys() - new.keys()):
        changes.append({"object": old[key]["name"], "change": "table_removed", "risk": "high"})
    for key in sorted(new.keys() - old.keys()):
        changes.append({"object": new[key]["name"], "change": "table_added", "risk": "low"})
    for key in sorted(old.keys() & new.keys()):
        before, after = old[key]["columns"], new[key]["columns"]
        for col in sorted(before.keys() - after.keys()):
            changes.append({"object": old[key]["name"], "column": before[col]["name"],
                            "change": "column_removed", "risk": "high"})
        for col in sorted(after.keys() - before.keys()):
            changes.append({"object": new[key]["name"], "column": after[col]["name"],
                            "change": "column_added", "risk": "low"})
        for col in sorted(before.keys() & after.keys()):
            old_type, new_type = before[col]["type"].casefold(), after[col]["type"].casefold()
            if old_type != new_type:
                changes.append({"object": new[key]["name"], "column": after[col]["name"],
                                "change": "column_type_changed", "old_type": before[col]["type"],
                                "new_type": after[col]["type"], "risk": "high"})
    return {"change_count": len(changes), "changes": changes,
            "status": "drift_detected" if changes else "no_drift",
            "analysis_mode": "metadata_snapshot_diff",
            "limitations": ["Only compares the supplied snapshots; it does not subscribe to catalog events or infer runtime compatibility."]}


def evaluate_quality(metrics: list[dict[str, Any]], thresholds: dict[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(metrics, list) or len(metrics) > 100_000 or any(not isinstance(m, dict) for m in metrics):
        raise ValueError("metrics must be a bounded list of objects")
    thresholds = thresholds or {}
    if not isinstance(thresholds, dict):
        raise ValueError("thresholds must be an object")
    defaults = {"null_rate_max": 0.05, "duplicate_rate_max": 0.01, "freshness_lag_seconds_max": 86400}
    for key, default in defaults.items():
        value = thresholds.get(key, default)
        if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
            raise ValueError(f"{key} must be a non-negative number")
        defaults[key] = float(value)
    findings = []
    for metric in metrics:
        name = _s(metric.get("dataset") or metric.get("table") or metric.get("name") or "unknown", 500)
        for key, limit, label in [
            ("null_rate", defaults["null_rate_max"], "null_rate_exceeded"),
            ("duplicate_rate", defaults["duplicate_rate_max"], "duplicate_rate_exceeded"),
            ("freshness_lag_seconds", defaults["freshness_lag_seconds_max"], "freshness_lag_exceeded"),
        ]:
            if key not in metric:
                continue
            value = metric[key]
            if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{key} for {name} must be a non-negative number")
            if value > limit:
                findings.append({"dataset": name, "metric": key, "observed": value,
                                 "threshold": limit, "rule": label, "severity": "high" if key != "freshness_lag_seconds" else "medium"})
    return {"metric_count": len(metrics), "finding_count": len(findings), "findings": findings,
            "status": "passed" if not findings else "needs_attention",
            "thresholds": defaults, "analysis_mode": "threshold_based_metric_evaluation",
            "limitations": ["Requires trusted metric inputs from an approved collector; this endpoint does not scan customer records or calculate metrics from raw data."]}


def _db_path() -> Path:
    raw = os.environ.get("DATALINEAGE_OPERATIONS_DB", "")
    return Path(raw).expanduser() if raw else Path(__file__).resolve().parents[1] / "data" / "operations.sqlite3"


def _connect() -> sqlite3.Connection:
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""CREATE TABLE IF NOT EXISTS operations_incidents (
        incident_id TEXT NOT NULL, tenant_key TEXT NOT NULL, event_key TEXT NOT NULL,
        created_at TEXT NOT NULL, incident_json TEXT NOT NULL,
        PRIMARY KEY(tenant_key, incident_id), UNIQUE(tenant_key, event_key))""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_operations_incidents_tenant_created ON operations_incidents(tenant_key, created_at DESC)")
    return conn


def persist_incidents(tenant_key: str, incidents: list[dict[str, Any]]) -> dict[str, int]:
    tenant = _s(tenant_key, 300)
    if not tenant:
        raise ValueError("tenant_key is required")
    if not isinstance(incidents, list) or len(incidents) > MAX_INCIDENTS:
        raise ValueError("incidents must be a bounded list")
    inserted = 0
    with _connect() as conn:
        for item in incidents:
            if not isinstance(item, dict):
                continue
            event_key = _s(item.get("event_id") or item.get("run_id") or item.get("incident_id"), 300)
            if not event_key:
                event_key = str(uuid4())
            cursor = conn.execute("INSERT OR IGNORE INTO operations_incidents VALUES(?,?,?,?,?)",
                (_s(item.get("incident_id"), 100) or str(uuid4()), tenant, event_key,
                 _utc_now(), json.dumps(item, ensure_ascii=False, separators=(",", ":"))))
            inserted += max(cursor.rowcount, 0)
    return {"received": len(incidents), "inserted": inserted, "duplicates_ignored": len(incidents) - inserted}


def list_incidents(tenant_key: str, limit: int = 100) -> list[dict[str, Any]]:
    tenant = _s(tenant_key, 300)
    if not tenant:
        raise ValueError("tenant_key is required")
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_INCIDENTS_PAGE:
        raise ValueError(f"limit must be between 1 and {MAX_INCIDENTS_PAGE}")
    with _connect() as conn:
        rows = conn.execute("SELECT incident_json, created_at FROM operations_incidents WHERE tenant_key=? ORDER BY created_at DESC LIMIT ?",
                            (tenant, limit)).fetchall()
    output = []
    for row in rows:
        item = json.loads(row["incident_json"])
        item["recorded_at"] = row["created_at"]
        output.append(item)
    return output
