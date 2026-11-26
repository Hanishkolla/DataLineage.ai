"""SQLite/PostgreSQL persistence for reusable SQL analysis runs.

Only analysis output is stored; uploaded SQL source text is not persisted.
SQLite remains the default unless DATALINEAGE_DATABASE_URL is configured.
"""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from contextlib import contextmanager
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .db_backend import configured_database_url, connect_postgres


def _db_path() -> Path:
    configured = os.getenv("DATALINEAGE_DB_PATH", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(__file__).resolve().parents[1] / "data" / "analysis_runs.sqlite3"


_POSTGRES_SCHEMA_READY_FOR: str | None = None

def _ensure_postgres_schema(connection: Any, database_url: str) -> None:
    global _POSTGRES_SCHEMA_READY_FOR
    if _POSTGRES_SCHEMA_READY_FOR == database_url:
        return
    connection.execute("""CREATE TABLE IF NOT EXISTS analysis_runs (
        run_id TEXT PRIMARY KEY,
        owner_email TEXT NOT NULL DEFAULT 'local',
        project_name TEXT NOT NULL,
        created_at TEXT NOT NULL,
        files_scanned INTEGER NOT NULL,
        files_with_errors INTEGER NOT NULL,
        tables_json TEXT NOT NULL,
        result_json TEXT NOT NULL,
        organization_id TEXT
    )""")
    connection.execute("ALTER TABLE analysis_runs ADD COLUMN IF NOT EXISTS owner_email TEXT NOT NULL DEFAULT 'local'")
    connection.execute("ALTER TABLE analysis_runs ADD COLUMN IF NOT EXISTS organization_id TEXT")
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_analysis_runs_owner_project_created "
        "ON analysis_runs(owner_email, project_name, created_at DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_analysis_runs_org_project_created "
        "ON analysis_runs(organization_id, project_name, created_at DESC)"
    )
    connection.execute("""CREATE TABLE IF NOT EXISTS organization_projects (
        project_id TEXT PRIMARY KEY, organization_id TEXT NOT NULL,
        name TEXT NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL,
        UNIQUE(organization_id, name))""")
    connection.commit()
    _POSTGRES_SCHEMA_READY_FOR = database_url

def database_backend() -> str:
    """Return the active backend name without exposing connection credentials."""
    return "postgresql" if configured_database_url() else "sqlite"

def _connect():
    database_url = configured_database_url()
    if database_url:
        connection = connect_postgres(database_url)
        try:
            _ensure_postgres_schema(connection, database_url)
            return connection
        except Exception:
            connection.rollback()
            connection.close()
            raise

    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute(
        """CREATE TABLE IF NOT EXISTS analysis_runs (
            run_id TEXT PRIMARY KEY,
            owner_email TEXT NOT NULL DEFAULT 'local',
            project_name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            files_scanned INTEGER NOT NULL,
            files_with_errors INTEGER NOT NULL,
            tables_json TEXT NOT NULL,
            result_json TEXT NOT NULL,
            organization_id TEXT
        )"""
    )
    columns = {row["name"] for row in connection.execute("PRAGMA table_info(analysis_runs)").fetchall()}
    if "owner_email" not in columns:
        connection.execute("ALTER TABLE analysis_runs ADD COLUMN owner_email TEXT NOT NULL DEFAULT 'local'")
    if "organization_id" not in columns:
        connection.execute("ALTER TABLE analysis_runs ADD COLUMN organization_id TEXT")
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_analysis_runs_owner_project_created "
        "ON analysis_runs(owner_email, project_name, created_at DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_analysis_runs_org_project_created "
        "ON analysis_runs(organization_id, project_name, created_at DESC)"
    )
    connection.execute("""CREATE TABLE IF NOT EXISTS organization_projects (
        project_id TEXT PRIMARY KEY, organization_id TEXT NOT NULL,
        name TEXT NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL,
        UNIQUE(organization_id, name))""")
    return connection


@contextmanager
def _session() -> Iterator[Any]:
    connection = _connect()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def validate_project_name(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("project_name must be a string")
    name = " ".join(value.strip().split())
    if not name or len(name) > 80:
        raise ValueError("project_name must contain 1 to 80 characters")
    if any(ord(char) < 32 for char in name):
        raise ValueError("project_name contains unsupported control characters")
    if "/" in name or "\\" in name:
        raise ValueError("project_name cannot contain path separators")
    return name


def save_analysis_run(project_name: str, result: dict[str, Any], owner_email: str = "local", organization_id: str | None = None) -> dict[str, Any]:
    project = validate_project_name(project_name)
    run_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    files_scanned = int(result.get("files_scanned", 0))
    files_with_errors = int(result.get("files_with_errors", 0))
    tables = result.get("tables", [])
    if not isinstance(tables, list):
        tables = []
    serialized = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
    with _session() as connection:
        connection.execute(
            """INSERT INTO analysis_runs
               (run_id, owner_email, project_name, created_at, files_scanned,
                files_with_errors, tables_json, result_json, organization_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (run_id, owner_email, project, created_at, files_scanned, files_with_errors,
             json.dumps(tables, ensure_ascii=False), serialized, organization_id),
        )
    return {
        "run_id": run_id,
        "project_name": project,
        "created_at": created_at,
        "files_scanned": files_scanned,
        "files_with_errors": files_with_errors,
        "tables_count": len(tables),
    }


def list_analysis_runs(project_name: str, limit: int = 20, owner_email: str = "local", organization_id: str | None = None) -> list[dict[str, Any]]:
    project = validate_project_name(project_name)
    safe_limit = max(1, min(int(limit), 100))
    with _session() as connection:
        if organization_id:
            rows = connection.execute(
                """SELECT run_id, project_name, created_at, files_scanned,
                          files_with_errors, tables_json
                   FROM analysis_runs WHERE project_name = ? AND organization_id = ?
                   ORDER BY created_at DESC, run_id DESC LIMIT ?""",
                (project, organization_id, safe_limit),
            ).fetchall()
        else:
            rows = connection.execute(
                """SELECT run_id, project_name, created_at, files_scanned,
                          files_with_errors, tables_json
                   FROM analysis_runs WHERE project_name = ? AND owner_email = ?
                   ORDER BY created_at DESC, run_id DESC LIMIT ?""",
                (project, owner_email, safe_limit),
            ).fetchall()
    return [
        {
            "run_id": row["run_id"],
            "project_name": row["project_name"],
            "created_at": row["created_at"],
            "files_scanned": row["files_scanned"],
            "files_with_errors": row["files_with_errors"],
            "tables": json.loads(row["tables_json"]),
            "tables_count": len(json.loads(row["tables_json"])),
        }
        for row in rows
    ]


def get_analysis_run(run_id: str, owner_email: str = "local", organization_id: str | None = None) -> dict[str, Any] | None:
    with _session() as connection:
        if organization_id:
            row = connection.execute("SELECT * FROM analysis_runs WHERE run_id = ? AND organization_id = ?", (run_id, organization_id)).fetchone()
        else:
            row = connection.execute("SELECT * FROM analysis_runs WHERE run_id = ? AND owner_email = ?", (run_id, owner_email)).fetchone()
    if row is None:
        return None
    return {
        "run_id": row["run_id"],
        "project_name": row["project_name"],
        "created_at": row["created_at"],
        "files_scanned": row["files_scanned"],
        "files_with_errors": row["files_with_errors"],
        "tables_count": len(json.loads(row["tables_json"])),
        "result": json.loads(row["result_json"]),
    }


def _edge_keys(result: dict[str, Any]) -> set[tuple[str, str]]:
    graph = result.get("graph", {})
    edges = graph.get("edges", []) if isinstance(graph, dict) else []
    output: set[tuple[str, str]] = set()
    for edge in edges:
        if isinstance(edge, dict) and isinstance(edge.get("source"), str) and isinstance(edge.get("target"), str):
            output.add((edge["source"], edge["target"]))
    return output


def _lineage_keys(result: dict[str, Any]) -> set[tuple[str, str, str, str]]:
    mappings = result.get("column_lineage", [])
    output: set[tuple[str, str, str, str]] = set()
    for item in mappings if isinstance(mappings, list) else []:
        if not isinstance(item, dict):
            continue
        values = tuple(item.get(key) or "" for key in
                       ("source_table", "source_column", "target_table", "target_column"))
        if all(isinstance(value, str) for value in values):
            output.add(values)
    return output


def compare_analysis_runs(run_a_id: str, run_b_id: str, owner_email: str = "local", organization_id: str | None = None) -> dict[str, Any]:
    first = get_analysis_run(run_a_id, owner_email=owner_email, organization_id=organization_id)
    second = get_analysis_run(run_b_id, owner_email=owner_email, organization_id=organization_id)
    if first is None or second is None:
        raise KeyError("One or both analysis runs were not found")
    a = first["result"]
    b = second["result"]
    tables_a, tables_b = set(a.get("tables", [])), set(b.get("tables", []))
    edges_a, edges_b = _edge_keys(a), _edge_keys(b)
    lineage_a, lineage_b = _lineage_keys(a), _lineage_keys(b)
    return {
        "run_a": {key: first[key] for key in ("run_id", "project_name", "created_at")},
        "run_b": {key: second[key] for key in ("run_id", "project_name", "created_at")},
        "tables_added": sorted(tables_b - tables_a),
        "tables_removed": sorted(tables_a - tables_b),
        "relationships_added": [
            {"source": source, "target": target} for source, target in sorted(edges_b - edges_a)
        ],
        "relationships_removed": [
            {"source": source, "target": target} for source, target in sorted(edges_a - edges_b)
        ],
        "column_mappings_added": [dict(zip(
            ("source_table", "source_column", "target_table", "target_column"), values
        )) for values in sorted(lineage_b - lineage_a)],
        "column_mappings_removed": [dict(zip(
            ("source_table", "source_column", "target_table", "target_column"), values
        )) for values in sorted(lineage_a - lineage_b)],
        "note": "A run-to-run difference is a review aid, not proof of runtime behavior or breakage.",
    }


def check_store() -> bool:
    """Return True when the configured analysis-run database can execute a query."""
    with _session() as connection:
        connection.execute("SELECT 1").fetchone()
    return True


def create_project(organization_id: str, name: str, created_by: str) -> dict[str, Any]:
    project = validate_project_name(name)
    project_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _session() as connection:
        connection.execute(
            "INSERT INTO organization_projects(project_id, organization_id, name, created_by, created_at) VALUES(?,?,?,?,?)",
            (project_id, organization_id, project, created_by, created_at),
        )
    return {"project_id": project_id, "organization_id": organization_id, "name": project, "created_by": created_by, "created_at": created_at}

def list_projects(organization_id: str) -> list[dict[str, Any]]:
    with _session() as connection:
        rows = connection.execute("SELECT project_id, organization_id, name, created_by, created_at FROM organization_projects WHERE organization_id=? ORDER BY created_at DESC", (organization_id,)).fetchall()
    return [dict(row) for row in rows]

def get_project(organization_id: str, name: str) -> dict[str, Any] | None:
    with _session() as connection:
        row = connection.execute("SELECT project_id, organization_id, name, created_by, created_at FROM organization_projects WHERE organization_id=? AND name=?", (organization_id, validate_project_name(name))).fetchone()
    return dict(row) if row else None

def migrate_legacy_runs(owner_email: str, organization_id: str) -> int:
    """Attach legacy account-owned runs to that account's personal workspace once."""
    with _session() as connection:
        cursor = connection.execute("UPDATE analysis_runs SET organization_id=? WHERE owner_email=? AND organization_id IS NULL", (organization_id, owner_email))
        return cursor.rowcount
