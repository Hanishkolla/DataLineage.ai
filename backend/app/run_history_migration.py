"""M44 migration helpers for the analysis-run SQLite store only."""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from .db_backend import connect_postgres

_RUN_COLUMNS = (
    "run_id", "owner_email", "project_name", "created_at", "files_scanned",
    "files_with_errors", "tables_json", "result_json", "organization_id",
)
_PROJECT_COLUMNS = ("project_id", "organization_id", "name", "created_by", "created_at")

def _sqlite_table_exists(connection: sqlite3.Connection, table: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    return row is not None

def _source_connection(source_path: str | Path) -> sqlite3.Connection:
    path = Path(source_path).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(f"SQLite source database was not found: {path}")
    connection = sqlite3.connect(str(path), timeout=15)
    connection.row_factory = sqlite3.Row
    integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
    if integrity != "ok":
        connection.close()
        raise RuntimeError(f"SQLite integrity_check failed: {integrity}")
    if not _sqlite_table_exists(connection, "analysis_runs"):
        connection.close()
        raise RuntimeError("SQLite source has no analysis_runs table")
    return connection

def _summary_from_connection(connection: sqlite3.Connection) -> dict[str, Any]:
    run_count = connection.execute("SELECT COUNT(*) FROM analysis_runs").fetchone()[0]
    project_count = (
        connection.execute("SELECT COUNT(*) FROM organization_projects").fetchone()[0]
        if _sqlite_table_exists(connection, "organization_projects") else 0
    )
    return {"integrity": "ok", "analysis_runs": run_count,
            "organization_projects": project_count}


def sqlite_source_summary(source_path: str | Path) -> dict[str, Any]:
    connection = _source_connection(source_path)
    try:
        return _summary_from_connection(connection)
    finally:
        connection.close()

def _select_source_rows(connection: sqlite3.Connection, table: str, columns: tuple[str, ...]):
    present = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
    expressions = []
    for column in columns:
        if column in present:
            expressions.append(column)
        elif column == "owner_email":
            expressions.append("'local' AS owner_email")
        elif column == "organization_id":
            expressions.append("NULL AS organization_id")
        else:
            raise RuntimeError(f"SQLite {table} is missing required column: {column}")
    return connection.execute(f"SELECT {', '.join(expressions)} FROM {table}")

def migrate_sqlite_runs_to_postgres(
    source_path: str | Path, database_url: str, *, dry_run: bool = False,
    batch_size: int = 500,
) -> dict[str, Any]:
    """Migrate run history/projects; conflicts are skipped, never overwritten."""
    if not database_url.startswith(("postgresql://", "postgres://")):
        raise ValueError("Target URL must use postgresql:// or postgres://")
    if not isinstance(batch_size, int) or isinstance(batch_size, bool) or not 1 <= batch_size <= 5000:
        raise ValueError("batch_size must be between 1 and 5000")
    source = _source_connection(source_path)
    try:
        summary = _summary_from_connection(source)
        if dry_run:
            return {**summary, "mode": "dry_run", "target_changed": False}

        target = connect_postgres(database_url)
        try:
            target.execute("""CREATE TABLE IF NOT EXISTS analysis_runs (
                run_id TEXT PRIMARY KEY, owner_email TEXT NOT NULL DEFAULT 'local',
                project_name TEXT NOT NULL, created_at TEXT NOT NULL,
                files_scanned INTEGER NOT NULL, files_with_errors INTEGER NOT NULL,
                tables_json TEXT NOT NULL, result_json TEXT NOT NULL, organization_id TEXT)""")
            target.execute("ALTER TABLE analysis_runs ADD COLUMN IF NOT EXISTS owner_email TEXT NOT NULL DEFAULT 'local'")
            target.execute("ALTER TABLE analysis_runs ADD COLUMN IF NOT EXISTS organization_id TEXT")
            target.execute("""CREATE TABLE IF NOT EXISTS organization_projects (
                project_id TEXT PRIMARY KEY, organization_id TEXT NOT NULL,
                name TEXT NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL,
                UNIQUE(organization_id, name))""")
            run_insert = (
                "INSERT INTO analysis_runs (" + ",".join(_RUN_COLUMNS) + ") VALUES (" +
                ",".join(["%s"] * len(_RUN_COLUMNS)) + ") ON CONFLICT DO NOTHING"
            )
            project_insert = (
                "INSERT INTO organization_projects (" + ",".join(_PROJECT_COLUMNS) + ") VALUES (" +
                ",".join(["%s"] * len(_PROJECT_COLUMNS)) + ") ON CONFLICT DO NOTHING"
            )
            with target._connection.cursor() as cursor:
                run_cursor = _select_source_rows(source, "analysis_runs", _RUN_COLUMNS)
                while True:
                    rows = run_cursor.fetchmany(batch_size)
                    if not rows:
                        break
                    cursor.executemany(run_insert, [tuple(row[column] for column in _RUN_COLUMNS) for row in rows])
                if _sqlite_table_exists(source, "organization_projects"):
                    project_cursor = _select_source_rows(source, "organization_projects", _PROJECT_COLUMNS)
                    while True:
                        rows = project_cursor.fetchmany(batch_size)
                        if not rows:
                            break
                        cursor.executemany(project_insert, [tuple(row[column] for column in _PROJECT_COLUMNS) for row in rows])
            # Verify within the same transaction; commit only when every source row
            # is represented byte-for-byte at the stored-column level.
            # Batched reads avoid loading the complete source database in memory.
            missing_runs = 0
            mismatched_runs = 0
            source_runs = _select_source_rows(source, "analysis_runs", _RUN_COLUMNS)
            with target._connection.cursor() as cursor:
                while True:
                    rows = source_runs.fetchmany(batch_size)
                    if not rows:
                        break
                    expected = {row["run_id"]: tuple(row[column] for column in _RUN_COLUMNS) for row in rows}
                    ids = list(expected)
                    placeholders = ",".join(["%s"] * len(ids))
                    cursor.execute(
                        f"SELECT {','.join(_RUN_COLUMNS)} FROM analysis_runs WHERE run_id IN ({placeholders})", ids
                    )
                    actual = {row["run_id"]: tuple(row[column] for column in _RUN_COLUMNS) for row in cursor.fetchall()}
                    missing_runs += sum(1 for key in ids if key not in actual)
                    mismatched_runs += sum(1 for key in ids if key in actual and actual[key] != expected[key])

            missing_projects = 0
            mismatched_projects = 0
            if _sqlite_table_exists(source, "organization_projects"):
                source_projects = _select_source_rows(source, "organization_projects", _PROJECT_COLUMNS)
                with target._connection.cursor() as cursor:
                    while True:
                        rows = source_projects.fetchmany(batch_size)
                        if not rows:
                            break
                        expected = {row["project_id"]: tuple(row[column] for column in _PROJECT_COLUMNS) for row in rows}
                        ids = list(expected)
                        placeholders = ",".join(["%s"] * len(ids))
                        cursor.execute(
                            f"SELECT {','.join(_PROJECT_COLUMNS)} FROM organization_projects WHERE project_id IN ({placeholders})", ids
                        )
                        actual = {row["project_id"]: tuple(row[column] for column in _PROJECT_COLUMNS) for row in cursor.fetchall()}
                        missing_projects += sum(1 for key in ids if key not in actual)
                        mismatched_projects += sum(1 for key in ids if key in actual and actual[key] != expected[key])
            verified = not missing_runs and not missing_projects and not mismatched_runs and not mismatched_projects
            if verified:
                target.commit()
            else:
                target.rollback()
            return {**summary, "mode": "migrated", "verified": verified,
                    "target_transaction_committed": verified,
                    "missing_analysis_run_ids": missing_runs,
                    "mismatched_analysis_runs": mismatched_runs,
                    "missing_project_ids": missing_projects,
                    "mismatched_projects": mismatched_projects,
                    "note": "Conflicting destination records were not overwritten. The transaction is committed only when every source row matches."}
        except Exception:
            target.rollback()
            raise
        finally:
            target.close()
    finally:
        source.close()
