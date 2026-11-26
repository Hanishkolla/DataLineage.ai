"""M46 migration of M41 API-key hashes and security audit events."""
from __future__ import annotations
import sqlite3
from pathlib import Path
from typing import Any
from .db_backend import connect_postgres

API_KEY_COLUMNS = ("key_id", "tenant_key", "owner_identity", "label", "key_hash", "role", "created_at", "expires_at", "revoked_at")
AUDIT_COLUMNS = ("sequence", "event_id", "tenant_key", "actor", "action", "resource_type", "resource_id", "outcome", "occurred_at", "details_json")


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is not None


def _open_source(path: str | Path) -> sqlite3.Connection:
    source_path = Path(path).expanduser().resolve()
    if not source_path.is_file():
        raise FileNotFoundError(f"SQLite security database not found: {source_path}")
    conn = sqlite3.connect(str(source_path), timeout=15)
    conn.row_factory = sqlite3.Row
    integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
    if integrity != "ok":
        conn.close()
        raise RuntimeError(f"SQLite integrity_check failed: {integrity}")
    if not _table_exists(conn, "api_keys") or not _table_exists(conn, "security_audit"):
        conn.close()
        raise RuntimeError("SQLite source must contain api_keys and security_audit tables")
    return conn


def sqlite_security_summary(path: str | Path) -> dict[str, Any]:
    conn = _open_source(path)
    try:
        return {"integrity": "ok",
                "api_keys": int(conn.execute("SELECT COUNT(*) FROM api_keys").fetchone()[0]),
                "security_audit": int(conn.execute("SELECT COUNT(*) FROM security_audit").fetchone()[0])}
    finally:
        conn.close()


def _batches(conn, table, columns, batch_size):
    present = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
    missing = set(columns) - present
    if missing:
        raise RuntimeError(f"SQLite {table} is missing columns: {', '.join(sorted(missing))}")
    cursor = conn.execute(f"SELECT {','.join(columns)} FROM {table} ORDER BY {columns[0]}")
    while True:
        rows = cursor.fetchmany(batch_size)
        if not rows:
            break
        yield [tuple(row[col] for col in columns) for row in rows]


def migrate_sqlite_security_to_postgres(source_path: str | Path, database_url: str, *,
                                         dry_run: bool = False, batch_size: int = 500) -> dict[str, Any]:
    if not database_url.startswith(("postgresql://", "postgres://")):
        raise ValueError("Target URL must use postgresql:// or postgres://")
    if not isinstance(batch_size, int) or isinstance(batch_size, bool) or not 1 <= batch_size <= 5000:
        raise ValueError("batch_size must be between 1 and 5000")
    source = _open_source(source_path)
    try:
        summary = {"integrity": "ok",
                   "api_keys": int(source.execute("SELECT COUNT(*) FROM api_keys").fetchone()[0]),
                   "security_audit": int(source.execute("SELECT COUNT(*) FROM security_audit").fetchone()[0])}
        if dry_run:
            return {**summary, "mode": "dry_run", "target_changed": False}
        target = connect_postgres(database_url)
        try:
            target.execute("""CREATE TABLE IF NOT EXISTS api_keys (
                key_id TEXT PRIMARY KEY, tenant_key TEXT NOT NULL, owner_identity TEXT NOT NULL,
                label TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE, role TEXT NOT NULL,
                created_at TEXT NOT NULL, expires_at TEXT, revoked_at TEXT)""")
            target.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_key, created_at DESC)")
            target.execute("""CREATE TABLE IF NOT EXISTS security_audit (
                sequence BIGSERIAL PRIMARY KEY, event_id TEXT NOT NULL UNIQUE,
                tenant_key TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
                resource_type TEXT NOT NULL, resource_id TEXT, outcome TEXT NOT NULL,
                occurred_at TEXT NOT NULL, details_json TEXT NOT NULL)""")
            target.execute("CREATE INDEX IF NOT EXISTS idx_security_audit_tenant_seq ON security_audit(tenant_key, sequence DESC)")
            for table, columns in (("api_keys", API_KEY_COLUMNS), ("security_audit", AUDIT_COLUMNS)):
                statement = ("INSERT INTO " + table + " (" + ",".join(columns) + ") VALUES (" +
                             ",".join(["%s"] * len(columns)) + ") ON CONFLICT DO NOTHING")
                with target._connection.cursor() as cursor:
                    for batch in _batches(source, table, columns, batch_size):
                        cursor.executemany(statement, batch)

            missing = {"api_keys": 0, "security_audit": 0}
            mismatches = {"api_keys": 0, "security_audit": 0}
            for table, columns in (("api_keys", API_KEY_COLUMNS), ("security_audit", AUDIT_COLUMNS)):
                with target._connection.cursor() as cursor:
                    for batch in _batches(source, table, columns, batch_size):
                        keys = [row[0] for row in batch]
                        cursor.execute(f"SELECT {','.join(columns)} FROM {table} WHERE {columns[0]} IN (" +
                                       ",".join(["%s"] * len(keys)) + ")", keys)
                        actual = {row[columns[0]]: tuple(row[c] for c in columns) for row in cursor.fetchall()}
                        for expected in batch:
                            found = actual.get(expected[0])
                            if found is None:
                                missing[table] += 1
                            elif found != expected:
                                mismatches[table] += 1
            if any(missing.values()) or any(mismatches.values()):
                target.rollback()
                raise RuntimeError(f"Security migration verification failed: missing={missing}, mismatches={mismatches}")
            target.execute("""SELECT setval(
                pg_get_serial_sequence('security_audit','sequence'),
                GREATEST(COALESCE((SELECT MAX(sequence) FROM security_audit), 1), 1),
                EXISTS(SELECT 1 FROM security_audit))""")
            target.commit()
            return {**summary, "mode": "applied", "verified": True,
                    "missing": missing, "mismatches": mismatches, "destination_overwrites": 0}
        except Exception:
            target.rollback()
            raise
        finally:
            target.close()
    finally:
        source.close()
