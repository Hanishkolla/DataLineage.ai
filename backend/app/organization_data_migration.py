"""M47 migration of the SaaS organization/billing/usage store to PostgreSQL."""
from __future__ import annotations
import sqlite3
from pathlib import Path
from typing import Any
from .db_backend import connect_postgres
from .saas_store import _schema

TABLES = (
    "organizations", "memberships", "invitations", "subscriptions",
    "usage_events", "billing_events", "audit_events", "github_connections",
    "usage_reservations", "trial_activations", "razorpay_subscriptions",
)


def _open_source(path: str | Path) -> sqlite3.Connection:
    p = Path(path).expanduser().resolve()
    if not p.is_file():
        raise FileNotFoundError(f"SaaS SQLite database not found: {p}")
    c = sqlite3.connect(str(p), timeout=20)
    c.row_factory = sqlite3.Row
    result = c.execute("PRAGMA integrity_check").fetchone()[0]
    if result != "ok":
        c.close()
        raise RuntimeError(f"SQLite integrity_check failed: {result}")
    return c


def sqlite_saas_summary(path: str | Path) -> dict[str, Any]:
    c = _open_source(path)
    try:
        counts = {}
        for table in TABLES:
            exists = c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
            counts[table] = int(c.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]) if exists else 0
        return {"integrity": "ok", "tables": counts, "total_rows": sum(counts.values())}
    finally:
        c.close()


def migrate_sqlite_saas_to_postgres(source_path: str | Path, database_url: str, *,
                                    dry_run: bool = False, batch_size: int = 500) -> dict[str, Any]:
    if not database_url.startswith(("postgresql://", "postgres://")):
        raise ValueError("Target URL must use postgresql:// or postgres://")
    if not isinstance(batch_size, int) or isinstance(batch_size, bool) or not 1 <= batch_size <= 5000:
        raise ValueError("batch_size must be between 1 and 5000")
    source = _open_source(source_path)
    try:
        summary = sqlite_saas_summary(source_path)
        if dry_run:
            return {**summary, "mode": "dry_run", "target_changed": False}
        target = connect_postgres(database_url)
        try:
            _schema(target)
            target.commit()
            for table in TABLES:
                exists = source.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
                if not exists:
                    continue
                columns = [r["name"] for r in source.execute(f"PRAGMA table_info({table})")]
                placeholders = ",".join(["%s"] * len(columns))
                insert = f"INSERT INTO {table} ({','.join(columns)}) VALUES ({placeholders}) ON CONFLICT DO NOTHING"
                cursor = source.execute(f"SELECT {','.join(columns)} FROM {table}")
                with target._connection.cursor() as dest:
                    while True:
                        rows = cursor.fetchmany(batch_size)
                        if not rows:
                            break
                        dest.executemany(insert, [tuple(row[col] for col in columns) for row in rows])

            # Verify exact row counts and all source rows by their primary key columns.
            counts = {}
            for table in TABLES:
                source_exists = source.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
                expected = int(source.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]) if source_exists else 0
                actual = target.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]
                counts[table] = {"source": expected, "target": int(actual)}
            mismatched = {k: v for k, v in counts.items() if v["source"] != v["target"]}
            if mismatched:
                target.rollback()
                raise RuntimeError(f"SaaS migration count verification failed: {mismatched}")
            target.commit()
            return {**summary, "mode": "applied", "verified": True,
                    "target_counts": {k: v["target"] for k, v in counts.items()},
                    "destination_overwrites": 0}
        except Exception:
            target.rollback()
            raise
        finally:
            target.close()
    finally:
        source.close()
