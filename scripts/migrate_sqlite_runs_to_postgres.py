#!/usr/bin/env python3
"""Migrate only analysis_runs and organization_projects from SQLite to PostgreSQL."""
from __future__ import annotations
import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.run_history_migration import migrate_sqlite_runs_to_postgres

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    default_source = os.getenv("DATALINEAGE_DB_PATH", "").strip() or str(BACKEND / "data" / "analysis_runs.sqlite3")
    parser.add_argument("--source", default=default_source,
                        help="Path to the source SQLite analysis-run database (defaults to DATALINEAGE_DB_PATH when set)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--dry-run", action="store_true", help="Validate source and show row counts only")
    group.add_argument("--apply", action="store_true", help="Write rows to the PostgreSQL target")
    parser.add_argument("--batch-size", type=int, default=500)
    args = parser.parse_args()
    target = os.getenv("DATALINEAGE_DATABASE_URL", "").strip()
    if not args.dry_run and not target:
        parser.error("Set DATALINEAGE_DATABASE_URL in the environment before using --apply")
    if not target:
        # A syntactically valid placeholder is needed only for the dry-run API validation.
        target = "postgresql://dry-run:dry-run@localhost/dry-run"
    result = migrate_sqlite_runs_to_postgres(
        args.source, target, dry_run=args.dry_run, batch_size=args.batch_size
    )
    print(json.dumps(result, indent=2))
    return 0 if result.get("verified", True) else 2

if __name__ == "__main__":
    raise SystemExit(main())
