#!/usr/bin/env python3
"""Migrate the SaaS organization, subscription, billing and usage store."""
from __future__ import annotations
import argparse, json, os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from app.organization_data_migration import migrate_sqlite_saas_to_postgres

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, help="Path to saas.sqlite3")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--batch-size", type=int, default=500)
    args = parser.parse_args()
    url = os.getenv("DATALINEAGE_DATABASE_URL", "")
    if args.apply and not url:
        parser.error("--apply requires DATALINEAGE_DATABASE_URL")
    result = migrate_sqlite_saas_to_postgres(
        args.source, url or "postgresql://dry-run:dry-run@localhost/dry-run",
        dry_run=args.dry_run, batch_size=args.batch_size)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0
if __name__ == "__main__":
    raise SystemExit(main())
