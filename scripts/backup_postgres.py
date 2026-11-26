#!/usr/bin/env python3
"""Create a PostgreSQL custom-format backup using pg_dump from PATH."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default="backups/postgres")
    parser.add_argument("--database-url", default=os.getenv("DATALINEAGE_DATABASE_URL", ""))
    args = parser.parse_args()
    if not args.database_url.startswith(("postgres://", "postgresql://")):
        parser.error("Set --database-url or DATALINEAGE_DATABASE_URL to a PostgreSQL DSN")
    pg_dump = shutil.which("pg_dump")
    if not pg_dump:
        parser.error("pg_dump was not found on PATH; install PostgreSQL client tools")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = output_dir / f"datalineage-{stamp}.dump"
    subprocess.run([pg_dump, "--format=custom", "--no-owner", "--file", str(output), args.database_url], check=True)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    manifest = {"format": "datalineage-postgres-custom-v1", "created_at": stamp, "filename": output.name, "sha256": digest, "bytes": output.stat().st_size}
    (output_dir / f"{output.stem}.manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
