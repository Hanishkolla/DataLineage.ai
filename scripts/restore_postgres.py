#!/usr/bin/env python3
"""Validate a PostgreSQL dump; restore only with explicit --apply."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dump", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--target-database-url", default=os.getenv("DATALINEAGE_RESTORE_DATABASE_URL", ""))
    parser.add_argument("--apply", action="store_true", help="Actually run pg_restore; default is verification only")
    args = parser.parse_args()
    dump, manifest_path = Path(args.dump), Path(args.manifest)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("format") != "datalineage-postgres-custom-v1" or manifest.get("filename") != dump.name:
        parser.error("Manifest does not describe this dump")
    digest = hashlib.sha256(dump.read_bytes()).hexdigest()
    if digest != manifest.get("sha256"):
        parser.error("Dump SHA-256 does not match manifest")
    pg_restore = shutil.which("pg_restore")
    if not pg_restore:
        parser.error("pg_restore was not found on PATH; install PostgreSQL client tools")
    subprocess.run([pg_restore, "--list", str(dump)], check=True, stdout=subprocess.DEVNULL)
    print("PostgreSQL dump checksum and archive structure verified.")
    if not args.apply:
        print("Verification only. Re-run with --apply and an explicit restore target to execute restore.")
        return 0
    if not args.target_database_url.startswith(("postgres://", "postgresql://")):
        parser.error("--apply requires --target-database-url or DATALINEAGE_RESTORE_DATABASE_URL")
    subprocess.run([pg_restore, "--no-owner", "--exit-on-error", "--dbname", args.target_database_url, str(dump)], check=True)
    print("Restore command completed. Validate application migrations and data before cutover.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
