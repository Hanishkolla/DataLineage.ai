#!/usr/bin/env python3
"""Consistent SQLite backups for DataLineage AI stores."""
from __future__ import annotations
import argparse, hashlib, json, os, sqlite3, time
from pathlib import Path

DB_NAMES = ("analysis_runs.sqlite3", "users.sqlite3", "saas.sqlite3", "security.sqlite3")

def backup_one(source: Path, destination: Path) -> dict:
    if not source.exists():
        return {"database": source.name, "status": "skipped_missing"}
    destination.parent.mkdir(parents=True, exist_ok=True)
    src = sqlite3.connect(str(source), timeout=30)
    dst = sqlite3.connect(str(destination))
    try:
        src.backup(dst)
        result = dst.execute("PRAGMA integrity_check").fetchone()[0]
        if result != "ok":
            raise RuntimeError(f"Integrity check failed for {source.name}: {result}")
    finally:
        dst.close()
        src.close()
    return {"database": source.name, "status": "backed_up", "bytes": destination.stat().st_size}

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", default=os.getenv("DATALINEAGE_DATA_DIR", "backend/data"))
    parser.add_argument("--backup-dir", default=os.getenv("DATALINEAGE_BACKUP_DIR", "backups"))
    args = parser.parse_args()
    data_dir, backup_dir = Path(args.data_dir), Path(args.backup_dir)
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    target = backup_dir / stamp
    results = [backup_one(data_dir / name, target / name) for name in DB_NAMES]
    backed_up = []
    for item in results:
        if item["status"] != "backed_up":
            continue
        file_path = target / item["database"]
        digest = hashlib.sha256(file_path.read_bytes()).hexdigest()
        backed_up.append({"filename": item["database"], "bytes": item["bytes"], "sha256": digest})
    if backed_up:
        manifest = {"format": "datalineage-sqlite-backup-v1", "created_at_utc": stamp, "databases": backed_up}
        (target / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({"backup_dir": str(target), "results": results, "manifest_created": bool(backed_up)}, indent=2))
    return 1 if not backed_up else 0

if __name__ == "__main__":
    raise SystemExit(main())
