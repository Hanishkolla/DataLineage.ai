#!/usr/bin/env python3
"""Non-destructive SQLite backup restore drill for M63 staging acceptance."""
from __future__ import annotations
import argparse
import importlib.util
import json
import sqlite3
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESTORE_SCRIPT = ROOT / "scripts" / "restore_sqlite_backup.py"


def _load_restore_module():
    spec = importlib.util.spec_from_file_location("datalineage_m63_restore_sqlite", RESTORE_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load SQLite restore helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_sqlite_restore_drill(backup_dir: str | Path) -> dict:
    source = Path(backup_dir).expanduser().resolve()
    restore_module = _load_restore_module()
    with tempfile.TemporaryDirectory(prefix="datalineage-m63-restore-") as temp_dir:
        restored_names = restore_module.restore(source, Path(temp_dir), overwrite=False)
        verified = []
        for name in restored_names:
            path = Path(temp_dir) / name
            with sqlite3.connect(str(path)) as connection:
                integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
                table_count = connection.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
            if integrity != "ok":
                raise RuntimeError(f"Restored database integrity check failed: {name}")
            verified.append({"database": name, "integrity": integrity, "table_count": int(table_count),
                             "restored_bytes": path.stat().st_size})
        if not verified:
            raise RuntimeError("Backup contained no SQLite databases")
        return {"milestone": "M63", "status": "passed", "restored_database_count": len(verified),
                "databases": verified,
                "restore_target": "temporary directory, automatically deleted after validation",
                "live_data_modified": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup-dir", required=True)
    parser.add_argument("--json-out", default="M63_RECOVERY_DRILL.json")
    args = parser.parse_args()
    report = run_sqlite_restore_drill(args.backup_dir)
    output = Path(args.json_out).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"status": report["status"], "restored_database_count": report["restored_database_count"],
                      "live_data_modified": False, "report": str(output)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
