#!/usr/bin/env python3
"""Verify SQLite backup files before restore."""
import argparse, sqlite3
from pathlib import Path

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("backup_dir")
    args = parser.parse_args()
    root = Path(args.backup_dir)
    found = list(root.glob("*.sqlite3"))
    if not found:
        raise SystemExit("No SQLite backup files found")
    failed = []
    for path in found:
        with sqlite3.connect(str(path)) as conn:
            status = conn.execute("PRAGMA integrity_check").fetchone()[0]
        print(f"{path.name}: {status}")
        if status != "ok":
            failed.append(path.name)
    raise SystemExit(1 if failed else 0)

if __name__ == "__main__":
    main()
