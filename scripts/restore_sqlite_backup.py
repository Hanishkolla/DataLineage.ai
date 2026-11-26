#!/usr/bin/env python3
"""Verify and restore an M59 SQLite backup without overwriting existing files."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import sqlite3
import tempfile
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_backup(backup_dir: Path) -> list[dict]:
    manifest_path = backup_dir / "manifest.json"
    if not manifest_path.is_file():
        raise ValueError("Backup manifest.json is missing")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("format") != "datalineage-sqlite-backup-v1":
        raise ValueError("Unsupported backup manifest format")
    entries = manifest.get("databases")
    if not isinstance(entries, list) or not entries:
        raise ValueError("Backup manifest contains no databases")
    for entry in entries:
        name = entry.get("filename", "")
        if Path(name).name != name or not name.endswith(".sqlite3"):
            raise ValueError(f"Unsafe database filename in manifest: {name!r}")
        source = backup_dir / name
        if not source.is_file() or sha256(source) != entry.get("sha256"):
            raise ValueError(f"Backup checksum mismatch or missing file: {name}")
        conn = sqlite3.connect(str(source))
        try:
            check = conn.execute("PRAGMA integrity_check").fetchone()[0]
            if check != "ok":
                raise ValueError(f"SQLite integrity check failed for {name}: {check}")
        finally:
            conn.close()
    return entries


def restore(backup_dir: Path, target_dir: Path, overwrite: bool = False) -> list[str]:
    entries = verify_backup(backup_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    restored: list[str] = []
    for entry in entries:
        name = entry["filename"]
        target = target_dir / name
        if target.exists() and not overwrite:
            raise FileExistsError(f"Refusing to overwrite existing database: {target}")
    for entry in entries:
        name = entry["filename"]
        source, target = backup_dir / name, target_dir / name
        fd, temp_name = tempfile.mkstemp(prefix=f".{name}.", suffix=".restore", dir=target_dir)
        os.close(fd)
        temp = Path(temp_name)
        try:
            temp.write_bytes(source.read_bytes())
            conn = sqlite3.connect(str(temp))
            try:
                if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise ValueError(f"Restored temporary database failed integrity check: {name}")
            finally:
                conn.close()
            os.replace(temp, target)
            restored.append(name)
        finally:
            if temp.exists():
                temp.unlink()
    return restored


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup-dir", required=True)
    parser.add_argument("--target-dir", required=True)
    parser.add_argument("--overwrite", action="store_true", help="Explicitly replace existing database files")
    args = parser.parse_args()
    result = restore(Path(args.backup_dir), Path(args.target_dir), args.overwrite)
    print(json.dumps({"restored": result, "target_dir": args.target_dir}, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
