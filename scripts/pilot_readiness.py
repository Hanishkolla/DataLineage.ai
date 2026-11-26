#!/usr/bin/env python3
"""Create a redacted DataLineage AI pilot environment readiness report."""
from __future__ import annotations
import argparse
import json
import os
import sys
from pathlib import Path
from typing import Mapping

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.pilot_readiness import inspect_pilot_environment, render_environment_markdown  # noqa: E402


def load_environment(env_file: str | Path | None, environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """Load backend/.env values, then let process environment override them."""
    loaded: dict[str, str] = {}
    path = Path(env_file).expanduser() if env_file else None
    if path and path.is_file():
        try:
            from dotenv import dotenv_values
        except ImportError as exc:
            raise RuntimeError("python-dotenv is required to read backend/.env; install backend/requirements.txt") from exc
        loaded = {key: value for key, value in dotenv_values(path).items() if key and value is not None}
    loaded.update(dict(os.environ if environ is None else environ))
    return loaded


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(ROOT), help="Project root folder")
    parser.add_argument("--env-file", default=None, help="Environment file (default: <root>/backend/.env)")
    parser.add_argument("--json-out", default="M62_PILOT_READINESS.json")
    parser.add_argument("--markdown-out", default="M62_PILOT_READINESS.md")
    args = parser.parse_args()
    root = Path(args.root).expanduser().resolve()
    env_file = Path(args.env_file).expanduser() if args.env_file else root / "backend" / ".env"
    try:
        environment = load_environment(env_file)
    except RuntimeError as exc:
        parser.error(str(exc))
    report = inspect_pilot_environment(root, environment)
    json_path = Path(args.json_out).expanduser().resolve()
    md_path = Path(args.markdown_out).expanduser().resolve()
    json_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    md_path.write_text(render_environment_markdown(report), encoding="utf-8")
    print(json.dumps({"status": report["status"], "blocker_count": len(report["blockers"]),
                      "warning_count": len(report["warnings"]), "json_report": str(json_path),
                      "markdown_report": str(md_path)}, indent=2))
    return 0 if report["status"] != "blocked" else 2

if __name__ == "__main__":
    raise SystemExit(main())
