#!/usr/bin/env python3
"""Probe configured PostgreSQL and Redis services for a live M63 staging pilot."""
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

from app.staging_health_checks import build_service_report, render_service_markdown  # noqa: E402


def load_environment(env_file: str | Path | None, environ: Mapping[str, str] | None = None) -> dict[str, str]:
    values: dict[str, str] = {}
    if env_file:
        path = Path(env_file).expanduser()
        if path.is_file():
            try:
                from dotenv import dotenv_values
            except ImportError as exc:
                raise RuntimeError("python-dotenv is required to read the selected environment file") from exc
            values = {key: value for key, value in dotenv_values(path).items() if key and value is not None}
    values.update(dict(os.environ if environ is None else environ))
    return values


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", default=str(ROOT / ".env"))
    parser.add_argument("--require-postgres", action="store_true")
    parser.add_argument("--require-redis", action="store_true")
    parser.add_argument("--timeout", type=int, default=3)
    parser.add_argument("--json-out", default="M63_SERVICE_READINESS.json")
    parser.add_argument("--markdown-out", default="M63_SERVICE_READINESS.md")
    args = parser.parse_args()
    if not 1 <= args.timeout <= 20:
        parser.error("--timeout must be between 1 and 20 seconds")
    try:
        env = load_environment(args.env_file)
    except RuntimeError as exc:
        parser.error(str(exc))
    report = build_service_report(env, require_postgres=args.require_postgres,
                                  require_redis=args.require_redis, timeout_seconds=args.timeout)
    json_path = Path(args.json_out).expanduser().resolve()
    markdown_path = Path(args.markdown_out).expanduser().resolve()
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    markdown_path.write_text(render_service_markdown(report), encoding="utf-8")
    print(json.dumps({"status": report["status"], "blockers": len(report["blockers"]),
                      "warnings": len(report["warnings"]), "json_report": str(json_path),
                      "markdown_report": str(markdown_path)}, indent=2))
    return 0 if report["status"] != "blocked" else 2


if __name__ == "__main__":
    raise SystemExit(main())
