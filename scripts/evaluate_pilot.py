#!/usr/bin/env python3
"""Evaluate curated DataLineage AI pilot metrics and produce a scorecard."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.pilot_readiness import evaluate_pilot_metrics, render_pilot_scorecard_markdown  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Path to a pilot metrics JSON file")
    parser.add_argument("--json-out", default="M62_PILOT_SCORECARD.json")
    parser.add_argument("--markdown-out", default="M62_PILOT_SCORECARD.md")
    args = parser.parse_args()
    source = Path(args.input).expanduser().resolve()
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("Pilot metrics input must be a JSON object")
        thresholds = payload.pop("thresholds", None)
        report = evaluate_pilot_metrics(payload, thresholds=thresholds)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))
    json_path = Path(args.json_out).expanduser().resolve()
    md_path = Path(args.markdown_out).expanduser().resolve()
    json_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    md_path.write_text(render_pilot_scorecard_markdown(report), encoding="utf-8")
    print(json.dumps({"status": report["status"], "json_report": str(json_path),
                      "markdown_report": str(md_path)}, indent=2))
    # A valid scorecard is a successful CLI run even when its decision is
    # iterate/hold; the report itself communicates the pilot outcome.
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
