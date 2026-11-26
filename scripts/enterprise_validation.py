#!/usr/bin/env python3
"""Run bounded synthetic graph performance validation for DataLineage AI M61."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.graph_benchmark import render_markdown, run_graph_benchmark  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nodes", type=int, default=10_000, help="Synthetic graph nodes (max 250000)")
    parser.add_argument("--edges", type=int, default=20_000, help="Synthetic graph edges (max 1000000)")
    parser.add_argument("--workers", type=int, default=4, help="Concurrent read-only workers (1-32)")
    parser.add_argument("--queries", type=int, default=4, help="Read queries to run (1-256)")
    parser.add_argument("--json-out", default="m61_benchmark.json", help="JSON output path")
    parser.add_argument("--markdown-out", default="M61_BENCHMARK_RESULTS.md", help="Markdown output path")
    args = parser.parse_args()

    try:
        report = run_graph_benchmark(args.nodes, args.edges, args.workers, args.queries)
    except (ValueError, RuntimeError) as exc:
        parser.error(str(exc))

    json_path = Path(args.json_out).expanduser().resolve()
    markdown_path = Path(args.markdown_out).expanduser().resolve()
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    markdown_path.write_text(render_markdown(report), encoding="utf-8")
    print(json.dumps({
        "status": "passed",
        "nodes": report["integrity"]["nodes_created"],
        "edges": report["integrity"]["edges_created"],
        "graph_build_seconds": report["measurements"]["graph_build_seconds"],
        "python_traced_peak_bytes": report["measurements"]["python_traced_peak_bytes"],
        "json_report": str(json_path),
        "markdown_report": str(markdown_path),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
