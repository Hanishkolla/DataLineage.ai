"""Milestone 61: reproducible synthetic lineage graph performance validation.

This harness measures the in-memory NetworkX graph representation used by the
project's dependency graph workflow. It is a benchmark, not an end-to-end API,
SQL parser, database, or production-capacity certification.
"""
from __future__ import annotations

import platform
import sys
import time
import tracemalloc
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

import networkx as nx

MAX_NODES = 250_000
MAX_EDGES = 1_000_000


def build_synthetic_lineage_graph(node_count: int, edge_count: int) -> nx.DiGraph:
    """Build a deterministic acyclic graph with exactly the requested edges."""
    if isinstance(node_count, bool) or not isinstance(node_count, int) or not 2 <= node_count <= MAX_NODES:
        raise ValueError(f"node_count must be an integer from 2 to {MAX_NODES}")
    if isinstance(edge_count, bool) or not isinstance(edge_count, int):
        raise ValueError("edge_count must be an integer")
    max_edges = min(MAX_EDGES, node_count * (node_count - 1) // 2)
    if not node_count - 1 <= edge_count <= max_edges:
        raise ValueError(f"edge_count must be between {node_count - 1} and {max_edges}")

    graph = nx.DiGraph()
    graph.add_nodes_from(range(node_count))
    # A directed chain ensures every node is reachable from node zero.
    graph.add_edges_from((node, node + 1) for node in range(node_count - 1))
    remaining = edge_count - (node_count - 1)
    # Add deterministic forward shortcuts, which preserve acyclicity and avoid
    # duplicate edges without building a second edge-sized set in memory.
    for distance in range(2, node_count):
        if remaining == 0:
            break
        for source in range(0, node_count - distance):
            graph.add_edge(source, source + distance)
            remaining -= 1
            if remaining == 0:
                break
    if remaining:
        raise RuntimeError("unable to generate the requested graph size")
    return graph


def _query(graph: nx.DiGraph, start_node: int) -> int:
    return len(nx.descendants(graph, start_node))


def run_graph_benchmark(
    node_count: int = 10_000,
    edge_count: int = 20_000,
    workers: int = 4,
    queries: int = 4,
) -> dict[str, Any]:
    """Measure graph creation, Python-traced peak memory and read-only queries."""
    if isinstance(workers, bool) or not isinstance(workers, int) or not 1 <= workers <= 32:
        raise ValueError("workers must be an integer from 1 to 32")
    if isinstance(queries, bool) or not isinstance(queries, int) or not 1 <= queries <= 256:
        raise ValueError("queries must be an integer from 1 to 256")

    tracemalloc.start()
    started = time.perf_counter()
    graph = build_synthetic_lineage_graph(node_count, edge_count)
    build_seconds = time.perf_counter() - started
    current_bytes, peak_bytes = tracemalloc.get_traced_memory()

    dag_started = time.perf_counter()
    is_dag = nx.is_directed_acyclic_graph(graph)
    dag_check_seconds = time.perf_counter() - dag_started

    query_nodes = [index % node_count for index in range(queries)]
    query_started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="dla-m61-bench") as pool:
        reachable_counts = list(pool.map(lambda node: _query(graph, node), query_nodes))
    query_seconds = time.perf_counter() - query_started
    _, final_peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    if graph.number_of_nodes() != node_count or graph.number_of_edges() != edge_count or not is_dag:
        raise RuntimeError("synthetic graph integrity check failed")

    return {
        "benchmark": "synthetic_networkx_lineage_graph",
        "measured_at_utc": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "python": sys.version.split()[0],
            "networkx": nx.__version__,
            "platform": platform.platform(),
        },
        "input": {"nodes_requested": node_count, "edges_requested": edge_count,
                  "read_workers": workers, "read_queries": queries},
        "integrity": {"nodes_created": graph.number_of_nodes(),
                      "edges_created": graph.number_of_edges(),
                      "directed_acyclic_graph": is_dag},
        "measurements": {
            "graph_build_seconds": round(build_seconds, 6),
            "dag_validation_seconds": round(dag_check_seconds, 6),
            "concurrent_read_queries_seconds": round(query_seconds, 6),
            "concurrent_read_queries_per_second": round(queries / query_seconds, 2) if query_seconds else None,
            "reachable_node_counts": reachable_counts,
            "python_traced_current_bytes_after_build": current_bytes,
            "python_traced_peak_bytes": final_peak_bytes,
        },
        "measurement_limits": [
            "Synthetic in-memory NetworkX graph only; SQL parsing and FastAPI request overhead are not measured.",
            "Python tracemalloc does not capture every native allocation or total process RSS.",
            "Concurrent checks are read-only graph traversals in one process, not multi-user or multi-instance load tests.",
            "Results depend on machine, Python, NetworkX version and runtime conditions; repeat on customer-like infrastructure.",
        ],
    }


def render_markdown(report: dict[str, Any]) -> str:
    env = report["environment"]
    inputs = report["input"]
    integrity = report["integrity"]
    metrics = report["measurements"]
    lines = [
        "# DataLineage AI — M61 Graph Benchmark",
        "",
        f"- Measured at: `{report['measured_at_utc']}`",
        f"- Python: `{env['python']}`",
        f"- NetworkX: `{env['networkx']}`",
        f"- Platform: `{env['platform']}`",
        "",
        "## Workload and integrity",
        "",
        f"- Nodes: {integrity['nodes_created']:,}",
        f"- Edges: {integrity['edges_created']:,}",
        f"- DAG validation: {'passed' if integrity['directed_acyclic_graph'] else 'failed'}",
        f"- Concurrent read workers / queries: {inputs['read_workers']} / {inputs['read_queries']}",
        "",
        "## Measurements",
        "",
        f"- Graph build: {metrics['graph_build_seconds']:.6f} seconds",
        f"- DAG validation: {metrics['dag_validation_seconds']:.6f} seconds",
        f"- Concurrent read queries: {metrics['concurrent_read_queries_seconds']:.6f} seconds",
        f"- Read query throughput: {metrics['concurrent_read_queries_per_second']} queries/second",
        f"- Python traced peak memory: {metrics['python_traced_peak_bytes']:,} bytes",
        "",
        "## Measurement limits",
        "",
    ]
    lines.extend(f"- {item}" for item in report["measurement_limits"])
    lines.extend([
        "",
        "## Reproduction",
        "",
        "```powershell",
        "cd backend",
        "python ..\\scripts\\enterprise_validation.py --nodes " + str(inputs["nodes_requested"]) +
        " --edges " + str(inputs["edges_requested"]) + " --workers " + str(inputs["read_workers"]) +
        " --queries " + str(inputs["read_queries"]),
        "```",
        "",
    ])
    return "\n".join(lines)
