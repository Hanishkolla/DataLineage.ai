"""Milestone 40: evidence-grounded data intelligence services.

This module intentionally uses deterministic, auditable methods. It does not claim
to be an LLM, execute SQL, access provider APIs, or perform automated remediation.
A future model provider can be added behind this evidence-first interface.
"""
from __future__ import annotations

import re
from collections import Counter, deque
from typing import Any

MAX_QUESTION = 3000
MAX_TABLES = 20000
MAX_EDGES = 500000
MAX_INCIDENTS = 10000


def _text(value: Any, limit: int = 1000) -> str:
    return str(value or "").strip()[:limit]


def _terms(value: str) -> list[str]:
    return [t for t in re.findall(r"[a-z0-9_]+", value.casefold()) if len(t) > 1]


def _tables(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(metadata, dict) or not isinstance(metadata.get("tables", []), list):
        raise ValueError("metadata must contain a tables list")
    tables = metadata.get("tables", [])
    if len(tables) > MAX_TABLES:
        raise ValueError("metadata exceeds table safety limit")
    return [t for t in tables if isinstance(t, dict)]


def copilot_query(question: str, metadata: dict[str, Any],
                  lineage_edges: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Retrieve matching metadata and explain only relationships in supplied lineage."""
    q = _text(question, MAX_QUESTION)
    if not q:
        raise ValueError("question is required")
    tables = _tables(metadata)
    terms = _terms(q)
    ranked = []
    for table in tables:
        name = _text(table.get("name"), 500)
        schema = _text(table.get("schema"), 300)
        columns = table.get("columns", [])
        if not isinstance(columns, list):
            columns = []
        col_names = [_text(c.get("name"), 300) for c in columns if isinstance(c, dict)]
        searchable = " ".join([name, schema, *col_names]).casefold()
        matched = sorted({term for term in terms if term in searchable})
        if matched:
            ranked.append((len(matched), name, schema, col_names, matched))
    ranked.sort(key=lambda item: (-item[0], item[1].casefold()))
    edges = lineage_edges or []
    if not isinstance(edges, list) or len(edges) > MAX_EDGES:
        raise ValueError("lineage_edges must be a bounded list")
    relevant_edges = []
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        source, target = _text(edge.get("source"), 600), _text(edge.get("target"), 600)
        if source and target and any(term in (source + " " + target).casefold() for term in terms):
            relevant_edges.append({"source": source, "target": target,
                                   "column": _text(edge.get("column"), 300) or None})
            if len(relevant_edges) >= 100:
                break
    evidence = [
        {"table": name, "schema": schema, "columns": cols[:200], "matched_terms": matched}
        for _, name, schema, cols, matched in ranked[:25]
    ]
    if evidence or relevant_edges:
        answer = f"Found {len(evidence)} matching metadata objects and {len(relevant_edges)} directly matching lineage relationships in the supplied evidence."
    else:
        answer = "No matching objects or lineage relationships were found in the supplied evidence."
    return {
        "answer": answer, "evidence": evidence, "lineage_evidence": relevant_edges,
        "matched_object_count": len(evidence), "analysis_mode": "evidence_grounded_retrieval",
        "limitations": [
            "This is deterministic retrieval, not a generative LLM response.",
            "Results are limited to metadata and lineage explicitly supplied in this request.",
            "No SQL, database query, cloud API call, or remediation action is executed."
        ]
    }


def explain_impact(changed_object: str, edges: list[dict[str, Any]],
                   max_results: int = 10000) -> dict[str, Any]:
    changed = _text(changed_object, 600)
    if not changed:
        raise ValueError("changed_object is required")
    if not isinstance(edges, list) or len(edges) > MAX_EDGES:
        raise ValueError("edges must be a bounded list")
    if not isinstance(max_results, int) or isinstance(max_results, bool) or not 1 <= max_results <= 50000:
        raise ValueError("max_results must be between 1 and 50000")
    graph: dict[str, set[str]] = {}
    for edge in edges:
        if isinstance(edge, dict):
            source, target = _text(edge.get("source"), 600), _text(edge.get("target"), 600)
            if source and target:
                graph.setdefault(source, set()).add(target)
    seen, queue = set(), deque([changed])
    while queue and len(seen) < max_results:
        node = queue.popleft()
        for nxt in sorted(graph.get(node, ())):
            if nxt != changed and nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
                if len(seen) >= max_results:
                    break
    objects = sorted(seen)
    return {
        "changed_object": changed, "downstream_object_count": len(objects),
        "downstream_objects": objects,
        "risk": "high" if len(objects) >= 20 else "medium" if objects else "low",
        "analysis_mode": "directed_graph_reachability",
        "evidence": {"input_edge_count": len(edges), "traversed_object_count": len(objects)},
        "limitations": ["Impact is graph reachability only; it does not model runtime, semantic, or business criticality."]
    }


def summarize_incidents(incidents: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(incidents, list) or len(incidents) > MAX_INCIDENTS:
        raise ValueError("incidents must be a bounded list")
    valid = [i for i in incidents if isinstance(i, dict)]
    causes = Counter(_text(i.get("cause_code") or "unclassified", 100) for i in valid)
    severities = Counter(_text(i.get("severity") or "unknown", 50).casefold() for i in valid)
    pipelines = Counter(_text(i.get("pipeline") or "unknown", 300) for i in valid)
    recommendations = []
    seen = set()
    for incident in valid:
        recommendation = _text(incident.get("recommendation"), 1000)
        if recommendation and recommendation not in seen:
            seen.add(recommendation)
            recommendations.append(recommendation)
        if len(recommendations) >= 20:
            break
    return {
        "incident_count": len(valid),
        "cause_distribution": dict(causes.most_common(20)),
        "severity_distribution": dict(severities.most_common(10)),
        "most_affected_pipelines": [{"pipeline": p, "count": n} for p, n in pipelines.most_common(20)],
        "recommended_actions": recommendations,
        "analysis_mode": "deterministic_incident_aggregation",
        "limitations": ["Summary reflects only the incidents supplied; it does not infer causality or access incident storage."]
    }


def assess_data_risk(schema_changes: list[dict[str, Any]] | None = None,
                     quality_findings: list[dict[str, Any]] | None = None,
                     incidents: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    schema_changes = schema_changes or []
    quality_findings = quality_findings or []
    incidents = incidents or []
    for name, value, limit in [
        ("schema_changes", schema_changes, 100000),
        ("quality_findings", quality_findings, 100000),
        ("incidents", incidents, MAX_INCIDENTS),
    ]:
        if not isinstance(value, list) or len(value) > limit:
            raise ValueError(f"{name} must be a bounded list")
    high_schema = sum(1 for x in schema_changes if isinstance(x, dict) and _text(x.get("risk")).casefold() == "high")
    high_quality = sum(1 for x in quality_findings if isinstance(x, dict) and _text(x.get("severity")).casefold() == "high")
    high_incidents = sum(1 for x in incidents if isinstance(x, dict) and _text(x.get("severity")).casefold() == "high")
    score = min(100, high_schema * 8 + high_quality * 6 + high_incidents * 10
                + max(0, len(schema_changes) - high_schema) * 2
                + max(0, len(quality_findings) - high_quality) * 2
                + max(0, len(incidents) - high_incidents))
    level = "critical" if score >= 75 else "high" if score >= 40 else "medium" if score >= 15 else "low"
    drivers = []
    if high_schema: drivers.append({"factor": "high_risk_schema_changes", "count": high_schema})
    if high_quality: drivers.append({"factor": "high_severity_quality_findings", "count": high_quality})
    if high_incidents: drivers.append({"factor": "high_severity_incidents", "count": high_incidents})
    return {
        "risk_score": score, "risk_level": level, "drivers": drivers,
        "input_counts": {"schema_changes": len(schema_changes), "quality_findings": len(quality_findings), "incidents": len(incidents)},
        "scoring_method": "transparent_weighted_heuristic_v1",
        "limitations": ["Heuristic prioritization, not a calibrated probability or compliance determination.",
                        "Requires validated upstream findings; no raw customer data is scanned."]
    }
