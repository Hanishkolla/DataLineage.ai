"""Milestone 57: deterministic data-quality intelligence and lineage-aware triage.

Analyzes caller-supplied sample rows and lineage edges only. It never connects to
source systems, executes SQL, or claims that heuristic root-cause candidates are
verified diagnoses.
"""
from __future__ import annotations

import re
from typing import Any

from .data_quality import profile_dataset, MAX_ROWS, MAX_COLUMNS

MAX_RULES = 2_000
MAX_LINEAGE_EDGES = 100_000
MAX_PATTERN_LENGTH = 500


def _text(value: Any, limit: int = 500) -> str:
    return str(value or "").strip()[:limit]


def _column_values(rows: list[dict[str, Any]], column: str) -> list[Any]:
    return [row.get(column) for row in rows]


def _is_null(value: Any) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


def _upstream_paths(target: str, edges: list[dict[str, Any]], max_depth: int = 12,
                    max_paths: int = 50) -> list[list[str]]:
    reverse: dict[str, list[str]] = {}
    for edge in edges:
        source = _text(edge.get("source_column"), 500)
        dest = _text(edge.get("target_column"), 500)
        if source and dest:
            reverse.setdefault(dest.casefold(), []).append(source)
    paths: list[list[str]] = []
    stack: list[tuple[str, list[str]]] = [(target, [target])]
    while stack and len(paths) < max_paths:
        node, path = stack.pop()
        parents = sorted(set(reverse.get(node.casefold(), [])), key=str.casefold)
        if not parents or len(path) >= max_depth:
            if len(path) > 1:
                paths.append(list(reversed(path)))
            continue
        progressed = False
        for parent in parents:
            if parent.casefold() in {part.casefold() for part in path}:
                continue
            progressed = True
            stack.append((parent, path + [parent]))
        if not progressed and len(path) > 1:
            paths.append(list(reversed(path)))
    return paths


def analyze_quality_intelligence(
    rows: list[dict[str, Any]], *, required_columns: list[str] | None = None,
    unique_columns: list[str] | None = None, allowed_values: dict[str, list[Any]] | None = None,
    rules: list[dict[str, Any]] | None = None,
    lineage_edges: list[dict[str, Any]] | None = None,
    upstream_quality_findings: list[str] | None = None,
) -> dict[str, Any]:
    """Profile a bounded sample, evaluate explicit rules and trace failed columns upstream."""
    base = profile_dataset(rows, required_columns, unique_columns, allowed_values)
    rules = rules or []
    lineage_edges = lineage_edges or []
    upstream_quality_findings = upstream_quality_findings or []
    if not isinstance(rules, list) or len(rules) > MAX_RULES or any(not isinstance(x, dict) for x in rules):
        raise ValueError(f"rules must be a list of at most {MAX_RULES} objects")
    if not isinstance(lineage_edges, list) or len(lineage_edges) > MAX_LINEAGE_EDGES or any(not isinstance(x, dict) for x in lineage_edges):
        raise ValueError(f"lineage_edges must be a list of at most {MAX_LINEAGE_EDGES} objects")
    if not isinstance(upstream_quality_findings, list) or len(upstream_quality_findings) > MAX_LINEAGE_EDGES:
        raise ValueError("upstream_quality_findings must be a bounded list")

    findings: list[dict[str, Any]] = []
    rule_results: list[dict[str, Any]] = []
    for index, rule in enumerate(rules):
        rule_id = _text(rule.get("id") or f"rule-{index + 1}", 100)
        column = _text(rule.get("column"), 300)
        kind = _text(rule.get("type"), 50).lower()
        if not column:
            raise ValueError(f"rule {rule_id} requires a column")
        values = _column_values(rows, column)
        non_null = [v for v in values if not _is_null(v)]
        failed = 0
        message = ""
        if kind == "max_null_rate":
            threshold = rule.get("threshold")
            if not isinstance(threshold, (int, float)) or isinstance(threshold, bool) or not 0 <= threshold <= 100:
                raise ValueError(f"rule {rule_id}: threshold must be between 0 and 100")
            actual = (sum(_is_null(v) for v in values) * 100 / len(values)) if values else 0
            failed = len(values) if actual > threshold else 0
            message = f"Null rate {actual:.2f}% {'exceeds' if failed else 'meets'} threshold {threshold:.2f}%"
            observed = round(actual, 2)
        elif kind == "numeric_range":
            minimum, maximum = rule.get("min"), rule.get("max")
            if minimum is not None and (not isinstance(minimum, (int, float)) or isinstance(minimum, bool)):
                raise ValueError(f"rule {rule_id}: min must be numeric")
            if maximum is not None and (not isinstance(maximum, (int, float)) or isinstance(maximum, bool)):
                raise ValueError(f"rule {rule_id}: max must be numeric")
            if minimum is not None and maximum is not None and minimum > maximum:
                raise ValueError(f"rule {rule_id}: min cannot exceed max")
            invalid = []
            for value in non_null:
                if not isinstance(value, (int, float)) or isinstance(value, bool):
                    invalid.append(value)
                elif (minimum is not None and value < minimum) or (maximum is not None and value > maximum):
                    invalid.append(value)
            failed = len(invalid)
            message = f"{failed} values are non-numeric or outside the configured range"
            observed = {"min": min((v for v in non_null if isinstance(v, (int, float)) and not isinstance(v, bool)), default=None),
                        "max": max((v for v in non_null if isinstance(v, (int, float)) and not isinstance(v, bool)), default=None)}
        elif kind == "regex":
            pattern = rule.get("pattern")
            if not isinstance(pattern, str) or len(pattern) > MAX_PATTERN_LENGTH:
                raise ValueError(f"rule {rule_id}: pattern must be a string of at most {MAX_PATTERN_LENGTH} characters")
            try:
                compiled = re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"rule {rule_id}: invalid regular expression") from exc
            failed = sum(1 for value in non_null if not isinstance(value, str) or compiled.fullmatch(value) is None)
            message = f"{failed} values do not match the configured pattern"
            observed = None
        elif kind == "not_null":
            failed = sum(_is_null(value) for value in values)
            message = f"{failed} null or blank values found"
            observed = failed
        else:
            raise ValueError(f"rule {rule_id}: unsupported rule type '{kind}'")
        result = {"rule_id": rule_id, "column": column, "type": kind,
                  "status": "failed" if failed else "passed", "failure_count": failed,
                  "message": message, "observed": observed}
        rule_results.append(result)
        if failed:
            severity = _text(rule.get("severity") or "medium", 20).lower()
            if severity not in {"low", "medium", "high", "critical"}:
                severity = "medium"
            paths = _upstream_paths(column, lineage_edges)
            upstream = sorted({path[0] for path in paths if path})
            known_bad = {str(x).casefold() for x in upstream_quality_findings}
            matching_bad = [name for name in upstream if name.casefold() in known_bad]
            findings.append({
                "finding_id": rule_id, "column": column, "severity": severity,
                "failure_count": failed, "rule_type": kind, "evidence": message,
                "upstream_paths": paths,
                "probable_root_cause_candidates": matching_bad or upstream,
                "root_cause_confidence": "corroborated_by_supplied_upstream_finding" if matching_bad else ("lineage_candidate_only" if upstream else "unknown"),
                "recommendation": "Inspect the upstream source columns and transformation logic; validate source freshness, schema changes and transformation rules before remediation.",
            })

    all_checks = list(base["checks"]) + rule_results
    failed_checks = sum(1 for item in all_checks if item.get("status") == "failed")
    score = round((len(all_checks) - failed_checks) * 100 / len(all_checks), 2) if all_checks else 100.0
    return {
        "row_count": base["row_count"], "column_count": base["column_count"],
        "quality_score_pct": score, "status": "needs_attention" if failed_checks else "passed",
        "failed_check_count": failed_checks, "rule_results": rule_results,
        "base_profile": base["column_profiles"], "findings": findings,
        "analysis_mode": "deterministic_quality_rules_with_lineage_triage",
        "limitations": [
            "Analysis uses only caller-supplied sample rows, rules and lineage edges; it does not connect to or scan source systems.",
            "Root-cause candidates are derived from supplied lineage and optional upstream findings; they are hypotheses, not verified diagnoses.",
            "Regex and numeric checks are deterministic rule evaluations; no automatic remediation is performed.",
            "The quality score is a simple pass-rate across evaluated checks and is not a regulatory or contractual certification.",
        ],
    }
