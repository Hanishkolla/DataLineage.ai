from __future__ import annotations

from collections import Counter
from typing import Any
import sqlglot
from sqlglot import exp


def _tables(tree: exp.Expression) -> set[str]:
    return {".".join(str(x) for x in (t.catalog, t.db, t.name) if x) for t in tree.find_all(exp.Table)}


def _columns(tree: exp.Expression) -> set[str]:
    return {c.name for c in tree.find_all(exp.Column) if c.name}


def _aliases_and_ambiguities(tree: exp.Expression) -> tuple[dict[str, set[str]], list[str]]:
    aliases: dict[str, set[str]] = {}
    for table in tree.find_all(exp.Table):
        name = ".".join(str(x) for x in (table.catalog, table.db, table.name) if x)
        aliases.setdefault(table.name.casefold(), set()).add(name)
        if table.alias:
            aliases.setdefault(table.alias.casefold(), set()).add(name)
    ambiguous = sorted(k for k, values in aliases.items() if len(values) > 1)
    return aliases, ambiguous


def _parse(sql: str, dialect: str = "") -> list[exp.Expression]:
    if not isinstance(sql, str) or not sql.strip():
        raise ValueError("SQL must be a non-empty string")
    if len(sql.encode("utf-8")) > 2 * 1024 * 1024:
        raise ValueError("SQL exceeds 2 MB")
    try:
        trees = [x for x in sqlglot.parse(sql, read=dialect or None) if x is not None]
    except Exception as exc:
        raise ValueError(f"SQL could not be parsed; unsupported syntax or dialect: {exc}") from exc
    if not trees:
        raise ValueError("No SQL statements were found")
    return trees


def compare_sql_changes(
    old_sql: str, new_sql: str, dialect: str = "",
    old_schema: dict[str, list[str]] | None = None,
    new_schema: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Static SQL/schema comparison. It does not execute SQL or claim runtime certainty."""
    old_trees, new_trees = _parse(old_sql, dialect), _parse(new_sql, dialect)
    old_tables = set().union(*(_tables(t) for t in old_trees))
    new_tables = set().union(*(_tables(t) for t in new_trees))
    old_columns = set().union(*(_columns(t) for t in old_trees))
    new_columns = set().union(*(_columns(t) for t in new_trees))
    old_aliases = {}
    new_aliases = {}
    ambiguous = set()
    for tree in old_trees + new_trees:
        aliases, issues = _aliases_and_ambiguities(tree)
        ambiguous.update(issues)
        (old_aliases if tree in old_trees else new_aliases).update(aliases)

    removed_tables = sorted(old_tables - new_tables)
    added_tables = sorted(new_tables - old_tables)
    removed_columns = sorted(old_columns - new_columns, key=str.casefold)
    added_columns = sorted(new_columns - old_columns, key=str.casefold)
    # Confidence is deliberately conservative: name-level SQL diffs cannot prove semantic equivalence.
    risk_points = (len(removed_tables) * 3 + len(removed_columns) * 2 +
                   len(ambiguous) * 2 + len(added_tables) + len(added_columns))
    risk = "high" if risk_points >= 5 else "medium" if risk_points >= 2 else "low"
    tests = []
    if removed_columns or removed_tables:
        tests += ["Run downstream model/table compilation and verify no references to removed objects remain.",
                  "Compare row counts and null rates for affected downstream outputs."]
    if added_columns:
        tests.append("Verify new columns are populated, typed correctly, and handled by downstream consumers.")
    if ambiguous:
        tests.append("Qualify ambiguous table aliases and column references before merging.")
    if not tests:
        tests.append("Run representative unit tests and compare output schema and row counts against the base version.")
    schema_diffs = []
    if old_schema is not None or new_schema is not None:
        old_schema, new_schema = old_schema or {}, new_schema or {}
        for table in sorted(set(old_schema) | set(new_schema)):
            before, after = set(old_schema.get(table, [])), set(new_schema.get(table, []))
            removed, added = sorted(before-after), sorted(after-before)
            rename_candidate = ({"old": removed[0], "new": added[0], "confidence": "low",
                                 "confirmed": False} if len(removed) == len(added) == 1 else None)
            schema_diffs.append({"table": table, "removed_columns": removed,
                                 "added_columns": added, "possible_rename": rename_candidate})
    return {
        "status": "analyzed",
        "dialect": dialect or "generic",
        "changes": {"removed_tables": removed_tables, "added_tables": added_tables,
                    "removed_columns": removed_columns, "added_columns": added_columns},
        "ambiguities": [{"type": "duplicate_table_alias", "alias": a,
                         "explanation": "The same unqualified name or alias resolves to multiple tables."}
                        for a in sorted(ambiguous)],
        "schema_comparison": schema_diffs,
        "risk": {"level": risk, "score": min(risk_points, 10),
                 "explanation": "Static heuristic based on object removals/additions and alias ambiguity; not a runtime failure probability."},
        "recommended_tests": tests,
        "confidence": "medium" if not ambiguous else "low",
        "limitations": [
            "Static parsing does not execute SQL or inspect production database metadata.",
            "Column names are compared across each SQL file, not fully resolved through every dialect-specific scope.",
            "Rename detection is heuristic and must be confirmed by an engineer.",
            "Unsupported syntax is reported as a parse error; no lineage is inferred from failed parsing.",
        ],
    }


def validate_dataset_snapshots(
    source_rows: list[dict[str, Any]], target_rows: list[dict[str, Any]],
    required_columns: list[str] | None = None,
    max_row_count_change_pct: float | None = None,
) -> dict[str, Any]:
    """Compare supplied in-memory row snapshots; no external database access."""
    if not isinstance(source_rows, list) or not isinstance(target_rows, list):
        raise ValueError("source_rows and target_rows must be lists")
    if any(not isinstance(r, dict) for r in source_rows + target_rows):
        raise ValueError("Every dataset row must be an object")
    source_cols = set().union(*(set(r) for r in source_rows)) if source_rows else set()
    target_cols = set().union(*(set(r) for r in target_rows)) if target_rows else set()
    missing = sorted(c for c in (required_columns or []) if c not in target_cols)
    unexpected = sorted(target_cols - source_cols)
    missing_values = {}
    for col in sorted(target_cols):
        count = sum(1 for row in target_rows if col not in row or row[col] is None or row[col] == "")
        if count:
            missing_values[col] = count
    source_count, target_count = len(source_rows), len(target_rows)
    change_pct = (abs(target_count-source_count) / source_count * 100) if source_count else (100.0 if target_count else 0.0)
    row_count_failed = max_row_count_change_pct is not None and change_pct > max_row_count_change_pct
    checks = [
        {"name": "required_columns_present", "passed": not missing, "details": missing},
        {"name": "unexpected_schema_changes", "passed": not unexpected, "details": unexpected},
        {"name": "missing_values", "passed": not missing_values, "details": missing_values},
        {"name": "row_count_change_threshold", "passed": not row_count_failed,
         "details": {"source_rows": source_count, "target_rows": target_count,
                     "absolute_change_percent": round(change_pct, 2),
                     "threshold_percent": max_row_count_change_pct}},
    ]
    failed = [c["name"] for c in checks if not c["passed"]]
    return {"status": "passed" if not failed else "failed",
            "source_row_count": source_count, "target_row_count": target_count,
            "source_columns": sorted(source_cols), "target_columns": sorted(target_cols),
            "missing_values_by_column": missing_values,
            "unexpected_columns": unexpected, "missing_required_columns": missing,
            "checks": checks, "failed_checks": failed,
            "limitations": ["Validation uses only the row snapshots supplied in this request.",
                            "It does not connect to or monitor a live database."]}
