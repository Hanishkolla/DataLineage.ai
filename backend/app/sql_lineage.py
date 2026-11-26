"""Milestone 38: SQL-derived table and column lineage across platform boundaries.

Uses sqlglot's AST (never regex-only SQL parsing). Analysis is static and read-only:
it does not connect to databases or execute SQL. Ambiguous/unresolved columns are
reported rather than guessed. CTE and simple derived-table lineage is expanded.
"""
from __future__ import annotations

from typing import Any
import re

MAX_SQL_CHARS = 1_000_000
MAX_STATEMENTS = 200
MAX_NODES = 20_000
SUPPORTED_DIALECTS = {
    "generic": None, "ansi": None, "postgres": "postgres", "postgresql": "postgres",
    "snowflake": "snowflake", "databricks": "databricks", "spark": "spark",
    "bigquery": "bigquery", "tsql": "tsql", "oracle": "oracle", "redshift": "redshift",
    "mysql": "mysql", "sqlite": "sqlite",
}


class SQLLineageError(ValueError):
    pass


def _clean(value: Any, limit: int = 500) -> str:
    return str(value or "").strip()[:limit]


def _sqlglot():
    try:
        import sqlglot  # type: ignore
        from sqlglot import exp  # type: ignore
    except ImportError as exc:
        raise RuntimeError("SQL lineage requires sqlglot. Install backend requirements.txt") from exc
    return sqlglot, exp


def _table_name(table: Any) -> str:
    # sqlglot's Table.sql() preserves catalog/db/schema qualification and quoting.
    return table.sql().strip('"`[]')


def _target_of(statement: Any, exp: Any) -> str | None:
    if isinstance(statement, exp.Insert):
        target = statement.this
        if isinstance(target, exp.Schema):
            target = target.this
        if isinstance(target, exp.Table):
            return _table_name(target)
    if isinstance(statement, exp.Create) and isinstance(statement.this, exp.Table):
        return _table_name(statement.this)
    return None


def _query_of(statement: Any, exp: Any) -> Any:
    if isinstance(statement, exp.Insert):
        return statement.expression
    if isinstance(statement, exp.Create):
        return statement.expression
    if isinstance(statement, exp.Update):
        return statement
    if isinstance(statement, exp.Delete):
        return statement
    if isinstance(statement, (exp.Select, exp.Subquery, exp.Union)):
        return statement
    return None


def _alias_map(query: Any, exp: Any) -> tuple[dict[str, Any], dict[str, Any], set[str], dict[str, str]]:
    """Return physical table aliases, CTE query definitions, and CTE names."""
    ctes: dict[str, Any] = {}
    with_clause = query.args.get("with_") if hasattr(query, "args") else None
    if with_clause:
        for cte in with_clause.expressions:
            alias = _clean(cte.alias_or_name, 300).casefold()
            if alias and cte.this is not None:
                ctes[alias] = cte.this
    physical: dict[str, Any] = {}
    cte_aliases: dict[str, str] = {}
    for table in query.find_all(exp.Table):
        name = _table_name(table)
        short = _clean(table.name, 300).casefold()
        if short in ctes:
            alias = _clean(table.alias_or_name, 300).casefold()
            if alias:
                cte_aliases[alias] = short
            continue
        alias = _clean(table.alias_or_name, 300).casefold()
        if alias:
            physical[alias] = table
        physical.setdefault(short, table)
    return physical, ctes, set(ctes), cte_aliases


def _resolve_column(column: Any, physical: dict[str, Any], cte_lineage: dict[str, dict[str, list[str]]],
                    cte_names: set[str], cte_aliases: dict[str, str], exp: Any) -> tuple[list[str], str | None]:
    col = _clean(column.name, 300)
    qualifier = _clean(column.table, 300).casefold()
    cte_name = cte_aliases.get(qualifier, qualifier)
    if cte_name in cte_names:
        mapped = cte_lineage.get(cte_name, {}).get(col.casefold())
        if mapped:
            return list(mapped), None
        return [], f"CTE column '{cte_name}.{col}' could not be resolved"
    if qualifier:
        table = physical.get(qualifier)
        if table is None:
            # Preserve explicit three/four-part qualification even when alias map differs.
            return [f"{qualifier}.{col}"], None
        return [f"{_table_name(table)}.{col}"], None
    unique = { _table_name(t) for t in physical.values() }
    if len(unique) == 1:
        return [f"{next(iter(unique))}.{col}"], None
    if not unique:
        return [], f"Column '{col}' has no resolvable table source"
    return [], f"Column '{col}' is unqualified across multiple sources"


def _analyze_query(query: Any, exp: Any, *, depth: int = 0) -> tuple[list[str], list[dict[str, Any]], list[str]]:
    if depth > 12:
        return [], [], ["Nested query/CTE expansion exceeded the depth limit"]
    physical, ctes, cte_names, cte_aliases = _alias_map(query, exp)
    cte_lineage: dict[str, dict[str, list[str]]] = {}
    warnings: list[str] = []
    for name, cte_query in ctes.items():
        _, cte_cols, cte_warn = _analyze_query(cte_query, exp, depth=depth + 1)
        mapping: dict[str, list[str]] = {}
        for edge in cte_cols:
            mapping.setdefault(edge["target_column"].casefold(), []).append(edge["source_column"])
        cte_lineage[name] = mapping
        warnings.extend(cte_warn)

    sources = sorted({_table_name(t) for t in physical.values()})
    columns: list[dict[str, Any]] = []
    select = query if isinstance(query, exp.Select) else next(query.find_all(exp.Select), None)
    if select is not None:
        for projection in select.expressions:
            output = _clean(projection.alias_or_name, 300)
            if not output:
                output = _clean(projection.sql(), 300)
            refs = list(projection.find_all(exp.Column))
            if isinstance(projection, exp.Column):
                refs.insert(0, projection)
            seen_refs: set[str] = set()
            for ref in refs:
                # Avoid duplicate traversal of a bare column projection.
                ref_key = ref.sql().casefold()
                if ref_key in seen_refs:
                    continue
                seen_refs.add(ref_key)
                resolved, warning = _resolve_column(ref, physical, cte_lineage, cte_names, cte_aliases, exp)
                if warning:
                    warnings.append(warning)
                for src_col in resolved:
                    columns.append({"source_column": src_col, "target_column": output,
                                    "expression": _clean(projection.sql(), 1000),
                                    "confidence": "static_ast"})
    return sources, columns, warnings


def analyze_sql_lineage(sql: str, *, dialect: str = "generic", source_platform: str = "unknown",
                        target_platform: str = "unknown", target_table: str | None = None,
                        table_platforms: dict[str, str] | None = None) -> dict[str, Any]:
    sql = _clean(sql, MAX_SQL_CHARS + 1)
    if not sql or len(sql) > MAX_SQL_CHARS:
        raise SQLLineageError(f"sql must contain between 1 and {MAX_SQL_CHARS} characters")
    dialect_key = _clean(dialect, 50).lower()
    if dialect_key not in SUPPORTED_DIALECTS:
        raise SQLLineageError(f"Unsupported SQL dialect: {dialect_key}")
    sqlglot, exp = _sqlglot()
    try:
        statements = sqlglot.parse(sql, read=SUPPORTED_DIALECTS[dialect_key])
    except Exception as exc:
        # Do not return raw parser internals or SQL text to clients.
        raise SQLLineageError("SQL could not be parsed for the selected dialect") from exc
    statements = [s for s in statements if s is not None]
    if not statements or len(statements) > MAX_STATEMENTS:
        raise SQLLineageError(f"SQL must contain between 1 and {MAX_STATEMENTS} statements")

    platform_map = {str(k).casefold(): _clean(v, 80).lower() for k, v in (table_platforms or {}).items()}
    table_edges: list[dict[str, str]] = []
    column_edges: list[dict[str, str]] = []
    unresolved: list[str] = []
    nodes: dict[str, dict[str, str]] = {}
    for index, statement in enumerate(statements):
        target = _target_of(statement, exp) or _clean(target_table, 500) or f"query_result_{index + 1}"
        query = _query_of(statement, exp)
        if query is None:
            unresolved.append(f"Statement {index + 1}: statement type {type(statement).__name__} is not lineage-supported")
            continue
        sources, cols, warns = _analyze_query(query, exp)
        unresolved.extend(warns)
        target_provider = _clean(target_platform, 80).lower() or "unknown"
        target_id = f"{target_provider}:{target}"
        nodes[target_id] = {"id": target_id, "name": target, "platform": target_provider, "kind": "table"}
        for source in sources:
            source_provider = platform_map.get(source.casefold(), _clean(source_platform, 80).lower() or "unknown")
            source_id = f"{source_provider}:{source}"
            nodes[source_id] = {"id": source_id, "name": source, "platform": source_provider, "kind": "table"}
            if source_id != target_id:
                table_edges.append({"source": source_id, "target": target_id, "kind": "table_dependency"})
        for col in cols:
            source_name = col.pop("source_column")
            source_table, _, source_col = source_name.rpartition(".")
            source_provider = platform_map.get(source_table.casefold(), _clean(source_platform, 80).lower() or "unknown")
            source_id = f"{source_provider}:{source_name}"
            target_col_id = f"{target_id}.{col['target_column']}"
            column_edges.append({"source": source_id, "target": target_col_id,
                                 "source_column": source_name, "target_column": col["target_column"],
                                 "target_table": target, "expression": col["expression"],
                                 "confidence": col["confidence"], "source_platform": source_provider,
                                 "target_platform": target_provider})
    # Stable de-duplication protects graph clients from repeated joins/projections.
    unique_tables = {(e["source"], e["target"], e["kind"]): e for e in table_edges}
    unique_columns = {(e["source"], e["target"]): e for e in column_edges}
    if len(nodes) > MAX_NODES:
        raise SQLLineageError(f"Lineage graph exceeds the {MAX_NODES} node safety limit")
    return {"dialect": dialect_key, "nodes": list(nodes.values()),
            "table_edges": list(unique_tables.values()), "column_edges": list(unique_columns.values()),
            "node_count": len(nodes), "table_edge_count": len(unique_tables),
            "column_edge_count": len(unique_columns), "unresolved": sorted(set(unresolved)),
            "analysis_mode": "static_sql_ast", "executed_sql": False,
            "limitations": ["Static SQL analysis cannot observe dynamic SQL, runtime values, stored procedure side effects or platform-specific execution semantics.",
                            "Unqualified columns across multiple source tables are reported as unresolved instead of guessed.",
                            "Column-level lineage is strongest for direct projections; complex expressions retain expression evidence but may need schema-aware validation."]}
