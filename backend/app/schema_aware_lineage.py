"""Milestone 56: schema-aware star expansion and UPDATE assignment lineage.

Static, read-only SQL analysis. It never connects to or executes customer SQL.
Ambiguous references are surfaced as warnings rather than guessed.
"""
from __future__ import annotations

from typing import Any

from .sql_lineage import (
    SQLLineageError, SUPPORTED_DIALECTS, _clean, _sqlglot, _table_name,
    analyze_sql_lineage,
)

MAX_SCHEMA_TABLES = 5_000
MAX_COLUMNS_PER_TABLE = 2_000
MAX_TOTAL_COLUMNS = 100_000


def normalize_schema_catalog(catalog: Any) -> dict[str, list[str]]:
    if catalog is None:
        return {}
    if not isinstance(catalog, dict) or len(catalog) > MAX_SCHEMA_TABLES:
        raise SQLLineageError("schema_catalog must be an object with at most 5000 tables")
    result: dict[str, list[str]] = {}
    total = 0
    for table, columns in catalog.items():
        table_name = _clean(table, 500)
        if not table_name or not isinstance(columns, list) or len(columns) > MAX_COLUMNS_PER_TABLE:
            raise SQLLineageError("Each schema_catalog table must have a name and a bounded columns array")
        cleaned = []
        for column in columns:
            name = _clean(column, 300)
            if not name:
                continue
            cleaned.append(name)
        total += len(cleaned)
        if total > MAX_TOTAL_COLUMNS:
            raise SQLLineageError("schema_catalog exceeds the total column safety limit")
        result[table_name.casefold()] = list(dict.fromkeys(cleaned))
    return result


def _schema_columns(table: Any, catalog: dict[str, list[str]]) -> list[str] | None:
    full = _table_name(table).casefold()
    short = _clean(table.name, 300).casefold()
    return catalog.get(full) or catalog.get(short)


def _expand_stars(statements: list[Any], exp: Any, catalog: dict[str, list[str]]) -> tuple[list[str], int]:
    warnings: list[str] = []
    expanded_count = 0
    for statement in statements:
        for select in list(statement.find_all(exp.Select)):
            tables = list(select.find_all(exp.Table))
            aliases: dict[str, Any] = {}
            for table in tables:
                aliases[_clean(table.alias_or_name, 300).casefold()] = table
                aliases[_clean(table.name, 300).casefold()] = table
            replacements = []
            for projection in list(select.expressions):
                star = isinstance(projection, exp.Star) or (
                    isinstance(projection, exp.Column) and isinstance(projection.this, exp.Star)
                )
                if not star:
                    replacements.append(projection)
                    continue
                qualifier = _clean(projection.table, 300).casefold() if isinstance(projection, exp.Column) else ""
                candidates = [aliases[qualifier]] if qualifier in aliases else (tables if not qualifier else [])
                if not candidates:
                    warnings.append(f"Could not resolve star projection '{projection.sql()}': source table is unknown")
                    replacements.append(projection)
                    continue
                expanded: list[Any] = []
                unresolved_tables = []
                for table in candidates:
                    columns = _schema_columns(table, catalog)
                    if columns is None:
                        unresolved_tables.append(_table_name(table))
                        continue
                    qualifier_name = _clean(table.alias_or_name, 300)
                    for column in columns:
                        expanded.append(exp.column(column, table=qualifier_name) if qualifier_name else exp.column(column))
                if unresolved_tables:
                    warnings.append("Star expansion incomplete; schema missing for: " + ", ".join(sorted(set(unresolved_tables))))
                if expanded:
                    replacements.extend(expanded)
                    expanded_count += len(expanded)
                else:
                    replacements.append(projection)
                    warnings.append(f"Star projection '{projection.sql()}' was not expanded because no source schema was available")
            select.set("expressions", replacements)
    return warnings, expanded_count


def _update_edges(statement: Any, exp: Any, catalog: dict[str, list[str]]) -> tuple[list[dict[str, Any]], list[str], str | None]:
    target_expr = statement.this
    target_table = target_expr.this if isinstance(target_expr, exp.TableAlias) else target_expr
    if not isinstance(target_table, exp.Table):
        return [], ["UPDATE target table could not be resolved"], None
    target_name = _table_name(target_table)
    target_alias = _clean(target_table.alias_or_name, 300).casefold()
    tables = list(statement.find_all(exp.Table))
    alias_map: dict[str, Any] = {}
    for table in tables:
        alias_map[_clean(table.alias_or_name, 300).casefold()] = table
        alias_map[_clean(table.name, 300).casefold()] = table
    edges: list[dict[str, Any]] = []
    warnings: list[str] = []
    for assignment in statement.expressions:
        if not isinstance(assignment, exp.EQ) or not isinstance(assignment.this, exp.Column):
            warnings.append("An UPDATE assignment could not be interpreted as a simple column assignment")
            continue
        target_column = _clean(assignment.this.name, 300)
        rhs = assignment.expression
        refs = list(rhs.find_all(exp.Column)) if rhs is not None else []
        if isinstance(rhs, exp.Column):
            refs.insert(0, rhs)
        seen = set()
        for ref in refs:
            key = ref.sql().casefold()
            if key in seen:
                continue
            seen.add(key)
            qualifier = _clean(ref.table, 300).casefold()
            source_table = alias_map.get(qualifier) if qualifier else None
            if source_table is None and not qualifier:
                # For UPDATE t SET a=b, the unqualified RHS belongs to t only
                # when no additional source table makes it ambiguous.
                if len({_table_name(t) for t in tables}) == 1:
                    source_table = target_table
                else:
                    matches = []
                    for candidate in tables:
                        cols = _schema_columns(candidate, catalog)
                        if cols and any(c.casefold() == ref.name.casefold() for c in cols):
                            matches.append(candidate)
                    if len(matches) == 1:
                        source_table = matches[0]
                    else:
                        warnings.append(f"UPDATE source column '{ref.name}' is ambiguous or unresolved")
                        continue
            if source_table is None:
                warnings.append(f"UPDATE source qualifier '{qualifier}' could not be resolved")
                continue
            source_name = f"{_table_name(source_table)}.{_clean(ref.name, 300)}"
            edges.append({
                "source_column": source_name,
                "target_column": target_column,
                "target_table": target_name,
                "expression": _clean(rhs.sql(), 1000),
                "confidence": "static_ast_assignment",
                "operation": "update",
            })
    return edges, warnings, target_name


def analyze_advanced_sql_lineage(
    sql: str, *, dialect: str = "generic", source_platform: str = "unknown",
    target_platform: str = "unknown", target_table: str | None = None,
    table_platforms: dict[str, str] | None = None,
    schema_catalog: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    dialect_key = _clean(dialect, 50).lower()
    if dialect_key not in SUPPORTED_DIALECTS:
        raise SQLLineageError(f"Unsupported SQL dialect: {dialect_key}")
    catalog = normalize_schema_catalog(schema_catalog)
    sql = _clean(sql, 1_000_001)
    if not sql or len(sql) > 1_000_000:
        raise SQLLineageError("sql must contain between 1 and 1000000 characters")
    sqlglot, exp = _sqlglot()
    try:
        statements = [s for s in sqlglot.parse(sql, read=SUPPORTED_DIALECTS[dialect_key]) if s is not None]
    except Exception as exc:
        raise SQLLineageError("SQL could not be parsed for the selected dialect") from exc
    if not statements or len(statements) > 200:
        raise SQLLineageError("SQL must contain between 1 and 200 statements")

    star_warnings, expanded_count = _expand_stars(statements, exp, catalog)
    rewritten_sql = ";\n".join(statement.sql(dialect=SUPPORTED_DIALECTS[dialect_key]) for statement in statements)
    result = analyze_sql_lineage(
        rewritten_sql, dialect=dialect_key, source_platform=source_platform,
        target_platform=target_platform, target_table=target_table,
        table_platforms=table_platforms,
    )
    result["unresolved"] = sorted(set(result.get("unresolved", []) + star_warnings))
    update_edges = []
    update_warnings = []
    platform_map = {str(k).casefold(): _clean(v, 80).lower() for k, v in (table_platforms or {}).items()}
    for statement in statements:
        if isinstance(statement, exp.Update):
            edges, warnings, update_target = _update_edges(statement, exp, catalog)
            update_warnings.extend(warnings)
            target_name = update_target or target_table or "unknown_update_target"
            target_provider = _clean(target_platform, 80).lower() or "unknown"
            target_id = f"{target_provider}:{target_name}"
            result["nodes"].append({"id": target_id, "name": target_name, "platform": target_provider, "kind": "table"})
            for edge in edges:
                source_name = edge["source_column"]
                source_table = source_name.rpartition(".")[0]
                source_provider = platform_map.get(source_table.casefold(), _clean(source_platform, 80).lower() or "unknown")
                source_id = f"{source_provider}:{source_name}"
                target_col_id = f"{target_id}.{edge['target_column']}"
                update_edges.append({
                    "source": source_id, "target": target_col_id,
                    **edge, "source_platform": source_provider,
                    "target_platform": target_provider,
                })
                result["nodes"].append({"id": f"{source_provider}:{source_table}", "name": source_table, "platform": source_provider, "kind": "table"})
                if source_table.casefold() != target_name.casefold():
                    result["table_edges"].append({"source": f"{source_provider}:{source_table}", "target": target_id, "kind": "table_dependency"})
    result["column_edges"] = result.get("column_edges", []) + update_edges
    result["unresolved"] = sorted(set(result["unresolved"] + update_warnings))
    # Stable de-duplication after adding UPDATE edges.
    result["column_edges"] = list({(e.get("source"), e.get("target")): e for e in result["column_edges"]}.values())
    result["table_edges"] = list({(e.get("source"), e.get("target"), e.get("kind")): e for e in result["table_edges"]}.values())
    result["nodes"] = list({n["id"]: n for n in result["nodes"]}.values())
    result["node_count"] = len(result["nodes"])
    result["table_edge_count"] = len(result["table_edges"])
    result["column_edge_count"] = len(result["column_edges"])
    result["analysis_mode"] = "static_sql_ast_schema_aware"
    result["schema_aware_star_expansions"] = expanded_count
    result["limitations"] = list(result.get("limitations", [])) + [
        "SELECT * expansion requires a supplied schema_catalog; incomplete schemas remain unresolved.",
        "UPDATE assignment lineage is static AST analysis; dialect-specific procedural behavior and runtime dynamic SQL are not evaluated.",
        "JOIN predicates and filters are not represented as output-column derivations unless referenced by an UPDATE assignment expression.",
    ]
    return result
