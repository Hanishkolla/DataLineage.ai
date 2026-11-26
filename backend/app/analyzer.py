from __future__ import annotations

from typing import Any

import networkx as nx
import sqlglot
from sqlglot import exp
from sqlglot.tokens import TokenType

from .ingestion import SQLFile


def _table_name(table: exp.Table) -> str:
    """Return a normalized, qualified table name where available."""
    parts = [str(part) for part in (table.catalog, table.db, table.name) if part]
    return ".".join(parts) if parts else table.name


def _target_table(statement: exp.Expression) -> str | None:
    target = None
    if isinstance(statement, (exp.Create, exp.Insert)):
        target = statement.this
    elif isinstance(statement, exp.Update):
        target = statement.this
    elif isinstance(statement, exp.Merge):
        target = statement.this
    elif isinstance(statement, exp.Delete):
        target = statement.this
    if isinstance(target, exp.Schema):
        target = target.this
    if isinstance(target, exp.Table):
        return _table_name(target)
    return None


def _cte_names(query: Any) -> set[str]:
    """Return CTE names when given an expression; tolerate non-expression AST args."""
    if not isinstance(query, exp.Expression):
        return set()
    return {
        cte.alias_or_name.casefold()
        for cte in query.find_all(exp.CTE)
        if cte.alias_or_name
    }


def _query_for_target(statement: exp.Expression) -> exp.Expression | None:
    """Return the statement's primary query, avoiding a nested CTE query first.

    SQLGlot stores the primary SELECT/Query in the ``expression`` argument for
    CREATE and INSERT. Falling back to a tree search keeps compatibility with
    SQLGlot versions and less common statement shapes.
    """
    if isinstance(statement, (exp.Create, exp.Insert)):
        expression = statement.args.get("expression")
        if isinstance(expression, exp.Query):
            return expression
        if isinstance(expression, exp.Expression):
            found = expression if isinstance(expression, exp.Query) else expression.find(exp.Query)
            if found is not None:
                return found
        return statement.find(exp.Query)
    if isinstance(statement, exp.Update):
        candidate = statement.args.get("from") or statement.args.get("using")
        return candidate if isinstance(candidate, exp.Expression) else None
    if isinstance(statement, exp.Delete):
        candidate = statement.args.get("using")
        return candidate if isinstance(candidate, exp.Expression) else None
    return None


def _resolve_cte_column(
    query: exp.Expression, table_ref: str, column_name: str,
    seen: set[tuple[str, str]] | None = None,
) -> list[dict[str, str]]:
    """Resolve a referenced CTE output column to physical source columns.

    This intentionally supports simple projection chains only. Unsupported or
    ambiguous cases return no result and are surfaced as unresolved by caller.
    """
    seen = set() if seen is None else seen
    key = (table_ref.casefold(), column_name.casefold())
    if key in seen:
        return []
    seen.add(key)
    for cte in query.find_all(exp.CTE):
        if cte.alias_or_name.casefold() != table_ref.casefold():
            continue
        cte_query = cte.this
        select = cte_query if isinstance(cte_query, exp.Select) else cte_query.find(exp.Select)
        if select is None:
            return []
        matches = []
        for projection in select.expressions:
            output_name = projection.alias_or_name
            value = projection.this if isinstance(projection, exp.Alias) else projection
            if output_name.casefold() != column_name.casefold():
                continue
            refs = [value] if isinstance(value, exp.Column) else list(value.find_all(exp.Column))
            physical_tables = {
                _table_name(t): t for t in cte_query.find_all(exp.Table)
                if t.name.casefold() not in _cte_names(cte_query)
            }
            aliases: dict[str, set[str]] = {}
            for physical_name, table in physical_tables.items():
                aliases.setdefault(table.name.casefold(), set()).add(physical_name)
                if table.alias:
                    aliases.setdefault(table.alias.casefold(), set()).add(physical_name)
            for ref in refs:
                if ref.table:
                    candidates = aliases.get(ref.table.casefold(), set())
                    if len(candidates) == 1:
                        matches.append({"table": next(iter(candidates)), "column": ref.name})
                    else:
                        nested = _resolve_cte_column(cte_query, ref.table, ref.name, seen)
                        matches.extend(nested)
                elif len(physical_tables) == 1:
                    matches.append({"table": next(iter(physical_tables)), "column": ref.name})
        # Stable de-duplication.
        unique = []
        for item in matches:
            if item not in unique:
                unique.append(item)
        return unique
    return []


def _direct_column_mappings(
    statement: exp.Expression, file_path: str, line: int | None = None
) -> list[dict[str, Any]]:
    """Trace source columns for direct projections and supported expressions.

    A computed projection can depend on several source columns. Emit one mapping
    per source column so schema-impact analysis can identify a removed input even
    when it contributes to arithmetic, casts, functions, or other expressions.
    Ambiguous sources are explicitly marked unresolved rather than guessed.
    """
    target = _target_table(statement)
    query = _query_for_target(statement)
    if not target or query is None:
        return []

    select = query if isinstance(query, exp.Select) else query.find(exp.Select)
    if select is None:
        return []

    cte_names = _cte_names(query)
    alias_to_tables: dict[str, set[str]] = {}
    physical_tables: list[str] = []
    for table in query.find_all(exp.Table):
        name = _table_name(table)
        if table.name.casefold() in cte_names:
            continue
        if name not in physical_tables:
            physical_tables.append(name)
        # The unqualified physical name can be ambiguous across schemas, so keep
        # candidate sets instead of silently choosing the last matching table.
        alias_to_tables.setdefault(table.name.casefold(), set()).add(name)
        if table.alias:
            alias_to_tables.setdefault(table.alias.casefold(), set()).add(name)

    mappings: list[dict[str, Any]] = []
    insert_target_columns: list[str] = []
    target_spec = statement.this if isinstance(statement, exp.Insert) else None
    if isinstance(target_spec, exp.Schema):
        for target_expr in target_spec.expressions:
            name = getattr(target_expr, "name", None) or getattr(target_expr, "this", None)
            if name:
                insert_target_columns.append(str(name))
    for projection_index, projection in enumerate(select.expressions):
        target_column = (
            insert_target_columns[projection_index]
            if projection_index < len(insert_target_columns)
            else projection.alias_or_name
        )
        value = projection.this if isinstance(projection, exp.Alias) else projection
        if not target_column:
            continue

        column_refs = [value] if isinstance(value, exp.Column) else list(value.find_all(exp.Column))
        if not column_refs:
            # Constants do not have source-column lineage.
            continue

        expression_sql = value.sql(pretty=False)
        transformation = "direct" if isinstance(value, exp.Column) else "expression"
        resolved_refs: list[dict[str, str]] = []
        unresolved_refs: list[exp.Column] = []
        for column in column_refs:
            source_table: str | None = None
            if column.table:
                candidates = alias_to_tables.get(column.table.casefold(), set())
                if len(candidates) == 1:
                    source_table = next(iter(candidates))
                elif column.table.casefold() in cte_names:
                    cte_sources = _resolve_cte_column(query, column.table, column.name)
                    if cte_sources:
                        for item in cte_sources:
                            if item not in resolved_refs:
                                resolved_refs.append(item)
                        continue
            else:
                # An unqualified output column may be projected from a CTE.
                # Resolve through that CTE before falling back to a physical table,
                # otherwise aliases such as event_id can be incorrectly attributed
                # to the underlying table as if event_id were a physical column.
                referenced_ctes = {
                    table.name for table in query.find_all(exp.Table)
                    if table.name.casefold() in cte_names
                }
                if len(referenced_ctes) == 1:
                    cte_name = next(iter(referenced_ctes))
                    cte_sources = _resolve_cte_column(query, cte_name, column.name)
                    if cte_sources:
                        for item in cte_sources:
                            if item not in resolved_refs:
                                resolved_refs.append(item)
                        continue
                if len(physical_tables) == 1:
                    source_table = physical_tables[0]

            if source_table:
                item = {"table": source_table, "column": column.name}
                if item not in resolved_refs:
                    resolved_refs.append(item)
            else:
                unresolved_refs.append(column)

        all_source_columns = list(resolved_refs)
        for source in resolved_refs:
            mappings.append({
                "source_table": source["table"],
                "source_column": source["column"],
                "target_table": target,
                "target_column": target_column,
                "confidence": "high",
                "resolution_status": "verified",
                "reason": (
                    "Direct column projection with a resolvable source table."
                    if transformation == "direct"
                    else "Source column participates in a computed output expression."
                ),
                "source_file": file_path,
                "source_line": line,
                "evidence": statement.sql(pretty=False)[:1200],
                "transformation": transformation,
                "expression_sql": expression_sql,
                "source_columns": all_source_columns,
            })

        for column in unresolved_refs:
            mappings.append({
                "source_table": None,
                "source_column": column.name,
                "target_table": target,
                "target_column": target_column,
                "confidence": "unresolved",
                "resolution_status": "unresolved",
                "reason": (
                    "Column source is ambiguous or its table alias cannot be resolved; "
                    "the analyzer does not infer a source table."
                ),
                "source_file": file_path,
                "source_line": line,
                "evidence": statement.sql(pretty=False)[:1200],
                "transformation": transformation,
                "expression_sql": expression_sql,
                "source_columns": all_source_columns,
            })
    return mappings


def _parse_error(content: str, dialect: str) -> str | None:
    try:
        tokens = sqlglot.Tokenizer().tokenize(content)
        depth = 0
        for token in tokens:
            if token.token_type == TokenType.L_PAREN:
                depth += 1
            elif token.token_type == TokenType.R_PAREN:
                depth -= 1
                if depth < 0:
                    return "Unbalanced parentheses in SQL statement."
        if depth:
            return "Unbalanced parentheses in SQL statement."
        sqlglot.parse(content, read=dialect or None, error_level="RAISE")
    except Exception as exc:
        return str(exc).splitlines()[0] or "SQL parsing failed."
    return None


def analyze_sql_files(files: list[SQLFile], dialect: str = "") -> dict[str, Any]:
    relationships: list[dict[str, Any]] = []
    parse_results: list[dict[str, Any]] = []
    column_lineage: list[dict[str, Any]] = []
    unresolved_references: list[dict[str, Any]] = []
    tables: set[str] = set()
    graph = nx.DiGraph()

    for sql_file in files:
        try:
            # Validate token balance and SQL syntax before processing statements.
            # This also catches incomplete inputs such as ``SELECT * FROM (``.
            validation_error = _parse_error(sql_file.content, dialect)
            if validation_error:
                raise ValueError(validation_error)
            statements = sqlglot.parse(
                sql_file.content, read=dialect or None, error_level="RAISE"
            )
        except Exception as exc:
            parse_results.append({
                "file": sql_file.path,
                "status": "error",
                "statement_count": 0,
                "errors": str(exc).splitlines() or ["SQL parsing failed."],
            })
            continue

        statement_count = 0
        file_errors: list[str] = []
        for statement in statements:
            if statement is None:
                continue
            statement_count += 1
            target = _target_table(statement)
            query = _query_for_target(statement)
            cte_names = _cte_names(query if isinstance(query, exp.Expression) else statement)
            all_tables = list(statement.find_all(exp.Table))
            sources: set[str] = set()
            for table in all_tables:
                name = _table_name(table)
                if table.name.casefold() in cte_names:
                    continue
                if target and name.casefold() == target.casefold():
                    continue
                sources.add(name)

            if target:
                tables.add(target)
                graph.add_node(target, object_type="table")
            for source in sorted(sources):
                tables.add(source)
                graph.add_node(source, object_type="table")
                if target:
                    graph.add_edge(source, target)
                    statement_kind = statement.key.upper()
                    relationships.append({
                        "source_table": source,
                        "target_table": target,
                        "relationship_type": "reads_from",
                        "operation": statement_kind,
                        "source_file": sql_file.path,
                        "line": statement.meta.get("line"),
                        "evidence": statement.sql(pretty=False)[:1200],
                        "confidence": "high",
                        "resolution_status": "verified",
                        "scope": "table_level",
                        "reason": f"{target} reads from {source} in this {statement_kind} statement.",
                    })

            # Read-only SELECT references are visible as graph nodes, but cannot
            # be assigned an output target without an explicit materialization.
            for table in all_tables:
                if table.name.casefold() not in cte_names:
                    tables.add(_table_name(table))

            if target:
                column_lineage.extend(_direct_column_mappings(
                    statement, sql_file.path, statement.meta.get("line")
                ))

            # Mark unresolved unqualified references when more than one physical
            # source table appears and a projection cannot be safely attributed.
            if query is not None:
                select = query if isinstance(query, exp.Select) else query.find(exp.Select)
                if select is not None and len(sources) > 1:
                    for projection in select.expressions:
                        value = projection.this if isinstance(projection, exp.Alias) else projection
                        if isinstance(value, exp.Column) and not value.table:
                            unresolved_references.append({
                                "file": sql_file.path,
                                "target_table": target,
                                "column": value.name,
                                "reason": "Unqualified column with multiple source tables; source cannot be determined safely.",
                            })

        parse_results.append({
            "file": sql_file.path,
            "status": "error" if file_errors else "parsed",
            "statement_count": statement_count,
            "errors": file_errors,
        })

    # Deterministic traversal helpers are exposed alongside the backwards-compatible graph.
    graph_nodes = [{"id": node, **graph.nodes[node]} for node in sorted(graph.nodes)]
    graph_edges = [
        {"source": source, "target": target}
        for source, target in sorted(graph.edges)
    ]
    cycles = [sorted(component) for component in nx.strongly_connected_components(graph)
              if len(component) > 1 or any(graph.has_edge(node, node) for node in component)]
    cycles.sort(key=lambda component: tuple(component))
    # Keep repeated SQL evidence across different files/statements, but collapse
    # exact duplicate relationship records deterministically.
    relationship_keys: set[tuple[Any, ...]] = set()
    unique_relationships: list[dict[str, Any]] = []
    for relationship in relationships:
        key = tuple(relationship.get(field) for field in (
            "source_table", "target_table", "relationship_type", "operation",
            "source_file", "line", "evidence"
        ))
        if key not in relationship_keys:
            relationship_keys.add(key)
            unique_relationships.append(relationship)
    unique_relationships.sort(key=lambda item: (
        item["source_table"].casefold(), item["target_table"].casefold(),
        item.get("source_file", "").casefold(), item.get("line") or 0,
        item.get("operation", "")
    ))
    return {
        "dialect": dialect or "auto/default",
        "files_scanned": len(files),
        "files_parsed": sum(1 for item in parse_results if item["status"] == "parsed"),
        "files_with_errors": sum(1 for item in parse_results if item["status"] == "error"),
        "tables": sorted(tables),
        "relationships": unique_relationships,
        "column_lineage": column_lineage,
        "unresolved_references": unresolved_references,
        "parse_results": parse_results,
        "graph": {"nodes": graph_nodes, "edges": graph_edges},
        "cycles": cycles,
        "dependencies": {
            "upstream": {
                node: sorted(nx.ancestors(graph, node)) for node in sorted(graph.nodes)
            },
            "downstream": {
                node: sorted(nx.descendants(graph, node)) for node in sorted(graph.nodes)
            },
        },
        "limitations": [
            "Cross-file dependencies are combined by normalized table name; source files are not required to be in execution order.",
            "Column lineage is emitted for CREATE/INSERT query projections; statement-specific UPDATE/DELETE column assignments require further dialect-aware handling.",
            "SELECT * expansion requires schema metadata and is not inferred without it.",
            "Simple CTE projection chains are resolved; recursive CTEs and complex nested derived-table scopes may remain unresolved.",
            "Ambiguous unqualified columns are not assigned invented source tables.",
            "Graph cycles are reported but do not prove the SQL execution order is valid.",
            "A missing relationship is not proof that a schema change is safe.",
            "Uploaded SQL is parsed only; it is never executed.",
        ],
    }
