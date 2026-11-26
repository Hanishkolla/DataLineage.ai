from __future__ import annotations

from typing import Any


def analyze_schema_change(
    source_table: str,
    old_columns: list[str],
    new_columns: list[str],
    column_lineage: list[dict[str, Any]] | None = None,
    dependency_graph: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compare schema metadata and trace supported downstream column mappings."""
    if not isinstance(source_table, str) or not source_table.strip():
        raise ValueError("source_table must not be empty")
    if not isinstance(old_columns, list) or not isinstance(new_columns, list):
        raise ValueError("old_columns and new_columns must be lists")
    if not all(isinstance(c, str) and c.strip() for c in old_columns + new_columns):
        raise ValueError("Column names must be non-empty strings")

    old_map = {c.strip().casefold(): c.strip() for c in old_columns}
    new_map = {c.strip().casefold(): c.strip() for c in new_columns}
    old_keys, new_keys = set(old_map), set(new_map)
    removed_columns = sorted((old_map[k] for k in old_keys - new_keys), key=str.casefold)
    added_columns = sorted((new_map[k] for k in new_keys - old_keys), key=str.casefold)
    unchanged_columns = sorted((new_map[k] for k in old_keys & new_keys), key=str.casefold)
    removed_keys = {c.casefold() for c in removed_columns}
    source_key = source_table.strip().casefold()

    impacted_mappings: list[dict[str, Any]] = []
    affected_tables: set[str] = set()
    for mapping in column_lineage or []:
        mapping_source = mapping.get("source_table") or ""
        mapping_column = mapping.get("source_column") or ""
        target_table = mapping.get("target_table") or ""
        target_column = mapping.get("target_column") or ""
        if mapping_source.strip().casefold() == source_key and mapping_column.strip().casefold() in removed_keys:
            impacted_mappings.append({
                "source_table": source_table,
                "source_column": mapping_column,
                "target_table": target_table,
                "target_column": target_column,
                "reason": (
                    f"Downstream output column {target_column or '(unknown)'} depends on removed source column {mapping_column}."
                    if mapping.get("transformation", "direct") == "direct"
                    else f"Removed source column {mapping_column} participates in expression {mapping.get('expression_sql', '(expression unavailable)')} for output column {target_column or '(unknown)'}."
                ),
                "confidence": mapping.get("confidence", "high"),
                "severity": "high" if mapping.get("confidence", "high") == "high" else "unknown",
                "transformation": mapping.get("transformation", "direct"),
                "expression_sql": mapping.get("expression_sql"),
            })
            if target_table:
                affected_tables.add(target_table)

    # Renames cannot be proven from column names alone. Offer a candidate only
    # when there is exactly one removal and one addition, and explicitly label it heuristic.
    possible_renames: list[dict[str, Any]] = []
    if len(removed_columns) == 1 and len(added_columns) == 1:
        possible_renames.append({
            "old_column": removed_columns[0],
            "new_column": added_columns[0],
            "confidence": "low",
            "confirmed": False,
            "reason": "Single removed/added-column pair is a rename candidate, but name-only comparison cannot confirm a rename.",
        })

    downstream_objects: list[dict[str, Any]] = []
    if dependency_graph and isinstance(dependency_graph, dict):
        edges = dependency_graph.get("edges", [])
        adjacency: dict[str, set[str]] = {}
        for edge in edges if isinstance(edges, list) else []:
            if isinstance(edge, dict) and isinstance(edge.get("source"), str) and isinstance(edge.get("target"), str):
                adjacency.setdefault(edge["source"].casefold(), set()).add(edge["target"])
        visited: set[str] = set()
        queue = [(target, 1) for target in sorted(adjacency.get(source_key, set()))]
        while queue:
            obj, depth = queue.pop(0)
            key = obj.casefold()
            if key in visited:
                continue
            visited.add(key)
            directly_affected = any(m.get("target_table", "").casefold() == key for m in impacted_mappings)
            downstream_objects.append({
                "object": obj,
                "depth": depth,
                "severity": "high" if directly_affected else "medium",
                "reason": "Direct column mapping references a removed column." if directly_affected else "Downstream of the changed table; impact is transitive and requires review.",
                "confidence": "high" if directly_affected else "medium",
            })
            queue.extend((child, depth + 1) for child in sorted(adjacency.get(key, set())) if child.casefold() not in visited)

    if removed_columns:
        status = "breaking_change_detected"
    elif added_columns:
        status = "columns_added"
    else:
        status = "no_column_changes_detected"

    return {
        "source_table": source_table,
        "status": status,
        "removed_columns": removed_columns,
        "added_columns": added_columns,
        "unchanged_columns": unchanged_columns,
        "possible_renames": possible_renames,
        "impacted_mappings": impacted_mappings,
        "affected_tables": sorted(affected_tables),
        "downstream_objects": downstream_objects,
        "severity": "high" if impacted_mappings else ("medium" if removed_columns else "low"),
        "explanation": (
            f"{len(removed_columns)} removed, {len(added_columns)} added, and "
            f"{len(unchanged_columns)} unchanged column(s) detected for {source_table}."
        ),
        "limitations": [
            "Rename candidates are heuristic only; schema names alone cannot confirm a rename.",
            "Only supplied, supported column lineage can identify direct column impacts.",
            "Transitive graph impacts are potential impacts unless direct column evidence is available.",
            "A missing mapping does not prove a change is safe.",
            "This is a metadata comparison, not a production database migration.",
        ],
    }
