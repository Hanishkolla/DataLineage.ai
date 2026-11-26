"""Milestone 29: dbt manifest and warehouse metadata snapshot ingestion.

This module processes user-supplied exports. It does not connect to live
Snowflake/PostgreSQL accounts or execute SQL.
"""
from __future__ import annotations
from typing import Any

MAX_OBJECTS = 100_000

def _bounded_text(value: Any, limit: int = 500) -> str:
    return str(value or "").strip()[:limit]

def analyze_dbt_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        raise ValueError("dbt manifest must be a JSON object")
    nodes = manifest.get("nodes", {})
    sources = manifest.get("sources", {})
    if not isinstance(nodes, dict) or not isinstance(sources, dict):
        raise ValueError("manifest nodes and sources must be objects")
    if len(nodes) + len(sources) > MAX_OBJECTS:
        raise ValueError("manifest contains too many objects")
    objects: dict[str, dict[str, Any]] = {}
    for unique_id, item in {**sources, **nodes}.items():
        if not isinstance(item, dict):
            continue
        resource_type = _bounded_text(item.get("resource_type") or ("source" if unique_id in sources else "model"))
        if resource_type not in {"model", "source", "seed", "snapshot", "test", "exposure", "metric"}:
            continue
        name = _bounded_text(item.get("name") or unique_id)
        depends = item.get("depends_on", {})
        dep_nodes = depends.get("nodes", []) if isinstance(depends, dict) else []
        objects[unique_id] = {
            "id": _bounded_text(unique_id, 1000), "name": name,
            "resource_type": resource_type,
            "database": _bounded_text(item.get("database")),
            "schema": _bounded_text(item.get("schema")),
            "depends_on": [_bounded_text(x, 1000) for x in dep_nodes if isinstance(x, str)],
        }
    edges = []
    for uid, item in objects.items():
        for parent in item["depends_on"]:
            if parent in objects:
                edges.append({"source": parent, "target": uid, "kind": "dbt_dependency"})
    return {
        "provider": "dbt", "manifest_metadata": manifest.get("metadata", {}),
        "object_count": len(objects), "objects": list(objects.values()), "edges": edges,
        "unresolved_dependencies": sorted({d for obj in objects.values() for d in obj["depends_on"] if d not in objects}),
        "warnings": ["Lineage is based on the supplied dbt manifest; freshness and runtime execution are not checked."]
    }

def normalize_warehouse_snapshot(snapshot: dict[str, Any], provider: str) -> dict[str, Any]:
    if provider not in {"snowflake", "postgresql"}:
        raise ValueError("provider must be snowflake or postgresql")
    if not isinstance(snapshot, dict):
        raise ValueError("snapshot must be a JSON object")
    raw = snapshot.get("tables", [])
    if not isinstance(raw, list) or len(raw) > MAX_OBJECTS:
        raise ValueError("tables must be a bounded list")
    tables = []
    seen = set()
    for table in raw:
        if not isinstance(table, dict):
            continue
        name = _bounded_text(table.get("name") or table.get("table_name"))
        if not name:
            continue
        key = name.casefold()
        if key in seen:
            continue
        seen.add(key)
        columns = []
        for col in table.get("columns", []) if isinstance(table.get("columns", []), list) else []:
            if isinstance(col, dict) and col.get("name"):
                columns.append({"name": _bounded_text(col["name"]), "type": _bounded_text(col.get("type") or col.get("data_type") or "unknown")})
        tables.append({"name": name, "schema": _bounded_text(table.get("schema") or table.get("table_schema")),
                       "columns": columns})
    return {"provider": provider, "table_count": len(tables), "tables": tables,
            "warnings": ["Imported from a supplied metadata snapshot; no live database connection was made."]}

def compare_warehouse_snapshots(before: dict[str, Any], after: dict[str, Any], provider: str) -> dict[str, Any]:
    old = normalize_warehouse_snapshot(before, provider)
    new = normalize_warehouse_snapshot(after, provider)
    old_map = {f'{t["schema"]}.{t["name"]}'.casefold(): t for t in old["tables"]}
    new_map = {f'{t["schema"]}.{t["name"]}'.casefold(): t for t in new["tables"]}
    added_tables = sorted(set(new_map) - set(old_map))
    removed_tables = sorted(set(old_map) - set(new_map))
    changed_tables = []
    for key in sorted(set(old_map) & set(new_map)):
        a, b = old_map[key], new_map[key]
        ac = {c["name"].casefold(): c["type"] for c in a["columns"]}
        bc = {c["name"].casefold(): c["type"] for c in b["columns"]}
        added = sorted(set(bc) - set(ac))
        removed = sorted(set(ac) - set(bc))
        changed = sorted(c for c in set(ac) & set(bc) if ac[c] != bc[c])
        if added or removed or changed:
            changed_tables.append({"table": b["name"], "schema": b["schema"],
                                   "added_columns": added, "removed_columns": removed,
                                   "type_changes": [{"column": c, "before": ac[c], "after": bc[c]} for c in changed]})
    risk = "high" if removed_tables or any(t["removed_columns"] for t in changed_tables) else (
        "medium" if any(t["type_changes"] for t in changed_tables) else "low")
    return {"provider": provider, "added_tables": added_tables, "removed_tables": removed_tables,
            "changed_tables": changed_tables, "risk": risk,
            "warnings": old["warnings"] + new["warnings"]}
