"""Milestone 28: safe, file/API-payload based ADF and Databricks metadata analysis.

This module analyzes exported metadata and SQL text. It does not connect to Azure,
execute notebooks, query customer workspaces, or mutate cloud resources.
"""
from __future__ import annotations
import re
from typing import Any

try:
    import sqlglot
    from sqlglot import exp
except Exception:  # Keep the application importable; report parser unavailable at runtime.
    sqlglot = None
    exp = None

_IDENT = re.compile(r"(?i)\b(?:from|join|into|update|merge\s+into)\s+([`\"\w.$-]+)")
_NOTEBOOK_SQL = re.compile(r"(?is)(?:%sql\s+|spark\.sql\s*\(\s*[\"'])(.*?)(?:[\"']\s*\)|(?=\n# COMMAND ----------)|$)")

def _safe_name(value: Any) -> str:
    return str(value or "").strip()[:300]

def analyze_sql_text(sql: str, dialect: str = "") -> dict[str, Any]:
    if not isinstance(sql, str) or not sql.strip():
        raise ValueError("sql must be a non-empty string")
    if len(sql) > 2_000_000:
        raise ValueError("SQL text exceeds 2 MB")
    tables = sorted(set(_IDENT.findall(sql)))
    result: dict[str, Any] = {
        "status": "analyzed" if sqlglot else "regex_fallback",
        "dialect": dialect or "generic",
        "tables": tables,
        "warnings": [],
        "lineage_available": False,
    }
    if sqlglot:
        try:
            statements = sqlglot.parse(sql, read=dialect or None)
            parsed_tables = set()
            for statement in statements:
                if statement is not None:
                    parsed_tables.update(t.name for t in statement.find_all(exp.Table) if t.name)
            result["tables"] = sorted(parsed_tables)
            result["status"] = "analyzed"
            result["lineage_available"] = True
        except Exception as exc:
            result["status"] = "manual_review"
            result["warnings"].append("SQL parser could not fully understand this input.")
            result["parser_error_type"] = type(exc).__name__
    else:
        result["warnings"].append("SQLGlot is unavailable; table detection uses a limited fallback.")
    return result

def analyze_adf_pipeline(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("ADF pipeline export must be a JSON object")
    props = payload.get("properties", payload)
    activities = props.get("activities", []) if isinstance(props, dict) else []
    if not isinstance(activities, list):
        raise ValueError("ADF properties.activities must be a list")
    nodes, edges = [], []
    names = set()
    for item in activities:
        if not isinstance(item, dict):
            continue
        name = _safe_name(item.get("name"))
        if not name:
            continue
        names.add(name)
        nodes.append({"id": name, "type": _safe_name((item.get("type") or "Activity")), "depends_on": []})
    for item in activities:
        if not isinstance(item, dict):
            continue
        name = _safe_name(item.get("name"))
        depends = item.get("dependsOn") or []
        for dep in depends:
            dep_name = _safe_name(dep.get("activity")) if isinstance(dep, dict) else ""
            if dep_name and dep_name in names:
                edges.append({"source": dep_name, "target": name})
                for node in nodes:
                    if node["id"] == name:
                        node["depends_on"].append(dep_name)
    return {"provider": "azure_data_factory", "pipeline_name": _safe_name(props.get("name") or payload.get("name")),
            "activity_count": len(nodes), "nodes": nodes, "edges": edges,
            "warnings": [] if activities else ["No activities found; confirm this is an exported ADF pipeline definition."]}

def analyze_databricks_notebook(source: str, language: str = "python") -> dict[str, Any]:
    if not isinstance(source, str) or not source.strip():
        raise ValueError("notebook source must be non-empty text")
    if len(source) > 2_000_000:
        raise ValueError("Notebook source exceeds 2 MB")
    snippets = []
    if language.lower() in {"sql", "databricks_sql"}:
        snippets = [source]
    else:
        snippets = [m.group(1).strip() for m in _NOTEBOOK_SQL.finditer(source) if m.group(1).strip()]
        # Also capture common spark.sql("...") statements with a bounded literal-only pattern.
        for match in re.finditer(r'(?is)spark\.sql\(\s*("""|\'\'\'|["\'])(.*?)\1\s*\)', source):
            if match.group(2).strip():
                snippets.append(match.group(2).strip())
    analyses = [analyze_sql_text(s, "databricks") for s in snippets]
    tables = sorted({t for a in analyses for t in a["tables"]})
    warnings = sorted({w for a in analyses for w in a["warnings"]})
    if not snippets:
        warnings.append("No statically extractable SQL cells or spark.sql string literals were found.")
    return {"provider": "azure_databricks", "language": language, "sql_statement_count": len(snippets),
            "tables": tables, "statements": analyses, "warnings": warnings}

def compare_delta_schemas(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    def columns(snapshot):
        if not isinstance(snapshot, dict):
            raise ValueError("schema snapshots must be JSON objects")
        raw = snapshot.get("columns", [])
        if not isinstance(raw, list):
            raise ValueError("columns must be a list")
        out = {}
        for col in raw:
            if isinstance(col, dict) and col.get("name"):
                out[_safe_name(col["name"])] = _safe_name(col.get("type", "unknown"))
        return out
    old, new = columns(before), columns(after)
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    changed = [{"column": c, "before": old[c], "after": new[c]} for c in sorted(set(old) & set(new)) if old[c] != new[c]]
    risk = "high" if removed else ("medium" if changed else ("low" if added else "low"))
    return {"provider": "delta_lake", "added_columns": added, "removed_columns": removed,
            "type_changes": changed, "risk": risk,
            "warnings": ["Schema comparison uses supplied snapshots; it does not query a live Delta table."]}

def build_cross_platform_lineage(adf: dict[str, Any] | None = None,
                                 notebooks: list[dict[str, Any]] | None = None,
                                 sql_analyses: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    nodes, edges = {}, []
    for item in (notebooks or []) + (sql_analyses or []):
        for table in item.get("tables", []):
            nodes[table] = {"id": table, "type": "table"}
    for pipeline in (adf or {}).get("nodes", []):
        key = "adf:" + pipeline["id"]
        nodes[key] = {"id": key, "type": "adf_activity"}
        for dep in pipeline.get("depends_on", []):
            edges.append({"source": "adf:" + dep, "target": key, "kind": "pipeline_dependency"})
    return {"nodes": list(nodes.values()), "edges": edges,
            "coverage_note": "Cross-platform edges are limited to explicitly supplied metadata; inferred SQL-to-pipeline joins require connector metadata."}
