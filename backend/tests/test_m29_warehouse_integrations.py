from app.warehouse_integrations import (
    analyze_dbt_manifest, normalize_warehouse_snapshot, compare_warehouse_snapshots
)

def test_dbt_manifest_builds_dependency_edges():
    manifest = {
        "metadata": {"dbt_version": "1.x"},
        "nodes": {
            "model.demo.base": {"name": "base", "resource_type": "model", "depends_on": {"nodes": []}},
            "model.demo.mart": {"name": "mart", "resource_type": "model", "depends_on": {"nodes": ["model.demo.base"]}},
        }, "sources": {}
    }
    result = analyze_dbt_manifest(manifest)
    assert result["object_count"] == 2
    assert result["edges"] == [{"source": "model.demo.base", "target": "model.demo.mart", "kind": "dbt_dependency"}]

def test_dbt_manifest_reports_unresolved_dependencies():
    result = analyze_dbt_manifest({"nodes": {"model.x": {"resource_type": "model", "depends_on": {"nodes": ["source.missing"]}}}, "sources": {}})
    assert result["unresolved_dependencies"] == ["source.missing"]

def test_snowflake_snapshot_normalizes_metadata():
    result = normalize_warehouse_snapshot({"tables": [{"name": "ORDERS", "schema": "PUBLIC", "columns": [{"name": "ID", "type": "NUMBER"}]}]}, "snowflake")
    assert result["table_count"] == 1
    assert result["tables"][0]["columns"][0]["type"] == "NUMBER"

def test_postgresql_snapshot_normalizes_data_type_alias():
    result = normalize_warehouse_snapshot({"tables": [{"table_name": "orders", "table_schema": "public", "columns": [{"name": "id", "data_type": "integer"}]}]}, "postgresql")
    assert result["tables"][0]["columns"][0]["type"] == "integer"

def test_snapshot_comparison_detects_added_removed_tables_and_columns():
    before = {"tables": [{"name": "orders", "schema": "public", "columns": [{"name": "id", "type": "int"}, {"name": "legacy", "type": "text"}]}, {"name": "old_table", "schema": "public", "columns": []}]}
    after = {"tables": [{"name": "orders", "schema": "public", "columns": [{"name": "id", "type": "int"}, {"name": "status", "type": "text"}]}, {"name": "new_table", "schema": "public", "columns": []}]}
    result = compare_warehouse_snapshots(before, after, "postgresql")
    assert result["added_tables"] == ["public.new_table"]
    assert result["removed_tables"] == ["public.old_table"]
    assert result["changed_tables"][0]["added_columns"] == ["status"]
    assert result["changed_tables"][0]["removed_columns"] == ["legacy"]
    assert result["risk"] == "high"

def test_invalid_provider_rejected():
    try:
        normalize_warehouse_snapshot({"tables": []}, "mysql")
    except ValueError as exc:
        assert "provider" in str(exc)
    else:
        assert False, "expected ValueError"
