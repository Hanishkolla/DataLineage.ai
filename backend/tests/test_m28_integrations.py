from app.pipeline_integrations import (
    analyze_adf_pipeline, analyze_databricks_notebook, compare_delta_schemas,
    build_cross_platform_lineage, analyze_sql_text,
)

def test_adf_activity_dependencies():
    data = {"name":"daily", "properties":{"activities":[
        {"name":"copy","type":"Copy"},
        {"name":"transform","type":"DatabricksNotebook","dependsOn":[{"activity":"copy","dependencyConditions":["Succeeded"]}]}
    ]}}
    out = analyze_adf_pipeline(data)
    assert out["activity_count"] == 2
    assert {"source":"copy","target":"transform"} in out["edges"]

def test_adf_rejects_bad_activity_shape():
    import pytest
    with pytest.raises(ValueError):
        analyze_adf_pipeline({"properties":{"activities":{}}})

def test_databricks_sql_notebook_extracts_tables():
    out = analyze_databricks_notebook("%sql\nSELECT * FROM bronze.orders JOIN silver.customers c ON 1=1", "sql")
    assert "bronze.orders" in out["tables"] or any("orders" in t for t in out["tables"])

def test_python_notebook_spark_sql_extraction():
    out = analyze_databricks_notebook('df = spark.sql("SELECT * FROM main.sales")', "python")
    assert any("sales" in t for t in out["tables"])

def test_delta_schema_detects_removed_and_type_changed():
    out = compare_delta_schemas(
        {"columns":[{"name":"id","type":"INT"},{"name":"old","type":"STRING"}]},
        {"columns":[{"name":"id","type":"BIGINT"},{"name":"new","type":"STRING"}]},
    )
    assert out["removed_columns"] == ["old"]
    assert out["added_columns"] == ["new"]
    assert out["type_changes"][0]["column"] == "id"
    assert out["risk"] == "high"

def test_delta_schema_validation():
    import pytest
    with pytest.raises(ValueError):
        compare_delta_schemas({}, {"columns":"bad"})

def test_cross_platform_graph_contains_pipeline_and_table_nodes():
    out = build_cross_platform_lineage(
        {"nodes":[{"id":"copy","depends_on":[]}]},
        [{"tables":["catalog.schema.orders"]}],
        []
    )
    ids = {n["id"] for n in out["nodes"]}
    assert "adf:copy" in ids
    assert "catalog.schema.orders" in ids

def test_sql_analysis_returns_reviewable_shape():
    out = analyze_sql_text("SELECT * FROM sales.orders")
    assert "tables" in out and "warnings" in out
