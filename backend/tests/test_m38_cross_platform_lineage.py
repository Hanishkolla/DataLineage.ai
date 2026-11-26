import pytest

pytest.importorskip("sqlglot")
from app.sql_lineage import analyze_sql_lineage, SQLLineageError


def test_select_produces_table_and_column_lineage():
    result = analyze_sql_lineage(
        "SELECT o.order_id AS id, o.customer_email FROM raw.orders o",
        dialect="postgres", source_platform="snowflake", target_platform="databricks",
        target_table="curated.orders",
    )
    assert result["table_edge_count"] == 1
    assert result["column_edge_count"] == 2
    assert any(e["source_column"] == "raw.orders.order_id" and e["target_column"] == "id"
               for e in result["column_edges"])
    assert result["executed_sql"] is False
    assert {n["platform"] for n in result["nodes"]} == {"snowflake", "databricks"}


def test_insert_target_is_detected():
    result = analyze_sql_lineage(
        "INSERT INTO analytics.daily_sales SELECT order_id FROM staging.orders",
        dialect="postgres", source_platform="aws", target_platform="snowflake",
    )
    assert any(n["name"] == "analytics.daily_sales" for n in result["nodes"])
    assert result["table_edge_count"] == 1


def test_cte_column_lineage_expands_to_base_table():
    result = analyze_sql_lineage(
        "WITH recent AS (SELECT order_id, customer_id FROM raw.orders) "
        "SELECT r.order_id AS id FROM recent r",
        source_platform="bigquery", target_platform="databricks", target_table="mart.orders",
    )
    assert any(e["source_column"] == "raw.orders.order_id" and e["target_column"] == "id"
               for e in result["column_edges"])


def test_ambiguous_unqualified_join_column_is_not_guessed():
    result = analyze_sql_lineage(
        "SELECT id FROM a JOIN b ON a.id = b.id",
        source_platform="postgresql", target_table="out.t",
    )
    assert any("unqualified" in warning for warning in result["unresolved"])
    assert not any(e["target_column"] == "id" for e in result["column_edges"])


def test_rejects_unsupported_dialect_and_oversized_sql():
    with pytest.raises(SQLLineageError, match="Unsupported SQL dialect"):
        analyze_sql_lineage("select 1", dialect="madeup")
    with pytest.raises(SQLLineageError, match="characters"):
        analyze_sql_lineage("x" * 1_000_001)
