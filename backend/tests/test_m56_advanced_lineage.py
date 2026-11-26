import pytest
from app.schema_aware_lineage import normalize_schema_catalog, analyze_advanced_sql_lineage
from app.sql_lineage import SQLLineageError


def test_schema_catalog_normalizes_and_deduplicates_columns():
    assert normalize_schema_catalog({"RAW.ORDERS": ["id", "email", "id"]}) == {
        "raw.orders": ["id", "email"]
    }


def test_schema_catalog_rejects_invalid_payload():
    with pytest.raises(SQLLineageError):
        normalize_schema_catalog(["not", "an", "object"])
    with pytest.raises(SQLLineageError):
        normalize_schema_catalog({"t": "id,email"})


def test_schema_catalog_enforces_total_column_limit():
    with pytest.raises(SQLLineageError, match="total column"):
        normalize_schema_catalog({f"t{i}": [f"c{j}" for j in range(2000)] for i in range(51)})


def test_rejects_unsupported_dialect_before_parser_import():
    with pytest.raises(SQLLineageError, match="Unsupported SQL dialect"):
        analyze_advanced_sql_lineage("SELECT 1", dialect="not-a-dialect")


def test_requires_sqlglot_for_ast_analysis():
    pytest.importorskip("sqlglot")
    result = analyze_advanced_sql_lineage(
        "SELECT * FROM raw.orders o", dialect="postgres", target_table="mart.orders",
        schema_catalog={"raw.orders": ["order_id", "customer_id"]},
    )
    assert result["schema_aware_star_expansions"] == 2
    assert {edge["target_column"] for edge in result["column_edges"]} == {"order_id", "customer_id"}


def test_update_assignment_lineage():
    pytest.importorskip("sqlglot")
    result = analyze_advanced_sql_lineage(
        "UPDATE analytics.customer_summary SET total_spend = total_spend + order_amount",
        dialect="postgres", source_platform="snowflake", target_platform="snowflake",
        schema_catalog={"analytics.customer_summary": ["total_spend", "order_amount"]},
    )
    assert any(edge.get("operation") == "update" and edge["target_column"] == "total_spend"
               for edge in result["column_edges"])
