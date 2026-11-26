from app.sql_change_intelligence import compare_sql_changes, validate_dataset_snapshots
import pytest


def test_sql_compare_detects_removed_column_and_recommends_tests():
    result = compare_sql_changes(
        "SELECT id, email FROM customers",
        "SELECT id FROM customers",
        "postgres",
    )
    assert result["changes"]["removed_columns"] == ["email"]
    assert result["risk"]["level"] in {"medium", "high"}
    assert result["recommended_tests"]


def test_sql_compare_detects_table_change():
    result = compare_sql_changes(
        "SELECT id FROM old_customers",
        "SELECT id FROM customers",
    )
    assert result["changes"]["removed_tables"] == ["old_customers"]
    assert result["changes"]["added_tables"] == ["customers"]


def test_sql_compare_schema_rename_is_only_candidate():
    result = compare_sql_changes(
        "SELECT id FROM t", "SELECT id FROM t",
        old_schema={"t": ["id", "old_name"]},
        new_schema={"t": ["id", "new_name"]},
    )
    candidate = result["schema_comparison"][0]["possible_rename"]
    assert candidate["confirmed"] is False
    assert candidate["confidence"] == "low"


def test_sql_compare_rejects_empty_or_unparseable_sql():
    with pytest.raises(ValueError):
        compare_sql_changes("", "SELECT 1")
    with pytest.raises(ValueError):
        compare_sql_changes("SELECT FROM", "SELECT 1")


def test_dataset_validation_detects_missing_values_schema_and_row_count():
    result = validate_dataset_snapshots(
        [{"id": 1, "name": "A"}, {"id": 2, "name": "B"}],
        [{"id": 1, "name": None, "extra": 3}],
        required_columns=["id", "name", "created_at"],
        max_row_count_change_pct=20,
    )
    assert result["status"] == "failed"
    assert "name" in result["missing_values_by_column"]
    assert "extra" in result["unexpected_columns"]
    assert "created_at" in result["missing_required_columns"]
    assert "row_count_change_threshold" in result["failed_checks"]


def test_dataset_validation_passes_clean_snapshot():
    result = validate_dataset_snapshots(
        [{"id": 1}], [{"id": 1}], required_columns=["id"],
        max_row_count_change_pct=0,
    )
    assert result["status"] == "passed"
    assert result["failed_checks"] == []
