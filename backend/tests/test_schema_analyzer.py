
import pytest

from app.schema_analyzer import analyze_schema_change


def test_removed_column_detected():
    result = analyze_schema_change(
        source_table="customers",
        old_columns=["id", "name", "email"],
        new_columns=["id", "name"],
    )

    assert result["status"] == "breaking_change_detected"
    assert result["removed_columns"] == ["email"]


def test_downstream_table_reported():
    lineage = [
        {
            "source_table": "customers",
            "source_column": "email",
            "target_table": "customer_summary",
            "target_column": "email",
        }
    ]

    result = analyze_schema_change(
        source_table="customers",
        old_columns=["id", "email"],
        new_columns=["id"],
        column_lineage=lineage,
    )

    assert result["affected_tables"] == ["customer_summary"]
    assert len(result["impacted_mappings"]) == 1
    assert result["impacted_mappings"][0]["source_column"] == "email"


def test_added_column_detected():
    result = analyze_schema_change(
        source_table="customers",
        old_columns=["id", "name"],
        new_columns=["id", "name", "email"],
    )

    assert result["status"] == "columns_added"
    assert result["added_columns"] == ["email"]
    assert result["removed_columns"] == []


def test_unchanged_schema():
    result = analyze_schema_change(
        source_table="customers",
        old_columns=["id", "name"],
        new_columns=["id", "name"],
    )

    assert result["status"] == "no_column_changes_detected"
    assert result["unchanged_columns"] == ["id", "name"]


def test_empty_source_table_rejected():
    with pytest.raises(ValueError):
        analyze_schema_change(
            source_table="",
            old_columns=["id"],
            new_columns=["id"],
        )
