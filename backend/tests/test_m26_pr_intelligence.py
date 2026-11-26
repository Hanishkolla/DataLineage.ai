from app.pull_request_intelligence import analyze_pr_sql_changes


def test_pr_sql_intelligence_reports_removed_column_and_tests():
    result = analyze_pr_sql_changes([{
        "filename": "models/customers.sql",
        "base_content": "SELECT id, email FROM customers",
        "head_content": "SELECT id FROM customers",
    }])
    assert result["counts"]["analyzed"] == 1
    assert result["risk"]["level"] in {"medium", "high"}
    comparison = result["files"][0]["comparison"]
    assert comparison["changes"]["removed_columns"] == ["email"]
    assert result["recommended_tests"]


def test_pr_sql_intelligence_flags_unsupported_sql_without_guessing():
    result = analyze_pr_sql_changes([{
        "filename": "models/unsupported.sql",
        "base_content": "SELECT FROM",
        "head_content": "SELECT 1",
    }])
    assert result["counts"]["unparsed"] == 1
    assert result["files"][0]["status"] == "unparsed"
    assert result["risk"]["level"] == "medium"


def test_pr_sql_intelligence_marks_added_and_removed_files():
    result = analyze_pr_sql_changes([
        {"filename": "models/new.sql", "base_content": None, "head_content": "SELECT 1"},
        {"filename": "models/old.sql", "base_content": "SELECT 1", "head_content": None},
    ])
    assert result["counts"]["added"] == 1
    assert result["counts"]["removed"] == 1
    assert {x["status"] for x in result["files"]} == {"added", "removed"}
