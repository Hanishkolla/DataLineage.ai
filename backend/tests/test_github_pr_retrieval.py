import base64
import pytest
from app.github_integration import decode_github_content, validate_repo, validate_pr_number, classify_file_changes


def test_decode_github_contents_api_base64():
    content = "select id from orders"
    encoded = base64.b64encode(content.encode()).decode()
    assert decode_github_content({"encoding": "base64", "content": encoded}) == content


def test_decode_github_content_rejects_wrong_encoding():
    with pytest.raises(ValueError):
        decode_github_content({"encoding": "none", "content": "select 1"})


def test_decode_github_content_rejects_oversize():
    with pytest.raises(ValueError):
        decode_github_content({"encoding": "base64", "content": "x" * (3 * 1024 * 1024 + 1)})


def test_renamed_sql_file_keeps_old_path_metadata():
    result = classify_file_changes([{
        "filename": "models/new.sql", "previous_filename": "models/old.sql",
        "status": "renamed", "patch": "@@ -1 +1 @@"
    }])
    assert result[0]["status"] == "renamed"
    assert result[0]["previous_filename"] == "models/old.sql"


def test_repository_and_pr_validation_remain_strict():
    assert validate_repo("org/repo") == "org/repo"
    assert validate_pr_number(4) == 4
    with pytest.raises(ValueError):
        validate_repo("https://example.com/org/repo")


def test_github_api_host_rejects_lookalike_domain(monkeypatch):
    from app.github_integration import github_configuration
    monkeypatch.setenv("DATALINEAGE_GITHUB_TOKEN", "fake-token")
    monkeypatch.setenv("DATALINEAGE_GITHUB_API_URL", "https://api.github.com.attacker.invalid")
    with pytest.raises(ValueError):
        github_configuration()
