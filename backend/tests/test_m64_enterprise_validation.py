from __future__ import annotations

import json
from app.tenant_isolation_validation import run_tenant_isolation_suite, render_markdown


def test_two_tenant_persistence_isolation_suite_passes(tmp_path):
    report = run_tenant_isolation_suite(tmp_path)
    assert report["milestone"] == "M64"
    assert report["status"] == "passed"
    assert report["synthetic_tenants"] == 2
    assert report["checks_failed"] == 0
    assert report["checks_passed"] >= 10
    assert {item["status"] for item in report["checks"]} == {"passed"}


def test_report_contains_limitations_and_no_secret_material(tmp_path):
    report = run_tenant_isolation_suite(tmp_path)
    encoded = json.dumps(report)
    assert "production database" not in encoded.lower()
    assert "password" not in encoded.lower()
    assert "PostgreSQL multi-tenant" in encoded
    markdown = render_markdown(report)
    assert "## Limitations" in markdown
    assert "tenant_summary_isolation" in markdown


def test_suite_restores_environment_after_execution(tmp_path, monkeypatch):
    monkeypatch.setenv("DATALINEAGE_DATABASE_URL", "postgresql://do-not-touch")
    monkeypatch.setenv("DATALINEAGE_SAAS_DB_PATH", str(tmp_path / "prior.sqlite"))
    before = {key: __import__("os").environ.get(key) for key in (
        "DATALINEAGE_DATABASE_URL", "DATALINEAGE_SAAS_DB_PATH", "DATALINEAGE_ACCESS_DB")}
    report = run_tenant_isolation_suite(tmp_path / "isolated")
    after = {key: __import__("os").environ.get(key) for key in before}
    assert report["status"] == "passed"
    assert after == before
