from __future__ import annotations

import json
import importlib.util
from pathlib import Path

import pytest

from app import pilot_readiness as m62
from app.pilot_readiness import (
    evaluate_pilot_metrics,
    inspect_pilot_environment,
    render_environment_markdown,
    render_pilot_scorecard_markdown,
)

ROOT = Path(__file__).resolve().parents[2]


def valid_environment():
    return {
        "DATALINEAGE_ENVIRONMENT": "staging",
        "DATALINEAGE_AUTH_ENABLED": "true",
        "DATALINEAGE_AUTH_USERNAME": "pilot-admin",
        "DATALINEAGE_AUTH_PASSWORD": "pilot-admin-password-123",
        "DATALINEAGE_SESSION_SECRET": "a" * 48,
        "DATALINEAGE_SECURE_COOKIE": "true",
        "DATALINEAGE_PUBLIC_BASE_URL": "https://pilot.company.com",
        "DATALINEAGE_CORS_ORIGINS": "https://pilot.company.com",
        "DATALINEAGE_REPLICAS": "1",
        "DATALINEAGE_DATABASE_URL": "postgresql://private:secret@db.invalid/app",
        "DATALINEAGE_REDIS_URL": "redis://private:secret@cache.invalid/0",
        "DATALINEAGE_REDIS_REQUIRED": "true",
        "DATALINEAGE_EMAIL_DEV_MODE": "false",
        "DATALINEAGE_SMTP_HOST": "smtp.company.com",
        "DATALINEAGE_SMTP_PORT": "465",
        "DATALINEAGE_SMTP_FROM_EMAIL": "no-reply@company.com",
        "DATALINEAGE_SMTP_USERNAME": "smtp-user-secret",
        "DATALINEAGE_SMTP_PASSWORD": "smtp-password-secret",
        "DATALINEAGE_SMTP_SSL": "true",
        "DATALINEAGE_SMTP_STARTTLS": "false",
    }


def install_core_package_specs(monkeypatch):
    monkeypatch.setattr(m62.importlib.util, "find_spec", lambda name: object())


def valid_metrics():
    return {
        "pilot_label": "pilot-alpha",
        "period_days": 14,
        "expected_dependencies": 100,
        "detected_dependencies": 98,
        "true_positive_dependencies": 95,
        "false_positive_dependencies": 3,
        "baseline_review_minutes": 60,
        "pilot_review_minutes": 40,
        "active_users": 4,
        "invited_users": 5,
        "open_critical_issues": 0,
    }


def test_pilot_environment_report_never_exposes_secret_values(monkeypatch):
    install_core_package_specs(monkeypatch)
    env = valid_environment()
    report = inspect_pilot_environment(ROOT, env)
    serialized = json.dumps(report) + render_environment_markdown(report)
    assert "private:secret" not in serialized
    assert "a" * 48 not in serialized
    assert "smtp-password-secret" not in serialized
    assert "pilot-admin-password-123" not in serialized
    assert report["environment"]["postgres_configured"] is True
    assert report["environment"]["redis_configured"] is True
    assert all(item["status"] != "blocker" for item in report["checks"])


def test_pilot_environment_fails_closed_when_auth_or_https_missing(monkeypatch):
    install_core_package_specs(monkeypatch)
    env = valid_environment()
    env["DATALINEAGE_AUTH_ENABLED"] = "false"
    env["DATALINEAGE_PUBLIC_BASE_URL"] = "http://pilot.example.org"
    report = inspect_pilot_environment(ROOT, env)
    assert report["status"] == "blocked"
    assert any("authentication" in item.lower() for item in report["blockers"])
    assert any("HTTPS" in item for item in report["blockers"])


def test_pilot_environment_warns_for_single_replica_sqlite_without_redis(monkeypatch):
    install_core_package_specs(monkeypatch)
    env = valid_environment()
    env.pop("DATALINEAGE_DATABASE_URL")
    env.pop("DATALINEAGE_REDIS_URL")
    env["DATALINEAGE_REDIS_REQUIRED"] = "false"
    report = inspect_pilot_environment(ROOT, env)
    assert report["status"] == "ready_with_warnings"
    assert len(report["warnings"]) == 2


def test_pilot_environment_reports_missing_core_dependency_as_blocker(monkeypatch):
    original = m62.importlib.util.find_spec
    monkeypatch.setattr(m62.importlib.util, "find_spec", lambda name: None if name == "sqlglot" else original(name))
    report = inspect_pilot_environment(ROOT, valid_environment())
    assert report["status"] == "blocked"
    assert any("sqlglot" in item for item in report["blockers"])


def test_pilot_environment_rejects_non_postgres_and_non_redis_urls(monkeypatch):
    install_core_package_specs(monkeypatch)
    env = valid_environment()
    env["DATALINEAGE_DATABASE_URL"] = "mysql://user:secret@db.invalid/app"
    env["DATALINEAGE_REDIS_URL"] = "http://cache.invalid"
    report = inspect_pilot_environment(ROOT, env)
    assert report["status"] == "blocked"
    assert any("PostgreSQL URL scheme" in item for item in report["blockers"])
    assert any("redis://" in item for item in report["blockers"])


def test_scorecard_reports_expansion_candidate_when_all_gates_pass():
    report = evaluate_pilot_metrics(valid_metrics())
    assert report["status"] == "expansion_candidate"
    assert report["metrics"]["dependency_recall"] == 0.95
    assert report["metrics"]["missed_dependencies"] == 5
    assert report["metrics"]["dependency_precision"] == pytest.approx(95 / 98, abs=0.00002)
    assert report["metrics"]["false_discovery_rate"] == pytest.approx(3 / 98, abs=0.00002)
    assert all(gate["passed"] for gate in report["gates"].values())
    assert "Expansion Candidate" in render_pilot_scorecard_markdown(report)


def test_scorecard_holds_when_critical_issue_open():
    payload = valid_metrics()
    payload["open_critical_issues"] = 1
    report = evaluate_pilot_metrics(payload)
    assert report["status"] == "hold"
    assert report["gates"]["open_critical_issues"]["passed"] is False


def test_scorecard_iterates_when_quality_or_adoption_gate_fails():
    payload = valid_metrics()
    payload["true_positive_dependencies"] = 70
    payload["false_positive_dependencies"] = 28
    payload["active_users"] = 1
    report = evaluate_pilot_metrics(payload)
    assert report["status"] == "iterate"
    assert report["gates"]["dependency_recall"]["passed"] is False
    assert report["gates"]["user_activation_rate"]["passed"] is False


@pytest.mark.parametrize("field,value", [
    ("period_days", 0), ("expected_dependencies", 0), ("invited_users", 0),
    ("active_users", -1), ("open_critical_issues", True),
])
def test_scorecard_rejects_invalid_integer_metrics(field, value):
    payload = valid_metrics()
    payload[field] = value
    with pytest.raises(ValueError):
        evaluate_pilot_metrics(payload)


@pytest.mark.parametrize("field,value", [
    ("baseline_review_minutes", 0), ("pilot_review_minutes", float("nan")),
    ("baseline_review_minutes", True),
])
def test_scorecard_rejects_invalid_review_times(field, value):
    payload = valid_metrics()
    payload[field] = value
    with pytest.raises(ValueError):
        evaluate_pilot_metrics(payload)


def test_scorecard_rejects_inconsistent_dependency_counts():
    payload = valid_metrics()
    payload["true_positive_dependencies"] = 96
    payload["false_positive_dependencies"] = 3
    payload["detected_dependencies"] = 98
    with pytest.raises(ValueError, match="must equal detected"):
        evaluate_pilot_metrics(payload)


def test_scorecard_rejects_unreviewed_detected_dependencies():
    payload = valid_metrics()
    payload["detected_dependencies"] += 1
    with pytest.raises(ValueError, match="must equal detected"):
        evaluate_pilot_metrics(payload)


def test_scorecard_accepts_customer_agreed_threshold_overrides():
    report = evaluate_pilot_metrics(valid_metrics(), {"minimum_dependency_precision": 0.90})
    assert report["status"] == "expansion_candidate"
    assert report["gates"]["dependency_precision"]["minimum"] == 0.90


def test_scorecard_rejects_unknown_thresholds():
    with pytest.raises(ValueError, match="Unknown threshold"):
        evaluate_pilot_metrics(valid_metrics(), {"magic_metric": 0.5})


def test_pilot_readiness_loader_merges_env_file_and_process_environment(tmp_path):
    script = ROOT / "scripts" / "pilot_readiness.py"
    spec = importlib.util.spec_from_file_location("pilot_readiness_cli", script)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    env_file = tmp_path / ".env"
    env_file.write_text("DATALINEAGE_AUTH_ENABLED=false\nDATALINEAGE_SESSION_SECRET=file-secret-value\n", encoding="utf-8")
    loaded = module.load_environment(env_file, {"DATALINEAGE_AUTH_ENABLED": "true", "EXTRA_FLAG": "yes"})
    assert loaded["DATALINEAGE_AUTH_ENABLED"] == "true"
    assert loaded["DATALINEAGE_SESSION_SECRET"] == "file-secret-value"
    assert loaded["EXTRA_FLAG"] == "yes"


def test_pilot_cli_scripts_compile():
    for script in (ROOT / "scripts" / "pilot_readiness.py", ROOT / "scripts" / "evaluate_pilot.py"):
        spec = importlib.util.spec_from_file_location(script.stem, script)
        assert spec is not None and spec.loader is not None
        assert script.is_file()
