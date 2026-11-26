"""Milestone 62: safe pilot diagnostics and evidence-based pilot scorecards.

Diagnostics deliberately report configuration presence/booleans, never secret
values, database URLs, SQL text, connector payloads, or customer records.
"""
from __future__ import annotations

import importlib.util
import math
import os
import platform
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

CORE_PACKAGES = ("fastapi", "uvicorn", "pydantic", "sqlglot", "networkx", "cryptography")
OPTIONAL_PACKAGES = ("psycopg", "redis", "firebase_admin", "boto3", "azure.identity", "azure.mgmt.datafactory")
REQUIRED_PATHS = (
    "backend/app/main.py",
    "backend/requirements.txt",
    "frontend/index.html",
    "scripts/deployment_preflight.py",
)
DEFAULT_THRESHOLDS = {
    "minimum_dependency_recall": 0.90,
    "minimum_dependency_precision": 0.95,
    "minimum_review_time_reduction": 0.20,
    "minimum_user_activation_rate": 0.50,
    "maximum_open_critical_issues": 0,
}


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def inspect_pilot_environment(
    project_root: str | Path,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Inspect a staging/pilot setup without exposing environment values."""
    env = os.environ if environ is None else environ
    root = Path(project_root).resolve()
    blockers: list[str] = []
    warnings: list[str] = []
    checks: list[dict[str, Any]] = []

    def add(name: str, passed: bool, detail: str, severity: str = "blocker") -> None:
        checks.append({"name": name, "status": "pass" if passed else severity, "detail": detail})
        if not passed:
            (blockers if severity == "blocker" else warnings).append(detail)

    environment = str(env.get("DATALINEAGE_ENVIRONMENT", "")).strip().lower()
    add("deployment_environment", environment in {"staging", "production"},
        "Deployment environment is staging/production." if environment in {"staging", "production"}
        else "Set DATALINEAGE_ENVIRONMENT to staging or production before an external pilot.")

    auth_enabled = _truthy(env.get("DATALINEAGE_AUTH_ENABLED"))
    add("authentication", auth_enabled,
        "Application authentication is enabled." if auth_enabled
        else "Authentication is disabled; enable DATALINEAGE_AUTH_ENABLED before exposing a pilot environment.")
    auth_username = str(env.get("DATALINEAGE_AUTH_USERNAME", "")).strip()
    add("bootstrap_admin_username", bool(auth_username),
        "A bootstrap administrator username is configured." if auth_username
        else "Set DATALINEAGE_AUTH_USERNAME for the initial administrator account.")
    auth_password = str(env.get("DATALINEAGE_AUTH_PASSWORD", ""))
    auth_password_ok = len(auth_password) >= 16 and not any(
        marker in auth_password.lower() for marker in ("change_me", "replace_with", "example")
    )
    add("bootstrap_admin_password", auth_password_ok,
        "A non-placeholder bootstrap administrator password is configured." if auth_password_ok
        else "Set a unique, non-placeholder DATALINEAGE_AUTH_PASSWORD of at least 16 characters.")

    secret = str(env.get("DATALINEAGE_SESSION_SECRET", ""))
    secret_ok = len(secret.encode("utf-8")) >= 32 and not any(
        marker in secret.lower() for marker in ("change_me", "replace_with", "example")
    )
    add("session_secret", secret_ok,
        "A non-placeholder session secret of at least 32 bytes is configured." if secret_ok
        else "Set a unique, non-placeholder DATALINEAGE_SESSION_SECRET of at least 32 bytes.")

    secure_cookie = _truthy(env.get("DATALINEAGE_SECURE_COOKIE"))
    add("secure_cookie", secure_cookie,
        "Secure session cookies are enabled." if secure_cookie
        else "Set DATALINEAGE_SECURE_COOKIE=true for HTTPS pilot access.")

    base_url = str(env.get("DATALINEAGE_PUBLIC_BASE_URL", "")).strip()
    parsed_base = urlparse(base_url)
    url_placeholders = ("example.com", ".example", "your-domain", "replace_with", "localhost", "127.0.0.1")
    https_base = (parsed_base.scheme == "https" and bool(parsed_base.hostname)
                  and parsed_base.username is None and parsed_base.password is None
                  and not any(marker in base_url.lower() for marker in url_placeholders))
    add("public_https_url", https_base,
        "A public HTTPS base URL is configured." if https_base
        else "Set DATALINEAGE_PUBLIC_BASE_URL to the pilot's real HTTPS URL.")

    origins = [item.strip() for item in str(env.get("DATALINEAGE_CORS_ORIGINS", "")).split(",") if item.strip()]
    cors_ok = bool(origins) and all(
        urlparse(item).scheme == "https" and bool(urlparse(item).hostname)
        and urlparse(item).path in ("", "/") and not urlparse(item).query
        and not urlparse(item).fragment and urlparse(item).username is None
        and urlparse(item).password is None and "*" not in item
        and not any(marker in item.lower() for marker in url_placeholders)
        for item in origins
    )
    add("cors_origins", cors_ok,
        "Explicit HTTPS CORS origins are configured." if cors_ok
        else "Configure DATALINEAGE_CORS_ORIGINS with explicit HTTPS origins only; no wildcard.")

    email_dev_mode = _truthy(env.get("DATALINEAGE_EMAIL_DEV_MODE", "true"))
    add("email_delivery_mode", not email_dev_mode,
        "Development email mode is disabled." if not email_dev_mode
        else "Set DATALINEAGE_EMAIL_DEV_MODE=false and configure a real mail provider before an external pilot.")
    smtp_host = str(env.get("DATALINEAGE_SMTP_HOST", "")).strip()
    smtp_from = str(env.get("DATALINEAGE_SMTP_FROM_EMAIL", "")).strip()
    smtp_placeholders = ("replace_with", "your-provider", "your-domain", ".example")
    smtp_configured = bool(smtp_host and smtp_from) and not any(
        marker in (smtp_host + " " + smtp_from).lower() for marker in smtp_placeholders
    )
    add("smtp_provider", smtp_configured,
        "SMTP host and sender address are configured." if smtp_configured
        else "Configure DATALINEAGE_SMTP_HOST and DATALINEAGE_SMTP_FROM_EMAIL with real provider values.")
    try:
        smtp_port = int(str(env.get("DATALINEAGE_SMTP_PORT", "587")))
        smtp_port_ok = 1 <= smtp_port <= 65535
    except ValueError:
        smtp_port_ok = False
    add("smtp_port", smtp_port_ok,
        "SMTP port is in the valid TCP port range." if smtp_port_ok
        else "DATALINEAGE_SMTP_PORT must be an integer between 1 and 65535.")
    smtp_ssl = _truthy(env.get("DATALINEAGE_SMTP_SSL"))
    smtp_starttls = _truthy(env.get("DATALINEAGE_SMTP_STARTTLS"))
    add("smtp_transport_security", smtp_ssl != smtp_starttls,
        "Exactly one SMTP transport security mode is enabled." if smtp_ssl != smtp_starttls
        else "Enable exactly one of DATALINEAGE_SMTP_SSL or DATALINEAGE_SMTP_STARTTLS.")
    smtp_username = str(env.get("DATALINEAGE_SMTP_USERNAME", ""))
    smtp_password = str(env.get("DATALINEAGE_SMTP_PASSWORD", ""))
    add("smtp_credentials", bool(smtp_username) == bool(smtp_password),
        "SMTP credentials are either both configured or both omitted." if bool(smtp_username) == bool(smtp_password)
        else "Configure both DATALINEAGE_SMTP_USERNAME and DATALINEAGE_SMTP_PASSWORD, or leave both empty.")

    try:
        replicas = int(str(env.get("DATALINEAGE_REPLICAS", "1")))
    except ValueError:
        replicas = 0
    add("replica_count", replicas == 1,
        "A single application replica is selected." if replicas == 1
        else "Use one application replica for this pilot; multi-replica readiness is not established.")

    db_url = str(env.get("DATALINEAGE_DATABASE_URL", "")).strip()
    parsed_db = urlparse(db_url)
    db_scheme = parsed_db.scheme.lower() if db_url else ""
    db_configured = db_scheme in {"postgres", "postgresql"} and bool(parsed_db.hostname)
    if db_url and not db_configured:
        add("database_backend", False, "DATALINEAGE_DATABASE_URL must use a PostgreSQL URL scheme (postgres:// or postgresql://).")
    else:
        add("database_backend", db_configured,
            "PostgreSQL connection URL is configured (connectivity not tested)." if db_configured
            else "SQLite is selected; keep this pilot to one replica and use durable storage.", "warning")

    redis_url = str(env.get("DATALINEAGE_REDIS_URL", "")).strip()
    parsed_redis = urlparse(redis_url)
    redis_scheme = parsed_redis.scheme.lower() if redis_url else ""
    redis_configured = redis_scheme in {"redis", "rediss"} and bool(parsed_redis.hostname)
    redis_required = _truthy(env.get("DATALINEAGE_REDIS_REQUIRED"))
    if redis_url and not redis_configured:
        add("redis_backend", False, "DATALINEAGE_REDIS_URL must use redis:// or rediss://.")
    elif redis_required and not redis_configured:
        add("redis_backend", False, "Redis is required but DATALINEAGE_REDIS_URL is not configured.")
    else:
        add("redis_backend", redis_configured,
            "Redis connection URL is configured (connectivity not tested)." if redis_configured
            else "Redis is not configured; verify that this single-process pilot does not depend on distributed workers/rate limits.",
            "warning" if not redis_configured else "blocker")

    for rel in REQUIRED_PATHS:
        present = (root / rel).is_file()
        add(f"project_file:{rel}", present,
            f"Required project file is present: {rel}." if present else f"Required project file is missing: {rel}.")

    package_results: dict[str, bool] = {}
    for package in CORE_PACKAGES:
        try:
            available = importlib.util.find_spec(package) is not None
        except (ImportError, ModuleNotFoundError, ValueError):
            available = False
        package_results[package] = available
        add(f"python_package:{package}", available,
            f"Core package is available: {package}." if available
            else f"Install backend/requirements.txt; core package is missing: {package}.")

    optional_results: dict[str, bool] = {}
    for package in OPTIONAL_PACKAGES:
        try:
            available = importlib.util.find_spec(package) is not None
        except (ImportError, ModuleNotFoundError, ValueError):
            available = False
        optional_results[package] = available

    status = "blocked" if blockers else ("ready_with_warnings" if warnings else "ready")
    return {
        "report": "datalineage_m62_pilot_environment",
        "status": status,
        "environment": {
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "deployment_environment": environment or "unset",
            "authentication_enabled": auth_enabled,
            "bootstrap_admin_username_configured": bool(auth_username),
            "bootstrap_admin_password_configured": bool(auth_password),
            "session_secret_configured": bool(secret),
            "email_dev_mode": email_dev_mode,
            "smtp_configured": smtp_configured,
            "secure_cookie_enabled": secure_cookie,
            "https_base_url_configured": https_base,
            "postgres_configured": db_configured,
            "redis_configured": redis_configured,
            "replicas": replicas,
        },
        "core_packages": package_results,
        "optional_packages": optional_results,
        "checks": checks,
        "blockers": blockers,
        "warnings": warnings,
        "security_note": "This report intentionally excludes secret values, connection strings, SQL text and customer records.",
    }


def evaluate_pilot_metrics(payload: Mapping[str, Any], thresholds: Mapping[str, float] | None = None) -> dict[str, Any]:
    """Calculate pilot outcome metrics and explicit expansion gates."""
    if not isinstance(payload, Mapping):
        raise ValueError("Pilot metrics must be a JSON object")
    required_ints = (
        "period_days", "expected_dependencies", "detected_dependencies",
        "true_positive_dependencies", "false_positive_dependencies",
        "active_users", "invited_users", "open_critical_issues",
    )
    values: dict[str, int] = {}
    for field in required_ints:
        value = payload.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"{field} must be a non-negative integer")
        values[field] = value
    for field in ("period_days", "expected_dependencies", "invited_users"):
        if values[field] < 1:
            raise ValueError(f"{field} must be at least 1")

    baseline = payload.get("baseline_review_minutes")
    pilot = payload.get("pilot_review_minutes")
    for field, value in (("baseline_review_minutes", baseline), ("pilot_review_minutes", pilot)):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
            raise ValueError(f"{field} must be a positive finite number")

    if values["active_users"] > values["invited_users"]:
        raise ValueError("active_users cannot exceed invited_users")
    if values["true_positive_dependencies"] > values["expected_dependencies"]:
        raise ValueError("true_positive_dependencies cannot exceed expected_dependencies")
    if values["true_positive_dependencies"] + values["false_positive_dependencies"] != values["detected_dependencies"]:
        raise ValueError("true positives plus false positives must equal detected dependencies so every detection is reviewer-classified")

    t = dict(DEFAULT_THRESHOLDS)
    if thresholds:
        unknown = set(thresholds) - set(t)
        if unknown:
            raise ValueError(f"Unknown threshold(s): {', '.join(sorted(unknown))}")
        t.update(thresholds)
    for key in ("minimum_dependency_recall", "minimum_dependency_precision", "minimum_review_time_reduction", "minimum_user_activation_rate"):
        value = t[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= 1:
            raise ValueError(f"{key} must be a number between 0 and 1")
    if isinstance(t["maximum_open_critical_issues"], bool) or not isinstance(t["maximum_open_critical_issues"], int) or t["maximum_open_critical_issues"] < 0:
        raise ValueError("maximum_open_critical_issues must be a non-negative integer")

    detected = values["detected_dependencies"]
    true_positive = values["true_positive_dependencies"]
    recall = true_positive / values["expected_dependencies"]
    precision = true_positive / detected if detected else 0.0
    false_discovery_rate = values["false_positive_dependencies"] / detected if detected else 0.0
    time_reduction = (float(baseline) - float(pilot)) / float(baseline)
    activation = values["active_users"] / values["invited_users"]

    gates = {
        "dependency_recall": {"actual": round(recall, 4), "minimum": t["minimum_dependency_recall"], "passed": recall >= t["minimum_dependency_recall"]},
        "dependency_precision": {"actual": round(precision, 4), "minimum": t["minimum_dependency_precision"], "passed": precision >= t["minimum_dependency_precision"]},
        "review_time_reduction": {"actual": round(time_reduction, 4), "minimum": t["minimum_review_time_reduction"], "passed": time_reduction >= t["minimum_review_time_reduction"]},
        "user_activation_rate": {"actual": round(activation, 4), "minimum": t["minimum_user_activation_rate"], "passed": activation >= t["minimum_user_activation_rate"]},
        "open_critical_issues": {"actual": values["open_critical_issues"], "maximum": t["maximum_open_critical_issues"], "passed": values["open_critical_issues"] <= t["maximum_open_critical_issues"]},
    }
    if not gates["open_critical_issues"]["passed"]:
        status = "hold"
        recommendation = "Do not expand the pilot while critical issues remain open; resolve and retest them first."
    elif all(item["passed"] for item in gates.values()):
        status = "expansion_candidate"
        recommendation = "The measured pilot gates passed. Review qualitative feedback, security approval and support capacity before expanding."
    else:
        status = "iterate"
        failed = [name for name, item in gates.items() if not item["passed"]]
        recommendation = "Run another focused iteration against the failed gates: " + ", ".join(failed) + "."

    label = str(payload.get("pilot_label", "pilot-unlabelled")).strip()[:80] or "pilot-unlabelled"
    return {
        "report": "datalineage_m62_pilot_scorecard",
        "pilot_label": label,
        "period_days": values["period_days"],
        "status": status,
        "metrics": {
            "dependency_recall": round(recall, 4),
            "dependency_precision": round(precision, 4),
            "false_discovery_rate": round(false_discovery_rate, 4),
            "review_time_reduction": round(time_reduction, 4),
            "user_activation_rate": round(activation, 4),
            "expected_dependencies": values["expected_dependencies"],
            "detected_dependencies": detected,
            "true_positive_dependencies": true_positive,
            "false_positive_dependencies": values["false_positive_dependencies"],
            "missed_dependencies": values["expected_dependencies"] - true_positive,
            "baseline_review_minutes": float(baseline),
            "pilot_review_minutes": float(pilot),
            "active_users": values["active_users"],
            "invited_users": values["invited_users"],
            "open_critical_issues": values["open_critical_issues"],
        },
        "gates": gates,
        "recommendation": recommendation,
        "interpretation": "This scorecard measures only the supplied curated pilot sample and usage metrics. It is not a guarantee of complete lineage, production readiness, security certification or commercial success.",
    }


def render_pilot_scorecard_markdown(report: Mapping[str, Any]) -> str:
    metrics = report["metrics"]
    lines = [
        "# DataLineage AI — Pilot Scorecard", "",
        f"- Pilot: `{report['pilot_label']}`",
        f"- Period: {report['period_days']} days",
        f"- Outcome: **{str(report['status']).replace('_', ' ').title()}**", "",
        "## Measured results", "",
        "| Metric | Result |", "|---|---:|",
        f"| Dependency recall | {metrics['dependency_recall']:.1%} |",
        f"| Dependency precision | {metrics['dependency_precision']:.1%} |",
        f"| False-discovery rate | {metrics['false_discovery_rate']:.1%} |",
        f"| Review-time reduction | {metrics['review_time_reduction']:.1%} |",
        f"| User activation | {metrics['user_activation_rate']:.1%} |",
        f"| Open critical issues | {metrics['open_critical_issues']} |", "",
        "## Expansion gates", "",
        "| Gate | Actual | Requirement | Result |", "|---|---:|---:|---|",
    ]
    for name, gate in report["gates"].items():
        requirement = f"≤ {gate['maximum']}" if "maximum" in gate else f"≥ {gate['minimum']:.1%}"
        actual = f"{gate['actual']}" if name == "open_critical_issues" else f"{gate['actual']:.1%}"
        lines.append(f"| {name.replace('_', ' ').title()} | {actual} | {requirement} | {'Pass' if gate['passed'] else 'Fail'} |")
    lines.extend(["", "## Recommendation", "", report["recommendation"], "", "## Interpretation", "", report["interpretation"], ""])
    return "\n".join(lines)


def render_environment_markdown(report: Mapping[str, Any]) -> str:
    env = report["environment"]
    lines = [
        "# DataLineage AI — Pilot Environment Readiness", "",
        f"- Status: **{str(report['status']).replace('_', ' ').title()}**",
        f"- Environment: `{env['deployment_environment']}`",
        f"- Python: `{env['python_version']}`",
        f"- Platform: `{env['platform']}`", "",
        "## Checks", "", "| Check | Status | Detail |", "|---|---|---|",
    ]
    for item in report["checks"]:
        detail = item["detail"].replace("|", "\\|")
        lines.append(f"| {item['name']} | {item['status']} | {detail} |")
    lines.extend(["", "## Blockers", ""])
    lines.extend([f"- {item}" for item in report["blockers"]] or ["- None."])
    lines.extend(["", "## Warnings", ""])
    lines.extend([f"- {item}" for item in report["warnings"]] or ["- None."])
    lines.extend(["", f"> {report['security_note']}", ""])
    return "\n".join(lines)
