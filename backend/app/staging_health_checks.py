"""M63 live staging service probes for DataLineage AI.

Only performs read-only checks: PostgreSQL SELECT 1 and Redis PING. Reports never
include connection strings, hostnames, usernames, passwords, SQL or customer data.
"""
from __future__ import annotations

from datetime import datetime, timezone
import time
from typing import Any, Mapping


def probe_postgres(database_url: str, timeout_seconds: int = 3) -> dict[str, Any]:
    if not database_url.strip():
        return {"backend": "postgresql", "configured": False, "status": "not_configured"}
    started = time.perf_counter()
    connection = None
    try:
        import psycopg  # type: ignore
        connection = psycopg.connect(database_url, connect_timeout=max(1, min(int(timeout_seconds), 20)), autocommit=True)
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            row = cursor.fetchone()
        if not row or int(row[0]) != 1:
            raise RuntimeError("unexpected health query result")
        return {"backend": "postgresql", "configured": True, "status": "connected",
                "latency_ms": round((time.perf_counter() - started) * 1000, 2),
                "check": "SELECT 1"}
    except ImportError:
        return {"backend": "postgresql", "configured": True, "status": "driver_missing",
                "error_type": "ImportError"}
    except Exception as exc:
        return {"backend": "postgresql", "configured": True, "status": "unavailable",
                "latency_ms": round((time.perf_counter() - started) * 1000, 2),
                "error_type": type(exc).__name__}
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass


def probe_redis(redis_url: str, timeout_seconds: int = 3) -> dict[str, Any]:
    if not redis_url.strip():
        return {"backend": "redis", "configured": False, "status": "not_configured"}
    started = time.perf_counter()
    client = None
    try:
        import redis  # type: ignore
        client = redis.Redis.from_url(
            redis_url,
            socket_connect_timeout=max(1, min(int(timeout_seconds), 20)),
            socket_timeout=max(1, min(int(timeout_seconds), 20)),
            decode_responses=True,
        )
        if client.ping() is not True:
            raise RuntimeError("Redis PING did not return PONG")
        return {"backend": "redis", "configured": True, "status": "connected",
                "latency_ms": round((time.perf_counter() - started) * 1000, 2),
                "check": "PING"}
    except ImportError:
        return {"backend": "redis", "configured": True, "status": "driver_missing",
                "error_type": "ImportError"}
    except Exception as exc:
        return {"backend": "redis", "configured": True, "status": "unavailable",
                "latency_ms": round((time.perf_counter() - started) * 1000, 2),
                "error_type": type(exc).__name__}
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def build_service_report(
    environment: Mapping[str, str],
    *,
    require_postgres: bool = False,
    require_redis: bool = False,
    postgres_probe=probe_postgres,
    redis_probe=probe_redis,
    timeout_seconds: int = 3,
) -> dict[str, Any]:
    """Probe configured services and apply explicit required/optional gates."""
    env = dict(environment)
    pg_url = env.get("DATALINEAGE_DATABASE_URL", "")
    redis_url = env.get("DATALINEAGE_REDIS_URL", "")
    pg_required = require_postgres or env.get("DATALINEAGE_POSTGRES_REQUIRED", "").strip().lower() in {"1", "true", "yes"}
    redis_required = require_redis or env.get("DATALINEAGE_REDIS_REQUIRED", "").strip().lower() in {"1", "true", "yes"}

    postgres = postgres_probe(pg_url, timeout_seconds) if pg_url else {
        "backend": "postgresql", "configured": False, "status": "not_configured"}
    redis = redis_probe(redis_url, timeout_seconds) if redis_url else {
        "backend": "redis", "configured": False, "status": "not_configured"}

    blockers: list[str] = []
    warnings: list[str] = []
    for label, result, required in (
        ("PostgreSQL", postgres, pg_required),
        ("Redis", redis, redis_required),
    ):
        status = result.get("status")
        if status == "connected":
            continue
        if status == "not_configured":
            message = f"{label} is not configured"
        elif status == "driver_missing":
            message = f"{label} client driver is not installed"
        else:
            message = f"{label} connectivity check failed ({result.get('error_type', 'unknown error')})"
        (blockers if required else warnings).append(message)

    return {
        "milestone": "M63",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "blocked" if blockers else ("ready_with_warnings" if warnings else "ready"),
        "checks": {"postgresql": postgres, "redis": redis},
        "required": {"postgresql": bool(pg_required), "redis": bool(redis_required)},
        "blockers": blockers,
        "warnings": warnings,
        "limitations": [
            "PostgreSQL validation is a read-only connection and SELECT 1 check; it does not prove every application store uses PostgreSQL.",
            "Redis validation is a PING check; it does not validate worker consumption, persistence, failover or retention policy.",
            "This report does not validate backup restoration, SMTP delivery, cloud connectors or multi-replica safety.",
        ],
    }


def render_service_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# DataLineage AI — M63 Staging Service Checks", "",
        f"- Generated: `{report['generated_at_utc']}`",
        f"- Status: **{report['status']}**", "",
        "## Service checks", "",
        "| Service | Required | Status | Latency |", "|---|---:|---|---:|",
    ]
    for key, label in (("postgresql", "PostgreSQL"), ("redis", "Redis")):
        result = report["checks"][key]
        latency = f"{result['latency_ms']} ms" if "latency_ms" in result else "—"
        lines.append(f"| {label} | {'yes' if report['required'][key] else 'no'} | {result['status']} | {latency} |")
    for section in ("blockers", "warnings"):
        if report[section]:
            lines.extend(["", f"## {section.title()}", ""])
            lines.extend(f"- {item}" for item in report[section])
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {item}" for item in report["limitations"])
    lines.append("")
    return "\n".join(lines)
