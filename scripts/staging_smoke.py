#!/usr/bin/env python3
"""Run authenticated HTTP and SQL-lineage smoke checks against a staging URL.

HTTPS is mandatory by default. Plain HTTP is permitted only for loopback hosts
when --allow-http is explicitly supplied. Credentials are read from environment
variables and are never written to the report or printed.
"""
from __future__ import annotations
import argparse
import http.cookiejar
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]


def _load_env(path: str | Path | None) -> dict[str, str]:
    values: dict[str, str] = {}
    if path:
        env_path = Path(path).expanduser()
        if env_path.is_file():
            try:
                from dotenv import dotenv_values
            except ImportError as exc:
                raise RuntimeError("python-dotenv is required to read the environment file") from exc
            values = {key: value for key, value in dotenv_values(env_path).items() if key and value is not None}
    values.update(os.environ)
    return values


def _decode_json(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"))
        return value if isinstance(value, dict) else {}
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}


def _validate_base_url(base_url: str, allow_http: bool) -> str:
    parsed = urllib.parse.urlsplit(base_url.strip())
    if parsed.username or parsed.password or parsed.query or parsed.fragment or not parsed.hostname:
        raise ValueError("--base-url must be an origin URL without credentials, query or fragment")
    if parsed.path not in ("", "/"):
        raise ValueError("--base-url must not include a path prefix")
    if parsed.scheme != "https":
        loopback = parsed.hostname.lower() in {"localhost", "127.0.0.1", "::1"}
        if not (allow_http and parsed.scheme == "http" and loopback):
            raise ValueError("HTTPS is required; --allow-http is limited to localhost/loopback testing")
    return f"{parsed.scheme}://{parsed.netloc}"


class HttpSession:
    def __init__(self, timeout: int = 8):
        self.timeout = timeout
        self.cookies = http.cookiejar.CookieJar()
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        self.opener = urllib.request.build_opener(
            NoRedirect(), urllib.request.HTTPCookieProcessor(self.cookies)
        )

    def request(self, method: str, url: str, payload: dict[str, Any] | None = None):
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Accept": "application/json", "User-Agent": "DataLineageAI-M63-StagingCheck/1.0"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        started = time.perf_counter()
        try:
            response = self.opener.open(request, timeout=self.timeout)
            raw = response.read(1_000_001)
            status = response.status
            response_headers = response.headers
        except urllib.error.HTTPError as exc:
            raw = exc.read(1_000_001)
            status = exc.code
            response_headers = exc.headers
        elapsed = round((time.perf_counter() - started) * 1000, 2)
        return status, _decode_json(raw), response_headers, elapsed


def run_smoke_test(
    base_url: str,
    *,
    username: str,
    password: str,
    allow_http: bool = False,
    timeout: int = 8,
    dialects: tuple[str, ...] = ("generic", "postgres", "snowflake", "databricks"),
    session: HttpSession | None = None,
) -> dict[str, Any]:
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 60:
        raise ValueError("timeout must be an integer from 1 to 60 seconds")
    if not isinstance(dialects, (tuple, list)) or not dialects or any(not isinstance(item, str) or not item.strip() for item in dialects):
        raise ValueError("at least one non-empty SQL dialect is required")
    if not isinstance(username, str) or not isinstance(password, str):
        raise ValueError("staging credentials must be strings")
    base = _validate_base_url(base_url, allow_http)
    client = session or HttpSession(timeout)
    checks: list[dict[str, Any]] = []

    def record(name: str, passed: bool, detail: str, latency_ms: float | None = None) -> bool:
        item: dict[str, Any] = {"name": name, "status": "passed" if passed else "failed", "detail": detail}
        if latency_ms is not None:
            item["latency_ms"] = latency_ms
        checks.append(item)
        return passed

    def call(method: str, path: str, payload: dict[str, Any] | None = None):
        return client.request(method, base + path, payload)

    try:
        status, body, _headers, latency = call("GET", "/health/live")
        if not record("liveness", status == 200 and body.get("status") == "alive",
                      "API process liveness endpoint", latency):
            raise RuntimeError("liveness check failed")

        status, body, _headers, latency = call("GET", "/health/ready")
        if not record("readiness", status == 200 and body.get("status") == "ready",
                      "API storage and rate-limit readiness endpoint", latency):
            raise RuntimeError("readiness check failed")

        status, auth_body, _headers, latency = call("GET", "/auth/status")
        auth_enabled = status == 200 and auth_body.get("enabled") is True
        if not record("authentication_enabled", auth_enabled,
                      "Authentication must be enabled for staging", latency):
            raise RuntimeError("authentication is disabled or auth status is unavailable")

        status, _body, _headers, latency = call("POST", "/api/v1/enterprise/lineage/sql", {
            "sql": "SELECT order_id, amount FROM raw.orders",
            "dialect": dialects[0] if dialects else "generic",
            "source_platform": "staging_source",
            "target_platform": "staging_target",
        })
        if not record("unauthenticated_api_denied", status == 401,
                      "Protected lineage API must reject requests without a session", latency):
            raise RuntimeError("protected API did not reject an unauthenticated request")

        if not username.strip() or not password:
            record("admin_login", False, "Staging username/password were not supplied")
            raise RuntimeError("staging credentials are required")

        status, login_body, headers, latency = call("POST", "/auth/login", {"username": username, "password": password})
        login_ok = status == 200 and login_body.get("status") == "authenticated" and len(client.cookies) > 0
        if not record("admin_login", login_ok, "Configured staging account login", latency):
            raise RuntimeError("staging login failed")
        if urllib.parse.urlsplit(base).scheme == "https":
            cookie_headers = headers.get_all("Set-Cookie") if hasattr(headers, "get_all") else [headers.get("Set-Cookie", "")]
            cookie_text = ";".join(item.lower() for item in cookie_headers if item)
            secure_cookie = ("secure" in cookie_text and "httponly" in cookie_text
                             and "samesite=strict" in cookie_text)
            if not record("secure_session_cookie", secure_cookie,
                          "HTTPS login response must set Secure, HttpOnly and SameSite=Strict"):
                raise RuntimeError("session cookie is missing Secure attribute")
        else:
            record("secure_session_cookie", True, "Not evaluated for explicitly allowed local HTTP")

        sql = "SELECT order_id, amount FROM raw.orders"
        for dialect in dialects:
            status, result, _headers, latency = call("POST", "/api/v1/enterprise/lineage/sql", {
                "sql": sql, "dialect": dialect,
                "source_platform": "staging_source", "target_platform": "staging_target",
            })
            valid = (status == 200 and result.get("analysis_mode") == "static_sql_ast"
                     and result.get("executed_sql") is False
                     and int(result.get("node_count", 0)) >= 2
                     and int(result.get("table_edge_count", 0)) >= 1)
            if not record(f"sql_lineage_{dialect}", valid,
                          "Authenticated static SQL lineage request; SQL must not be executed", latency):
                raise RuntimeError(f"SQL lineage smoke check failed for dialect {dialect}")

        status, logout_body, _headers, latency = call("POST", "/auth/logout")
        if not record("logout", status == 200 and logout_body.get("status") == "logged_out",
                      "Session logout endpoint", latency):
            raise RuntimeError("logout failed")
        status, _body, _headers, latency = call("POST", "/api/v1/enterprise/lineage/sql", {
            "sql": sql, "dialect": dialects[0] if dialects else "generic",
        })
        if not record("session_revoked_after_logout", status == 401,
                      "Protected API must reject the session after logout", latency):
            raise RuntimeError("session remained usable after logout")
    except Exception as exc:
        # Only exception class is retained, never URL, response body or credentials.
        if not any(item["status"] == "failed" for item in checks):
            record("smoke_execution", False, f"Smoke execution failed ({type(exc).__name__})")

    failures = [item for item in checks if item["status"] == "failed"]
    return {
        "milestone": "M63",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "failed" if failures else "passed",
        "checks": checks,
        "summary": {"passed": sum(item["status"] == "passed" for item in checks),
                    "failed": len(failures)},
        "security_notes": [
            "Credentials are supplied in-memory and are not recorded in the report.",
            "SQL lineage endpoint uses static parsing; the test verifies executed_sql is false.",
            "This smoke test does not establish tenant-to-tenant data isolation or high-concurrency capacity.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--env-file", default=str(ROOT / ".env"))
    parser.add_argument("--username", default=None)
    parser.add_argument("--password", default=None)
    parser.add_argument("--allow-http", action="store_true", help="Allow HTTP only for localhost/loopback")
    parser.add_argument("--timeout", type=int, default=8)
    parser.add_argument("--dialects", default="generic,postgres,snowflake,databricks")
    parser.add_argument("--json-out", default="M63_STAGING_SMOKE.json")
    parser.add_argument("--markdown-out", default="M63_STAGING_SMOKE.md")
    args = parser.parse_args()
    if not 1 <= args.timeout <= 60:
        parser.error("--timeout must be between 1 and 60 seconds")
    try:
        env = _load_env(args.env_file)
    except RuntimeError as exc:
        parser.error(str(exc))
    base_url = args.base_url or env.get("DATALINEAGE_PUBLIC_BASE_URL", "")
    username = args.username if args.username is not None else env.get("DATALINEAGE_AUTH_USERNAME", "")
    password = args.password if args.password is not None else env.get("DATALINEAGE_AUTH_PASSWORD", "")
    dialects = tuple(dict.fromkeys(x.strip().lower() for x in args.dialects.split(",") if x.strip()))
    if not dialects:
        parser.error("--dialects must contain at least one dialect")
    try:
        report = run_smoke_test(base_url, username=username, password=password,
                                allow_http=args.allow_http, timeout=args.timeout, dialects=dialects)
    except ValueError as exc:
        parser.error(str(exc))
    json_path = Path(args.json_out).expanduser().resolve()
    markdown_path = Path(args.markdown_out).expanduser().resolve()
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    lines = ["# DataLineage AI — M63 Staging HTTP Smoke Test", "",
             f"- Generated: `{report['generated_at_utc']}`", f"- Status: **{report['status']}**", "",
             "| Check | Status | Latency | Detail |", "|---|---|---:|---|"]
    for item in report["checks"]:
        latency = f"{item['latency_ms']} ms" if "latency_ms" in item else "—"
        lines.append(f"| {item['name']} | {item['status']} | {latency} | {item['detail']} |")
    lines.extend(["", "## Security notes", ""])
    lines.extend(f"- {item}" for item in report["security_notes"])
    markdown_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], **report["summary"],
                      "json_report": str(json_path), "markdown_report": str(markdown_path)}, indent=2))
    return 0 if report["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
