from __future__ import annotations

from pathlib import Path
import re
import os
from typing import Any
from uuid import uuid4
from datetime import datetime, timezone
import hashlib, hmac, json
from fastapi import FastAPI, File, Form, HTTPException, UploadFile, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi import Query

from .analyzer import analyze_sql_files
from .auth import COOKIE_NAME, auth_configuration_error, production_configuration_error, create_session, credentials_valid, verify_session
from .user_store import (authenticate_user, create_user, issue_token, create_token_for_existing_user, consume_verification_token, consume_password_reset, user_is_verified)
from .rate_limit import (login_retry_after, record_login_failure, clear_login_failures,
                         signup_retry_after, record_signup_attempt, token_retry_after, record_token_attempt,
                         action_retry_after, record_action_attempt, consume_shared_limit, rate_limit_backend_status)
from .config import settings
from .email_delivery import email_configuration_error, send_action_email, EmailDeliveryError
from .payments import PRICING, PLAN_NAMES, create_subscription as create_razorpay_subscription, PaymentConfigurationError
from .ingestion import SQLFile, read_uploads
from .schema_analyzer import analyze_schema_change
from .sql_change_intelligence import compare_sql_changes, validate_dataset_snapshots
from .pipeline_integrations import (analyze_adf_pipeline, analyze_databricks_notebook, analyze_sql_text, compare_delta_schemas, build_cross_platform_lineage)
from .github_integration import (github_configuration, github_get, github_api_request, github_api_pages, decode_github_content, validate_repo, validate_branch, validate_pr_number, compare_sql_file, build_pr_impact, verify_webhook_signature, accept_webhook_delivery, classify_file_changes, verify_ci_bearer)
from .run_store import (
    compare_analysis_runs, get_analysis_run, list_analysis_runs,
    save_analysis_run, validate_project_name, check_store, create_project,
    list_projects, get_project, database_backend,
)
from .api_key_authentication import authenticate_authorization_header as m43_authenticate_api_key, api_key_path_allowed as m43_api_key_path_allowed, tenant_principal as m43_tenant_principal

app = FastAPI(
    title=settings.app_name,
    version="0.6.0",
    description="SQL lineage, schema impact, and authenticated multi-account local analysis",
)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
FRONTEND_FILE = PROJECT_ROOT / "frontend" / "index.html"


@app.get("/", include_in_schema=False)
def serve_frontend():
    if not FRONTEND_FILE.is_file():
        raise HTTPException(status_code=404, detail="Frontend index.html was not found")
    return FileResponse(FRONTEND_FILE)


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Request-ID", "X-Organization-ID"],
)


@app.middleware("http")
async def security_and_request_middleware(request, call_next):
    """Apply security headers consistently and enforce request/deployment guards."""
    request_id = request.headers.get("x-request-id", "").strip()
    if not request_id or len(request_id) > 100 or any(ord(ch) < 32 for ch in request_id):
        request_id = str(uuid4())

    def secure_response(response):
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'self'"
        if request.url.path.startswith("/auth/") or request.url.path.startswith("/api/v1/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    # A misconfigured production deployment must not serve the app or APIs. Keep
    # liveness available for orchestration; readiness and all other paths fail closed.
    if settings.app_environment == "production" and request.url.path not in {"/health", "/health/live"}:
        if production_configuration_error():
            return secure_response(JSONResponse(status_code=503, content={
                "detail": "Production security configuration is incomplete",
            }))

    # Gate every API endpoint, including stateless schema-impact analysis.
    if settings.auth_enabled and request.url.path.startswith("/api/v1/"):
        config_error = auth_configuration_error()
        if config_error:
            return secure_response(JSONResponse(status_code=503, content={"detail": "Authentication is enabled but not configured correctly"}))
        session_user = verify_session(request.cookies.get(COOKIE_NAME))
        ci_token_ok = request.url.path.startswith("/api/v1/github/") and verify_ci_bearer(request.headers.get("authorization"))
        api_key_principal = None
        if session_user is None and request.url.path.startswith("/api/v1/enterprise/"):
            # API keys are deliberately excluded from security administration endpoints.
            if not request.url.path.startswith("/api/v1/enterprise/security"):
                api_key_record = m43_authenticate_api_key(request.headers.get("authorization"))
                if api_key_record and m43_api_key_path_allowed(
                    request.url.path, request.method, api_key_record.get("role", "")
                ):
                    api_key_principal = m43_tenant_principal(api_key_record)
                    request.state.api_key_principal = api_key_principal
                elif api_key_record:
                    return secure_response(JSONResponse(status_code=403, content={"detail": "API key role does not permit this operation"}))
        if session_user is None and not ci_token_ok and api_key_principal is None:
            return secure_response(JSONResponse(status_code=401, content={"detail": "Authentication required"}))

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            declared_length = int(content_length)
        except ValueError:
            return secure_response(JSONResponse(status_code=400, content={"detail": "Invalid Content-Length header", "request_id": request_id}))
        if declared_length < 0:
            return secure_response(JSONResponse(status_code=400, content={"detail": "Invalid Content-Length header", "request_id": request_id}))
        if declared_length > settings.max_request_bytes:
            return secure_response(JSONResponse(status_code=413, content={
                "detail": "Request body exceeds the configured size limit",
            }))

    response = await call_next(request)
    return secure_response(response)


@app.get("/auth/status")
def auth_status(request: Request) -> dict[str, Any]:
    """Tell the local frontend whether login is required and whether this browser is signed in."""
    enabled = settings.auth_enabled
    user = verify_session(request.cookies.get(COOKIE_NAME)) if enabled else None
    return {"enabled": enabled, "authenticated": bool(user), "username": user}


def _session_response(identity: str, role: str) -> JSONResponse:
    token = create_session(identity)
    response = JSONResponse(content={"status": "authenticated", "email": identity, "role": role})
    response.set_cookie(
        key=COOKIE_NAME, value=token, max_age=settings.session_ttl_seconds,
        httponly=True, secure=settings.secure_cookie, samesite="strict", path="/",
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/auth/signup")
def auth_signup(payload: dict[str, Any], request: Request) -> JSONResponse:
    """Create an unverified account and send its one-time email verification link."""
    if not settings.auth_enabled:
        raise HTTPException(status_code=400, detail="Authentication must be enabled before signup")
    config_error = auth_configuration_error()
    if config_error:
        raise HTTPException(status_code=503, detail="Authentication is not configured correctly")
    email, password = payload.get("email"), payload.get("password")
    if not isinstance(email, str) or not isinstance(password, str):
        raise HTTPException(status_code=422, detail="email and password must be strings")
    delivery_error = email_configuration_error()
    if delivery_error:
        raise HTTPException(status_code=503, detail=delivery_error)
    client_ip = request.client.host if request.client else "unknown"
    retry_after = consume_shared_limit(client_ip, 10, 60, "signup")
    if retry_after:
        raise HTTPException(status_code=429, detail="Too many signup attempts. Try again later.", headers={"Retry-After": str(retry_after)})
    try:
        user = create_user(email, password)
        raw_token, _ = issue_token(user["email"], "verify_email", settings.verification_ttl_seconds)
        url = f"{settings.public_base_url}/#verify_token={raw_token}"
        send_action_email(user["email"], "Verify your DataLineage AI email", url, "verify your email address")
        result: dict[str, Any] = {"status": "verification_required", "message": "Account created. Check your email for a verification link before signing in."}
        if settings.email_dev_mode and settings.app_environment == "development":
            result["development_url"] = url
        response = JSONResponse(status_code=202, content=result)
        response.headers["Cache-Control"] = "no-store"
        return response
    except ValueError as exc:
        raise HTTPException(status_code=409 if "already exists" in str(exc) else 422, detail=str(exc)) from exc
    except EmailDeliveryError as exc:
        # The account remains unverified; the resend endpoint can issue a fresh link after delivery is fixed.
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=500, detail="Could not create account in local storage") from exc


@app.post("/auth/verification/request")
def request_verification(payload: dict[str, Any], request: Request) -> JSONResponse:
    if not settings.auth_enabled:
        raise HTTPException(status_code=400, detail="Authentication is disabled")
    delivery_error = email_configuration_error()
    if delivery_error:
        raise HTTPException(status_code=503, detail=delivery_error)
    client_ip = request.client.host if request.client else "unknown"
    key = f"verify:{client_ip}"
    retry_after = consume_shared_limit(key, 5, 300, "token")
    if retry_after:
        raise HTTPException(status_code=429, detail="Too many requests. Try again later.", headers={"Retry-After": str(retry_after)})
    email = payload.get("email")
    result: dict[str, Any] = {"message": "If the account exists and needs verification, a verification email will be attempted. If it does not arrive, try again later."}
    if isinstance(email, str):
        issued = create_token_for_existing_user(email, "verify_email", settings.verification_ttl_seconds)
        if issued:
            raw_token, _ = issued
            url = f"{settings.public_base_url}/#verify_token={raw_token}"
            try:
                send_action_email(email.strip().lower(), "Verify your DataLineage AI email", url, "verify your email address")
            except EmailDeliveryError:
                # Keep the response identical for existing and unknown addresses.
                # The generic message does not claim delivery succeeded.
                pass
            if settings.email_dev_mode and settings.app_environment == "development":
                result["development_url"] = url
    response = JSONResponse(status_code=202, content=result)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/auth/verify-email")
def verify_email_endpoint(payload: dict[str, Any], request: Request) -> JSONResponse:
    client_ip = request.client.host if request.client else "unknown"
    key = f"verify-complete:{client_ip}"
    retry_after = consume_shared_limit(key, 5, 300, "token")
    if retry_after:
        raise HTTPException(status_code=429, detail="Too many verification attempts. Try again later.", headers={"Retry-After": str(retry_after)})
    token = payload.get("token")
    if not isinstance(token, str) or not consume_verification_token(token):
        raise HTTPException(status_code=400, detail="Verification link is invalid, expired, or already used.")
    response = JSONResponse(content={"status": "verified", "message": "Email verified. You can now sign in."})
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/auth/password-reset/request")
def request_password_reset(payload: dict[str, Any], request: Request) -> JSONResponse:
    if not settings.auth_enabled:
        raise HTTPException(status_code=400, detail="Authentication is disabled")
    delivery_error = email_configuration_error()
    if delivery_error:
        raise HTTPException(status_code=503, detail=delivery_error)
    client_ip = request.client.host if request.client else "unknown"
    key = f"reset:{client_ip}"
    retry_after = consume_shared_limit(key, 5, 300, "token")
    if retry_after:
        raise HTTPException(status_code=429, detail="Too many requests. Try again later.", headers={"Retry-After": str(retry_after)})
    email = payload.get("email")
    result: dict[str, Any] = {"message": "If a verified account exists, a password-reset email will be attempted. If it does not arrive, try again later."}
    if isinstance(email, str):
        issued = create_token_for_existing_user(email, "password_reset", settings.password_reset_ttl_seconds)
        if issued:
            raw_token, _ = issued
            url = f"{settings.public_base_url}/#reset_token={raw_token}"
            try:
                send_action_email(email.strip().lower(), "Reset your DataLineage AI password", url, "reset your password")
            except EmailDeliveryError:
                # Avoid distinguishing eligible and unknown addresses on SMTP failures.
                pass
            if settings.email_dev_mode and settings.app_environment == "development":
                result["development_url"] = url
    response = JSONResponse(status_code=202, content=result)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/auth/password-reset/confirm")
def confirm_password_reset(payload: dict[str, Any], request: Request) -> JSONResponse:
    client_ip = request.client.host if request.client else "unknown"
    key = f"reset-complete:{client_ip}"
    retry_after = consume_shared_limit(key, 5, 300, "token")
    if retry_after:
        raise HTTPException(status_code=429, detail="Too many password-reset attempts. Try again later.", headers={"Retry-After": str(retry_after)})
    token, password = payload.get("token"), payload.get("password")
    if not isinstance(token, str) or not isinstance(password, str):
        raise HTTPException(status_code=422, detail="token and password must be strings")
    if len(password) < 12 or len(password) > 256:
        raise HTTPException(status_code=422, detail="Password must be between 12 and 256 characters")
    if not consume_password_reset(token, password):
        raise HTTPException(status_code=400, detail="Password-reset link is invalid, expired, or already used.")
    response = JSONResponse(content={"status": "password_reset", "message": "Password updated. Please sign in again."})
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/auth/login")
def auth_login(payload: dict[str, Any], request: Request) -> JSONResponse:
    """Sign in with the configured admin username or a registered email address."""
    if not settings.auth_enabled:
        return JSONResponse(status_code=400, content={"detail": "Authentication is disabled"})
    config_error = auth_configuration_error()
    if config_error:
        raise HTTPException(status_code=503, detail=config_error)
    identity = payload.get("email", payload.get("username"))
    password = payload.get("password")
    if not isinstance(identity, str) or not isinstance(password, str):
        raise HTTPException(status_code=422, detail="email/username and password must be strings")
    client_ip = request.client.host if request.client else "unknown"
    key = f"{client_ip}:{identity.strip().lower()}"
    retry_after = login_retry_after(key)
    if retry_after:
        raise HTTPException(status_code=429, detail="Too many failed sign-in attempts. Try again later.", headers={"Retry-After": str(retry_after)})
    if credentials_valid(identity, password):
        clear_login_failures(key)
        try:
            return _session_response(settings.auth_username, "admin")
        except ValueError as exc:
            raise HTTPException(status_code=503, detail="Authentication is not configured correctly") from exc
    if authenticate_user(identity, password):
        clear_login_failures(key)
        try:
            return _session_response(identity.strip().lower(), "user")
        except ValueError as exc:
            raise HTTPException(status_code=503, detail="Authentication is not configured correctly") from exc
    record_login_failure(key)
    raise HTTPException(status_code=401, detail="Invalid email/username or password")


@app.post("/auth/logout")
def auth_logout() -> JSONResponse:
    response = JSONResponse(content={"status": "logged_out"})
    response.delete_cookie(key=COOKIE_NAME, path="/", httponly=True, secure=settings.secure_cookie, samesite="strict")
    response.headers["Cache-Control"] = "no-store"
    return response




@app.get("/api/v1/github/status")
def github_status(request: Request) -> dict[str, Any]:
    """Return active-tenant configuration state only; never return credential material."""
    token = _github_token_for_request(request, {"owner", "admin", "developer", "viewer"})
    try:
        cfg = github_configuration(token)
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {"configured": cfg["configured"], "provider": "GitHub", "mode": "read-only"}


@app.get("/api/v1/github/repositories/{owner}/{repo}")
async def github_repository(owner: str, repo: str, request: Request) -> dict[str, Any]:
    token = _github_token_for_request(request, {"owner", "admin", "developer", "viewer"})
    try:
        full_name = validate_repo(f"{owner}/{repo}")
        data = await github_api_request("GET", f"/repos/{full_name}", token_override=token)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        # Do not expose upstream response bodies or credential-bearing headers.
        raise HTTPException(status_code=502, detail="GitHub API request failed") from exc
    return {"full_name": data.get("full_name"), "private": data.get("private"),
            "default_branch": data.get("default_branch"), "html_url": data.get("html_url")}


@app.post("/api/v1/github/analyze")
def github_analyze(payload: dict[str, Any], request: Request) -> dict[str, Any]:
    """Analyze caller-supplied PR file contents; SQL is parsed, never executed."""
    context = _organization_context(request, {"owner", "admin", "developer"})
    reservation = None
    if context:
        try:
            reservation = saas.reserve_analysis(context["email"], context["organization_id"], 1, str(uuid4()))
        except OverflowError as exc:
            raise HTTPException(status_code=429, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
    try:
        repo = validate_repo(payload.get("repository"))
        base = validate_branch(payload.get("base_branch"))
        head = validate_branch(payload.get("head_branch"))
        pr_number = validate_pr_number(payload.get("pull_request_number"))
        files = payload.get("files")
        if not isinstance(files, list) or len(files) > 500:
            raise ValueError("files must be a list containing at most 500 entries")
        comparisons = []
        sql_inputs = []
        for item in files:
            if not isinstance(item, dict): raise ValueError("each file must be an object")
            filename = item.get("filename")
            old_sql = item.get("base_content")
            new_sql = item.get("head_content")
            comparison = compare_sql_file(old_sql, new_sql, filename)
            comparisons.append({k:v for k,v in comparison.items() if k not in {"old_content","new_content"}})
            if new_sql is not None:
                sql_inputs.append(SQLFile(path=filename, content=new_sql))
        analyses = [analyze_sql_files(sql_inputs)] if sql_inputs else []
        impact = build_pr_impact([{"filename":x["filename"],"status":x["status"]} for x in comparisons], analyses)
        impact.update({"repository":repo,"base_branch":base,"head_branch":head,"pull_request_number":pr_number,
                       "file_comparisons":comparisons,"report_url":None,
                       "analysis_note":"This endpoint analyzes supplied base/head SQL snapshots. Configure a GitHub App or token-backed trusted integration to retrieve PR content automatically."})
        if context and reservation and reservation != "duplicate":
            saas.complete_analysis_reservation(reservation, len(sql_inputs))
            saas.record_usage(context["email"], context["organization_id"], "pr_analyses", 1, str(uuid4()))
        return impact
    except ValueError as exc:
        if reservation and reservation != "duplicate": saas.release_analysis_reservation(reservation)
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception:
        if reservation and reservation != "duplicate": saas.release_analysis_reservation(reservation)
        raise


@app.post("/api/v1/github/webhook")
async def github_webhook(request: Request) -> dict[str, Any]:
    """Verify GitHub webhook delivery; processing is intentionally non-mutating."""
    import os
    secret = os.getenv("DATALINEAGE_GITHUB_WEBHOOK_SECRET", "")
    if not secret:
        raise HTTPException(status_code=503, detail="GitHub webhook is not configured")
    body = await request.body()
    signature = request.headers.get("x-hub-signature-256", "")
    if not verify_webhook_signature(body, signature, secret):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")
    delivery = request.headers.get("x-github-delivery", "")
    timestamp = request.headers.get("x-datalineage-timestamp", "")
    if not accept_webhook_delivery(delivery, timestamp):
        raise HTTPException(status_code=409, detail="Webhook delivery is invalid, expired, or already processed")
    return {"accepted":True,"message":"Webhook signature verified; event queued for configured processing."}


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness check: confirms the API process is responding."""
    return {"status": "ok", "service": settings.app_name, "version": "0.6.0"}


@app.get("/ready")
def readiness() -> dict[str, str]:
    """Readiness check: confirms the API and local run store are available."""
    try:
        check_store()
    except Exception as exc:
        # Do not expose internal database paths or exception details.
        raise HTTPException(status_code=503, detail="Analysis history store is unavailable") from exc
    return {"status": "ready", "service": settings.app_name, "storage": "ok"}


def _owner_for_request(request: Request) -> str:
    if not settings.auth_enabled:
        return "local"
    return verify_session(request.cookies.get(COOKIE_NAME)) or "local"


@app.post("/api/v1/analyze")
async def analyze(
    request: Request,
    files: list[UploadFile] = File(...),
    dialect: str = Form(default=""),
    project_name: str = Form(default="default"),
) -> dict[str, Any]:
    """Analyze uploaded SQL and save the analysis output as a reusable local run."""
    try:
        project = validate_project_name(project_name)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    context = _organization_context(request, {"owner", "admin", "developer"})
    _ensure_project_for_analysis(context, project)
    reservation = None
    if context:
        try:
            reservation = saas.reserve_analysis(context["email"], context["organization_id"], 1, str(uuid4()))
        except OverflowError as exc:
            raise HTTPException(status_code=429, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
    try:
        sql_files = await read_uploads(files)
        result = analyze_sql_files(sql_files, dialect=dialect.strip())
        run = save_analysis_run(project, result, owner_email=_owner_for_request(request), organization_id=context["organization_id"] if context else None)
        if reservation and reservation != "duplicate":
            saas.complete_analysis_reservation(reservation, len(sql_files))
        result["run"] = run
        return result
    except Exception:
        if reservation and reservation != "duplicate":
            saas.release_analysis_reservation(reservation)
        raise


@app.post("/api/v1/analyze/text")
def analyze_text(payload: dict[str, Any], request: Request) -> dict[str, Any]:
    """Convenience endpoint for local tests and scripted demos."""
    sql = payload.get("sql")
    if not isinstance(sql, str) or not sql.strip():
        raise HTTPException(status_code=422, detail="Field 'sql' must be a non-empty string")
    if len(sql.encode("utf-8")) > 2 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="SQL text exceeds 2 MB limit")
    name = payload.get("filename", "inline.sql")
    if not isinstance(name, str) or not name.lower().endswith(".sql"):
        raise HTTPException(status_code=422, detail="filename must end with .sql")
    dialect = payload.get("dialect", "")
    if not isinstance(dialect, str):
        raise HTTPException(status_code=422, detail="dialect must be a string")
    try:
        project = validate_project_name(payload.get("project_name", "default"))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    context = _organization_context(request, {"owner", "admin", "developer"})
    _ensure_project_for_analysis(context, project)
    reservation = None
    if context:
        try:
            reservation = saas.reserve_analysis(context["email"], context["organization_id"], 1, str(uuid4()))
        except OverflowError as exc:
            raise HTTPException(status_code=429, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
    try:
        result = analyze_sql_files([SQLFile(path=name, content=sql)], dialect=dialect)
        result["run"] = save_analysis_run(project, result, owner_email=_owner_for_request(request), organization_id=context["organization_id"] if context else None)
        if reservation and reservation != "duplicate":
            saas.complete_analysis_reservation(reservation, 1)
        return result
    except Exception:
        if reservation and reservation != "duplicate":
            saas.release_analysis_reservation(reservation)
        raise


@app.post("/api/v1/schema/impact")
def schema_impact(payload: dict[str, Any]) -> dict[str, Any]:
    """Compare table schemas and report supported direct and transitive impacts."""
    source_table = payload.get("source_table")
    old_columns = payload.get("old_columns")
    new_columns = payload.get("new_columns")
    column_lineage = payload.get("column_lineage", [])
    dependency_graph = payload.get("graph", payload.get("dependency_graph"))

    if not isinstance(source_table, str) or not source_table.strip():
        raise HTTPException(status_code=422, detail="source_table must be a non-empty string")
    for field_name, columns in (("old_columns", old_columns), ("new_columns", new_columns)):
        if not isinstance(columns, list) or not all(isinstance(c, str) and c.strip() for c in columns):
            raise HTTPException(status_code=422, detail=f"{field_name} must be a list of non-empty strings")
    if not isinstance(column_lineage, list):
        raise HTTPException(status_code=422, detail="column_lineage must be a list")
    if not all(
        isinstance(item, dict)
        and all(item.get(key) is None or isinstance(item.get(key, ""), str)
                for key in ("source_table", "source_column", "target_table", "target_column"))
        for item in column_lineage
    ):
        raise HTTPException(status_code=422, detail="Each column_lineage entry must contain string-valued fields")
    if dependency_graph is not None and not isinstance(dependency_graph, dict):
        raise HTTPException(status_code=422, detail="graph must be a graph object")

    try:
        return analyze_schema_change(
            source_table=source_table,
            old_columns=old_columns,
            new_columns=new_columns,
            column_lineage=column_lineage,
            dependency_graph=dependency_graph,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc



@app.post("/api/v1/intelligence/sql-compare")
def intelligence_sql_compare(payload: dict[str, Any]) -> dict[str, Any]:
    """Compare SQL revisions and return static change-risk and test guidance."""
    old_sql, new_sql = payload.get("old_sql"), payload.get("new_sql")
    dialect = payload.get("dialect", "")
    if not isinstance(old_sql, str) or not isinstance(new_sql, str):
        raise HTTPException(status_code=422, detail="old_sql and new_sql must be strings")
    if not isinstance(dialect, str):
        raise HTTPException(status_code=422, detail="dialect must be a string")
    old_schema, new_schema = payload.get("old_schema"), payload.get("new_schema")
    if old_schema is not None and (not isinstance(old_schema, dict) or any(not isinstance(v, list) or not all(isinstance(c, str) for c in v) for v in old_schema.values())):
        raise HTTPException(status_code=422, detail="old_schema must map table names to column-name lists")
    if new_schema is not None and (not isinstance(new_schema, dict) or any(not isinstance(v, list) or not all(isinstance(c, str) for c in v) for v in new_schema.values())):
        raise HTTPException(status_code=422, detail="new_schema must map table names to column-name lists")
    try:
        return compare_sql_changes(old_sql, new_sql, dialect, old_schema, new_schema)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/v1/intelligence/dataset-validate")
def intelligence_dataset_validate(payload: dict[str, Any]) -> dict[str, Any]:
    """Run validation checks against caller-supplied source and target row snapshots."""
    source_rows, target_rows = payload.get("source_rows"), payload.get("target_rows")
    required_columns = payload.get("required_columns", [])
    threshold = payload.get("max_row_count_change_pct")
    if not isinstance(source_rows, list) or not isinstance(target_rows, list):
        raise HTTPException(status_code=422, detail="source_rows and target_rows must be lists of row objects")
    if not isinstance(required_columns, list) or not all(isinstance(c, str) for c in required_columns):
        raise HTTPException(status_code=422, detail="required_columns must be a list of strings")
    if threshold is not None and (not isinstance(threshold, (int, float)) or threshold < 0 or threshold > 10000):
        raise HTTPException(status_code=422, detail="max_row_count_change_pct must be between 0 and 10000")
    try:
        return validate_dataset_snapshots(source_rows, target_rows, required_columns, threshold)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/v1/projects/{project_name}/runs")
def project_runs(request: Request, project_name: str, limit: int = Query(default=20, ge=1, le=100)) -> dict[str, Any]:
    """List recent saved runs for a project name."""
    try:
        project = validate_project_name(project_name)
        context = _organization_context(request, {"owner", "admin", "developer", "viewer"})
        runs = list_analysis_runs(project, limit=limit, owner_email=_owner_for_request(request), organization_id=context["organization_id"] if context else None)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"project_name": project, "count": len(runs), "runs": runs}


@app.get("/api/v1/runs/{run_id}")
def get_run(run_id: str, request: Request) -> dict[str, Any]:
    """Retrieve one saved analysis result without re-uploading source files."""
    context = _organization_context(request, {"owner", "admin", "developer", "viewer"})
    run = get_analysis_run(run_id, owner_email=_owner_for_request(request), organization_id=context["organization_id"] if context else None)
    if run is None:
        raise HTTPException(status_code=404, detail="Analysis run was not found")
    return run


@app.post("/api/v1/runs/compare")
def compare_runs(payload: dict[str, Any], request: Request) -> dict[str, Any]:
    """Compare two saved analysis runs and report graph/lineage changes."""
    run_a_id = payload.get("run_a_id")
    run_b_id = payload.get("run_b_id")
    if not isinstance(run_a_id, str) or not run_a_id.strip():
        raise HTTPException(status_code=422, detail="run_a_id must be a non-empty string")
    if not isinstance(run_b_id, str) or not run_b_id.strip():
        raise HTTPException(status_code=422, detail="run_b_id must be a non-empty string")
    try:
        context = _organization_context(request, {"owner", "admin", "developer", "viewer"})
        return compare_analysis_runs(run_a_id, run_b_id, owner_email=_owner_for_request(request), organization_id=context["organization_id"] if context else None)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


def _github_error(exc: Exception) -> HTTPException:
    """Map upstream errors without returning GitHub bodies or credential details."""
    import httpx
    if isinstance(exc, ValueError):
        return HTTPException(status_code=422, detail=str(exc))
    if isinstance(exc, RuntimeError):
        return HTTPException(status_code=503, detail=str(exc))
    if isinstance(exc, httpx.TimeoutException):
        return HTTPException(status_code=504, detail="GitHub API timed out")
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        if status == 404:
            return HTTPException(status_code=404, detail="GitHub resource was not found or is not accessible")
        if status == 403:
            return HTTPException(status_code=503, detail="GitHub denied access or rate limit was reached")
        if status == 401:
            return HTTPException(status_code=503, detail="GitHub credentials are invalid or expired")
    return HTTPException(status_code=502, detail="GitHub API request failed")


@app.get("/api/v1/github/repositories")
async def github_repositories(request: Request) -> dict[str, Any]:
    """List repositories visible to the active organization's GitHub credential."""
    token = _github_token_for_request(request, {"owner", "admin", "developer", "viewer"})
    try:
        repos = await github_api_pages("/user/repos?visibility=all&sort=updated", token_override=token)
        return {"repositories": [{"full_name": r.get("full_name"), "private": r.get("private"),
            "default_branch": r.get("default_branch"), "html_url": r.get("html_url")}
            for r in repos if isinstance(r.get("full_name"), str)]}
    except Exception as exc:
        raise _github_error(exc) from exc


@app.get("/api/v1/github/repositories/{owner}/{repo}/branches")
async def github_branches(owner: str, repo: str, request: Request) -> dict[str, Any]:
    token = _github_token_for_request(request, {"owner", "admin", "developer", "viewer"})
    try:
        full = validate_repo(f"{owner}/{repo}")
        from urllib.parse import quote
        rows = await github_api_pages(f"/repos/{full}/branches", token_override=token)
        return {"repository": full, "branches": [x.get("name") for x in rows if isinstance(x.get("name"), str)]}
    except Exception as exc:
        raise _github_error(exc) from exc


@app.get("/api/v1/github/repositories/{owner}/{repo}/pulls")
async def github_pull_requests(owner: str, repo: str, request: Request, state: str = "open") -> dict[str, Any]:
    token = _github_token_for_request(request, {"owner", "admin", "developer", "viewer"})
    try:
        full = validate_repo(f"{owner}/{repo}")
        if state not in {"open", "closed", "all"}:
            raise ValueError("state must be open, closed or all")
        rows = await github_api_pages(f"/repos/{full}/pulls?state={state}", token_override=token)
        return {"repository": full, "pull_requests": [{
            "number": x.get("number"), "title": x.get("title"),
            "state": x.get("state"), "html_url": x.get("html_url"),
            "base_branch": (x.get("base") or {}).get("ref"),
            "head_branch": (x.get("head") or {}).get("ref"),
            "base_sha": (x.get("base") or {}).get("sha"),
            "head_sha": (x.get("head") or {}).get("sha"),
        } for x in rows]}
    except Exception as exc:
        raise _github_error(exc) from exc


@app.post("/api/v1/github/analyze-pr")
async def github_analyze_pull_request(payload: dict[str, Any], request: Request) -> dict[str, Any]:
    """Fetch SQL snapshots from one authorized PR and run existing lineage analysis."""
    from urllib.parse import quote
    context = _organization_context(request, {"owner", "admin", "developer"})
    token = _github_token_for_request(request, {"owner", "admin", "developer"})
    reservation = None
    if context:
        try:
            reservation = saas.reserve_analysis(context["email"], context["organization_id"], 1, str(uuid4()))
        except OverflowError as exc:
            raise HTTPException(status_code=429, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
    try:
        repo = validate_repo(payload.get("repository"))
        number = validate_pr_number(payload.get("pull_request_number"))
        owner, name = repo.split("/", 1)
        pr = await github_api_request("GET", f"/repos/{repo}/pulls/{number}", token_override=token)
        if not isinstance(pr, dict) or not isinstance(pr.get("base"), dict) or not isinstance(pr.get("head"), dict):
            raise ValueError("GitHub pull request metadata is incomplete")
        base_sha = pr["base"].get("sha")
        head_sha = pr["head"].get("sha")
        base_branch = validate_branch(pr["base"].get("ref"))
        head_branch = validate_branch(pr["head"].get("ref"))
        if not all(isinstance(x, str) and re.fullmatch(r"[0-9a-fA-F]{40,64}", x) for x in (base_sha, head_sha)):
            raise ValueError("GitHub returned invalid commit references")
        changed = await github_api_pages(f"/repos/{repo}/pulls/{number}/files", token_override=token)
        snapshots = []
        for item in changed:
            filename = item.get("filename")
            status = item.get("status")
            if not isinstance(filename, str) or not filename.lower().endswith(".sql"):
                continue
            validate_sql_path(filename)
            old_path = item.get("previous_filename") if status == "renamed" else filename
            if status == "renamed" and (not isinstance(old_path, str) or not old_path.lower().endswith(".sql")):
                old_path = None
            old_content = new_content = None
            if status != "added" and old_path:
                old_obj = await github_api_request("GET", f"/repos/{repo}/contents/{quote(old_path, safe='/')}?ref={base_sha}", token_override=token)
                old_content = decode_github_content(old_obj)
            if status != "removed":
                new_obj = await github_api_request("GET", f"/repos/{repo}/contents/{quote(filename, safe='/')}?ref={head_sha}", token_override=token)
                new_content = decode_github_content(new_obj)
            snapshots.append({"filename": filename, "base_content": old_content, "head_content": new_content})
        comparisons = []
        sql_inputs = []
        for item in snapshots:
            cmp = compare_sql_file(item["base_content"], item["head_content"], item["filename"])
            comparisons.append({k:v for k,v in cmp.items() if k not in {"old_content", "new_content"}})
            if item["head_content"] is not None:
                sql_inputs.append(SQLFile(path=item["filename"], content=item["head_content"]))
        analyses = [analyze_sql_files(sql_inputs)] if sql_inputs else []
        report = build_pr_impact(
            [{"filename": x["filename"], "status": x["status"]} for x in comparisons],
            analyses,
        )
        # Milestone 26: run Milestone 25 SQL comparison for each retrieved PR snapshot.
        from .pull_request_intelligence import analyze_pr_sql_changes
        change_intelligence = analyze_pr_sql_changes(snapshots)
        report.update({"repository": repo, "pull_request_number": number,
            "base_branch": base_branch, "head_branch": head_branch,
            "base_sha": base_sha, "head_sha": head_sha,
            "pull_request_url": pr.get("html_url"), "title": pr.get("title"),
            "file_comparisons": comparisons,
            "change_intelligence": change_intelligence,
            "analysis_note": "Retrieved from GitHub pull request snapshots. SQL was parsed, never executed."})
        if context and reservation and reservation != "duplicate":
            saas.complete_analysis_reservation(reservation, len(sql_inputs))
            saas.record_usage(context["email"], context["organization_id"], "pr_analyses", 1, str(uuid4()))
            saas.record_usage(context["email"], context["organization_id"], "github_calls", 1, str(uuid4()))
        return report
    except Exception as exc:
        if reservation and reservation != "duplicate": saas.release_analysis_reservation(reservation)
        raise _github_error(exc) from exc


@app.post("/api/v1/github/publish-check")
async def github_publish_check(payload: dict[str, Any], request: Request) -> dict[str, Any]:
    """Publish a non-blocking-by-default GitHub Check Run on the supplied head SHA."""
    token = _github_token_for_request(request, {"owner", "admin"})
    try:
        repo = validate_repo(payload.get("repository"))
        sha = payload.get("head_sha")
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-fA-F]{40,64}", sha):
            raise ValueError("head_sha must be a valid commit SHA")
        report = payload.get("report")
        if not isinstance(report, dict):
            raise ValueError("report must be an impact report object")
        enforcement = os.getenv("DATALINEAGE_GITHUB_ENFORCE", "false").lower() in {"1", "true", "yes", "on"}
        status = report.get("status")
        conclusion = "neutral" if status == "neutral" else "success"
        if enforcement and report.get("potential_breaking_changes", 0):
            conclusion = "failure"
        summary = (
            f"Changed SQL files: {int(report.get('changed_sql_files', 0))}\\n"
            f"Dependencies: {int(report.get('dependency_count', 0))}\\n"
            f"Direct impacts: {int(report.get('directly_affected_objects', 0))}\\n"
            f"Transitive impacts: {int(report.get('transitive_affected_objects', 0))}\\n"
            f"Unresolved warnings: {len(report.get('unresolved_lineage_warnings', []))}\\n"
            "A lack of detected impacts does not prove a change is safe."
        )[:60000]
        body = {"name": "DataLineage AI SQL Impact", "head_sha": sha,
            "status": "completed", "conclusion": conclusion,
            "output": {"title": "Pull request SQL impact analysis", "summary": summary}}
        result = await github_api_request("POST", f"/repos/{repo}/check-runs", body, token_override=token)
        return {"published": True, "id": result.get("id"), "html_url": result.get("html_url"),
                "conclusion": conclusion, "enforcement_enabled": enforcement}
    except Exception as exc:
        raise _github_error(exc) from exc



@app.post("/api/v1/github/publish-review")
async def github_publish_review(payload: dict[str, Any], request: Request) -> dict[str, Any]:
    """Publish an idempotent GitHub Check Run and optional PR summary comment.

    This endpoint is opt-in. It never changes branch protection or merges a PR.
    """
    from .github_review_policy import evaluate_review_policy, format_pr_comment, check_run_payload
    token = _github_token_for_request(request, {"owner", "admin"})
    try:
        repo = validate_repo(payload.get("repository"))
        number = validate_pr_number(payload.get("pull_request_number"))
        sha = payload.get("head_sha")
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-fA-F]{40,64}", sha):
            raise ValueError("head_sha must be a valid commit SHA")
        report = payload.get("report")
        if not isinstance(report, dict):
            raise ValueError("report must be an impact report object")
        policy = payload.get("policy") or {}
        if not isinstance(policy, dict):
            raise ValueError("policy must be an object")
        policy_result = evaluate_review_policy(report, policy)
        check_payload = check_run_payload(sha, report, policy_result)
        result: dict[str, Any] = {
            "repository": repo, "pull_request_number": number,
            "policy": policy_result, "check": {"published": False},
            "comment": {"published": False},
            "merge_blocking": False,
            "note": "GitHub branch protection must separately require this check to enforce merge blocking."
        }
        # Update our existing check run when possible, avoiding duplicate checks.
        check_path = f"/repos/{repo}/commits/{sha}/check-runs"
        try:
            existing = await github_api_pages(check_path, max_pages=2, token_override=token)
            match = next((x for x in existing if x.get("name") == check_payload["name"]), None)
            if match and isinstance(match.get("id"), int):
                response = await github_api_request("PATCH",
                    f"/repos/{repo}/check-runs/{match['id']}", check_payload, token_override=token)
            else:
                response = await github_api_request("POST",
                    f"/repos/{repo}/check-runs", check_payload, token_override=token)
            result["check"] = {"published": True, "id": response.get("id"),
                               "html_url": response.get("html_url"),
                               "conclusion": policy_result["check_conclusion"]}
        except Exception as exc:
            result["check"] = {"published": False, "error": str(exc)[:300]}
        # PR comment is optional; marker-based update avoids repeated comments.
        if payload.get("publish_comment", True) is True:
            marker = "<!-- datalineage-ai-sql-review -->"
            body = marker + "\\n" + format_pr_comment(report, policy_result)
            try:
                comments = await github_api_pages(
                    f"/repos/{repo}/issues/{number}/comments", max_pages=2, token_override=token)
                prior = next((x for x in comments if marker in str(x.get("body", ""))), None)
                if prior and isinstance(prior.get("id"), int):
                    response = await github_api_request("PATCH",
                        f"/repos/{repo}/issues/comments/{prior['id']}",
                        {"body": body}, token_override=token)
                else:
                    response = await github_api_request("POST",
                        f"/repos/{repo}/issues/{number}/comments",
                        {"body": body}, token_override=token)
                result["comment"] = {"published": True, "id": response.get("id"),
                                     "html_url": response.get("html_url")}
            except Exception as exc:
                result["comment"] = {"published": False, "error": str(exc)[:300]}
        result["published"] = bool(result["check"]["published"] or result["comment"]["published"])
        return result
    except Exception as exc:
        raise _github_error(exc) from exc


# Milestone 19: additive organization and SaaS management APIs.
from . import saas_store as saas


def _saas_identity(request: Request) -> str:
    identity = _owner_for_request(request)
    if identity == 'local':
        raise HTTPException(status_code=401, detail='A verified user account is required for organization features')
    return identity


def _organization_context(request: Request, allowed_roles: set[str] | None = None):
    """Resolve the active tenant from a verified session and explicit org selector."""
    if not settings.auth_enabled:
        return None
    api_key_principal = getattr(request.state, "api_key_principal", None)
    if api_key_principal:
        selected = request.headers.get("x-organization-id", "").strip()
        tenant_id = api_key_principal["organization_id"]
        if selected and selected != tenant_id:
            raise HTTPException(status_code=403, detail="API key is scoped to a different organization")
        if allowed_roles and api_key_principal["role"] not in allowed_roles:
            raise HTTPException(status_code=403, detail="API key role does not permit this action")
        return {
            "email": api_key_principal["email"],
            "organization_id": tenant_id,
            "role": api_key_principal["role"],
            "auth_method": "api_key",
            "api_key_id": api_key_principal["api_key_id"],
        }
    identity = _saas_identity(request)
    selected = request.headers.get("x-organization-id", "").strip()
    available = saas.memberships(identity)
    if not available:
        personal = saas.ensure_personal_org(identity)
        available = [personal]
    if selected:
        org = saas.get_org(identity, selected)
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")
    elif len(available) == 1:
        org = available[0]
    else:
        raise HTTPException(status_code=400, detail="Select an organization using the X-Organization-ID header")
    if allowed_roles and org["role"] not in allowed_roles:
        raise HTTPException(status_code=403, detail="Your organization role does not permit this action")
    # One-time, additive migration: preserve legacy account-owned history in the
    # user's personal workspace. Existing rows are never discarded.
    if len(available) == 1:
        from .run_store import migrate_legacy_runs
        migrate_legacy_runs(identity, org["id"])
    return {"email": identity, "organization_id": org["id"], "role": org["role"]}


def _ensure_project_for_analysis(context: dict[str, Any] | None, project_name: str) -> None:
    if not context:
        return
    existing = get_project(context["organization_id"], project_name)
    if existing:
        return
    plan_id = saas.summary(context["email"], context["organization_id"])["plan"]["id"]
    limit = saas.PLANS[plan_id]["projects"]
    current = list_projects(context["organization_id"])
    if limit is not None and len(current) >= limit:
        raise HTTPException(status_code=409, detail="Project limit reached for the current plan")
    try:
        create_project(context["organization_id"], project_name, context["email"])
    except Exception as exc:
        # A concurrent create of the same project is harmless; other failures surface.
        if get_project(context["organization_id"], project_name) is None:
            raise HTTPException(status_code=409, detail="Project could not be created") from exc


def _github_token_for_request(request: Request, allowed_roles: set[str]) -> str | None:
    # Existing CI bearer workflow remains a deployment-managed integration. It is
    # distinct from user workspaces and uses only the configured server credential.
    if verify_ci_bearer(request.headers.get("authorization")):
        return None
    context = _organization_context(request, allowed_roles)
    if context is None:
        return None  # local, single-operator development keeps the legacy env credential
    try:
        token = saas.get_github_token(context["email"], context["organization_id"])
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not token:
        raise HTTPException(status_code=503, detail="Connect a GitHub credential for this organization first")
    return token


def _saas_error(exc: Exception):
    if isinstance(exc, PermissionError):
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    if isinstance(exc, OverflowError):
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if isinstance(exc, ValueError):
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    raise exc


@app.get('/api/v1/account/summary')
def account_summary(request: Request):
    """Return only the signed-in user's own company and subscription details."""
    identity = _saas_identity(request)
    organizations = saas.memberships(identity)
    if not organizations:
        organizations = [saas.ensure_personal_org(identity)]
    now = datetime.now(timezone.utc)
    result = []
    for organization in organizations:
        details = saas.summary(identity, organization['id'])
        subscription = details['subscription']
        days_remaining = None
        raw_end = subscription.get('period_end')
        if raw_end:
            try:
                end = datetime.fromisoformat(raw_end.replace('Z', '+00:00'))
                if end.tzinfo is None:
                    end = end.replace(tzinfo=timezone.utc)
                days_remaining = max(0, (end - now).days)
            except (TypeError, ValueError):
                pass
        result.append({
            'id': organization['id'],
            'company_name': organization['name'],
            'role': organization['role'],
            'plan': details['plan'],
            'subscription': subscription,
            'days_remaining': days_remaining,
            'period': details['period'],
            'usage': details['usage'],
            'limits': details['limits'],
            'members': details['members'],
            'projects': details['projects'],
            'warnings': details['warnings'],
        })
    return {'email': identity, 'organizations': result}


@app.get('/api/v1/organizations')
def saas_list_organizations(request: Request):
    identity = _saas_identity(request)
    organizations = saas.memberships(identity)
    if not organizations:
        organizations = [saas.ensure_personal_org(identity)]
    return {'organizations': organizations}


@app.post('/api/v1/organizations')
def saas_create_organization(payload: dict[str, Any], request: Request):
    identity = _saas_identity(request)
    key = f"organization-create:{identity}"
    retry = consume_shared_limit(key, 5, 3600, "action")
    if retry:
        raise HTTPException(status_code=429, detail="Organization creation rate limit reached", headers={"Retry-After": str(retry)})
    try:
        return saas.create_org(identity, payload.get('name', ''))
    except (ValueError, PermissionError, OverflowError) as exc: _saas_error(exc)


@app.get('/api/v1/organizations/{org_id}')
def saas_get_organization(org_id: str, request: Request):
    result=saas.get_org(_saas_identity(request),org_id)
    if not result: raise HTTPException(status_code=404,detail='Organization not found')
    return result


@app.patch('/api/v1/organizations/{org_id}')
def saas_update_organization(org_id: str, payload: dict[str, Any], request: Request):
    try: return saas.rename_org(_saas_identity(request),org_id,payload.get('name',''))
    except (ValueError, PermissionError, OverflowError) as exc: _saas_error(exc)


@app.get('/api/v1/organizations/{org_id}/members')
def saas_members(org_id: str, request: Request):
    try: return {'members':saas.members(_saas_identity(request),org_id)}
    except (ValueError, PermissionError) as exc: _saas_error(exc)


@app.post('/api/v1/organizations/{org_id}/invitations')
def saas_invite(org_id: str, payload: dict[str, Any], request: Request):
    identity = _saas_identity(request)
    key = f"organization-invite:{identity}:{org_id}"
    retry = consume_shared_limit(key, 10, 3600, "action")
    if retry:
        raise HTTPException(status_code=429, detail="Invitation rate limit reached", headers={"Retry-After": str(retry)})
    try:
        invitation = saas.invite(identity,org_id,payload.get('email',''),payload.get('role','viewer'))
        # Invitation secrets are delivered through the configured email channel, never returned by the API.
        invite_url = f"{settings.public_base_url}/#organization_invite={invitation['token']}"
        try:
            send_action_email(invitation['email'], 'DataLineage AI organization invitation', invite_url, 'accept your organization invitation')
        except EmailDeliveryError as exc:
            # Revoke the just-created invitation rather than expose its secret as a fallback.
            with saas.db() as connection:
                connection.execute("UPDATE invitations SET status='revoked' WHERE org_id=? AND email=? AND status='pending'", (org_id, invitation['email']))
            raise HTTPException(status_code=503, detail='Invitation email could not be delivered') from exc
        invitation.pop('token', None)
        return invitation
    except (ValueError, PermissionError, OverflowError) as exc: _saas_error(exc)


@app.post('/api/v1/organizations/invitations/accept')
def saas_accept_invitation(payload: dict[str, Any], request: Request):
    try: return saas.accept_invite(_saas_identity(request),payload.get('token',''))
    except (ValueError, PermissionError) as exc: _saas_error(exc)


@app.delete('/api/v1/organizations/{org_id}/invitations/{invitation_id}')
def saas_revoke_invitation(org_id: str, invitation_id: str, request: Request):
    try: return {'revoked':saas.revoke_invite(_saas_identity(request),org_id,invitation_id)}
    except (ValueError, PermissionError) as exc: _saas_error(exc)


@app.get('/api/v1/organizations/{org_id}/subscription')
def saas_subscription(org_id: str, request: Request):
    try: return saas.summary(_saas_identity(request),org_id)
    except (ValueError, PermissionError) as exc: _saas_error(exc)


@app.post('/api/v1/organizations/{org_id}/subscription/plan')
def saas_change_plan(org_id: str, payload: dict[str, Any], request: Request):
    try: return saas.change_plan(_saas_identity(request),org_id,payload.get('plan',''))
    except (ValueError, PermissionError, OverflowError) as exc: _saas_error(exc)


@app.post('/api/v1/organizations/{org_id}/usage')
def saas_record_usage(org_id: str, payload: dict[str, Any], request: Request):
    try: return saas.record_usage(_saas_identity(request),org_id,payload.get('metric',''),payload.get('quantity',1),payload.get('idempotency_key'))
    except (ValueError, PermissionError, OverflowError) as exc: _saas_error(exc)


@app.get('/api/v1/organizations/{org_id}/usage/history')
def organization_usage_history(org_id: str, request: Request):
    try:
        return {"history": saas.usage_history(_saas_identity(request), org_id)}
    except PermissionError as exc:
        _saas_error(exc)


@app.get('/api/v1/organizations/{org_id}/subscription/history')
def organization_subscription_history(org_id: str, request: Request):
    try:
        return {"subscriptions": saas.subscription_history(_saas_identity(request), org_id)}
    except PermissionError as exc:
        _saas_error(exc)


@app.get('/api/v1/organizations/{org_id}/billing/history')
def saas_billing_history(org_id: str, request: Request):
    try: return {'events':saas.billing_events(_saas_identity(request),org_id)}
    except (ValueError, PermissionError) as exc: _saas_error(exc)




@app.get('/api/v1/billing/catalog')
def billing_catalog(request: Request):
    """Return published monthly prices; no payment credentials are exposed."""
    identity = _saas_identity(request)
    return {
        "provider": "razorpay",
        "mode": settings.razorpay_mode,
        "configured": bool(settings.razorpay_key_id and settings.razorpay_key_secret),
        "plans": {currency: {"country": values["country"], "symbol": values["symbol"], "plans": {plan: {"name": PLAN_NAMES[plan], "amount": values[plan], "currency": currency, "interval": "monthly"} for plan in PLAN_NAMES}} for currency, values in PRICING.items()},
        "enterprise": "Contact sales for custom pricing",
    }


@app.post('/api/v1/organizations/{org_id}/billing/checkout')
def billing_checkout(org_id: str, payload: dict[str, Any], request: Request):
    identity = _saas_identity(request)
    try:
        saas.require_role(identity, org_id, {"owner"})
        organization = saas.get_org(identity, org_id)
        if not organization:
            raise PermissionError("Organization not found")
        checkout = create_razorpay_subscription(
            org_id=org_id, plan=str(payload.get("plan", "")).lower(),
            currency=str(payload.get("currency", "INR")).upper(), customer_email=identity,
        )
        saas.save_razorpay_subscription(identity, org_id, checkout)
        return {"checkout_url": checkout["short_url"], "subscription_id": checkout["subscription_id"], "plan": checkout["plan"], "currency": checkout["currency"], "amount": checkout["amount"], "status": checkout["status"]}
    except PaymentConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except (ValueError, PermissionError, OverflowError) as exc:
        _saas_error(exc)


@app.post('/webhooks/razorpay')
async def razorpay_webhook(request: Request):
    """Public provider webhook. HMAC verification is mandatory before processing."""
    body = await request.body()
    signature = request.headers.get("X-Razorpay-Signature", "")
    secret = settings.razorpay_webhook_secret
    if not secret or not signature:
        raise HTTPException(status_code=503, detail="Razorpay webhook is not configured")
    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status_code=400, detail="Invalid webhook signature")
    try:
        event = json.loads(body.decode("utf-8"))
        event_id = str(event.get("id", ""))
        event_type = str(event.get("event", ""))
        entity = event.get("payload", {}).get("subscription", {}).get("entity", {})
        subscription_id = str(entity.get("id", ""))
        if not event_id or not event_type or not subscription_id:
            return {"received": True, "processed": False, "reason": "unsupported event payload"}
        def iso_epoch(value):
            try:
                return datetime.fromtimestamp(int(value), timezone.utc).isoformat() if value else None
            except (TypeError, ValueError, OSError):
                return None
        result = saas.apply_razorpay_webhook(
            event_id, event_type, body.decode("utf-8"), subscription_id,
            str(entity.get("status", "unknown")), iso_epoch(entity.get("current_start")), iso_epoch(entity.get("current_end")),
        )
        return {"received": True, **result}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="Malformed Razorpay webhook payload") from exc


@app.post('/api/v1/organizations/{org_id}/migrate-legacy-history')
def organization_migrate_legacy_history(org_id: str, request: Request):
    identity = _saas_identity(request)
    try:
        saas.require_role(identity, org_id, {"owner"})
        from .run_store import migrate_legacy_runs
        migrated = migrate_legacy_runs(identity, org_id)
        return {"migrated_runs": migrated, "organization_id": org_id}
    except PermissionError as exc:
        _saas_error(exc)


@app.get('/api/v1/organizations/{org_id}/projects')
def organization_projects(org_id: str, request: Request):
    identity = _saas_identity(request)
    if not saas.get_org(identity, org_id):
        raise HTTPException(status_code=404, detail="Organization not found")
    return {"projects": list_projects(org_id)}


@app.post('/api/v1/organizations/{org_id}/projects')
def organization_create_project(org_id: str, payload: dict[str, Any], request: Request):
    identity = _saas_identity(request)
    try:
        org = saas.require_role(identity, org_id, {"owner", "admin", "developer"})
        current = list_projects(org_id)
        limit = saas.PLANS[saas.summary(identity, org_id)["plan"]["id"]]["projects"]
        if limit is not None and len(current) >= limit:
            raise OverflowError("Project limit reached for the current plan")
        return create_project(org_id, payload.get("name", ""), identity)
    except (ValueError, PermissionError, OverflowError) as exc:
        _saas_error(exc)
    except Exception as exc:
        import sqlite3
        if isinstance(exc, sqlite3.IntegrityError):
            raise HTTPException(status_code=409, detail="Project already exists in this organization") from exc
        raise


@app.get('/api/v1/organizations/{org_id}/invitations')
def organization_list_invitations(org_id: str, request: Request):
    try:
        return {"invitations": saas.pending_invitations(_saas_identity(request), org_id)}
    except (ValueError, PermissionError) as exc:
        _saas_error(exc)


@app.patch('/api/v1/organizations/{org_id}/members/{member_email}')
def organization_change_member_role(org_id: str, member_email: str, payload: dict[str, Any], request: Request):
    try:
        return {"updated": saas.set_member_role(_saas_identity(request), org_id, member_email, payload.get("role", ""))}
    except (ValueError, PermissionError) as exc:
        _saas_error(exc)


@app.delete('/api/v1/organizations/{org_id}/members/{member_email}')
def organization_remove_member(org_id: str, member_email: str, request: Request):
    try:
        return {"removed": saas.remove_member(_saas_identity(request), org_id, member_email)}
    except (ValueError, PermissionError) as exc:
        _saas_error(exc)


@app.get('/api/v1/organizations/{org_id}/github/connection')
def organization_github_connection(org_id: str, request: Request):
    try:
        connection = saas.get_github_connection(_saas_identity(request), org_id)
        return {"connection": connection}
    except PermissionError as exc:
        _saas_error(exc)


@app.put('/api/v1/organizations/{org_id}/github/connection')
def organization_save_github_connection(org_id: str, payload: dict[str, Any], request: Request):
    identity = _saas_identity(request)
    key = f"github-credential-update:{identity}:{org_id}"
    retry = consume_shared_limit(key, 5, 3600, "action")
    if retry:
        raise HTTPException(status_code=429, detail="GitHub credential update rate limit reached", headers={"Retry-After": str(retry)})
    try:
        return saas.save_github_connection(identity, org_id, payload.get("account_name", ""), payload.get("access_token", ""))
    except (ValueError, PermissionError) as exc:
        _saas_error(exc)


@app.post('/api/v1/organizations/{org_id}/subscription/trial')
def organization_start_trial(org_id: str, payload: dict[str, Any], request: Request):
    try:
        return saas.start_trial(_saas_identity(request), org_id, payload.get("plan", "starter"), payload.get("days", 14))
    except (ValueError, PermissionError) as exc:
        _saas_error(exc)


@app.post('/api/v1/organizations/{org_id}/subscription/status')
def organization_subscription_status(org_id: str, payload: dict[str, Any], request: Request):
    try:
        return saas.change_subscription_status(_saas_identity(request), org_id, payload.get("status", ""), payload.get("grace_until"))
    except (ValueError, PermissionError) as exc:
        _saas_error(exc)


@app.get('/api/v1/saas/plans')
def saas_plans():
    return {'plans':saas.PLANS}


# Milestone 28 — Azure ecosystem metadata analysis (static/import-based).
@app.post("/api/v1/integrations/azure-data-factory/analyze")
def m28_analyze_adf(payload: dict[str, Any]):
    try:
        return analyze_adf_pipeline(payload)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/v1/integrations/azure-databricks/notebook/analyze")
def m28_analyze_databricks_notebook(payload: dict[str, Any]):
    try:
        return analyze_databricks_notebook(payload.get("source", ""), payload.get("language", "python"))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/v1/integrations/azure-databricks/sql/analyze")
def m28_analyze_databricks_sql(payload: dict[str, Any]):
    try:
        return {"provider": "azure_databricks", **analyze_sql_text(payload.get("sql", ""), "databricks")}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/v1/integrations/delta-lake/schema/compare")
def m28_compare_delta_schema(payload: dict[str, Any]):
    try:
        return compare_delta_schemas(payload.get("before", {}), payload.get("after", {}))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/v1/integrations/lineage/combined")
def m28_combined_lineage(payload: dict[str, Any]):
    adf = analyze_adf_pipeline(payload["adf"]) if isinstance(payload.get("adf"), dict) else None
    notebooks = [analyze_databricks_notebook(x.get("source", ""), x.get("language", "python"))
                 for x in payload.get("notebooks", []) if isinstance(x, dict)]
    sql_analyses = [analyze_sql_text(x.get("sql", ""), x.get("dialect", ""))
                    for x in payload.get("sql", []) if isinstance(x, dict)]
    return build_cross_platform_lineage(adf, notebooks, sql_analyses)

# Milestone 29: dbt and warehouse metadata snapshot endpoints.
from .warehouse_integrations import (
    analyze_dbt_manifest, normalize_warehouse_snapshot, compare_warehouse_snapshots,
)

@app.post("/api/v1/integrations/dbt/manifest")
def api_m29_dbt_manifest(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        return analyze_dbt_manifest(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

@app.post("/api/v1/integrations/warehouse/{provider}/snapshot")
def api_m29_warehouse_snapshot(provider: str, payload: dict[str, Any]) -> dict[str, Any]:
    try:
        return normalize_warehouse_snapshot(payload, provider.lower())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

@app.post("/api/v1/integrations/warehouse/{provider}/compare")
def api_m29_warehouse_compare(provider: str, payload: dict[str, Any]) -> dict[str, Any]:
    try:
        return compare_warehouse_snapshots(payload.get("before"), payload.get("after"), provider.lower())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

# Milestone 30: SQL Server, Oracle and Apache Airflow metadata imports.
from .database_integrations import normalize_database_snapshot, compare_database_snapshots, analyze_airflow_dag
@app.post("/api/v1/integrations/database/{provider}/snapshot")
def api_m30_database_snapshot(provider: str, payload: dict[str, Any]) -> dict[str, Any]:
    try: return normalize_database_snapshot(payload, provider.lower())
    except ValueError as exc: raise HTTPException(status_code=400, detail=str(exc))
@app.post("/api/v1/integrations/database/{provider}/compare")
def api_m30_database_compare(provider: str, payload: dict[str, Any]) -> dict[str, Any]:
    try: return compare_database_snapshots(payload.get("before"), payload.get("after"), provider.lower())
    except ValueError as exc: raise HTTPException(status_code=400, detail=str(exc))
@app.post("/api/v1/integrations/airflow/dag")
def api_m30_airflow_dag(payload: dict[str, Any]) -> dict[str, Any]:
    try: return analyze_airflow_dag(payload)
    except ValueError as exc: raise HTTPException(status_code=400, detail=str(exc))

# Milestone 32: dataset quality profiling and source/target comparison.
from .data_quality import profile_dataset, compare_dataset_rows

@app.post("/api/v1/quality/profile")
def api_m32_quality_profile(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        return profile_dataset(payload.get("rows"), payload.get("required_columns"),
            payload.get("unique_columns"), payload.get("allowed_values"))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

@app.post("/api/v1/quality/compare")
def api_m32_quality_compare(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        return compare_dataset_rows(payload.get("source_rows"), payload.get("target_rows"))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


# Milestone 33: bounded cache and asynchronous dataset quality jobs.
from .async_job_management import TTLCache, JobRegistry

_m33_quality_cache = TTLCache(max_entries=128, ttl_seconds=60)
_m33_jobs = JobRegistry(max_workers=2, max_jobs=250)


def _m33_cache_key(payload: dict[str, Any]) -> str:
    # Hash canonical input; raw dataset contents are not used as cache keys.
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _m33_profile_job(payload: dict[str, Any]) -> dict[str, Any]:
    return profile_dataset(payload.get("rows"), payload.get("required_columns"),
        payload.get("unique_columns"), payload.get("allowed_values"))


@app.post("/api/v1/quality/profile/async")
def api_m33_quality_profile_async(payload: dict[str, Any]) -> dict[str, Any]:
    # Validate the request synchronously before accepting a background job.
    try:
        profile_dataset(payload.get("rows"), payload.get("required_columns"),
            payload.get("unique_columns"), payload.get("allowed_values"))
        job_id = _m33_jobs.submit(_m33_profile_job, payload)
        return {"job_id": job_id, "status": "queued",
                "status_url": f"/api/v1/performance/jobs/{job_id}"}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.get("/api/v1/performance/jobs/{job_id}")
def api_m33_job_status(job_id: str) -> dict[str, Any]:
    result = _m33_jobs.get(job_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Job not found or no longer retained")
    return result


# M50: Redis Streams queue for durable, worker-independent quality profiling.
from .job_queue import (enqueue_quality_profile as m50_enqueue_quality_profile,
    get_job as m50_get_job, queue_status as m50_queue_status, QueueUnavailable as M50QueueUnavailable)

@app.post("/api/v1/quality/profile/queued", status_code=202)
def api_m50_quality_profile_queued(payload: dict[str, Any], request: Request) -> dict[str, Any]:
    try:
        # Validate before enqueueing so malformed requests fail synchronously.
        profile_dataset(payload.get("rows"), payload.get("required_columns"),
            payload.get("unique_columns"), payload.get("allowed_values"))
        owner = _owner_for_request(request)
        context = _organization_context(request)
        tenant_id = context["organization_id"] if context else None
        job_id = m50_enqueue_quality_profile(payload, owner, tenant_id)
        return {"job_id":job_id,"status":"queued",
            "status_url":f"/api/v1/quality/queued-jobs/{job_id}","queue":"redis_streams"}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except M50QueueUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

@app.get("/api/v1/quality/queued-jobs/{job_id}")
def api_m50_quality_queued_job_status(job_id: str, request: Request) -> dict[str, Any]:
    context = _organization_context(request)
    tenant_id = context["organization_id"] if context else None
    try:
        result = m50_get_job(job_id, _owner_for_request(request), tenant_id)
    except M50QueueUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return result

@app.get("/api/v1/quality/queue-status")
def api_m50_quality_queue_status() -> dict[str, Any]:
    try:
        return m50_queue_status()
    except M50QueueUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/api/v1/quality/profile/cached")
def api_m33_quality_profile_cached(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        key = _m33_cache_key(payload)
        cached = _m33_quality_cache.get(key)
        if cached is not None:
            return {"cache": "hit", "result": cached}
        result = profile_dataset(payload.get("rows"), payload.get("required_columns"),
            payload.get("unique_columns"), payload.get("allowed_values"))
        _m33_quality_cache.set(key, result)
        return {"cache": "miss", "result": result}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/v1/performance/status")
def api_async_job_management_status() -> dict[str, Any]:
    return {"cache": _m33_quality_cache.stats(), "jobs": _m33_jobs.stats(),
            "execution_model": "single-process in-memory; not shared across workers or restarts"}


# Milestone 34: deployment health and readiness probes.
@app.get("/health/live", include_in_schema=False)
def m34_liveness() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health/ready", include_in_schema=False)
def m34_readiness() -> JSONResponse:
    try:
        check_store()
        limiter = rate_limit_backend_status()
        if limiter["status"] != "ok":
            raise RuntimeError("Shared rate-limit backend unavailable")
        return JSONResponse(status_code=200, content={
            "status": "ready",
            "checks": {"analysis_run_store": "ok", "analysis_run_backend": database_backend(),
                       "rate_limit_backend": limiter},
        })
    except Exception:
        # Keep internal paths and database exception details out of health responses.
        return JSONResponse(status_code=503, content={
            "status": "not_ready",
            "checks": {"analysis_run_store": "failed"},
        })

# Milestone 36 — enterprise metadata and intelligence APIs.
from .metadata_governance import (
    PROVIDERS as M36_PROVIDERS, normalize_metadata as m36_normalize_metadata,
    build_unified_lineage as m36_build_unified_lineage,
    analyze_pipeline_events as m36_analyze_pipeline_events,
    classify_metadata as m36_classify_metadata,
    evaluate_governance as m36_evaluate_governance,
    simulate_impact as m36_simulate_impact,
    copilot_answer as m36_copilot_answer,
)

@app.get("/api/v1/enterprise/connectors/catalog")
def m36_connector_catalog() -> dict[str, Any]:
    return {"providers": sorted(M36_PROVIDERS), "ingestion_modes": ["metadata_snapshot", "trusted_collector_payload", "live_read_only_discovery"],
            "live_connectors_available": True,
            "live_connectors": ["aws_glue", "azure_data_factory"],
            "note": "AWS Glue and Azure Data Factory support bounded read-only metadata discovery. Other providers remain snapshot/collector integrations."}

@app.post("/api/v1/enterprise/connectors/{provider}/metadata")
def m36_ingest_metadata(provider: str, payload: dict[str, Any]) -> dict[str, Any]:
    try: return m36_normalize_metadata(payload, provider)
    except ValueError as exc: raise HTTPException(status_code=422, detail=str(exc)) from exc

@app.post("/api/v1/enterprise/lineage/unified")
def m36_unified_lineage(payload: dict[str, Any]) -> dict[str, Any]:
    try: return m36_build_unified_lineage(payload.get("sources", []))
    except ValueError as exc: raise HTTPException(status_code=422, detail=str(exc)) from exc

@app.post("/api/v1/enterprise/observability/analyze")
def m36_pipeline_observability(payload: dict[str, Any]) -> dict[str, Any]:
    try: return m36_analyze_pipeline_events(payload.get("events", []))
    except ValueError as exc: raise HTTPException(status_code=422, detail=str(exc)) from exc

@app.post("/api/v1/enterprise/classification/scan")
def m36_sensitive_classification(payload: dict[str, Any]) -> dict[str, Any]:
    try: return m36_classify_metadata(payload)
    except ValueError as exc: raise HTTPException(status_code=422, detail=str(exc)) from exc

@app.post("/api/v1/enterprise/governance/evaluate")
def m36_governance_evaluate(payload: dict[str, Any]) -> dict[str, Any]:
    try: return m36_evaluate_governance(payload.get("metadata", {}), payload.get("policies", []))
    except ValueError as exc: raise HTTPException(status_code=422, detail=str(exc)) from exc

@app.post("/api/v1/enterprise/impact/simulate")
def m36_impact_simulate(payload: dict[str, Any]) -> dict[str, Any]:
    try: return m36_simulate_impact(payload.get("changed_object", ""), payload.get("edges", []), payload.get("objects"))
    except ValueError as exc: raise HTTPException(status_code=422, detail=str(exc)) from exc

@app.post("/api/v1/enterprise/copilot/ask")
def m36_copilot_ask(payload: dict[str, Any]) -> dict[str, Any]:
    try: return m36_copilot_answer(payload.get("question", ""), payload.get("metadata", {}))
    except ValueError as exc: raise HTTPException(status_code=422, detail=str(exc)) from exc


# Milestone 37 — live read-only AWS Glue and Azure Data Factory connectors.
from .cloud_connectors import (
    ConnectorConfigurationError as M37ConnectorConfigurationError,
    discover_aws_glue as m37_discover_aws_glue,
    discover_azure_data_factory as m37_discover_azure_data_factory,
)

@app.post("/api/v1/enterprise/connectors/aws/glue/discover")
def m37_aws_glue_discover(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        return m37_discover_aws_glue(payload.get("region", ""), payload.get("catalog_id"))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except M37ConnectorConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        # SDK errors can contain account/resource details; never echo them to API clients.
        raise HTTPException(status_code=502, detail="AWS Glue metadata discovery failed; check connector permissions and service availability") from exc

@app.post("/api/v1/enterprise/connectors/azure/data-factory/discover")
def m37_azure_adf_discover(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        return m37_discover_azure_data_factory(payload.get("subscription_id", ""),
            payload.get("resource_group", ""), payload.get("factory_name", ""))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except M37ConnectorConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Azure Data Factory metadata discovery failed; check managed identity permissions and resource availability") from exc


# Milestone 38 — static cross-platform table and column lineage from SQL ASTs.
from .sql_lineage import (
    SQLLineageError as M38SQLLineageError, analyze_sql_lineage as m38_analyze_sql_lineage,
)

@app.post("/api/v1/enterprise/lineage/sql")
def m38_sql_lineage(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        return m38_analyze_sql_lineage(
            payload.get("sql", ""),
            dialect=payload.get("dialect", "generic"),
            source_platform=payload.get("source_platform", "unknown"),
            target_platform=payload.get("target_platform", "unknown"),
            target_table=payload.get("target_table"),
            table_platforms=payload.get("table_platforms", {}),
        )
    except M38SQLLineageError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# Milestone 39 — evidence-based data operations and incident intelligence.
from .data_operations import (
    analyze_runs as m39_analyze_runs, detect_schema_drift as m39_detect_schema_drift,
    evaluate_quality as m39_evaluate_quality, persist_incidents as m39_persist_incidents,
    list_incidents as m39_list_incidents,
)

def _m39_tenant_key(request: Request) -> str:
    context = _organization_context(request)
    return context["organization_id"] if context else _owner_for_request(request)

@app.post("/api/v1/enterprise/operations/runs/analyze")
def m39_analyze_run_events(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        return m39_analyze_runs(payload.get("events", []))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

@app.post("/api/v1/enterprise/operations/runs/ingest")
def m39_ingest_run_events(payload: dict[str, Any], request: Request) -> dict[str, Any]:
    try:
        result = m39_analyze_runs(payload.get("events", []))
        stored = m39_persist_incidents(_m39_tenant_key(request), result["incidents"])
        return {**result, "persistence": stored}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=503, detail="Incident storage is unavailable") from exc

@app.get("/api/v1/enterprise/operations/incidents")
def m39_get_incidents(request: Request, limit: int = Query(default=100, ge=1, le=500)) -> dict[str, Any]:
    try:
        incidents = m39_list_incidents(_m39_tenant_key(request), limit)
        return {"incident_count": len(incidents), "incidents": incidents, "tenant_scoped": True}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=503, detail="Incident storage is unavailable") from exc

@app.post("/api/v1/enterprise/operations/schema-drift")
def m39_schema_drift(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        return m39_detect_schema_drift(payload.get("previous", {}), payload.get("current", {}))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

@app.post("/api/v1/enterprise/operations/data-quality")
def m39_data_quality(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        return m39_evaluate_quality(payload.get("metrics", []), payload.get("thresholds"))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


# Milestone 40 — evidence-grounded AI intelligence (deterministic, auditable baseline).
from .ai_copilot import (
    copilot_query as m40_copilot_query,
    explain_impact as m40_explain_impact,
    summarize_incidents as m40_summarize_incidents,
    assess_data_risk as m40_assess_data_risk,
)

@app.post("/api/v1/enterprise/intelligence/copilot")
def m40_intelligence_copilot(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        return m40_copilot_query(payload.get("question", ""), payload.get("metadata", {}),
                                 payload.get("lineage_edges", []))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

@app.post("/api/v1/enterprise/intelligence/impact/explain")
def m40_intelligence_impact(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        return m40_explain_impact(payload.get("changed_object", ""),
                                  payload.get("edges", []), payload.get("max_results", 10000))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

@app.post("/api/v1/enterprise/intelligence/incidents/summarize")
def m40_intelligence_incident_summary(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        return m40_summarize_incidents(payload.get("incidents", []))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

@app.post("/api/v1/enterprise/intelligence/risk/assess")
def m40_intelligence_risk_assess(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        return m40_assess_data_risk(payload.get("schema_changes", []),
                                    payload.get("quality_findings", []),
                                    payload.get("incidents", []))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc



# Milestone 52 — persistent tenant-scoped governance operations.
from .governance_risk import assess_governance_risk as m51_assess_governance_risk
from . import governance_repository as m52_governance


def _m52_governance_org(request: Request, write: bool = False) -> str:
    if settings.auth_enabled:
        context = _organization_context(request, {"owner", "admin"} if write else {"owner", "admin", "developer", "analyst", "viewer"})
        return str(context["organization_id"])
    return "local_development"


@app.get("/api/v1/enterprise/governance/risk-controls")
def m52_governance_risk_controls(request: Request) -> dict[str, Any]:
    _m52_governance_org(request)
    return {"controls":[{"id":"owner_required","kind":"owner","severity":"medium"},{"id":"classification_required","kind":"classification","severity":"high"},{"id":"sensitive_lineage","kind":"lineage","severity":"high"},{"id":"required_tag","kind":"required_tag","severity":"high"},{"id":"allowed_provider","kind":"allowed_provider","severity":"high"}],"analysis_mode":"metadata_only","requires_human_review":True}


@app.post("/api/v1/enterprise/governance/risk-assess")
def m52_governance_risk_assess(request: Request, payload: dict[str, Any]) -> dict[str, Any]:
    org_id=_m52_governance_org(request, write=True)
    try:
        policies=payload.get("policies")
        if policies is None:
            saved=m52_governance.list_policies(org_id)
            policies=[p["policy"] for p in saved if p["enabled"]] or None
        result=m51_assess_governance_risk(payload.get("metadata",{}),payload.get("edges",[]),policies)
        persisted=m52_governance.save_scan(org_id,result)
        result["persistence"]=persisted
        result["tenant_scope"]=org_id
        return result
    except ValueError as exc:
        raise HTTPException(status_code=422,detail=str(exc)) from exc


@app.get("/api/v1/enterprise/governance/scans")
def m52_governance_scans(request: Request, limit: int=50) -> dict[str, Any]:
    org_id=_m52_governance_org(request)
    return {"scans":m52_governance.list_scans(org_id,limit)}


@app.get("/api/v1/enterprise/governance/findings")
def m52_governance_findings(request: Request, status: str|None=None, severity: str|None=None, limit: int=100) -> dict[str, Any]:
    org_id=_m52_governance_org(request)
    try: return {"findings":m52_governance.list_findings(org_id,status,severity,limit)}
    except ValueError as exc: raise HTTPException(status_code=422,detail=str(exc)) from exc


@app.patch("/api/v1/enterprise/governance/findings/{finding_id}")
def m52_governance_update_finding(finding_id: str, request: Request, payload: dict[str, Any]) -> dict[str, Any]:
    org_id=_m52_governance_org(request,write=True)
    try:
        row=m52_governance.update_finding(org_id,finding_id,status=payload.get("status"),owner=payload.get("owner"),due_date=payload.get("due_date"),resolution_note=payload.get("resolution_note"))
        if row is None: raise HTTPException(status_code=404,detail="Finding not found")
        _, actor = _m53_actor(request, write=True)
        m53_audit.append_event(org_id, actor, "governance.finding.updated", "governance_finding", finding_id,
                               {"status": row.get("status"), "owner": row.get("owner"), "due_date": row.get("due_date")})
        return {"finding":row}
    except ValueError as exc: raise HTTPException(status_code=422,detail=str(exc)) from exc


@app.get("/api/v1/enterprise/governance/summary")
def m52_governance_summary(request: Request) -> dict[str, Any]:
    return m52_governance.summary(_m52_governance_org(request))


@app.put("/api/v1/enterprise/governance/policies")
def m52_governance_save_policy(request: Request, payload: dict[str, Any]) -> dict[str, Any]:
    org_id=_m52_governance_org(request,write=True)
    try:
        saved = m52_governance.save_policy(org_id,payload)
        _, actor = _m53_actor(request, write=True)
        m53_audit.append_event(org_id, actor, "governance.policy.saved", "governance_policy", saved["id"],
                               {"name": saved["name"], "enabled": saved["enabled"]})
        return {"policy": saved}
    except ValueError as exc: raise HTTPException(status_code=422,detail=str(exc)) from exc


@app.get("/api/v1/enterprise/governance/policies")
def m52_governance_list_policies(request: Request) -> dict[str, Any]:
    return {"policies":m52_governance.list_policies(_m52_governance_org(request))}

# Milestone 53 — governance audit evidence and approval workflow.
from . import audit_approvals as m53_audit


def _m53_actor(request: Request, write: bool = False) -> tuple[str, str]:
    if settings.auth_enabled:
        context = _organization_context(request, {"owner", "admin"} if write else {"owner", "admin", "developer", "analyst", "viewer"})
        return str(context["organization_id"]), str(context["email"])
    return "local_development", "local_development"


@app.get("/api/v1/enterprise/governance/audit-events")
def m53_governance_audit_events(request: Request, limit: int = 100) -> dict[str, Any]:
    org_id, _ = _m53_actor(request)
    return {"events": m53_audit.list_events(org_id, limit)}


@app.get("/api/v1/enterprise/governance/audit-verification")
def m53_governance_audit_verification(request: Request) -> dict[str, Any]:
    org_id, _ = _m53_actor(request)
    return m53_audit.verify_chain(org_id)


@app.post("/api/v1/enterprise/governance/approvals")
def m53_governance_request_approval(request: Request, payload: dict[str, Any]) -> dict[str, Any]:
    org_id, actor = _m53_actor(request, write=True)
    try:
        result = m53_audit.request_approval(org_id, actor, payload.get("resource_type", ""),
            payload.get("resource_id", ""), payload.get("action", ""), payload.get("reason", ""))
        return {"approval": result}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/v1/enterprise/governance/approvals")
def m53_governance_list_approvals(request: Request, status: str | None = None, limit: int = 100) -> dict[str, Any]:
    org_id, _ = _m53_actor(request)
    try:
        return {"approvals": m53_audit.list_approvals(org_id, status, limit)}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/v1/enterprise/governance/approvals/{approval_id}/decision")
def m53_governance_decide_approval(approval_id: str, request: Request, payload: dict[str, Any]) -> dict[str, Any]:
    org_id, actor = _m53_actor(request, write=True)
    try:
        result = m53_audit.decide_approval(org_id, approval_id, actor,
            payload.get("decision", ""), payload.get("note", ""))
        if result is None:
            raise HTTPException(status_code=404, detail="Approval request not found")
        return {"approval": result}
    except ValueError as exc:
        raise HTTPException(status_code=409 if "already" in str(exc) or "own request" in str(exc) or "concurrently" in str(exc) else 422, detail=str(exc)) from exc

# Milestone 41 — tenant-scoped API key management, audit trail and security posture.
from . import api_key_security as m41_security

def _m41_admin_context(request: Request) -> dict[str, Any]:
    context = _organization_context(request, {"owner", "admin"})
    if context is None:
        raise HTTPException(status_code=403, detail="Verified organization administrator session is required")
    return context

@app.post("/api/v1/enterprise/security/api-keys")
def m41_create_api_key(payload: dict[str, Any], request: Request) -> dict[str, Any]:
    context = _m41_admin_context(request)
    try:
        result = m41_security.create_api_key(
            context["organization_id"], context["email"], payload.get("label", ""),
            payload.get("role", "viewer"), payload.get("expires_at"))
        m41_security.record_audit(context["organization_id"], context["email"],
                                  "api_key.created", "api_key", result["key_id"],
                                  details={"label": result["label"], "role": result["role"]})
        return result
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=503, detail="Security storage is unavailable") from exc

@app.get("/api/v1/enterprise/security/api-keys")
def m41_list_api_keys(request: Request) -> dict[str, Any]:
    context = _m41_admin_context(request)
    return {"keys": m41_security.list_api_keys(context["organization_id"]),
            "note": "Secret key material is never returned by this endpoint."}

@app.delete("/api/v1/enterprise/security/api-keys/{key_id}")
def m41_revoke_api_key(key_id: str, request: Request) -> dict[str, Any]:
    context = _m41_admin_context(request)
    revoked = m41_security.revoke_api_key(context["organization_id"], key_id)
    m41_security.record_audit(context["organization_id"], context["email"],
                              "api_key.revoked", "api_key", key_id,
                              outcome="success" if revoked else "not_found")
    if not revoked:
        raise HTTPException(status_code=404, detail="Active API key not found")
    return {"status": "revoked", "key_id": key_id}

@app.get("/api/v1/enterprise/security/audit")
def m41_list_security_audit(request: Request, limit: int = Query(default=100, ge=1, le=500),
                            before_sequence: int | None = Query(default=None, ge=1)) -> dict[str, Any]:
    context = _m41_admin_context(request)
    try:
        events = m41_security.list_audit(context["organization_id"], limit, before_sequence)
        return {"event_count": len(events), "events": events, "append_only_api": True}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

@app.get("/api/v1/enterprise/security/posture")
def m41_security_posture(request: Request) -> dict[str, Any]:
    context = _m41_admin_context(request)
    result = m41_security.security_posture({
        "auth_enabled": settings.auth_enabled,
        "secure_cookie": settings.secure_cookie,
        "secret_manager": bool(os.environ.get("DATALINEAGE_SECRET_MANAGER_CONFIGURED")),
        "tls_enforced": bool(os.environ.get("DATALINEAGE_TLS_ENFORCED")),
    })
    m41_security.record_audit(context["organization_id"], context["email"],
                              "security.posture_viewed", "security_posture")
    return result


# Milestone 54 — persistent scheduled governance monitoring.
from . import governance_monitoring as m54_monitor


@app.post("/api/v1/enterprise/governance/monitor-schedules")
def m54_create_monitor_schedule(request: Request, payload: dict[str, Any]) -> dict[str, Any]:
    org_id, actor = _m53_actor(request, write=True)
    try:
        return {"schedule": m54_monitor.create_schedule(org_id, actor, payload)}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/v1/enterprise/governance/monitor-schedules")
def m54_list_monitor_schedules(request: Request, limit: int = 100) -> dict[str, Any]:
    org_id, _ = _m53_actor(request)
    return {"schedules": m54_monitor.list_schedules(org_id, limit)}


@app.patch("/api/v1/enterprise/governance/monitor-schedules/{schedule_id}")
def m54_update_monitor_schedule(schedule_id: str, request: Request, payload: dict[str, Any]) -> dict[str, Any]:
    org_id, actor = _m53_actor(request, write=True)
    try:
        result = m54_monitor.set_enabled(org_id, schedule_id, payload.get("enabled"), actor)
        if result is None:
            raise HTTPException(status_code=404, detail="Monitoring schedule not found")
        return {"schedule": result}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/v1/enterprise/governance/monitor-runs")
def m54_list_monitor_runs(request: Request, schedule_id: str | None = None, limit: int = 100) -> dict[str, Any]:
    org_id, _ = _m53_actor(request)
    return {"runs": m54_monitor.list_runs(org_id, schedule_id, limit)}


# Milestone 55 — read-only enterprise metadata connectors and snapshot drift tracking.
from . import metadata_connectors as m55_connectors


def _m55_reject_inline_secrets(payload: dict[str, Any]) -> None:
    try:
        m55_connectors.reject_inline_secrets(payload)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc



@app.get("/api/v1/enterprise/connectors/providers")
def m55_connector_providers(request: Request) -> dict[str, Any]:
    org_id, _ = _m53_actor(request)
    del org_id
    return {"providers": m55_connectors.provider_status()}


@app.post("/api/v1/enterprise/connectors/{provider}/discover")
def m55_connector_discover(provider: str, request: Request, payload: dict[str, Any]) -> dict[str, Any]:
    org_id, actor = _m53_actor(request, write=True)
    _m55_reject_inline_secrets(payload)
    try:
        provider = provider.casefold()
        if provider == "snowflake":
            result = m55_connectors.discover_snowflake(payload.get("database", ""), payload.get("schema"))
        elif provider == "databricks":
            result = m55_connectors.discover_databricks(payload.get("catalog", ""), payload.get("schema"))
        elif provider == "bigquery":
            result = m55_connectors.discover_bigquery(payload.get("project"), payload.get("dataset"))
        else:
            raise ValueError("provider must be snowflake, databricks or bigquery")
        saved = m55_connectors.save_snapshot(org_id, actor, result)
        return {"discovery": result, "snapshot": saved}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except m55_connectors.ConnectorConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"{provider} metadata discovery failed; check read-only permissions and service availability") from exc


@app.post("/api/v1/enterprise/connectors/{provider}/snapshots")
def m55_save_connector_snapshot(provider: str, request: Request, payload: dict[str, Any]) -> dict[str, Any]:
    org_id, actor = _m53_actor(request, write=True)
    try:
        if provider.casefold() not in {"snowflake", "databricks", "bigquery", "aws_glue", "azure_data_factory"}:
            raise ValueError("unsupported provider")
        result = m55_connectors.save_snapshot(org_id, actor, {"provider": provider, "tables": payload.get("tables", []), "metadata": payload.get("metadata", {})})
        return {"snapshot": result}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/v1/enterprise/connectors/snapshots")
def m55_list_connector_snapshots(request: Request, provider: str | None = None, limit: int = 50) -> dict[str, Any]:
    org_id, _ = _m53_actor(request)
    return {"snapshots": m55_connectors.list_snapshots(org_id, provider, limit)}


@app.get("/api/v1/enterprise/connectors/changes")
def m55_list_connector_changes(request: Request, provider: str | None = None, limit: int = 50) -> dict[str, Any]:
    org_id, _ = _m53_actor(request)
    return {"changes": m55_connectors.list_changes(org_id, provider, limit)}

# Milestone 56 — schema-aware star expansion and UPDATE assignment lineage.
from .schema_aware_lineage import (
    analyze_advanced_sql_lineage as m56_analyze_advanced_sql_lineage,
)

@app.post("/api/v1/enterprise/lineage/sql/advanced")
def m56_advanced_sql_lineage(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        return m56_analyze_advanced_sql_lineage(
            payload.get("sql", ""),
            dialect=payload.get("dialect", "generic"),
            source_platform=payload.get("source_platform", "unknown"),
            target_platform=payload.get("target_platform", "unknown"),
            target_table=payload.get("target_table"),
            table_platforms=payload.get("table_platforms", {}),
            schema_catalog=payload.get("schema_catalog", {}),
        )
    except M38SQLLineageError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

# Milestone 57 — lineage-aware data-quality intelligence and root-cause triage.
from .quality_intelligence import analyze_quality_intelligence as m57_analyze_quality_intelligence

@app.post("/api/v1/quality/intelligence/analyze")
def api_quality_intelligence(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        return m57_analyze_quality_intelligence(
            payload.get("rows"), required_columns=payload.get("required_columns"),
            unique_columns=payload.get("unique_columns"), allowed_values=payload.get("allowed_values"),
            rules=payload.get("rules"), lineage_edges=payload.get("lineage_edges"),
            upstream_quality_findings=payload.get("upstream_quality_findings"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

# Milestone 58 — organization-scoped fine-grained access policy foundation.
from . import role_access_control as m58_access


def _m58_access_context(request: Request, write: bool = False) -> dict[str, str]:
    if settings.auth_enabled:
        allowed = {"owner", "admin"} if write else {"owner", "admin", "developer", "analyst", "viewer"}
        context = _organization_context(request, allowed)
        return {"organization_id": str(context["organization_id"]),
                "identity": str(context["email"]), "role": str(context["role"])}
    return {"organization_id": "local_development", "identity": "local_development", "role": "owner"}


@app.get("/api/v1/enterprise/security/access-profile")
def m58_access_profile(request: Request) -> dict[str, Any]:
    context = _m58_access_context(request)
    return m58_access.access_profile(context["organization_id"], context["identity"], context["role"])


@app.get("/api/v1/enterprise/security/access-policy")
def m58_list_access_policies(request: Request) -> dict[str, Any]:
    context = _m58_access_context(request, write=True)
    return {"policies": m58_access.list_role_policies(context["organization_id"]),
            "permission_catalog": sorted(m58_access.PERMISSIONS)}


@app.put("/api/v1/enterprise/security/access-policy")
def m58_save_access_policy(request: Request, payload: dict[str, Any]) -> dict[str, Any]:
    context = _m58_access_context(request, write=True)
    try:
        saved = m58_access.save_role_policy(context["organization_id"], context["identity"],
                                            payload.get("role", ""), payload.get("permissions"))
        m53_audit.append_event(context["organization_id"], context["identity"],
                               "security.access_policy.updated", "access_policy", saved["role"],
                               {"permissions": saved["permissions"]})
        return {"policy": saved}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

# Milestone 60 — unified tenant-scoped enterprise intelligence overview.
from . import governance_overview as m60_intelligence


@app.get("/enterprise-intelligence", include_in_schema=False)
def m60_enterprise_intelligence_page():
    page = PROJECT_ROOT / "frontend" / "enterprise_intelligence.html"
    if not page.is_file():
        raise HTTPException(status_code=404, detail="Enterprise Intelligence Center page was not found")
    return FileResponse(page)


@app.get("/api/v1/enterprise/intelligence/overview")
def m60_enterprise_intelligence_overview(request: Request) -> dict[str, Any]:
    org_id, _ = _m53_actor(request)
    try:
        return m60_intelligence.build_unified_overview(org_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
