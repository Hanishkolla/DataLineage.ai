import io
import zipfile
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

from app.main import app
from app.analyzer import analyze_sql_files
from app.ingestion import SQLFile
from app.config import settings
from app.schema_analyzer import analyze_schema_change

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_frontend_serves_interactive_lineage_graph():
    response = client.get("/")
    assert response.status_code == 200
    assert 'id="graphCanvas"' in response.text
    assert 'id="graphSearch"' in response.text
    assert "function renderGraph(data)" in response.text
    assert "downloadHTMLReport" in response.text
    assert "downloadAnalysisReport" in response.text
    assert 'id="runHistoryPanel"' in response.text
    assert "function compareSelectedRuns()" in response.text
    assert 'id="projectName"' in response.text


def test_create_table_as_select_dependency():
    response = client.post("/api/v1/analyze/text", json={
        "filename": "daily_sales.sql",
        "sql": "CREATE TABLE daily_sales AS SELECT order_id, total_amount FROM raw_orders;",
    })
    assert response.status_code == 200
    data = response.json()
    assert "raw_orders" in data["tables"]
    assert "daily_sales" in data["tables"]
    assert {"source": "raw_orders", "target": "daily_sales"} in data["graph"]["edges"]
    assert data["files_parsed"] == 1


def test_insert_select_dependency():
    response = client.post("/api/v1/analyze/text", json={
        "sql": "INSERT INTO analytics_orders SELECT order_id FROM staging_orders;"
    })
    assert response.status_code == 200
    assert {"source": "staging_orders", "target": "analytics_orders"} in response.json()["graph"]["edges"]


def test_invalid_payload_rejected():
    response = client.post("/api/v1/analyze/text", json={"sql": "   "})
    assert response.status_code == 422


def test_malformed_sql_reported():
    response = client.post("/api/v1/analyze/text", json={"sql": "SELECT * FROM ("})
    assert response.status_code == 200
    data = response.json()
    assert data["files_with_errors"] == 1
    assert data["parse_results"][0]["status"] == "error"


def test_multi_file_connected_dependencies_and_three_levels():
    files = [
        SQLFile("01.sql", "CREATE TABLE stage AS SELECT id FROM raw;"),
        SQLFile("02.sql", "CREATE TABLE curated AS SELECT id FROM stage;"),
        SQLFile("03.sql", "CREATE TABLE mart AS SELECT id FROM curated;"),
    ]
    result = analyze_sql_files(files)
    assert result["files_parsed"] == 3
    assert {"source": "raw", "target": "stage"} in result["graph"]["edges"]
    assert {"source": "stage", "target": "curated"} in result["graph"]["edges"]
    assert {"source": "curated", "target": "mart"} in result["graph"]["edges"]
    assert result["dependencies"]["downstream"]["raw"] == ["curated", "mart", "stage"]


def test_alias_join_and_column_lineage():
    result = analyze_sql_files([SQLFile(
        "join.sql",
        "CREATE TABLE result AS SELECT c.id AS customer_id FROM customers c JOIN orders o ON c.id=o.customer_id",
    )])
    assert {"source": "customers", "target": "result"} in result["graph"]["edges"]
    assert {"source": "orders", "target": "result"} in result["graph"]["edges"]
    assert any(m["source_table"] == "customers" and m["source_column"] == "id"
               and m["target_column"] == "customer_id" for m in result["column_lineage"])


def test_cte_does_not_become_physical_source_dependency():
    result = analyze_sql_files([SQLFile(
        "cte.sql",
        "CREATE TABLE result AS WITH recent AS (SELECT id FROM raw_events) SELECT id FROM recent",
    )])
    assert "raw_events" in result["tables"]
    assert "recent" not in result["tables"]
    assert {"source": "raw_events", "target": "result"} in result["graph"]["edges"]


def test_ambiguous_unqualified_column_is_not_fabricated():
    result = analyze_sql_files([SQLFile(
        "ambiguous.sql",
        "CREATE TABLE result AS SELECT id FROM customers c JOIN orders o ON c.id=o.customer_id",
    )])
    assert any(item["confidence"] == "unresolved" for item in result["column_lineage"])


def test_schema_added_removed_and_rename_candidate():
    result = analyze_schema_change("customers", ["id", "old_name"], ["id", "new_name"])
    assert result["removed_columns"] == ["old_name"]
    assert result["added_columns"] == ["new_name"]
    assert result["possible_renames"][0]["confirmed"] is False
    assert result["possible_renames"][0]["confidence"] == "low"


def test_schema_change_traces_three_downstream_levels():
    lineage = [{
        "source_table": "raw",
        "source_column": "email",
        "target_table": "stage",
        "target_column": "email",
        "confidence": "high",
    }]
    graph = {"edges": [
        {"source": "raw", "target": "stage"},
        {"source": "stage", "target": "curated"},
        {"source": "curated", "target": "mart"},
    ]}
    result = analyze_schema_change("raw", ["id", "email"], ["id"], lineage, graph)
    assert result["affected_tables"] == ["stage"]
    assert [x["object"] for x in result["downstream_objects"]] == ["stage", "curated", "mart"]
    assert result["downstream_objects"][0]["severity"] == "high"


def test_schema_impact_api_accepts_analysis_graph_and_lineage():
    response = client.post("/api/v1/schema/impact", json={
        "source_table": "raw", "old_columns": ["id", "email"], "new_columns": ["id"],
        "column_lineage": [{"source_table": "raw", "source_column": "email",
                            "target_table": "stage", "target_column": "email", "confidence": "high"}],
        "graph": {"edges": [{"source": "raw", "target": "stage"}, {"source": "stage", "target": "mart"}]},
    })
    assert response.status_code == 200
    assert response.json()["downstream_objects"][-1]["object"] == "mart"


def test_empty_upload_rejected():
    response = client.post("/api/v1/analyze", files=[])
    assert response.status_code in (400, 422)


def test_unsupported_file_rejected():
    response = client.post("/api/v1/analyze", files=[("files", ("notes.txt", b"hello", "text/plain"))])
    assert response.status_code == 400


def test_response_contract_keeps_legacy_fields():
    response = client.post("/api/v1/analyze/text", json={"sql": "CREATE TABLE b AS SELECT id FROM a"})
    data = response.json()
    for key in ("dialect", "files_scanned", "files_parsed", "files_with_errors",
                "tables", "relationships", "column_lineage", "parse_results", "graph", "limitations"):
        assert key in data


def test_unresolved_table_is_reported_as_node_not_invented_edge():
    result = analyze_sql_files([SQLFile("read.sql", "SELECT id FROM missing_source")])
    assert "missing_source" in result["tables"]
    assert result["graph"]["edges"] == []


def test_zip_decompression_total_limit(monkeypatch):
    # A small compressed ZIP can expand into much more SQL text; cap expanded size.
    monkeypatch.setattr(settings, "max_upload_bytes", 1024)
    monkeypatch.setattr(settings, "max_total_sql_bytes", 200)
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("large.sql", "SELECT 1;\n" + (" " * 600))
    response = client.post(
        "/api/v1/analyze",
        files={"files": ("bundle.zip", payload.getvalue(), "application/zip")},
    )
    assert response.status_code == 413
    assert "uncompressed SQL" in response.json()["detail"]


def test_computed_expression_lineage_tracks_each_source_column():
    result = analyze_sql_files([SQLFile(
        "computed.sql",
        "CREATE TABLE order_value AS SELECT o.price * o.quantity AS gross FROM orders o",
    )])
    mappings = [m for m in result["column_lineage"] if m["target_column"] == "gross"]
    assert {(m["source_table"], m["source_column"]) for m in mappings} == {
        ("orders", "price"), ("orders", "quantity")
    }
    assert all(m["transformation"] == "expression" for m in mappings)
    assert all(m["expression_sql"] == "o.price * o.quantity" for m in mappings)
    assert all(m["confidence"] == "high" for m in mappings)


def test_join_expression_lineage_tracks_multiple_source_tables():
    result = analyze_sql_files([SQLFile(
        "joined_expression.sql",
        "CREATE TABLE enriched AS SELECT o.amount + c.credit AS exposure FROM orders o JOIN customers c ON o.customer_id = c.id",
    )])
    mappings = [m for m in result["column_lineage"] if m["target_column"] == "exposure"]
    assert {(m["source_table"], m["source_column"]) for m in mappings} == {
        ("orders", "amount"), ("customers", "credit")
    }
    assert all(m["transformation"] == "expression" for m in mappings)


def test_ambiguous_expression_lineage_is_marked_unresolved():
    result = analyze_sql_files([SQLFile(
        "ambiguous_expression.sql",
        "CREATE TABLE totals AS SELECT amount + quantity AS total FROM orders o JOIN stock s ON o.id = s.order_id",
    )])
    mappings = [m for m in result["column_lineage"] if m["target_column"] == "total"]
    assert len(mappings) == 2
    assert all(m["source_table"] is None for m in mappings)
    assert all(m["confidence"] == "unresolved" for m in mappings)


def test_schema_impact_explains_removed_column_inside_expression():
    lineage = [{
        "source_table": "orders",
        "source_column": "quantity",
        "target_table": "order_value",
        "target_column": "gross",
        "confidence": "high",
        "transformation": "expression",
        "expression_sql": "price * quantity",
    }]
    result = analyze_schema_change(
        "orders", ["price", "quantity"], ["price"], lineage,
        {"edges": [{"source": "orders", "target": "order_value"}]},
    )
    assert len(result["impacted_mappings"]) == 1
    impact = result["impacted_mappings"][0]
    assert impact["transformation"] == "expression"
    assert impact["expression_sql"] == "price * quantity"
    assert "participates in expression" in impact["reason"]


def test_saved_project_runs_can_be_reloaded_and_compared(tmp_path, monkeypatch):
    monkeypatch.setenv("DATALINEAGE_DB_PATH", str(tmp_path / "runs.sqlite3"))
    first = client.post("/api/v1/analyze/text", json={
        "project_name": "sales-demo",
        "filename": "first.sql",
        "sql": "CREATE TABLE stage AS SELECT id FROM raw;",
    })
    second = client.post("/api/v1/analyze/text", json={
        "project_name": "sales-demo",
        "filename": "second.sql",
        "sql": "CREATE TABLE stage AS SELECT id FROM raw; CREATE TABLE mart AS SELECT id FROM stage;",
    })
    assert first.status_code == 200
    assert second.status_code == 200
    run_a = first.json()["run"]
    run_b = second.json()["run"]
    assert run_a["project_name"] == "sales-demo"
    assert run_a["run_id"] != run_b["run_id"]

    listed = client.get("/api/v1/projects/sales-demo/runs")
    assert listed.status_code == 200
    assert listed.json()["count"] == 2

    reopened = client.get(f"/api/v1/runs/{run_a['run_id']}")
    assert reopened.status_code == 200
    assert "raw" in reopened.json()["result"]["tables"]

    comparison = client.post("/api/v1/runs/compare", json={
        "run_a_id": run_a["run_id"], "run_b_id": run_b["run_id"]
    })
    assert comparison.status_code == 200
    diff = comparison.json()
    assert "mart" in diff["tables_added"]
    assert {"source": "stage", "target": "mart"} in diff["relationships_added"]


def test_saved_run_project_name_validation(tmp_path, monkeypatch):
    monkeypatch.setenv("DATALINEAGE_DB_PATH", str(tmp_path / "runs.sqlite3"))
    response = client.post("/api/v1/analyze/text", json={
        "project_name": "   ", "sql": "SELECT 1",
    })
    assert response.status_code == 422


def test_saved_run_not_found_returns_404(tmp_path, monkeypatch):
    monkeypatch.setenv("DATALINEAGE_DB_PATH", str(tmp_path / "runs.sqlite3"))
    response = client.get("/api/v1/runs/not-a-real-run-id")
    assert response.status_code == 404


def test_security_headers_and_request_id():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.headers.get("x-request-id")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_readiness_endpoint():
    response = client.get("/ready")
    assert response.status_code == 200
    assert response.json()["status"] == "ready"
    assert response.json()["storage"] == "ok"


def test_invalid_content_length_is_rejected():
    response = client.get("/health", headers={"content-length": "invalid"})
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid Content-Length header"


def test_authentication_disabled_status_is_public(monkeypatch):
    monkeypatch.setattr(settings, "auth_enabled", False)
    response = client.get("/auth/status")
    assert response.status_code == 200
    assert response.json() == {"enabled": False, "authenticated": False, "username": None}


def test_authentication_protects_api_and_uses_http_only_cookie(monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(settings, "auth_username", "demo-admin")
    monkeypatch.setattr(settings, "auth_password", "test-only-password")
    monkeypatch.setattr(settings, "session_secret", "test-session-secret-32-bytes-minimum")
    monkeypatch.setattr(settings, "secure_cookie", False)
    auth_client = TestClient(app)

    denied = auth_client.post("/api/v1/analyze/text", json={"sql": "SELECT 1"})
    assert denied.status_code == 401
    assert denied.headers["x-content-type-options"] == "nosniff"
    assert denied.headers["x-frame-options"] == "DENY"
    assert denied.headers["cache-control"] == "no-store"
    assert auth_client.post("/api/v1/schema/impact", json={
        "source_table": "raw", "old_columns": ["id"], "new_columns": []
    }).status_code == 401

    bad_login = auth_client.post("/auth/login", json={"username": "demo-admin", "password": "wrong"})
    assert bad_login.status_code == 401

    login = auth_client.post("/auth/login", json={"username": "demo-admin", "password": "test-only-password"})
    assert login.status_code == 200
    set_cookie = login.headers.get("set-cookie", "").lower()
    assert "httponly" in set_cookie
    assert "samesite=strict" in set_cookie

    allowed = auth_client.post("/api/v1/analyze/text", json={"sql": "SELECT 1"})
    assert allowed.status_code == 200

    logout = auth_client.post("/auth/logout")
    assert logout.status_code == 200
    denied_after_logout = auth_client.post("/api/v1/analyze/text", json={"sql": "SELECT 1"})
    assert denied_after_logout.status_code == 401


def test_auth_session_rejects_tampered_and_expired_tokens(monkeypatch):
    from app.auth import create_session, verify_session

    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(settings, "auth_username", "demo-admin")
    monkeypatch.setattr(settings, "auth_password", "test-only-password")
    monkeypatch.setattr(settings, "session_secret", "test-session-secret-32-bytes-minimum")
    monkeypatch.setattr(settings, "session_ttl_seconds", 60)

    token = create_session("demo-admin", now=100)
    assert verify_session(token, now=120) == "demo-admin"
    assert verify_session(token + "tampered", now=120) is None
    assert verify_session(token, now=160) is None


def test_email_signup_login_and_duplicate_rejection(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(settings, "auth_username", "demo-admin")
    monkeypatch.setattr(settings, "auth_password", "test-only-password")
    monkeypatch.setattr(settings, "session_secret", "test-session-secret-32-bytes-minimum")
    monkeypatch.setattr(settings, "secure_cookie", False)
    monkeypatch.setattr(settings, "email_dev_mode", True)
    monkeypatch.setattr(settings, "app_environment", "development")
    monkeypatch.setattr(settings, "public_base_url", "http://testserver")
    monkeypatch.setenv("DATALINEAGE_USERS_DB_PATH", str(tmp_path / "users.sqlite3"))
    auth_client = TestClient(app)

    created = auth_client.post("/auth/signup", json={
        "email": "Test.User@example.com",
        "password": "A-long-test-password-123",
    })
    assert created.status_code == 202
    assert created.json()["status"] == "verification_required"
    assert "datalineage_session" not in created.cookies
    verification_token = parse_qs(urlparse(created.json()["development_url"]).fragment)["verify_token"][0]
    verified = auth_client.post("/auth/verify-email", json={"token": verification_token})
    assert verified.status_code == 200

    duplicate = auth_client.post("/auth/signup", json={
        "email": "test.user@example.com",
        "password": "Another-long-password-123",
    })
    assert duplicate.status_code == 409

    login = auth_client.post("/auth/login", json={
        "email": "test.user@example.com",
        "password": "A-long-test-password-123",
    })
    assert login.status_code == 200
    assert "httponly" in login.headers.get("set-cookie", "").lower()
    assert auth_client.get("/auth/status").json()["authenticated"] is True


def test_signup_rejects_short_password_and_invalid_email(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(settings, "email_dev_mode", True)
    monkeypatch.setattr(settings, "app_environment", "development")
    monkeypatch.setattr(settings, "auth_username", "demo-admin")
    monkeypatch.setattr(settings, "auth_password", "test-only-password")
    monkeypatch.setattr(settings, "session_secret", "test-session-secret-32-bytes-minimum")
    monkeypatch.setenv("DATALINEAGE_USERS_DB_PATH", str(tmp_path / "users.sqlite3"))
    auth_client = TestClient(app)
    short = auth_client.post("/auth/signup", json={"email": "person@example.com", "password": "short"})
    assert short.status_code == 422
    invalid = auth_client.post("/auth/signup", json={"email": "not-an-email", "password": "A-long-test-password-123"})
    assert invalid.status_code == 422



def test_login_rate_limit_returns_429(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(settings, "auth_username", "demo-admin")
    monkeypatch.setattr(settings, "auth_password", "test-only-password")
    monkeypatch.setattr(settings, "session_secret", "test-session-secret-32-bytes-minimum")
    auth_client = TestClient(app)
    for _ in range(5):
        response = auth_client.post("/auth/login", json={"email": "nobody@example.com", "password": "incorrect-password"})
        assert response.status_code == 401
    limited = auth_client.post("/auth/login", json={"email": "nobody@example.com", "password": "incorrect-password"})
    assert limited.status_code == 429
    assert int(limited.headers["retry-after"]) > 0


def test_analysis_runs_are_scoped_to_owner(tmp_path, monkeypatch):
    monkeypatch.setenv("DATALINEAGE_DB_PATH", str(tmp_path / "runs.sqlite3"))
    from app.run_store import save_analysis_run, get_analysis_run, list_analysis_runs
    result = {"tables": ["raw"], "files_scanned": 1, "files_with_errors": 0}
    run = save_analysis_run("private-project", result, owner_email="one@example.com")
    assert get_analysis_run(run["run_id"], owner_email="one@example.com") is not None
    assert get_analysis_run(run["run_id"], owner_email="two@example.com") is None
    assert len(list_analysis_runs("private-project", owner_email="one@example.com")) == 1
    assert list_analysis_runs("private-project", owner_email="two@example.com") == []


def test_frontend_has_email_signup_and_password_confirmation():
    response = client.get("/")
    assert response.status_code == 200
    assert 'id="authConfirmPassword"' in response.text
    assert 'auth/${signup ? "signup" : "login"}' in response.text
    assert 'id="authEmail"' in response.text


def test_cte_column_lineage_resolves_to_physical_source():
    result = analyze_sql_files([SQLFile(
        "cte_lineage.sql",
        "CREATE TABLE result AS WITH recent AS (SELECT id AS event_id FROM raw_events) SELECT event_id FROM recent",
    )])
    assert any(
        item["source_table"] == "raw_events"
        and item["source_column"] == "id"
        and item["target_table"] == "result"
        and item["target_column"] == "event_id"
        and item["resolution_status"] == "verified"
        for item in result["column_lineage"]
    )


def test_create_view_is_a_table_level_dependency_with_evidence():
    result = analyze_sql_files([SQLFile(
        "view.sql", "CREATE VIEW reporting_view AS SELECT id FROM source_table"
    )])
    assert {"source": "source_table", "target": "reporting_view"} in result["graph"]["edges"]
    relationship = next(r for r in result["relationships"] if r["source_table"] == "source_table")
    assert relationship["operation"] == "CREATE"
    assert relationship["evidence"]
    assert relationship["resolution_status"] == "verified"


def test_dependency_cycles_are_reported_without_crashing():
    result = analyze_sql_files([
        SQLFile("a.sql", "CREATE TABLE a AS SELECT id FROM b"),
        SQLFile("b.sql", "CREATE TABLE b AS SELECT id FROM a"),
    ])
    assert ["a", "b"] in result["cycles"]
    assert result["graph"]["edges"] == [
        {"source": "a", "target": "b"},
        {"source": "b", "target": "a"},
    ]


def test_exact_duplicate_relationships_are_collapsed_deterministically():
    statement = "CREATE TABLE target AS SELECT id FROM source"
    result = analyze_sql_files([
        SQLFile("same.sql", statement + ";" + statement),
    ])
    # Evidence and source line are part of identity; exact duplicate statements
    # from the same file are collapsed rather than duplicated in the response.
    assert len([r for r in result["relationships"] if r["source_table"] == "source"]) == 1


def test_column_lineage_includes_source_evidence_and_line():
    result = analyze_sql_files([SQLFile(
        "evidence.sql", "CREATE TABLE output AS SELECT src.id AS output_id FROM source_table src"
    )])
    mapping = next(m for m in result["column_lineage"] if m["target_column"] == "output_id")
    assert mapping["source_file"] == "evidence.sql"
    assert mapping["evidence"]
    assert mapping["resolution_status"] == "verified"


def test_insert_target_columns_map_by_position():
    result = analyze_sql_files([SQLFile(
        "insert_columns.sql",
        "INSERT INTO reporting (customer_key) SELECT id FROM customers",
    )])
    assert any(
        item["source_table"] == "customers"
        and item["source_column"] == "id"
        and item["target_table"] == "reporting"
        and item["target_column"] == "customer_key"
        for item in result["column_lineage"]
    )


def test_update_from_and_delete_using_expose_table_dependencies():
    update_result = analyze_sql_files([SQLFile(
        "update.sql", "UPDATE target_table SET value = source_table.value FROM source_table"
    )])
    assert {"source": "source_table", "target": "target_table"} in update_result["graph"]["edges"]

    delete_result = analyze_sql_files([SQLFile(
        "delete.sql", "DELETE FROM target_table USING source_table WHERE target_table.id = source_table.id"
    )])
    assert {"source": "source_table", "target": "target_table"} in delete_result["graph"]["edges"]
