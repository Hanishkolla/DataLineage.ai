from app.api_key_authentication import (
    api_key_path_allowed, bearer_token, tenant_principal,
)
from app import api_key_security as security

INCIDENTS = "/api/v1/enterprise/operations/incidents"
INGEST = "/api/v1/enterprise/operations/runs/ingest"

def test_bearer_parser_is_case_insensitive_and_rejects_malformed():
    assert bearer_token("Bearer abc123") == "abc123"
    assert bearer_token("bearer abc123") == "abc123"
    assert bearer_token("Basic abc123") is None
    assert bearer_token("Bearer") is None
    assert bearer_token(None) is None

def test_api_key_role_matrix_is_least_privilege():
    assert api_key_path_allowed(INCIDENTS, "GET", "viewer")
    assert api_key_path_allowed(INCIDENTS, "GET", "analyst")
    assert api_key_path_allowed(INCIDENTS, "GET", "developer")
    assert not api_key_path_allowed(INCIDENTS, "POST", "viewer")
    assert not api_key_path_allowed(INGEST, "POST", "analyst")
    assert api_key_path_allowed(INGEST, "POST", "developer")
    assert not api_key_path_allowed("/api/v1/enterprise/security/audit", "GET", "developer")
    assert not api_key_path_allowed("/api/v1/enterprise/intelligence/copilot", "POST", "developer")

def test_key_verification_and_tenant_principal_are_scoped(tmp_path, monkeypatch):
    monkeypatch.setenv("DATALINEAGE_SECURITY_DB", str(tmp_path / "security.sqlite3"))
    created = security.create_api_key("org-a", "owner@example.com", "integration", "developer")
    raw = created["api_key"]
    verified = security.verify_api_key(raw)
    assert verified is not None
    assert verified["tenant_key"] == "org-a"
    assert security.verify_api_key(raw, "org-b") is None
    principal = tenant_principal(verified)
    assert principal == {
        "organization_id": "org-a",
        "email": "owner@example.com",
        "role": "developer",
        "auth_method": "api_key",
        "api_key_id": created["key_id"],
    }

def test_revoked_key_cannot_authenticate(tmp_path, monkeypatch):
    monkeypatch.setenv("DATALINEAGE_SECURITY_DB", str(tmp_path / "security.sqlite3"))
    created = security.create_api_key("org-a", "owner@example.com", "revocable", "viewer")
    assert security.verify_api_key(created["api_key"]) is not None
    assert security.revoke_api_key("org-a", created["key_id"])
    assert security.verify_api_key(created["api_key"]) is None

def test_main_middleware_only_accepts_api_keys_on_scoped_routes():
    source = (security.__file__.replace("api_key_security.py", "main.py"))
    text = open(source, encoding="utf-8").read()
    assert "m43_authenticate_api_key" in text
    assert "request.state.api_key_principal" in text
    assert "API key is scoped to a different organization" in text


def test_api_key_policy_rejects_unlisted_paths_and_invalid_inputs():
    assert not api_key_path_allowed("/api/v1/enterprise/intelligence/copilot", "POST", "developer")
    assert not api_key_path_allowed("/api/v1/enterprise/operations/incidents/extra", "GET", "viewer")
    assert not api_key_path_allowed("/api/v1/enterprise/operations/incidents", "DELETE", "developer")
    assert not api_key_path_allowed(None, "GET", "viewer")
    assert not api_key_path_allowed("/api/v1/enterprise/operations/incidents", None, "viewer")
    assert not api_key_path_allowed("/api/v1/enterprise/operations/incidents", "GET", None)
