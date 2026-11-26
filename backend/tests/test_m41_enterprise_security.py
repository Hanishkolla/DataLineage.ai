import pytest
from app import api_key_security as sec


def test_api_key_created_once_verified_scoped_and_revoked(tmp_path, monkeypatch):
    monkeypatch.setenv("DATALINEAGE_SECURITY_DB", str(tmp_path / "security.sqlite3"))
    created = sec.create_api_key("tenant-a", "admin@example.test", "read-only", "viewer")
    raw = created["api_key"]
    assert raw.startswith(sec.KEY_PREFIX)
    assert sec.verify_api_key(raw, "tenant-a")["role"] == "viewer"
    assert sec.verify_api_key(raw, "tenant-b") is None
    assert "api_key" not in sec.list_api_keys("tenant-a")[0]
    assert sec.revoke_api_key("tenant-a", created["key_id"])
    assert sec.verify_api_key(raw, "tenant-a") is None


def test_api_key_role_and_expiry_validation(tmp_path, monkeypatch):
    monkeypatch.setenv("DATALINEAGE_SECURITY_DB", str(tmp_path / "security.sqlite3"))
    with pytest.raises(ValueError):
        sec.create_api_key("t", "admin", "bad", "owner")
    with pytest.raises(ValueError):
        sec.create_api_key("t", "admin", "expired", "viewer", "2000-01-01T00:00:00Z")


def test_audit_log_is_tenant_scoped_and_redacts_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("DATALINEAGE_SECURITY_DB", str(tmp_path / "security.sqlite3"))
    sec.record_audit("tenant-a", "admin", "login", "session",
                     details={"ip": "127.0.0.1", "token": "do-not-store"})
    sec.record_audit("tenant-b", "admin", "export", "report")
    events = sec.list_audit("tenant-a")
    assert len(events) == 1
    assert events[0]["details"] == {"ip": "127.0.0.1"}
    assert sec.list_audit("tenant-b")[0]["action"] == "export"


def test_audit_pagination_and_input_validation(tmp_path, monkeypatch):
    monkeypatch.setenv("DATALINEAGE_SECURITY_DB", str(tmp_path / "security.sqlite3"))
    first = sec.record_audit("t", "a", "one", "x")
    sec.record_audit("t", "a", "two", "x")
    page = sec.list_audit("t", 1)
    assert len(page) == 1
    older = sec.list_audit("t", 10, page[0]["sequence"])
    assert len(older) == 1
    assert older[0]["action"] == "one"
    with pytest.raises(ValueError):
        sec.list_audit("t", 0)


def test_security_posture_does_not_claim_compliance():
    result = sec.security_posture({"auth_enabled": True, "secure_cookie": True})
    assert result["overall_status"] == "assessment_only"
    assert result["compliance_claim"] is False
    assert any(x["status"] == "not_implemented" for x in result["checks"])
