import pytest
from app.audit_permissions import permissions_for_role, role_allows, require_permission, record_audit_event, list_audit_events

def test_owner_has_member_and_billing_permissions():
    assert role_allows("owner","member:manage")
    assert role_allows("owner","billing:manage")

def test_viewer_is_read_only():
    assert role_allows("viewer","project:read")
    assert not role_allows("viewer","project:write")

def test_unknown_role_has_no_permissions():
    assert permissions_for_role("superuser") == set()

def test_require_permission_denies_unauthorized_role():
    with pytest.raises(PermissionError):
        require_permission("viewer","project:delete")

def test_audit_event_persists_and_redacts_sensitive_fields(tmp_path):
    db=str(tmp_path/"audit.sqlite3")
    record_audit_event("alice","project.updated","project","p1",{"status":"ok","access_token":"dont-store","count":2},db)
    rows=list_audit_events(10,db)
    assert rows[0]["actor"]=="alice"
    assert rows[0]["details"]["access_token"]=="[REDACTED]"
    assert rows[0]["details"]["count"]==2

def test_audit_limit_is_bounded():
    with pytest.raises(ValueError): list_audit_events(501, "missing.sqlite3")
