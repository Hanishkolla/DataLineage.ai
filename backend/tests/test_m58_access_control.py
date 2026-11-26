import json
import pytest

from app import role_access_control as access


def _use_temp_db(monkeypatch, tmp_path):
    monkeypatch.setenv("DATALINEAGE_ACCESS_DB", str(tmp_path / "access.sqlite3"))
    monkeypatch.delenv("DATALINEAGE_DATABASE_URL", raising=False)


def test_default_role_permissions_are_least_privilege(monkeypatch, tmp_path):
    _use_temp_db(monkeypatch, tmp_path)
    assert "security.manage" in access.effective_permissions("org-a", "owner")
    assert "security.manage" not in access.effective_permissions("org-a", "admin")
    assert "billing.manage" not in access.effective_permissions("org-a", "developer")
    assert access.authorize("org-a", "viewer", "lineage.read")
    assert not access.authorize("org-a", "viewer", "lineage.manage")


def test_policy_can_reduce_but_not_escalate_role(monkeypatch, tmp_path):
    _use_temp_db(monkeypatch, tmp_path)
    saved = access.save_role_policy("org-a", "owner@example.com", "developer", ["lineage.read"])
    assert saved["permissions"] == ["lineage.read"]
    assert access.effective_permissions("org-a", "developer") == {"lineage.read"}
    with pytest.raises(ValueError, match="above the built-in role ceiling"):
        access.save_role_policy("org-a", "owner@example.com", "viewer", ["security.manage"])


def test_unknown_permissions_rejected(monkeypatch, tmp_path):
    _use_temp_db(monkeypatch, tmp_path)
    with pytest.raises(ValueError, match="unknown permissions"):
        access.save_role_policy("org-a", "owner@example.com", "analyst", ["root.shell"])


def test_invalid_role_rejected(monkeypatch, tmp_path):
    _use_temp_db(monkeypatch, tmp_path)
    with pytest.raises(ValueError, match="role must be"):
        access.effective_permissions("org-a", "superuser")


def test_corrupt_policy_fails_closed(monkeypatch, tmp_path):
    _use_temp_db(monkeypatch, tmp_path)
    with access._db() as conn:
        conn.execute("INSERT INTO access_policies VALUES(?,?,?,?,?)",
                     ("org-a", "analyst", "{broken", "admin", access._now()))
    assert access.effective_permissions("org-a", "analyst") == set()


def test_policy_is_tenant_scoped(monkeypatch, tmp_path):
    _use_temp_db(monkeypatch, tmp_path)
    access.save_role_policy("org-a", "owner@example.com", "analyst", ["lineage.read"])
    assert "audit.read" in access.effective_permissions("org-b", "analyst")
    assert "audit.read" not in access.effective_permissions("org-a", "analyst")


def test_profile_contains_only_current_role_permissions(monkeypatch, tmp_path):
    _use_temp_db(monkeypatch, tmp_path)
    profile = access.access_profile("org-a", "viewer@example.com", "viewer")
    assert profile["role"] == "viewer"
    assert profile["identity"] == "viewer@example.com"
    assert "members.manage" not in profile["permissions"]
