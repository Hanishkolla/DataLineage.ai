from __future__ import annotations
import sqlite3
import pytest
from app import run_store, saas_store

@pytest.fixture
def isolated_stores(tmp_path, monkeypatch):
    monkeypatch.setattr(run_store, "_db_path", lambda: tmp_path / "runs.sqlite3")
    monkeypatch.setattr(saas_store, "_path", lambda: tmp_path / "saas.sqlite3")
    return tmp_path

def test_analysis_runs_are_scoped_to_organization(isolated_stores):
    a = saas_store.create_org("a@example.com", "A")
    b = saas_store.create_org("b@example.com", "B")
    result = {"tables": ["orders"], "graph": {"edges": []}, "column_lineage": []}
    run_a = run_store.save_analysis_run("sales", result, "a@example.com", a["id"])
    run_b = run_store.save_analysis_run("sales", result, "b@example.com", b["id"])
    assert run_store.get_analysis_run(run_a["run_id"], organization_id=a["id"])
    assert run_store.get_analysis_run(run_a["run_id"], organization_id=b["id"]) is None
    assert len(run_store.list_analysis_runs("sales", organization_id=a["id"])) == 1
    with pytest.raises(KeyError):
        run_store.compare_analysis_runs(run_a["run_id"], run_b["run_id"], organization_id=a["id"])

def test_project_names_are_unique_per_organization(isolated_stores):
    a = saas_store.create_org("a@example.com", "A")
    b = saas_store.create_org("b@example.com", "B")
    run_store.create_project(a["id"], "warehouse", "a@example.com")
    run_store.create_project(b["id"], "warehouse", "b@example.com")
    assert len(run_store.list_projects(a["id"])) == 1
    assert len(run_store.list_projects(b["id"])) == 1
    assert run_store.get_project(a["id"], "warehouse")["organization_id"] == a["id"]

def test_legacy_analysis_runs_migrate_without_deletion(isolated_stores):
    import json, sqlite3
    a = saas_store.create_org("legacy@example.com", "Personal workspace")
    legacy_path = isolated_stores / "runs.sqlite3"
    connection = sqlite3.connect(legacy_path)
    connection.execute("""CREATE TABLE analysis_runs (
        run_id TEXT PRIMARY KEY, owner_email TEXT NOT NULL DEFAULT 'local',
        project_name TEXT NOT NULL, created_at TEXT NOT NULL,
        files_scanned INTEGER NOT NULL, files_with_errors INTEGER NOT NULL,
        tables_json TEXT NOT NULL, result_json TEXT NOT NULL)""")
    result = {"tables": ["legacy_table"], "graph": {"edges": []}, "column_lineage": []}
    connection.execute("INSERT INTO analysis_runs VALUES(?,?,?,?,?,?,?,?)", ("legacy-run", "legacy@example.com", "legacy", "2026-01-01T00:00:00Z", 1, 0, json.dumps(result["tables"]), json.dumps(result)))
    connection.commit(); connection.close()
    # _connect performs the additive organization_id column migration.
    with run_store._session() as migrated:
        assert "organization_id" in {row["name"] for row in migrated.execute("PRAGMA table_info(analysis_runs)")}
    assert run_store.migrate_legacy_runs("legacy@example.com", a["id"]) == 1
    assert run_store.get_analysis_run("legacy-run", organization_id=a["id"])
    assert run_store.migrate_legacy_runs("legacy@example.com", a["id"]) == 0

def test_last_owner_cannot_be_removed_or_demoted(isolated_stores):
    org = saas_store.create_org("owner@example.com", "Acme")
    with pytest.raises(PermissionError):
        saas_store.remove_member("owner@example.com", org["id"], "owner@example.com")
    with pytest.raises(PermissionError):
        saas_store.set_member_role("owner@example.com", org["id"], "owner@example.com", "admin")

def test_member_limit_counts_pending_invitations(isolated_stores):
    org = saas_store.create_org("owner@example.com", "Acme")
    saas_store.change_plan("owner@example.com", org["id"], "starter")
    saas_store.invite("owner@example.com", org["id"], "one@example.com", "viewer")
    saas_store.invite("owner@example.com", org["id"], "two@example.com", "viewer")
    with pytest.raises(OverflowError):
        saas_store.invite("owner@example.com", org["id"], "three@example.com", "viewer")

def test_analysis_reservations_prevent_concurrent_limit_overrun(isolated_stores):
    org = saas_store.create_org("owner@example.com", "Acme")
    first = saas_store.reserve_analysis("owner@example.com", org["id"], 49, "reserve-1")
    with pytest.raises(OverflowError):
        saas_store.reserve_analysis("owner@example.com", org["id"], 2, "reserve-2")
    saas_store.complete_analysis_reservation(first, 3)
    with pytest.raises(OverflowError):
        saas_store.reserve_analysis("owner@example.com", org["id"], 2, "reserve-3")
    summary = saas_store.summary("owner@example.com", org["id"])
    assert summary["usage"]["analyses"] == 49
    assert summary["usage"]["sql_files"] == 3

def test_github_token_is_encrypted_and_not_returned(isolated_stores, monkeypatch):
    cryptography = pytest.importorskip("cryptography.fernet")
    key = cryptography.Fernet.generate_key().decode()
    monkeypatch.setenv("DATALINEAGE_GITHUB_CREDENTIAL_KEY", key)
    org = saas_store.create_org("owner@example.com", "Acme")
    token = "github_pat_" + "x" * 40
    saved = saas_store.save_github_connection("owner@example.com", org["id"], "acme", token)
    assert "token" not in saved and "access_token" not in saved
    assert saas_store.get_github_token("owner@example.com", org["id"]) == token
    with saas_store.db() as c:
        stored = c.execute("SELECT credential_ref FROM github_connections WHERE org_id=?", (org["id"],)).fetchone()[0]
    assert token not in stored


def test_subscription_lifecycle_rejects_invalid_transition(isolated_stores):
    org = saas_store.create_org("owner@example.com", "Acme")
    saas_store.change_subscription_status("owner@example.com", org["id"], "past_due")
    saas_store.change_subscription_status("owner@example.com", org["id"], "active")
    with pytest.raises(ValueError):
        saas_store.change_subscription_status("owner@example.com", org["id"], "trial")

def test_subscription_history_is_scoped_and_preserved(isolated_stores):
    a = saas_store.create_org("a@example.com", "A")
    b = saas_store.create_org("b@example.com", "B")
    saas_store.change_plan("a@example.com", a["id"], "starter")
    history = saas_store.subscription_history("a@example.com", a["id"])
    assert [item["plan"] for item in history] == ["starter", "free"]
    assert saas_store.subscription_history("b@example.com", b["id"])[0]["plan"] == "free"

def test_expired_invitation_is_rejected(isolated_stores):
    org = saas_store.create_org("owner@example.com", "Acme")
    saas_store.change_plan("owner@example.com", org["id"], "starter")
    invitation = saas_store.invite("owner@example.com", org["id"], "new@example.com", "developer", ttl=60)
    with saas_store.db() as c:
        c.execute("UPDATE invitations SET expires_at=0 WHERE org_id=?", (org["id"],))
    with pytest.raises(PermissionError):
        saas_store.accept_invite("new@example.com", invitation["token"])

def test_github_credentials_are_isolated_between_organizations(isolated_stores, monkeypatch):
    cryptography = pytest.importorskip("cryptography.fernet")
    monkeypatch.setenv("DATALINEAGE_GITHUB_CREDENTIAL_KEY", cryptography.Fernet.generate_key().decode())
    a = saas_store.create_org("a@example.com", "A")
    b = saas_store.create_org("b@example.com", "B")
    token_a = "github_pat_" + "a" * 40
    token_b = "github_pat_" + "b" * 40
    saas_store.save_github_connection("a@example.com", a["id"], "account-a", token_a)
    saas_store.save_github_connection("b@example.com", b["id"], "account-b", token_b)
    assert saas_store.get_github_token("a@example.com", a["id"]) == token_a
    assert saas_store.get_github_token("b@example.com", b["id"]) == token_b
    assert saas_store.get_github_token("a@example.com", a["id"]) != token_b

def test_viewer_cannot_write_usage_or_manage_subscription(isolated_stores):
    org = saas_store.create_org("owner@example.com", "Acme")
    saas_store.change_plan("owner@example.com", org["id"], "starter")
    invite = saas_store.invite("owner@example.com", org["id"], "viewer@example.com", "viewer")
    saas_store.accept_invite("viewer@example.com", invite["token"])
    with pytest.raises(PermissionError):
        saas_store.record_usage("viewer@example.com", org["id"], "analyses", 1, "viewer-event")
    with pytest.raises(PermissionError):
        saas_store.change_plan("viewer@example.com", org["id"], "business")


def test_trial_can_only_be_activated_once(isolated_stores):
    org = saas_store.create_org("owner@example.com", "Acme")
    trial = saas_store.start_trial("owner@example.com", org["id"], "starter", 14)
    assert trial["subscription"]["status"] == "trial"
    with pytest.raises(ValueError):
        saas_store.start_trial("owner@example.com", org["id"], "professional", 14)

def test_manual_analysis_usage_cannot_overrun_pending_reservations(isolated_stores):
    org = saas_store.create_org("owner@example.com", "Acme")
    reservation = saas_store.reserve_analysis("owner@example.com", org["id"], 49, "pending-49")
    with pytest.raises(OverflowError):
        saas_store.record_usage("owner@example.com", org["id"], "analyses", 2, "manual-extra")
    saas_store.release_analysis_reservation(reservation)
