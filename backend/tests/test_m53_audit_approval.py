import pytest
from app import audit_approvals as store


def setup_db(tmp_path, monkeypatch):
    monkeypatch.setenv("DATALINEAGE_SAAS_DB_PATH", str(tmp_path / "saas.sqlite3"))
    monkeypatch.delenv("DATALINEAGE_DATABASE_URL", raising=False)


def test_hash_chained_events_verify_and_are_tenant_scoped(tmp_path, monkeypatch):
    setup_db(tmp_path, monkeypatch)
    first=store.append_event("org-a","owner@example.com","policy.saved","policy","p1",{"enabled":True})
    second=store.append_event("org-a","admin@example.com","finding.updated","finding","f1",{"status":"resolved"})
    assert first["event_hash"] != second["event_hash"]
    assert store.verify_chain("org-a")["valid"] is True
    assert store.verify_chain("org-a")["events_checked"] == 2
    assert len(store.list_events("org-a")) == 2
    assert store.list_events("org-b") == []


def test_hash_chain_detects_payload_tampering(tmp_path, monkeypatch):
    setup_db(tmp_path, monkeypatch)
    store.append_event("org-a","owner","policy.saved","policy","p1",{"enabled":True})
    with store._db() as c:
        c.execute("UPDATE governance_audit_events SET payload_json=? WHERE org_id=?", ('{"enabled":false}',"org-a"))
    result=store.verify_chain("org-a")
    assert result["valid"] is False
    assert result["reason"] == "event_hash_mismatch"


def test_approval_requires_separate_reviewer_and_is_tenant_scoped(tmp_path, monkeypatch):
    setup_db(tmp_path, monkeypatch)
    approval=store.request_approval("org-a","requester@example.com","finding","f-1","accept_risk","Business exception")
    assert approval["status"] == "pending"
    assert store.list_approvals("org-b") == []
    with pytest.raises(ValueError, match="own request"):
        store.decide_approval("org-a",approval["id"],"requester@example.com","approved")
    decided=store.decide_approval("org-a",approval["id"],"reviewer@example.com","approved","Reviewed evidence")
    assert decided["status"] == "approved"
    assert decided["decided_by"] == "reviewer@example.com"
    with pytest.raises(ValueError, match="already been decided"):
        store.decide_approval("org-a",approval["id"],"other@example.com","rejected")
    assert store.verify_chain("org-a")["valid"] is True


def test_validation_and_limits(tmp_path, monkeypatch):
    setup_db(tmp_path, monkeypatch)
    with pytest.raises(ValueError):
        store.append_event("","actor","x","y","z")
    with pytest.raises(ValueError):
        store.request_approval("org-a","actor","finding","f1","approve","" )
    with pytest.raises(ValueError):
        store.list_approvals("org-a", "invalid")
