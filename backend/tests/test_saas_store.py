import pytest
from app import saas_store as s

@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(s, '_path', lambda: tmp_path/'saas.sqlite3')

def test_org_creation_and_membership_isolation():
    org=s.create_org('owner@example.com','Acme Data')
    assert org['role']=='owner'
    assert s.get_org('outsider@example.com',org['id']) is None
    assert s.memberships('owner@example.com')[0]['id']==org['id']

def test_roles_are_enforced_server_side():
    org=s.create_org('owner@example.com','Acme')
    with pytest.raises(PermissionError): s.rename_org('owner@example.com',org['id'],'New') if False else s.invite('outsider@example.com',org['id'],'dev@example.com','developer')

def test_invitation_token_is_single_use_and_email_bound():
    org=s.create_org('owner@example.com','Acme')
    s.change_plan('owner@example.com',org['id'],'starter')
    invitation=s.invite('owner@example.com',org['id'],'dev@example.com','developer')
    with pytest.raises(PermissionError): s.accept_invite('other@example.com',invitation['token'])
    accepted=s.accept_invite('dev@example.com',invitation['token'])
    assert accepted['role']=='developer'
    with pytest.raises(PermissionError): s.accept_invite('dev@example.com',invitation['token'])

def test_duplicate_pending_invitation_rejected():
    org=s.create_org('owner@example.com','Acme')
    s.change_plan('owner@example.com',org['id'],'starter')
    s.invite('owner@example.com',org['id'],'dev@example.com','viewer')
    with pytest.raises(Exception): s.invite('owner@example.com',org['id'],'dev@example.com','viewer')

def test_free_plan_limits_and_idempotent_usage():
    org=s.create_org('owner@example.com','Acme')
    a=s.record_usage('owner@example.com',org['id'],'analyses',49,'batch-1')
    b=s.record_usage('owner@example.com',org['id'],'analyses',49,'batch-1')
    assert a['recorded'] is True and b['recorded'] is False
    with pytest.raises(OverflowError): s.record_usage('owner@example.com',org['id'],'analyses',2,'batch-2')

def test_plan_change_owner_only():
    org=s.create_org('owner@example.com','Acme')
    changed=s.change_plan('owner@example.com',org['id'],'starter')
    assert changed['plan']['id']=='starter'
    with pytest.raises(PermissionError): s.change_plan('dev@example.com',org['id'],'business')

def test_plan_catalog_prices():
    assert s.PLANS['starter']['price_inr']==1999
    assert s.PLANS['professional']['analyses']==3000
    assert s.PLANS['enterprise']['members'] is None

def test_webhook_hmac_verification():
    import hashlib,hmac
    body=b'{"id":"evt_1"}'
    sig=hmac.new(b'test-secret',body,hashlib.sha256).hexdigest()
    assert s.verify_webhook_signature('test-secret',body,sig)
    assert not s.verify_webhook_signature('wrong',body,sig)

def test_payment_event_idempotency():
    org=s.create_org('owner@example.com','Acme')
    one=s.process_mock_event('owner@example.com',org['id'],'mock','evt-1','succeeded')
    two=s.process_mock_event('owner@example.com',org['id'],'mock','evt-1','succeeded')
    assert one['processed'] is True and two['processed'] is False

def test_billing_history_is_tenant_scoped():
    a=s.create_org('a@example.com','A')
    b=s.create_org('b@example.com','B')
    s.process_mock_event('a@example.com',a['id'],'mock','evt-a','succeeded')
    assert s.billing_events('b@example.com',b['id'])==[]
