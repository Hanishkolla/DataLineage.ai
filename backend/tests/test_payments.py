import hashlib, hmac, json
import pytest
from app import saas_store as saas
from app.payments import PRICING, PLAN_NAMES

@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(saas, '_path', lambda: tmp_path/'saas.sqlite3')

def test_global_price_catalog_has_expected_currencies():
    assert {'INR','USD','GBP','EUR','SGD','AED','AUD'} <= set(PRICING)
    assert PRICING['INR']['starter'] == 1999
    assert PRICING['USD']['professional'] == 99
    assert set(PLAN_NAMES) == {'starter','professional','business'}

def test_save_razorpay_subscription_is_owner_only():
    org = saas.create_org('owner@example.com', 'Acme')
    payload = {'subscription_id':'sub_test_1','plan':'starter','currency':'INR','amount':1999,'status':'created'}
    assert saas.save_razorpay_subscription('owner@example.com', org['id'], payload)['saved']
    with pytest.raises(PermissionError):
        saas.save_razorpay_subscription('other@example.com', org['id'], {**payload,'subscription_id':'sub_test_2'})

def test_razorpay_webhook_is_idempotent_and_activates_plan():
    org = saas.create_org('owner@example.com', 'Acme')
    saas.save_razorpay_subscription('owner@example.com', org['id'], {'subscription_id':'sub_test_1','plan':'professional','currency':'USD','amount':99,'status':'created'})
    first = saas.apply_razorpay_webhook('evt_1','subscription.activated',json.dumps({'id':'evt_1'}),'sub_test_1','active','2026-11-03T00:00:00+00:00','2026-12-03T00:00:00+00:00')
    duplicate = saas.apply_razorpay_webhook('evt_1','subscription.activated','{}','sub_test_1','active')
    assert first['processed'] is True
    assert duplicate['processed'] is False
    assert saas.summary('owner@example.com',org['id'])['plan']['id'] == 'professional'
