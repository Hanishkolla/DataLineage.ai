import hashlib, hmac, os
import pytest
from fastapi.testclient import TestClient
from app.github_integration import (validate_repo, validate_branch, validate_pr_number, validate_sql_path,
    classify_file_changes, compare_sql_file, verify_webhook_signature, accept_webhook_delivery, build_pr_impact)
from app.main import app


def test_repo_branch_pr_and_path_validation():
    assert validate_repo('acme/warehouse') == 'acme/warehouse'
    assert validate_branch('feature/lineage') == 'feature/lineage'
    assert validate_pr_number(12) == 12
    for bad in ['https://evil.test/x','../x/y','owner/repo?x=1']:
        with pytest.raises(ValueError): validate_repo(bad)
    for bad in ['../main','/main','a..b']:
        with pytest.raises(ValueError): validate_branch(bad)
    for bad in [0,-1,True,'12']:
        with pytest.raises(ValueError): validate_pr_number(bad)
    for bad in ['../x.sql','/tmp/a.sql','x.txt','x\\y.sql']:
        with pytest.raises(ValueError): validate_sql_path(bad)


def test_changed_sql_file_classification():
    result=classify_file_changes([
        {'filename':'new.sql','status':'added'},
        {'filename':'edit.sql','status':'modified'},
        {'filename':'gone.sql','status':'removed'}])
    assert [x['status'] for x in result] == ['added','modified','removed']


def test_sql_diff_is_hint_not_confirmed_breaking_change():
    result=compare_sql_file('select id from old_table','select id from new_table','models/a.sql')
    assert result['added_table_references']
    assert result['removed_table_references']
    assert result['text_changed'] is True


def test_webhook_hmac_and_replay_guard():
    body=b'{"action":"opened"}'; secret='test-secret'
    signature='sha256='+hmac.new(secret.encode(),body,hashlib.sha256).hexdigest()
    assert verify_webhook_signature(body,signature,secret)
    assert not verify_webhook_signature(body,'sha256=bad',secret)
    assert accept_webhook_delivery('delivery-test-1','1000',now=1000)
    assert not accept_webhook_delivery('delivery-test-1','1000',now=1000)
    assert not accept_webhook_delivery('delivery-test-2','1',now=1000)


def test_impact_report_includes_limitations_and_unresolved():
    report=build_pr_impact([{'filename':'x.sql','status':'modified'}],[{'unresolved_references':['unknown_table'],'graph':{'edges':[]},'column_lineage':[]}])
    assert report['status']=='neutral'
    assert report['changed_sql_files']==1
    assert report['unresolved_lineage_warnings']==['unknown_table']
    assert report['limitations']


def test_github_status_never_exposes_token(monkeypatch):
    monkeypatch.setenv('DATALINEAGE_GITHUB_TOKEN','secret-token-value')
    response=TestClient(app).get('/api/v1/github/status')
    assert response.status_code==200
    assert 'secret-token-value' not in response.text
    assert response.json()['configured'] is True


def test_github_analyze_validates_and_reports_without_live_credentials():
    response=TestClient(app).post('/api/v1/github/analyze',json={
        'repository':'acme/warehouse','base_branch':'main','head_branch':'feature/test','pull_request_number':7,
        'files':[{'filename':'models/a.sql','base_content':'select id from orders','head_content':'select id from orders'}]})
    assert response.status_code==200
    data=response.json()
    assert data['repository']=='acme/warehouse'
    assert data['changed_sql_files']==1
    assert data['limitations']


def test_github_analyze_rejects_invalid_repo_and_pr():
    client=TestClient(app)
    base={'repository':'https://evil.test','base_branch':'main','head_branch':'feature','pull_request_number':1,'files':[]}
    assert client.post('/api/v1/github/analyze',json=base).status_code==422
    base['repository']='acme/repo'; base['pull_request_number']=-1
    assert client.post('/api/v1/github/analyze',json=base).status_code==422


def test_github_api_missing_credentials(monkeypatch):
    monkeypatch.delenv('DATALINEAGE_GITHUB_TOKEN',raising=False)
    from app.github_integration import github_configuration
    assert github_configuration()['configured'] is False
