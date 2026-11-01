"""The supplied UI reads real native evidence through the protected FastAPI API."""
import json
import time
from copy import deepcopy

from navi.api import Settings, create_app
from navi.engine import scan
from navi.runtime import load_config
from navi.ui import issue_view
from conftest import ROOT
from test_api_reports import local_client


def test_ui_scan_evidence_and_export_history_survive_restart(shop, tmp_path):
    settings = Settings(source=str(ROOT/'examples/shop'), target='http://127.0.0.1:5050',
        config_path=str(ROOT/'examples/shop/policy.json'), output=str(tmp_path), browser=False, api_token='t'*32)
    headers = {'Authorization': 'Bearer '+'t'*32, 'X-Navi': 'local-scan'}
    with local_client(create_app(settings)) as client:
        assert client.get('/api/ui/scans').status_code == 401
        assert client.post('/api/scans', json={}, headers=headers).status_code == 202
        for _ in range(100):
            state = client.get('/api/state', headers=headers).json()
            if not state['running']: break
            time.sleep(.02)
        assert state['error'] is None and not state['running']
        scan_id = state['report']['id']
        view = client.get('/api/ui/scans/'+scan_id, headers=headers).json()
        assert view['counts'] == {'confirmed': 0, 'runtime_only': 4, 'code_only': 5}
        assert view['coverage']['files_parsed'] > 0
        issues = client.get('/api/ui/issues', params={'scan_id': scan_id}, headers=headers).json()
        assert len(issues) == 9 and all(i['reasoning']['native'] for i in issues)
        runtime = next(i for i in issues if i['status']=='runtime_only' and i['cwe']==639)
        assert runtime['sast'] is None and runtime['dast']
        assert runtime['dast']['payload'] == '2'  # exact object ID in the recorded access-policy request
        assert runtime['dast']['observations'] and runtime['dast']['response']['headers']
        assert runtime['correlation']['accepted'] is False
        detail = client.get('/api/ui/issues/'+runtime['id'], params={'scan_id':scan_id}, headers=headers)
        assert detail.json() == runtime
        assert client.get('/api/ui/routes',params={'scan_id':scan_id}, headers=headers).json()
        exported = client.get('/api/ui/reports/'+scan_id, headers=headers)
        assert exported.json()['id'] == scan_id and 'attachment' in exported.headers['content-disposition']
        assert client.get('/api/ui/scans/not-an-id',headers=headers).status_code == 404
    with local_client(create_app(settings)) as client:
        rows = client.get('/api/ui/scans',headers=headers).json()
        assert rows[0]['id']==scan_id
        assert client.get('/api/ui/scans/'+scan_id,headers=headers).json()['counts']['confirmed']==0
    other = deepcopy(settings); other.target = 'http://127.0.0.1:9999'
    with local_client(create_app(other)) as client:
        assert client.get('/api/ui/scans',headers=headers).json() == []
        assert client.get('/api/ui/scans/'+scan_id,headers=headers).status_code==404


def test_supplied_static_ui_is_public_and_api_stays_protected(tmp_path):
    ui = tmp_path/'ui'; ui.mkdir(); (ui/'index.html').write_text('<h1>Supplied UI</h1>')
    with local_client(create_app(Settings(ui_dir=str(ui),api_token='t'*32, output=str(tmp_path/'reports')))) as client:
        assert client.get('/').text=='<h1>Supplied UI</h1>'
        assert client.get('/api/ui/scans').status_code==401
        assert client.post('/api/scans',json={},headers={'Authorization':'Bearer '+'t'*32, 'X-Navi':'local-scan'}).status_code==422


def test_unconfigured_server_never_uses_a_bundled_target(tmp_path, monkeypatch):
    monkeypatch.delenv('NAVI_SOURCE', raising=False)
    monkeypatch.delenv('NAVI_TARGET', raising=False)
    assert Settings.environment().source is None and Settings.environment().target is None
    with local_client(create_app(Settings(output=str(tmp_path)))) as client:
        assert client.get('/api/state').json()['target'] is None
        assert client.post('/api/scans',json={},headers={'X-Navi':'local-scan'}).status_code==422


def test_source_policy_is_not_implicitly_executed(tmp_path):
    from argparse import Namespace
    from navi.project import resolve
    (tmp_path/'app.py').write_text('print("example")')
    (tmp_path/'policy.json').write_text('{"scope":{"allowed_origins":["https://unexpected.invalid"]}}')
    assert resolve(Namespace(source=str(tmp_path)))['config'] == {'scanners': {'mode': 'templates'}}
