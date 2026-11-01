"""Generic HTTP/API scanning against an unrelated FastAPI/SQLite application."""
import io
import json
import sqlite3
import time
from argparse import Namespace

import pytest
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from navi.api import Settings, create_app
from navi.cli import main
from navi.engine import scan
from navi.openapi import import_spec
from navi.project import initialize, load_project, plan, resolve
from navi.runtime import validate_scan_options
from test_api_reports import local_client


@pytest.fixture
def catalog(monkeypatch):
    app = FastAPI()

    @app.get('/', response_class=HTMLResponse)
    def index():
        return '<form action="/api/catalog"><input name="sku" value="book"></form>'

    def lookup(sku, safe=False):
        with sqlite3.connect(':memory:') as database:
            database.execute('CREATE TABLE products (sku TEXT, title TEXT)')
            database.execute("INSERT INTO products VALUES ('book', 'Practical security')")
            try:
                rows = database.execute('SELECT title FROM products WHERE sku=?', (sku,)) if safe else database.execute(f"SELECT title FROM products WHERE sku='{sku}'")
                return {'products': [r[0] for r in rows]}
            except sqlite3.Error:
                return {'error': 'Invalid query'}

    @app.get('/api/catalog')
    def vulnerable(sku: str = 'book'):
        return lookup(sku)

    @app.get('/api/protected')
    def protected(sku: str = 'book'):
        return lookup(sku, True)

    with local_client(app) as client:
        class Connection:
            def __init__(self, *args, **kwargs): pass
            def request(self, method, url, body=None, headers=None):
                response = client.request(method, url, content=body, headers=headers, follow_redirects=False)
                self.response = io.BytesIO(response.content)
                self.response.status = response.status_code
                self.response.getheaders = lambda: list(response.headers.items())
            def getresponse(self): return self.response
            def close(self): pass
        monkeypatch.setattr('navi.transport.http.client.HTTPConnection', Connection)
        yield app


def write_spec(tmp_path, paths, **extra):
    path = tmp_path / 'api.json'
    path.write_text(json.dumps({'openapi': '3.0.3', 'paths': paths, **extra}))
    return path


def catalog_spec(tmp_path):
    operation = {'parameters': [{'in': 'query', 'name': 'sku', 'schema': {'type': 'string', 'default': 'book'}}]}
    return write_spec(tmp_path, {'/api/catalog': {'get': operation}, '/api/protected': {'get': operation}}, servers=[{'url': 'https://never-contact.invalid'}])


def assert_runtime_proof(report):
    assert report['source'] is None and report['source_digest'] is None
    assert report['scan_mode'] == 'dast' and 'profile' not in report
    assert report['summary'] == {'total': 1, 'confirmed': 0, 'code_only': 0, 'runtime_only': 1, 'verified': 1, 'coverage_gaps': len(report['coverage']['gaps']), 'probable_source_links': 0}
    issue = report['issues'][0]
    assert issue['cwe'] == 'CWE-89' and issue['status'] == 'Runtime only'
    assert not report['function_map']['nodes']
    assert report['worklist']['items'][0]['priority'] == 'P2'
    assert report['build']['status'] == 'unverified'
    assert any('No source supplied' in gap['reason'] for gap in report['coverage']['gaps'])


def test_source_free_discovery_reproduces_unrelated_app(catalog, monkeypatch, tmp_path):
    monkeypatch.setattr('navi.engine.analyze', lambda *a, **kw: pytest.fail('Target-only scan must not analyze bundled source'))
    report = scan(None, 'http://127.0.0.1:7351', {'interval': 0}, tmp_path, browser=False)
    assert_runtime_proof(report)
    assert report['discovery']['inputs'][0]['route'] == '/api/catalog'
    assert (tmp_path / 'report.sarif').is_file()
    assert main(['report', str(tmp_path / 'report.json')]) == 0


def test_source_free_api_import_and_protected_control(catalog, tmp_path):
    config = import_spec(catalog_spec(tmp_path), {'discovery': {'enabled': False}, 'interval': 0})
    report = scan(None, 'http://127.0.0.1:7351', config, tmp_path / 'reports', browser=False)
    assert_runtime_proof(report)
    assert not report['discovery']['pages']
    assert any(check['cwe'] == 'CWE-89' and check['route'] == '/api/protected' and check['outcome'] == 'not_reproduced' for check in report['checks'])
    assert config.get('scope') is None


def test_explicit_target_ignores_local_project(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / 'navi.json').write_text('invalid stale project')
    resolved = resolve(Namespace(target='http://127.0.0.1:7351'))
    assert resolved['source'] is None and 'profile' not in resolved
    assert resolved['config']['discovery']['enabled']
    with pytest.raises(json.JSONDecodeError):
        resolve(Namespace(target='http://127.0.0.1:7351', project='navi.json'))


def test_target_project_plan_no_network(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    spec = catalog_spec(tmp_path)
    initialize('navi.json', target='http://127.0.0.1:7351', openapi=spec, ai=True)
    project = load_project('navi.json')
    assert project['source'] is None and project['openapi'] == str(spec)
    assert project['ai']['max_requests'] == 5
    monkeypatch.setattr('navi.transport.Transport.request', lambda *a, **kw: pytest.fail('Planning must not contact target or provider'))
    assert main(['plan', '--no-browser']) == 0
    result = json.loads(capsys.readouterr().out)
    assert len(result['tests']) == 10 and result['source_digest'] is None
    assert result['function_map']['nodes'] == []


def test_no_implicit_fixture_default(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(['scan']) == 2
    assert 'No target selected' in capsys.readouterr().err


def test_target_only_doctor(catalog, capsys):
    assert main(['doctor', '--target', 'http://127.0.0.1:7351', '--no-browser']) == 0
    checks = json.loads(capsys.readouterr().out)['checks']
    assert next(c for c in checks if c['name'] == 'source')['status'] == 'warning'
    assert next(c for c in checks if c['name'] == 'target')['status'] == 'ok'


def test_api_target_only_lifecycle(catalog, tmp_path):
    config = import_spec(catalog_spec(tmp_path), {'discovery': {'enabled': False}, 'interval': 0})
    settings = Settings(source=None, target='http://127.0.0.1:7351', scan_config=config, output=str(tmp_path / 'server'), browser=False, api_token='a' * 32)
    with local_client(create_app(settings)) as client:
        assert client.get('/api/worklist').status_code == 401
        headers = {'Authorization': 'Bearer ' + 'a' * 32, 'X-Navi': 'local-scan'}
        assert client.post('/api/scans', json={}, headers=headers).status_code == 202
        for _ in range(150):
            state = client.get('/api/state', headers=headers).json()
            if not state['running']: break
            time.sleep(.02)
        assert not state['running'] and state['error'] is None
        assert_runtime_proof(state['report'])
        assert client.get('/api/worklist', headers=headers).json()['items'][0]['priority'] == 'P2'


def test_api_override_validated_and_environment_no_fixture(monkeypatch):
    with pytest.raises(ValueError, match='allowed_methods'):
        create_app(Settings(source=None, scan_config={'allowed_methods': ['no']}))
    monkeypatch.delenv('NAVI_SOURCE', raising=False)
    monkeypatch.setenv('NAVI_TARGET', 'http://127.0.0.1:7351')
    assert Settings.environment().source is None


def test_openapi_local_refs_path_json_seeds_and_methods(tmp_path):
    parameter = {'name': 'id', 'in': 'path', 'schema': {'type': 'integer'}}
    path = write_spec(tmp_path, {'/records/{id}': {'parameters': [{'$ref': '#/components/parameters/RecordId'}], 'put': {
        'requestBody': {'content': {'application/json': {'schema': {'$ref': '#/components/schemas/Record'}}}}}}}, components={
        'parameters': {'RecordId': parameter}, 'schemas': {'Record': {'type': 'object', 'properties': {'title': {'type': 'string', 'default': 'default'}}}}})
    disabled = import_spec(path, {})
    assert disabled['runtime_inputs'] == []
    assert any('PUT is not enabled' in g['reason'] for g in disabled['import_gaps'])
    config = import_spec(path, {'allowed_methods': ['GET', 'PUT'], 'requests': {'PUT /records/<int:id>': {'path': {'id': 17}, 'json': {'title': 'operator seed'}}}})
    assert config['requests']['PUT /records/<int:id>'] == {'path': {'id': 17}, 'json': {'title': 'operator seed'}}
    assert {i['location'] for i in config['runtime_inputs']} == {'json', 'path'}
    assert import_spec(path, config)['runtime_inputs'] == config['runtime_inputs']


def test_openapi_external_cycles_and_unsupported_inputs_are_gaps(tmp_path):
    path = write_spec(tmp_path, {
        '/external': {'$ref': 'https://never-contact.invalid/openapi.json'},
        '/cycle': {'$ref': '#/paths/~1cycle'},
        '/private': {'get': {'security': [{'bearer': []}], 'parameters': [
            {'name': 'q', 'in': 'query', 'schema': {'type': 'array'}},
            {'name': 'X-Key', 'in': 'header', 'schema': {'type': 'string'}},
            {'name': 'token', 'in': 'query', 'schema': {'type': 'string'}},
            {'name': 'broken', 'in': 'query', 'schema': {'enum': {}}}]}}})
    config = import_spec(path, {})
    assert not config['runtime_inputs']
    reasons = ' '.join(g['reason'] for g in config['import_gaps'])
    for expected in ('External or cyclic', 'authentication', 'array', 'Header/cookie', 'security controls', 'enum must be an array'):
        assert expected in reasons


@pytest.mark.parametrize('notes', ['bad', [None], [{'component': 'openapi'}]])
def test_import_gap_validation(notes):
    with pytest.raises(ValueError, match='import_gaps'):
        validate_scan_options({'import_gaps': notes})


def test_target_only_full_ai_skips_source_and_never_invents_code(catalog, tmp_path, monkeypatch):
    from test_ai import SyntheticModel
    from navi.ai.client import OpenAIClient
    model = SyntheticModel()
    monkeypatch.setattr(OpenAIClient, 'complete', lambda self, messages, control: model.complete(messages, control))
    config = import_spec(catalog_spec(tmp_path), {'ai': {'enabled': True, 'workflow': 'full'}, 'discovery': {'enabled': False}, 'interval': 0})
    report = scan(None, 'http://127.0.0.1:7351', config, tmp_path / 'ai', browser=False)
    assert_runtime_proof(report)
    assert model.stages == ['CorrelationReview', 'RemediationReview', 'CoverageReview']
    assert report['ai']['call_attempts'] == 3
    assert report['ai']['status'] == 'completed'
    assert report['ai']['stages']['source_review']['status'] == 'skipped'
    assert report['ai']['stages']['test_planning']['status'] == 'skipped'
    assert all(not fix.get('patch') and not fix.get('source_id') for fix in report['ai']['fixes'])


def test_no_testable_inputs_report_actionable_gap(monkeypatch, tmp_path):
    from navi.transport import Response
    monkeypatch.setattr('navi.transport.Transport.request', lambda *a, **kw: Response(200, {}, b'<h1>Welcome</h1>', 'http://127.0.0.1/', 0))
    report = scan(None, 'http://127.0.0.1:7351', {}, tmp_path, browser=False)
    assert not report['issues']
    assert any('No native test inputs' in gap['reason'] for gap in report['coverage']['gaps'])


def test_target_only_cli_verified_ci_gate(catalog, tmp_path):
    spec = catalog_spec(tmp_path)
    assert main(['scan', '--target', 'http://127.0.0.1:7351', '--openapi', str(spec), '--no-browser', '--no-ai', '--output', str(tmp_path / 'cli'), '--fail-on-verified-high']) == 1
    report = json.loads((tmp_path / 'cli/report.json').read_text())
    assert_runtime_proof(report)
