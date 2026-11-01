"""Product requirements against a separately supplied app, with real SQL execution."""
from copy import deepcopy
import json
import runpy

import pytest

from navi.correlate import correlate
from navi.engine import scan
from navi.model import Finding, Binding, Analysis
from navi.ui import issue_view, routes_view
from navi.store import compare
from navi.evidence import runtime_observations


@pytest.fixture
def order_app(tmp_path, connect_app):
    source = tmp_path / 'application'; source.mkdir()
    (source / 'orders.py').write_text('''from flask import Flask, request
import sqlite3
app = Flask(__name__)
@app.get('/api/orders')
def get_orders():
    db = sqlite3.connect(':memory:')
    db.execute('CREATE TABLE orders(id INTEGER, name TEXT)')
    db.execute("INSERT INTO orders VALUES (1, 'fixture-order')")
    value = request.args.get('id', '1')
    rows = db.execute('SELECT name FROM orders WHERE id=' + value).fetchall()
    db.close()
    return str(rows)
''')
    connect_app(runpy.run_path(str(source / 'orders.py'))['app'])
    return source


def test_full_finding_contract_without_target_instrumentation_and_repeat_dedup(order_app, tmp_path):
    config = {'interval': 0, 'ai': {'enabled': False}}
    first = scan(order_app, 'http://127.0.0.1:8234', config, tmp_path / 'reports/scans/first', browser=False)
    second = scan(order_app, 'http://127.0.0.1:8234', config, tmp_path / 'reports/scans/second', browser=False)
    assert first['build']['status'] == 'unverified'
    issue = next(i for i in first['issues'] if i['cwe'] == 'CWE-89')
    assert issue['status'] == 'Confirmed' and issue['source_link']['status'] == 'Confirmed source link'
    assert issue['source_link']['policy'] == 'prd' and first['correlation']['policy'] == 'prd'
    assert len(issue['findings']) == 2 and issue['evidence'] and issue['fix']
    assert 'Deployment identity is unverified' in issue['reasoning']['native']
    assert issue['source']['file'] == 'orders.py' and issue['source']['line'] == 10
    assert 'db.execute' in issue['source']['snippet']
    assert issue['severity'] == 'high' and issue['risk_score'] == 9.0
    assert len(issue['correlation_checks']) == 8
    for name in ('Runtime trace', 'Deployment identity'):
        check = next(c for c in issue['correlation_checks'] if c['name'] == name)
        assert check['result'] == 'unknown' and not check['required']
    assert {edge['kind'] for edge in issue['evidence_graph']['edges']} == {'prd_input_correlation'}
    assert issue['evidence_graph']['source_flows'][0]['binding'] == {
        'route': '/api/orders', 'method': 'GET', 'location': 'query', 'parameter': 'id'}
    signals = [f for f in first['findings'] if f['id'] in issue['findings']]
    assert {f['origin'] for f in signals} == {'sast', 'dast'}
    assert signals[0].keys() == signals[1].keys()
    assert all(f['fingerprint'] == f['id'] and f['cwe'] == 'CWE-89' for f in signals)
    dast = next(f for f in signals if f['origin'] == 'dast')
    assert len(dast['runtime']) == len(dast['evidence'])
    view = issue_view(issue, first)
    assert view['dast']['parameter'] == 'id' and view['dast']['method'] == 'GET'
    assert view['dast']['url'].startswith('http://127.0.0.1:8234/api/orders')
    assert 'AND' in view['dast']['payload']
    assert view['dast']['payload'] == json.loads(view['dast']['request'])['tested_input']['value']
    assert view['sast']['snippet']['code'] and view['fix'] and view['reasoning']['ai_status'] == 'disabled'
    assert view['correlation']['accepted'] and view['correlation']['source_link']['policy'] == 'prd'
    route = next(r for r in routes_view(first) if r['path'] == '/api/orders')
    assert route['handler'] == {'name': 'get_orders', 'file': 'orders.py', 'line_start': 5, 'line_end': 12}
    assert route['params'] == ['id']
    assert not second['comparison']['new']
    assert set(second['comparison']['still_observed']) == {i['id'] for i in first['issues']}
    again = next(i for i in second['issues'] if i['id'] == issue['id'])
    assert again['first_seen'] == issue['first_seen']
    assert again['evidence'] != issue['evidence']  # fresh randomized probes, stable bug ID
    other = scan(order_app, 'http://127.0.0.1:8235', config, tmp_path / 'reports/scans/other', browser=False)
    assert other['comparison']['previous_scan'] is None


@pytest.mark.parametrize('boundary', ['method', 'parameter', 'location', 'cwe', 'mismatch', 'strict', 'ambiguous', 'unverified_runtime'])
@pytest.mark.parametrize('cwe', ['CWE-89', 'CWE-79', 'CWE-78', 'CWE-22', 'CWE-601'])
def test_correlation_boundaries_prevent_wrong_links(boundary, cwe):
    b = Binding('/api/orders', 'GET', 'id', 'query', 'get_orders')
    source = Finding('source', 'sast', cwe, 'Candidate', 'high',
        source={'file': 'orders.py', 'line': 88, 'snippet': 'db.execute(sql)'}, bindings=[deepcopy(b)])
    runtime = Finding('runtime', 'dast', cwe, 'Candidate', 'high', bindings=[deepcopy(b)], verification='verified')
    build = {'status': 'unverified'}
    analysis = Analysis('digest', [], [source], [], 1)
    strict = boundary == 'strict'
    if boundary in {'method', 'parameter', 'location'}:
        setattr(runtime.bindings[0], boundary, {'method': 'POST', 'parameter': 'other_id', 'location': 'form'}[boundary])
    if boundary == 'cwe': runtime.cwe = 'CWE-999'
    if boundary == 'mismatch': build['status'] = 'mismatch'
    if boundary == 'unverified_runtime': runtime.verification = 'unverified'
    if boundary == 'ambiguous':
        other = deepcopy(source); other.id = 'different-operation'; other.source['line'] = 90
        analysis.findings.append(other)
    issues = correlate(analysis, [runtime], build, require_build_match=strict)
    assert not any(i['status'] == 'Confirmed' for i in issues)


@pytest.mark.parametrize('location', ['query', 'form', 'json', 'path', 'header', 'cookie', 'session'])
def test_all_input_locations_preserve_the_actual_tested_payload(location):
    from navi.transport import Response
    from navi.runtime import Runtime
    class Recorder:
        def set_cookie(self, *a): pass
        def request(self, *a, **k):
            return Response(200, {}, b'ok', 'http://127.0.0.1/test', 0,
                            {'method': 'GET', 'url': 'http://127.0.0.1/test', 'headers': {'Authorization': '[redacted]'}})
    config = {'requests': {'GET /test': {'prepare': {'path': '/prepare', 'parameter': 'id'}}}}
    runtime = Runtime(Analysis(None, [], [], [], 0), 'http://127.0.0.1', config, browser=False, transport=Recorder())
    binding = Binding('/test', 'GET', 'id', location, 'handler')
    response = runtime.request(binding, 'injected-value')
    observation = runtime_observations([response.evidence()], [vars(binding)])[0]
    assert observation['payload'] == 'injected-value' and observation['location'] == location
    assert observation['parameter'] == 'id'
    assert observation['request']['headers']['Authorization'] == '[redacted]'


def test_ai_analysis_reaches_frontend_with_native_link_intact(order_app, tmp_path, monkeypatch):
    from test_ai_correlation import CorrelationModel, install_model
    install_model(monkeypatch, CorrelationModel())
    report = scan(order_app, 'http://127.0.0.1:8234', {'interval': 0, 'ai': {'enabled': True}}, tmp_path / 'ai', browser=False)
    issue = next(i for i in report['issues'] if i['cwe'] == 'CWE-89')
    view = issue_view(issue, report)
    assert report['ai']['call_attempts'] == 1
    assert view['reasoning']['ai'] and view['reasoning']['ai_status'] == 'reviewed'
    assert view['reasoning']['ai_provider'] == 'groq' and view['reasoning']['ai_model'] == 'openai/gpt-oss-20b'
    assert view['status'] == 'confirmed' and view['correlation']['accepted']
    assert view['correlation']['source_link']['status'] == 'Confirmed source link'


def test_priority_is_confirmed_first_then_risk_even_for_unverified_critical_code():
    from navi.worklist import build_worklist
    source = Finding('high-risk-source', 'sast', 'CWE-78', 'OS command injection', 'critical', source={'file': 'run.py', 'line': 1})
    runtime = Finding('medium-risk-runtime', 'dast', 'CWE-601', 'Open redirect', 'medium', verification='verified')
    analysis = Analysis(None, [], [source], [], 1)
    report = {'issues': correlate(analysis, [runtime], {'status': 'unverified'}), 'findings': [source.to_dict(), runtime.to_dict()]}
    build_worklist(report)
    assert [i['id'] for i in report['issues']] == ['high-risk-source', 'medium-risk-runtime']
    assert [i['triage']['rank'] for i in report['issues']] == [1, 2]


@pytest.mark.parametrize('quote', ["'", '"', ''])
def test_sql_boolean_context_variants_use_real_database(quote, connect_app):
    import sqlite3
    from flask import Flask, request
    from navi.runtime import Runtime
    app = Flask(__name__)
    @app.get('/lookup')
    def lookup():
        db = sqlite3.connect(':memory:')
        try:
            db.execute('CREATE TABLE items(id INTEGER, value TEXT)')
            db.execute("INSERT INTO items VALUES(1, 'entry')")
            value = request.args.get('id', '1')
            return str(db.execute('SELECT value FROM items WHERE id=' + quote + value + quote).fetchall())
        except sqlite3.Error:
            return 'query failed', 400
        finally:
            db.close()
    connect_app(app)
    runtime = Runtime(Analysis(None, [], [], [], 0), 'http://127.0.0.1', {'interval': 0}, browser=False)
    outcome, _, evidence = runtime.sql(Binding('/lookup', 'GET', 'id', 'query', 'lookup'))
    assert outcome == 'verified'
    assert [e['label'] for e in evidence[-2:]] == ['repeated true condition', 'repeated false condition']


@pytest.mark.parametrize('separator', ['; ', "'; ", '"; ', '|', '\n', '&&', '||'])
def test_command_separator_variants_execute_independent_markers(separator, connect_app):
    import subprocess
    import secrets
    from flask import Flask, request
    from navi.runtime import Runtime
    app = Flask(__name__)
    seed = 'job_' + secrets.token_hex(5)
    @app.get('/execute')
    def execute():
        value = request.args.get('input', '')
        # Independent fixture: only this case's separator reaches a POSIX shell.
        # Invalid alternatives are rejected, so the verifier must reach each variant.
        if not value.startswith(seed + separator): return 'ready'
        if separator == "'; ": command = "printf %s '" + value + "'"
        elif separator == '"; ': command = 'printf %s "' + value + '"'
        elif separator == '||': command = 'false ' + value
        else: command = 'printf %s ' + value
        return subprocess.run(['/bin/sh', '-c', command], capture_output=True, timeout=2).stdout.decode()
    connect_app(app)
    runtime = Runtime(Analysis(None, [], [], [], 0), 'http://127.0.0.1',
                      {'interval': 0, 'requests': {'GET /execute': {'query': {'input': seed}}}}, browser=False)
    outcome, _, evidence = runtime.command(Binding('/execute', 'GET', 'input', 'query', 'execute'))
    assert outcome == 'verified'
    proofs = [e['execution_proof'] for e in evidence if e.get('execution_proof', {}).get('observed')]
    assert len(proofs) == 2 and proofs[0]['expected_marker'] != proofs[1]['expected_marker']
    assert all(not p['marker_in_payload'] for p in proofs)
