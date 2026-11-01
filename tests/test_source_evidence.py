"""Source attribution regressions; these are local fixtures, not unseen accuracy scores."""
import base64
from copy import deepcopy
import hashlib
import hmac
import json
import runpy

import pytest

from navi.correlate import correlate
from navi.engine import scan
from navi.model import Finding
from navi.static import analyze
from navi.tracing import verify

KEY = b'synthetic-test-key-with-at-least-32-bytes'


def signed(data):
    encoded = base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip('=')
    return encoded, hmac.new(KEY, encoded.encode(), hashlib.sha256).hexdigest()


def payload(analysis, finding, nonce='a' * 32):
    return {'version': 2, 'request_id': nonce, 'method': 'GET', 'path': '/products',
            'source_digest': analysis.digest, 'truncated': False, 'operations': [
                {'operation_id': finding.id, 'file': finding.source['file'], 'line': finding.source['line'],
                 'cwe': finding.cwe, 'inputs': [{'location': 'query', 'parameter': 'id'}]}]}


@pytest.fixture
def flow_app(tmp_path):
    (tmp_path / 'app.py').write_text('''from flask import Flask, request
app = Flask(__name__)
def user(db, value):
    query = 'SELECT * FROM users WHERE id=' + value
    return db.execute(query)
def product(db, value):
    return db.execute('SELECT * FROM products WHERE id=' + str(int(value)))
@app.get('/products')
def products():
    value = request.args.get('id')
    user(None, value)
    product(None, value)
    return 'done'
''')
    return tmp_path


def proof(analysis, source):
    encoded, signature = signed(payload(analysis, source))
    trace = verify(encoded, signature, KEY, 'a' * 32, 'GET', 'http://localhost/products?id=1', analysis.digest)
    return Finding('runtime', 'dast', source.cwe, source.title, source.severity,
                   bindings=deepcopy(source.bindings), verification='verified', evidence=[{
                       'request': {'method': 'GET', 'trace_request_id': 'a' * 32,
                                   'tested_input': {'route': '/products', 'location': 'query', 'parameter': 'id', 'value': '1 AND 1=1'}},
                       'trace': trace}])


def test_exact_input_flow_excludes_sanitized_sibling_and_build_is_mandatory(flow_app):
    analysis = analyze(flow_app)
    sql = [f for f in analysis.findings if f.cwe == 'CWE-89']
    assert len(sql) == 1 and sql[0].source['function'] == 'user'
    graph = sql[0].source_flows[0]
    assert graph['complete']
    assert {'http_input', 'input_source', 'propagation', 'sensitive_sink'} <= {n['kind'] for n in graph['nodes']}
    assert any('query' in n.get('label', '') for n in graph['nodes'])
    assert graph['edges'] and graph['operation_id'] == sql[0].id
    runtime = proof(analysis, sql[0])
    issues = correlate(analysis, [runtime], {'status': 'matched'})
    confirmed = next(i for i in issues if i['status'] == 'Confirmed')
    assert confirmed['source_link']['status'] == 'Confirmed source link'
    assert confirmed['evidence_graph']['edges'][0]['to_operation'] == sql[0].id
    for strict in (True, False):
        issues = correlate(analysis, [runtime], {'status': 'unverified'}, require_build_match=strict)
        issue = next(i for i in issues if i['id'] == 'runtime')
        assert issue['verification'] == 'verified'
        assert issue['source_link']['status'] == 'Probable source link'
        assert issue['source'] is None and issue['findings'] == ['runtime']


@pytest.mark.parametrize('boundary', ['missing_trace', 'legacy_trace', 'wrong_input', 'other_operation', 'request_replay', 'unverified_runtime', 'external_scanner', 'build_mismatch', 'incomplete_flow', 'missing_flow', 'wrong_line'])
def test_insufficient_evidence_never_confirms(flow_app, boundary):
    analysis = analyze(flow_app)
    source = next(f for f in analysis.findings if f.cwe == 'CWE-89')
    runtime = proof(analysis, source)
    build = {'status': 'matched'}
    trace = runtime.evidence[0]['trace']
    if boundary == 'missing_trace': runtime.evidence[0].pop('trace')
    if boundary == 'legacy_trace': trace['version'] = 1
    if boundary == 'wrong_input': trace['operations'][0]['inputs'][0]['parameter'] = 'other'
    if boundary == 'other_operation': trace['operations'][0]['operation_id'] = 'f' * 20
    if boundary == 'request_replay': trace['request_id'] = 'b' * 32
    if boundary == 'unverified_runtime': runtime.verification = 'template_match'
    if boundary == 'external_scanner': runtime.scanner = 'imported'
    if boundary == 'build_mismatch': build['status'] = 'mismatch'
    if boundary == 'incomplete_flow': source.source_flows[0]['complete'] = False
    if boundary == 'missing_flow': source.source_flows.clear()
    if boundary == 'wrong_line': source.source['line'] += 1
    issues = correlate(analysis, [runtime], build)
    assert not any(i['status'] == 'Confirmed' for i in issues)
    assert next(i for i in issues if i['id'] == 'runtime')['verification'] == runtime.verification


def test_same_line_operations_need_exact_operation_identity(flow_app):
    path = flow_app / 'app.py'
    path.write_text(path.read_text().replace("return db.execute(query)", "db.execute(query); return db.execute(query + ' ')") )
    analysis = analyze(flow_app)
    first, second = [f for f in analysis.findings if f.cwe == 'CWE-89']
    assert first.source['line'] == second.source['line'] and first.id != second.id
    runtime = proof(analysis, second)
    issues = correlate(analysis, [runtime], {'status': 'matched'})
    assert next(i for i in issues if i['status'] == 'Confirmed')['id'] == second.id
    assert next(i for i in issues if i['id'] == first.id)['status'] == 'Code only'
    both = deepcopy(runtime.evidence[0]['trace']['operations'][0]); both['operation_id'] = first.id
    runtime.evidence[0]['trace']['operations'].append(both)
    assert not any(i['status'] == 'Confirmed' for i in correlate(analysis, [runtime], {'status': 'matched'}))


def test_unknown_transformation_stays_incomplete(flow_app):
    path = flow_app / 'app.py'
    path.write_text(path.read_text().replace("query = 'SELECT * FROM users WHERE id=' + value", "query = mystery(value)"))
    analysis = analyze(flow_app)
    source = next(f for f in analysis.findings if f.cwe == 'CWE-89')
    assert not source.source_flows[0]['complete']
    assert not any(i['status'] == 'Confirmed' for i in correlate(analysis, [proof(analysis, source)], {'status': 'matched'}))


def test_competing_traced_operation_missing_from_static_results_prevents_link(flow_app):
    analysis = analyze(flow_app)
    source = next(f for f in analysis.findings if f.cwe == 'CWE-89')
    runtime = proof(analysis, source)
    other = deepcopy(runtime.evidence[0]['trace']['operations'][0])
    other.update(operation_id='b' * 20, file='unmodeled.php', line=17)
    runtime.evidence[0]['trace']['operations'].append(other)
    issues = correlate(analysis, [runtime], {'status': 'matched'})
    assert not any(i['status'] == 'Confirmed' for i in issues)
    assert next(i for i in issues if i['id'] == 'runtime')['verification'] == 'verified'


@pytest.mark.parametrize('change', ['signature', 'nonce', 'digest', 'path', 'truncated', 'operation_id', 'inputs', 'malformed'])
def test_trace_authentication_boundaries(flow_app, change):
    analysis = analyze(flow_app)
    source = next(f for f in analysis.findings if f.cwe == 'CWE-89')
    data = payload(analysis, source)
    if change == 'nonce': data['request_id'] = 'b' * 32
    if change == 'digest': data['source_digest'] = 'f' * 64
    if change == 'path': data['path'] = '/other'
    if change == 'truncated': data['truncated'] = True
    if change == 'operation_id': data['operations'][0]['operation_id'] = '../wrong'
    if change == 'inputs': data['operations'][0]['inputs'] = []
    encoded, signature = signed(data)
    if change == 'signature': signature = '0' * 64
    if change == 'malformed': encoded = 'bad*encoding'
    assert verify(encoded, signature, KEY, 'a' * 32, 'GET', 'http://localhost/products', analysis.digest)['status'] == 'rejected'


def test_real_sql_scan_to_report_with_signed_operation_evidence(tmp_path, connect_app, monkeypatch):
    from flask import g, request
    root = tmp_path / 'source'; root.mkdir()
    (root / 'application.py').write_text('''from flask import Flask, request, g
import sqlite3
app = Flask(__name__)
@app.get('/products')
def products():
    db = sqlite3.connect(':memory:')
    db.execute('CREATE TABLE products(id INTEGER, name TEXT)')
    db.execute("INSERT INTO products VALUES(1, 'entry')")
    value = request.args.get('id', '1')
    query = 'SELECT name FROM products WHERE id=' + value
    g.operation_executed = True
    try:
        return str(db.execute(query).fetchall())
    except sqlite3.Error:
        return 'invalid', 400
    finally:
        db.close()
''')
    analysis = analyze(root)
    source = next(f for f in analysis.findings if f.cwe == 'CWE-89')
    app = runpy.run_path(str(root / 'application.py'))['app']
    app.add_url_rule('/build', 'build', lambda: {'source_digest': analysis.digest})
    @app.after_request
    def instrument(response):
        nonce = request.headers.get('X-Navi-Request-ID')
        if nonce:
            data = payload(analysis, source, nonce)
            data.update(method=request.method, path=request.path)
            if not getattr(g, 'operation_executed', False): data['operations'] = []
            encoded, signature = signed(data)
            response.headers['X-Navi-Trace'] = encoded
            response.headers['X-Navi-Trace-Signature'] = signature
        return response
    connect_app(app)
    monkeypatch.setenv('NAVI_TRACE_KEY', KEY.decode())
    report = scan(root, 'http://127.0.0.1', {'interval': 0, 'trace': {'enabled': True}, 'build': {'path': '/build'},
                  'ai': {'enabled': False}, 'discovery': {'enabled': False}}, tmp_path / 'reports', browser=False)
    issue = next(i for i in report['issues'] if i['status'] == 'Confirmed')
    assert issue['source_link']['status'] == 'Confirmed source link'
    assert len(issue['findings']) == 2 and report['tracing']['verified'] > 0
    assert all(o['trace']['status'] == 'verified' for o in issue['runtime'])
    assert 'Confirmed source link' in (tmp_path / 'reports/report.html').read_text()
    from navi.ui import issue_view
    assert issue_view(issue, report)['correlation']['evidence_graph']['edges']
    saved = json.loads((tmp_path / 'reports/report.sarif').read_text())
    assert any(r['properties']['sourceLink']['status'] == 'Confirmed source link' for r in saved['runs'][0]['results'])


@pytest.mark.parametrize('cwe,body', [
    ('CWE-89', "return db.execute('SELECT * FROM t WHERE id=' + value)"),
    ('CWE-78', 'os.system(value)'),
    ('CWE-79', 'return value'),
    ('CWE-22', 'return send_file(value)'),
    ('CWE-601', 'return redirect(value)'),
])
def test_all_cwes_require_exact_binding_even_with_valid_trace(tmp_path, cwe, body):
    (tmp_path / 'app.py').write_text('from flask import Flask, request, send_file, redirect\nimport os\n'
        "app=Flask(__name__)\n@app.get('/products')\ndef products():\n    value=request.args.get('id')\n    " + body + '\n')
    analysis = analyze(tmp_path)
    source = next(f for f in analysis.findings if f.cwe == cwe)
    runtime = proof(analysis, source)
    assert any(i['status'] == 'Confirmed' for i in correlate(analysis, [runtime], {'status': 'matched'}))
    for field, wrong in [('method', 'POST'), ('route', '/unrelated'), ('location', 'form'), ('parameter', 'other_id')]:
        changed = deepcopy(runtime)
        setattr(changed.bindings[0], field, wrong)
        assert not any(i['status'] == 'Confirmed' for i in correlate(analysis, [changed], {'status': 'matched'}))


def test_flow_budget_exhaustion_cannot_become_complete_again(tmp_path):
    steps = '\n'.join(f'    value = value + {index}' for index in range(100))
    (tmp_path / 'app.py').write_text("from flask import Flask, request\napp=Flask(__name__)\n@app.get('/products')\ndef products():\n    value=request.args.get('id')\n" + steps + "\n    return db.execute(value)\n")
    analysis = analyze(tmp_path)
    source = next(f for f in analysis.findings if f.cwe == 'CWE-89')
    assert not source.source_flows[0]['complete']
    assert len(source.source_flows[0]['nodes']) <= 66  # internal bound plus HTTP/sink nodes
    assert not any(i['status'] == 'Confirmed' for i in correlate(analysis, [proof(analysis, source)], {'status': 'matched'}))
