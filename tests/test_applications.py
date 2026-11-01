from html import escape
import json
from pathlib import Path
import secrets
import shutil
import sqlite3
from urllib.parse import unquote

from flask import Flask, make_response, request, session
import pytest

from navi.discovery import authenticate, discover, local_reference, Page
from navi.model import Analysis, Binding
from navi.runtime import Runtime, load_config
from navi.static import analyze
from navi.transport import Transport, TargetError
from conftest import ROOT


def empty_analysis():
    return Analysis("unknown", [], [], [], 0, {"nodes": [], "edges": []})


def test_login_cookies_csrf_rotation_and_redaction(connect_app):
    app = Flask(__name__); app.secret_key = "local-session-test"
    @app.route('/login.php', methods=['GET', 'POST'])
    def login():
        if request.method == 'GET':
            session['csrf'] = secrets.token_hex(8)
            return f'<form><input type="hidden" name="user_token" value="{session["csrf"]}"></form>'
        if request.form.get('user_token') != session.get('csrf') or request.form.get('password') != 'local-pass': return 'denied', 403
        session['user'] = 'admin'
        result = make_response('', 302)
        result.headers['Location'] = 'https://outside.invalid/'
        result.set_cookie('second_cookie', 'present')
        return result
    @app.get('/index.php')
    def index():
        if session.get('user') != 'admin' or request.cookies.get('second_cookie') != 'present': return 'login', 403
        return '<a href="logout.php">Logout</a>'
    @app.route('/edit', methods=['GET', 'POST'])
    def edit():
        if request.method == 'GET':
            session['csrf'] = secrets.token_hex(8)
            return f'<input type="hidden" name="user_token" value="{session["csrf"]}">'
        if request.form.get('user_token') != session.pop('csrf', None): return 'bad token', 403
        return request.form['name']
    connect_app(app)
    config = {'session': {'login': {'path': '/login.php', 'form': {'password': 'local-pass'}, 'csrf_field': 'user_token', 'verify_path': '/index.php', 'success_contains': 'logout.php'}},
              'requests': {'POST /edit': {'form': {'name': 'seed'}, 'csrf': {'path': '/edit', 'field': 'user_token', 'location': 'form'}}}}
    transport = Transport('http://127.0.0.1', interval=0)
    authenticate(transport, config)
    assert transport.count == 3  # No request to the login response's external Location.
    runtime = Runtime(empty_analysis(), 'http://127.0.0.1', config, transport=transport)
    for text in ['one', 'two']:
        response = runtime.request(Binding('/edit', 'POST', 'name', 'form', ''), text)
        assert response.status == 200 and response.text == text
        assert response.evidence()['request']['headers']['Cookie'] == '[redacted]'


def test_failed_login_stops_authenticated_probes(connect_app):
    app = Flask(__name__)
    app.add_url_rule('/login', 'login', lambda: 'no', methods=['GET', 'POST'])
    app.add_url_rule('/verify', 'verify', lambda: ('denied', 403))
    connect_app(app)
    runtime = Runtime(empty_analysis(), 'http://127.0.0.1', {'session': {'login': {'path': '/login', 'form': {}, 'verify_path': '/verify', 'success_contains': 'logout'}}})
    assert runtime.run() == []
    assert runtime.transport.count == 3
    assert any(g['component'] == 'authentication' for g in runtime.gaps)


def test_discovery_follows_base_path_and_form_semantics(connect_app):
    app = Flask(__name__)
    app.add_url_rule('/portal/start', 'start', lambda: '''<a href="next?id=1">next</a><a href="https://elsewhere.invalid/">external</a>
      <a href="/outside">outside base</a><a href="logout.php">logout</a>
      <form action="submit" method="post"><input type="hidden" name="user_token" value="token">
      <input name="name"><select name="choice"><option value="a">A</option><option value="b" selected>B</option></select>
      <input type="submit" name="save" value="Save"><input type="submit" name="btnClear" value="Clear"></form>''')
    app.add_url_rule('/portal/next', 'next', lambda: 'done')
    connect_app(app)
    config = {'allowed_methods': ['GET', 'POST'], 'discovery': {'enabled': True, 'paths': ['/start']}}
    inputs, pages, gaps = discover(Transport('http://127.0.0.1/portal', interval=0), config)
    assert {p['route'] for p in pages} == {'/start', '/next'}
    assert {b.parameter for b in inputs} == {'id', 'name', 'choice'}
    form = config['requests']['POST /submit']
    assert form['form']['choice'] == 'b'
    assert form['form']['save'] == 'Save' and 'btnClear' not in form['form']
    assert form['form_refresh']['path'] == '/start'
    assert form['form']['user_token'] == 'token'
    assert local_reference('http://127.0.0.1/portal', 'http://127.0.0.1/portal/start', '//evil.invalid/x') is None
    assert local_reference('http://127.0.0.1/portal', 'http://127.0.0.1/portal/start', '/portal/%2e%2e/admin') is None


@pytest.mark.parametrize('location', ['query', 'form', 'cookie', 'session'])
@pytest.mark.parametrize('protected', [False, True])
def test_sql_across_request_locations_with_html_echo(connect_app, location, protected):
    app = Flask(__name__); app.secret_key = 'test-state'
    @app.post('/set-id')
    def set_id():
        session['id'] = request.form['id']
        return 'stored'
    @app.route('/sql', methods=['GET', 'POST'])
    def sql():
        value = (request.args.get('id') if location == 'query' else request.form.get('id') if location == 'form'
                 else unquote(request.cookies.get('id', '')) if location == 'cookie' else session.get('id', ''))
        with sqlite3.connect(':memory:') as db:
            db.execute('CREATE TABLE items (id INTEGER, name TEXT)'); db.execute("INSERT INTO items VALUES (1,'Alice'),(2,'Bob')")
            try:
                rows = db.execute('SELECT name FROM items WHERE id=?', (value,)).fetchall() if protected else db.execute('SELECT name FROM items WHERE id=' + value).fetchall()
            except sqlite3.Error: return 'invalid query', 400
        return f'<form><input type="hidden" value="{secrets.token_hex(8)}"></form><pre>ID: {escape(value)}<br>' + '<br>'.join(r[0] for r in rows) + '</pre>'
    connect_app(app)
    method = 'POST' if location == 'form' else 'GET'
    settings = {'cookies' if location == 'cookie' else location: {'id': '1'}} if location != 'session' else {'prepare': {'path': '/set-id', 'parameter': 'id', 'value': '1'}}
    config = {'requests': {f'{method} /sql': settings}, 'interval': 0}
    result = Runtime(empty_analysis(), 'http://127.0.0.1', config).sql(Binding('/sql', method, 'id', location, ''))
    assert result[0] == ('not_reproduced' if protected else 'verified'), result[1]


def test_html_reflection_and_random_content_cannot_prove_sql(connect_app):
    app = Flask(__name__)
    @app.get('/echo')
    def echo(): return '<pre>' + escape(request.args.get('id', '')) + '</pre>'
    @app.get('/random')
    def random(): return secrets.token_hex(10)
    connect_app(app)
    runtime = Runtime(empty_analysis(), 'http://127.0.0.1', {'interval': 0})
    assert runtime.sql(Binding('/echo', 'GET', 'id', 'query', ''))[0] == 'not_reproduced'
    assert runtime.sql(Binding('/random', 'GET', 'id', 'query', ''))[0] == 'inconclusive'


def test_blind_sql_with_repeated_404_false_control(connect_app):
    app = Flask(__name__)
    @app.get('/blind')
    def blind():
        with sqlite3.connect(':memory:') as db:
            try: row = db.execute('SELECT 1 WHERE 1=' + request.args.get('id', '1')).fetchone()
            except sqlite3.Error: return 'query rejected', 400
        return ('exists', 200) if row else ('missing', 404)
    connect_app(app)
    runtime = Runtime(empty_analysis(), 'http://127.0.0.1', {'interval': 0})
    assert runtime.sql(Binding('/blind', 'GET', 'id', 'query', ''))[0] == 'verified'


@pytest.mark.parametrize('mode', ['absolute', 'scheme-relative', 'substring', 'protected'])
def test_redirect_variants_and_fixed_allowlist(connect_app, mode):
    app = Flask(__name__)
    destination = '/' + secrets.token_hex(5) + '.php'
    @app.get('/redirect')
    def redirect():
        value = request.args.get('next', '')
        allowed = mode == 'absolute' or (mode == 'scheme-relative' and 'http:' not in value and 'https:' not in value) or (mode == 'substring' and destination in value)
        return ('', 302, {'Location': value}) if allowed else ('no', 400)
    connect_app(app)
    result = Runtime(empty_analysis(), 'http://127.0.0.1', {'interval': 0, 'requests': {'GET /redirect': {'query': {'next': destination}}}}).redirect(Binding('/redirect', 'GET', 'next', 'query', ''))
    assert result[0] == ('not_reproduced' if mode == 'protected' else 'verified')


def test_dast_discovers_proof_without_static_finding(connect_app):
    app = Flask(__name__)
    app.add_url_rule('/', 'index', lambda: '<form action="/go"><input name="next" value="/home"></form>')
    app.add_url_rule('/go', 'go', lambda: ('', 302, {'Location': request.args.get('next', '/home')}))
    connect_app(app)
    runtime = Runtime(empty_analysis(), 'http://127.0.0.1', {'interval': 0, 'discovery': {'enabled': True}}, browser=False)
    findings = runtime.run()
    assert any(f.cwe == 'CWE-601' and f.verification == 'verified' for f in findings)
    assert runtime.discovered_inputs


@pytest.mark.parametrize('field,value', [('discovery', {'paths': ['https://example.org/']}), ('php_routes', [{'route': '/x', 'file': '../x.php'}]), ('session', {'login': {'path': '/login'}})])
def test_application_config_rejects_invalid_scope(tmp_path, field, value):
    file = tmp_path / 'policy.json'; file.write_text(json.dumps({field: value}))
    with pytest.raises(ValueError): load_config(str(file))


def test_stored_workflow_does_not_write_when_browser_unavailable(connect_app):
    app = Flask(__name__)
    writes = []
    app.add_url_rule('/write', 'write', lambda: writes.append(request.form.to_dict()) or 'ok', methods=['POST'])
    connect_app(app)
    runtime = Runtime(empty_analysis(), 'http://127.0.0.1', {'allowed_methods': ['GET', 'POST'], 'stored_xss': [
        {'write': {'route': '/write', 'parameter': 'text'}, 'read': {'route': '/read'}, 'cleanup': {'route': '/clean', 'form': {}}}]}, browser=False)
    runtime.stored_xss()
    assert not writes and not runtime.findings
    assert runtime.checks[0].outcome == 'inconclusive'


def test_stored_workflow_separate_read_and_cleanup_even_without_execution(connect_app, monkeypatch):
    app = Flask(__name__); records = []; stages = []
    @app.post('/write')
    def write():
        stages.append('write'); records.append(request.form['text']); return request.form['text']
    @app.get('/read')
    def read():
        stages.append('read'); return ''.join(escape(record) for record in records)
    @app.post('/clean')
    def clean():
        stages.append('clean'); records.clear(); return '', 204
    connect_app(app)
    runtime = Runtime(empty_analysis(), 'http://127.0.0.1', {'allowed_methods': ['GET', 'POST'], 'stored_xss': [
        {'write': {'route': '/write', 'parameter': 'text'}, 'read': {'route': '/read'}, 'cleanup': {'route': '/clean', 'form': {}}}]})
    # This unit check tests workflow ordering, not JavaScript execution proof.
    monkeypatch.setattr(runtime.browser, 'start', lambda: None)
    monkeypatch.setattr(runtime.browser, 'verify', lambda response, token: {'executed': False})
    runtime.stored_xss()
    assert stages == ['read', 'write', 'read', 'clean', 'read']
    assert not records and not runtime.findings
    assert runtime.checks[0].outcome == 'not_reproduced'


def test_stored_read_is_not_correlated_to_a_write_time_echo():
    from navi.model import Finding
    from navi.correlate import correlate
    binding = Binding('/message', 'POST', 'text', 'form', 'configured stored-XSS workflow')
    static = Finding('static', 'sast', 'CWE-79', 'XSS', 'high', source={'file': 'app.py', 'line': 10}, bindings=[binding])
    analysis = empty_analysis(); analysis.findings = [static]
    finding = Finding('runtime', 'dast', 'CWE-79', 'XSS', 'high', bindings=[binding], verification='verified')
    assert {issue['status'] for issue in correlate(analysis, [finding], {'status': 'matched'})} == {'Code only', 'Runtime only'}
