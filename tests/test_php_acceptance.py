"""Execute independently generated PHP, with optional real loopback HTTP.

The CLI bridge tests real PHP bodies/shell execution but does not pretend to be
HTTP or to capture SAPI headers. The separate server test covers actual HTTP.
Neither test supplies vulnerability routes, request seeds or branch selectors.
"""
import json
import secrets
import shutil
import socket
import subprocess
import time
from urllib.parse import urlencode

import pytest

from navi.engine import scan
from navi.static import analyze
from navi.runtime import Runtime
from navi.browser import BrowserUnavailable
from navi.transport import Response, TargetError, Transport

pytestmark = pytest.mark.skipif(not shutil.which('php'), reason='PHP CLI required')


@pytest.fixture
def independent_php(tmp_path):
    root = tmp_path / 'php-application'
    public = root / 'public'
    public.mkdir(parents=True)
    names = {key: 'p' + secrets.token_hex(5) for key in ['unsafe', 'safe', 'reflect', 'parameter', 'gate', 'submit', 'function', 'redirect']}
    parameter, gate, submit, function = (names[key] for key in ['parameter', 'gate', 'submit', 'function'])
    (root / 'helpers.php').write_text(f'''<?php
function {function}($argument) {{
    return shell_exec('printf "job: %s" ' . $argument);
}}
function {function}_safe($argument) {{
    return shell_exec('printf "job: %s" ' . escapeshellarg($argument));
}}
''')
    forms = []
    for kind in ['unsafe', 'safe', 'reflect']:
        route = names[kind] + '.php'
        forms.append(f'''<form method="post" action="{route}">
<input type="hidden" name="mode" value="{gate}">
<input name="{parameter}" value="sample">
<button name="{submit}" value="Execute">Execute</button></form>''')
        result = f'{function}($value)' if kind == 'unsafe' else f'{function}_safe($value)' if kind == 'safe' else '$value'
        (public / route).write_text(f'''<?php
require_once dirname(__DIR__) . '/helpers.php';
$value = $_POST['{parameter}'] ?? '';
if (isset($_POST['{submit}']) && ($_POST['mode'] ?? '') === '{gate}') {{
    echo {result};
}} else {{ echo 'Submit the form'; }}
''')
    destination = '/p' + secrets.token_hex(6) + '.php'
    forms.append(f'<form action="{names["redirect"]}.php"><input name="destination" value="{destination}"></form>')
    (public / (names['redirect'] + '.php')).write_text(f'''<?php
$destination = $_GET['destination'] ?? '{destination}';
if (str_contains($destination, '{destination}')) {{ header('Location: ' . $destination); }}
else {{ http_response_code(400); }}
''')
    (public / 'index.php').write_text('<!doctype html><h1>Independent PHP jobs</h1>' + '\n'.join(forms))
    return root, public, names


class PHPBodyTransport:
    """Test-only subprocess bridge for the generated fixture, never user code."""
    runner = r'''$data=json_decode(stream_get_contents(STDIN),true);
$_GET=$data['query'];$_POST=$data['form'];$_REQUEST=array_merge($_GET,$_POST);
$_SERVER['REQUEST_METHOD']=$data['method'];chdir(dirname($data['file']));
ob_start();include $data['file'];$body=ob_get_clean();
echo json_encode(['status'=>http_response_code()?:200,'body'=>$body]);'''

    def __init__(self, public):
        self.public, self.count, self.max_requests = public, 0, 600
        self.target = 'http://127.0.0.1:9999'

    def request(self, route, method='GET', *, query=None, form=None, **kwargs):
        if self.count >= self.max_requests: raise TargetError('Request budget exhausted.')
        self.count += 1
        path = self.public / (route.lstrip('/') or 'index.php')
        assert path.resolve().is_relative_to(self.public)
        url = self.target + route + ('?' + urlencode(query) if query else '')
        metadata = {'method': method, 'url': url, 'query': query or {}, 'form': form, 'headers': {}}
        if not path.is_file(): return Response(404, {'content-type': 'text/html'}, b'missing', url, 0, metadata)
        process = subprocess.run(['php', '-d', 'display_errors=0', '-r', self.runner],
                                 input=json.dumps({'file': str(path), 'query': query or {}, 'form': form or {}, 'method': method}),
                                 capture_output=True, text=True, timeout=3)
        assert process.returncode == 0, process.stderr
        data = json.loads(process.stdout)
        return Response(data['status'], {'content-type': 'text/html'}, data['body'].encode(), url, 0, metadata)


def assert_shell_result(report, names):
    findings = [i for i in report['issues'] if i['cwe'] == 'CWE-78' and i['verification'] == 'verified']
    assert len(findings) == 1
    issue = findings[0]
    assert issue['source_link']['status'] == 'Confirmed source link'
    candidate = issue
    assert candidate['source']['file'] == 'helpers.php' and candidate['source']['line'] == 3
    assert candidate['source']['function'] == names['function']
    assert issue['runtime'] and issue['fix'] and issue['reasoning']
    assert any(b['method'] == 'POST' and b['parameter'] == names['parameter'] for b in issue['bindings'])
    assert any(p['route'] == '/' for p in report['discovery']['pages'])
    assert candidate['evidence_graph']['source_flows']
    assert any('execution trace' in reason for reason in issue['link_reasons'])
    assert all('/' + names['safe'] + '.php' != b['route'] for b in issue['bindings'])
    return issue


@pytest.mark.parametrize('scanner', ['native', 'templates'])
def test_actual_php_discovery_command_proof_and_repeat_identity(independent_php, tmp_path, scanner):
    root, public, names = independent_php
    config = {'php_document_root': 'public', 'allowed_methods': ['GET', 'POST'], 'ai': {'enabled': False}, 'interval': 0}
    config['scanners'] = {'mode': scanner}
    reports = []
    for number in range(2):
        bridge = PHPBodyTransport(public)
        report = scan(root, bridge.target, config, tmp_path / 'reports/scans' / str(number), browser=False, transport=bridge)
        assert_shell_result(report, names)
        reports.append(report)
    assert {i['id'] for i in reports[0]['issues']} == {i['id'] for i in reports[1]['issues']}
    # Plain reflection and escapeshellarg controls must not pass shell proof.
    for name in ['safe', 'reflect']:
        checks = [c for c in reports[0]['checks'] if c['cwe'] == 'CWE-78' and c['route'] == '/' + names[name] + '.php']
        assert checks and all(c['outcome'] == 'not_reproduced' for c in checks)


def test_live_php_http_without_vulnerability_configuration(independent_php, tmp_path):
    root, public, names = independent_php
    try:
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
    except PermissionError:
        pytest.skip('This environment prohibits loopback sockets; real PHP HTTP validation must run on the host.')
    target = f'http://127.0.0.1:{port}'
    with (tmp_path / 'php-server.log').open('w') as log:
        server = subprocess.Popen(['php', '-S', f'127.0.0.1:{port}', '-t', str(public)], stdout=log, stderr=log)
        try:
            transport = Transport(target, interval=0)
            for _ in range(50):
                if server.poll() is not None: pytest.fail('Temporary PHP server failed to start.')
                try:
                    if transport.request('/').status == 200: break
                except OSError: time.sleep(.05)
            else: pytest.fail('Temporary PHP server did not become ready.')
            report = scan(root, target, {'php_document_root': 'public', 'allowed_methods': ['GET', 'POST'],
                          'interval': 0, 'max_requests': 600, 'ai': {'enabled': False}}, tmp_path / 'http-report', browser=False)
            assert_shell_result(report, names)
            redirects = [i for i in report['issues'] if i['cwe'] == 'CWE-601' and i['verification'] == 'verified']
            assert len(redirects) == 1
            candidate = redirects[0]
            assert candidate['source']['file'] == 'public/' + names['redirect'] + '.php'
            assert any(e.get('variant') == 'observed-destination-path' for e in redirects[0]['evidence'])
        finally:
            server.terminate()
            try: server.wait(timeout=3)
            except subprocess.TimeoutExpired: server.kill(); server.wait(timeout=3)


@pytest.fixture
def php_sql_app(tmp_path):
    public = tmp_path / 'database-app'
    public.mkdir()
    name, parameter = 'p' + secrets.token_hex(5), 'q' + secrets.token_hex(5)
    seed = str(secrets.randbelow(800) + 100)
    forms = []
    for protected in [False, True]:
        script = name + ('_bound' if protected else '') + '.php'
        forms.append(f'<form action="{script}"><input name="{parameter}" value="{seed}"></form>')
        sql = "$stmt=$db->prepare('SELECT name FROM items WHERE id=?'); $stmt->execute([$value]);" if protected else "$stmt=$db->query(\"SELECT name FROM items WHERE id='$value'\");"
        (public / script).write_text(f'''<?php
$db = new PDO('sqlite::memory:');
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$db->exec('CREATE TABLE items (id INTEGER, name TEXT)');
$db->exec("INSERT INTO items VALUES ({seed}, 'fixture-product')");
$value=$_GET['{parameter}'] ?? '';
{sql}
echo json_encode($stmt->fetchAll(PDO::FETCH_COLUMN));
''')
    (public / 'index.php').write_text('\n'.join(forms))
    return public, name, parameter


def test_php_sql_source_locates_query_and_rejects_bound_decoy(php_sql_app):
    public, name, parameter = php_sql_app
    findings = [f for f in analyze(public).findings if f.cwe == 'CWE-89']
    assert len(findings) == 1
    assert findings[0].source['file'] == name + '.php'
    assert findings[0].source['line'] == 7
    assert {b.parameter for b in findings[0].bindings} == {parameter}


def test_real_php_sqlite_with_discovered_nondefault_seed(php_sql_app, tmp_path):
    result = subprocess.run(['php', '-r', 'echo extension_loaded("pdo_sqlite") ? "yes" : "no";'], capture_output=True, text=True, timeout=3)
    if result.stdout != 'yes': pytest.skip('PHP PDO SQLite driver is required for actual PHP SQL execution.')
    public, name, parameter = php_sql_app
    transport = PHPBodyTransport(public)
    report = scan(public, transport.target, {'ai': {'enabled': False}, 'interval': 0}, tmp_path / 'sql-report', transport=transport, browser=False)
    findings = [i for i in report['issues'] if i['cwe'] == 'CWE-89' and i['verification'] == 'verified']
    assert len(findings) == 1 and findings[0]['source_link']['status'] == 'Confirmed source link'
    candidate = findings[0]
    assert candidate['source']['file'] == name + '.php'
    assert any(c['route'] == '/' + name + '_bound.php' and c['cwe'] == 'CWE-89' and c['outcome'] == 'not_reproduced' for c in report['checks'])


def test_actual_php_html_browser_execution(independent_php, tmp_path):
    root, public, names = independent_php
    # A missing browser is a skipped execution check, never synthetic proof.
    runtime = Runtime(analyze(root, {'php_document_root': 'public'}), 'http://127.0.0.1', {}, transport=PHPBodyTransport(public))
    try: runtime.browser.start()
    except BrowserUnavailable as error: pytest.skip(str(error))
    finally: runtime.browser.close()
    transport = PHPBodyTransport(public)
    report = scan(root, transport.target, {'php_document_root': 'public', 'allowed_methods': ['GET', 'POST'],
                  'interval': 0, 'ai': {'enabled': False}}, tmp_path / 'browser-report', transport=transport)
    assert any(i['cwe'] == 'CWE-79' and i['source_link']['status'] == 'Confirmed source link' and
               i['source']['file'] == 'public/' + names['reflect'] + '.php'
               for i in report['issues'])
