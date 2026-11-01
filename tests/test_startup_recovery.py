"""Regressions for the user's root Playwright install, occupied port, and HTML SQL output."""
from contextlib import contextmanager
import errno
import socket
import subprocess
from types import SimpleNamespace

import pytest
from flask import Flask, request
import sqlite3
from html import escape

from navi.browser import BrowserUnavailable, BrowserVerifier, check_driver
from navi.cli import serve
from navi.model import Analysis, Binding
from navi.runtime import Runtime
from navi.server import dashboard_socket


def test_missing_distro_driver_is_reported_before_playwright_starts(monkeypatch, capsys, tmp_path):
    from playwright._impl import _driver
    from playwright import sync_api
    monkeypatch.setattr(_driver, 'compute_driver_executable', lambda: ('/usr/bin/node', str(tmp_path / 'missing/cli.js')))
    def forbidden(): pytest.fail('A broken driver must not start Playwright async tasks.')
    monkeypatch.setattr(sync_api, 'sync_playwright', forbidden)
    verifier = BrowserVerifier()
    for _ in range(2):
        with pytest.raises(BrowserUnavailable, match='driver is missing') as result: verifier.start()
        assert 'scripts/setup_environment.py' in str(result.value)
    verifier.close()
    assert 'Task exception' not in capsys.readouterr().err


def test_driver_module_failure_does_not_leak_node_traceback(monkeypatch, tmp_path, capsys):
    from playwright._impl import _driver
    node = tmp_path / 'node'; node.write_text('fixture'); node.chmod(0o755)
    cli = tmp_path / 'cli.js'; cli.write_text('fixture')
    monkeypatch.setattr(_driver, 'compute_driver_executable', lambda: (str(node), str(cli)))
    def failed(command, **kwargs):
        assert command == [str(node), str(cli), '--version'] and kwargs['capture_output']
        return SimpleNamespace(returncode=1, stderr='node: internal stack traceback')
    monkeypatch.setattr(subprocess, 'run', failed)
    with pytest.raises(BrowserUnavailable, match='startup check'): check_driver()
    assert not capsys.readouterr().err


@pytest.fixture
def sockets(monkeypatch):
    created = []
    class FakeSocket:
        busy = {8080}
        def __init__(self, *args): self.closed = False; self.port = None; created.append(self)
        def setsockopt(self, *args): pass
        def bind(self, address):
            self.port = address[1]
            if self.port in self.busy: raise OSError(errno.EADDRINUSE, 'Address already in use')
            if self.port == 0: self.port = 49152
        def listen(self, count): pass
        def getsockname(self): return '127.0.0.1', self.port
        def close(self): self.closed = True
    monkeypatch.setattr(socket, 'socket', FakeSocket)
    return created, FakeSocket


def test_default_port_falls_back_and_remains_reserved(sockets):
    created, _ = sockets
    with dashboard_socket('127.0.0.1') as listener:
        assert listener.port == 8081 and not listener.closed
        assert created[0].closed
    assert listener.closed


def test_explicit_busy_port_is_not_silently_changed(sockets):
    created, _ = sockets
    with pytest.raises(ValueError, match='--port 0'):
        with dashboard_socket('127.0.0.1', 8080): pass
    assert len(created) == 1 and created[0].closed


def test_zero_selects_available_port(sockets):
    with dashboard_socket('127.0.0.1', 0) as listener: assert listener.port == 49152


def test_exhausted_defaults_have_clear_recovery(sockets):
    created, cls = sockets; cls.busy = set(range(8080, 8090))
    with pytest.raises(ValueError, match='--port 0'):
        with dashboard_socket('127.0.0.1'): pass
    assert len(created) == 10 and all(s.closed for s in created)


def test_cli_passes_reserved_socket_to_uvicorn(monkeypatch, tmp_path, capsys):
    import uvicorn
    calls = []
    listener = SimpleNamespace(getsockname=lambda: ('127.0.0.1', 8081))
    @contextmanager
    def reserve(host, port): yield listener
    monkeypatch.setattr('navi.server.dashboard_socket', reserve)
    monkeypatch.setattr('navi.api.create_app', lambda settings: object())
    class Server:
        def __init__(self, config): assert config.port == 8081
        def run(self, sockets): calls.extend(sockets)
    monkeypatch.setattr(uvicorn, 'Server', Server)
    args = SimpleNamespace(host='127.0.0.1', port=None, command='serve', output=str(tmp_path), database_url=None, no_browser=True)
    assert serve(args, str(tmp_path), 'http://127.0.0.1:4281', None) == 0
    assert calls == [listener]
    assert 'http://127.0.0.1:8081' in capsys.readouterr().err


@pytest.mark.parametrize('protected', [False, True])
def test_quoted_sql_with_html_reflection_and_footer(connect_app, protected):
    app = Flask(__name__)
    @app.get('/sqli')
    def sql():
        value = request.args.get('id', '1')
        with sqlite3.connect(':memory:') as db:
            db.execute('CREATE TABLE users(user_id INTEGER, first_name TEXT)')
            db.execute("INSERT INTO users VALUES (1,'admin')")
            try:
                rows = db.execute('SELECT first_name FROM users WHERE user_id=?', (value,)).fetchall() if protected else db.execute(f"SELECT first_name FROM users WHERE user_id='{value}';").fetchall()
            except sqlite3.Error: return 'Invalid query', 400
        result = ''.join(f'<pre>ID: {escape(value)}<br>First name: {name}</pre>' for name, in rows)
        return '<form><input name="id"></form>' + result + '<footer>PHP 8.1.10 / 1 database / test application</footer>'
    connect_app(app)
    runtime = Runtime(Analysis('', [], [], [], 0), 'http://127.0.0.1', {'interval': 0})
    outcome, _, evidence = runtime.sql(Binding('/sqli', 'GET', 'id', 'query', ''))
    assert outcome == ('not_reproduced' if protected else 'verified')
    if not protected:
        assert any(e['label'] == 'repeated false condition' for e in evidence)
        assert evidence[1]['request']['query']['id'].endswith('-- ')


def test_reflection_with_constant_number_is_not_sql_proof(connect_app):
    app = Flask(__name__)
    @app.get('/echo')
    def echo(): return '<pre>ID: ' + escape(request.args.get('id', '1')) + '</pre><footer>1 service / v1.10</footer>'
    connect_app(app)
    runtime = Runtime(Analysis('', [], [], [], 0), 'http://127.0.0.1', {'interval': 0})
    assert runtime.sql(Binding('/echo', 'GET', 'id', 'query', ''))[0] == 'not_reproduced'
