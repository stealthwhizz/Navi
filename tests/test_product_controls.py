"""Operational regressions: scope, TLS identity, interrupted evidence, and API access."""
import io
import json
import socket
import ssl
import subprocess
import threading
from copy import deepcopy

import pytest

from navi.api import Settings, create_app
from navi.control import ScanControl, ScanStopped
from navi.engine import scan
from navi.identity import git_revision
from navi.model import Analysis
from navi.runtime import Runtime, load_config
from navi.transport import Transport, TargetError, Response, PinnedHTTPSConnection, validate_target
from test_api_reports import local_client
from conftest import ROOT


def test_explicit_scope_pins_https_hostname_and_refuses_other_origin(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("10.10.2.3", 443))])
    assert validate_target("https://staging.example/app", ["https://staging.example"]) == ("10.10.2.3", 443, "staging.example", "/app")
    for target in ["http://staging.example", "https://staging.example:444", "https://other.example"]:
        with pytest.raises(TargetError): validate_target(target, ["https://staging.example"])
    captured = {}
    class Connection:
        def __init__(self, address, port, **kwargs): captured.update(address=address, port=port, **kwargs)
        def request(self, method, url, **kwargs): captured.update(path=url)
        def getresponse(self):
            result = io.BytesIO(b"ok"); result.status = 200; result.getheaders = lambda: []
            return result
        def close(self): pass
    monkeypatch.setattr("navi.transport.PinnedHTTPSConnection", Connection)
    response = Transport("https://staging.example/app", allowed_origins=["https://staging.example"], interval=0).request("/health")
    assert captured["address"] == "10.10.2.3" and captured["server_hostname"] == "staging.example"
    assert captured["context"].check_hostname and captured["context"].verify_mode == ssl.CERT_REQUIRED
    assert response.url == "https://staging.example/app/health"


def test_tls_wrap_uses_original_hostname(monkeypatch):
    raw = object()
    def connect(self): self.sock = raw
    monkeypatch.setattr("http.client.HTTPConnection.connect", connect)
    context = ssl.create_default_context()
    connection = PinnedHTTPSConnection("10.0.0.2", 443, server_hostname="stage.example", timeout=2, context=context)
    class Context:
        def wrap_socket(self, sock, server_hostname):
            assert sock is raw and server_hostname == "stage.example"
            return "verified TLS socket"
    connection._context = Context()
    connection.connect()
    assert connection.sock == "verified TLS socket"


@pytest.mark.parametrize("address", ["169.254.169.254", "0.0.0.0", "224.0.0.1"])
def test_explicit_scope_still_rejects_special_addresses(address):
    with pytest.raises(TargetError): validate_target(f"https://{address}", [f"https://{address}"])


@pytest.mark.parametrize("route", ["/../other", "/%2e%2e/other", "/%252e%252e/other", "/%25252e%25252e/other", "/%5c../other", "/x/../../other", "/\\other"])
def test_base_path_cannot_be_escaped(route):
    with pytest.raises(TargetError): Transport("http://127.0.0.1/app").request(route)


def test_deadline_interrupts_drip_response_and_closes_connection(monkeypatch):
    now = [0.0]; closed = []
    control = ScanControl(seconds=1, clock=lambda: now[0])
    class Connection:
        def __init__(self, *a, **k): pass
        def request(self, *a, **k): pass
        def getresponse(self):
            class Stream:
                def read1(self, size): now[0] += .6; return b"x"
            return Stream()
        def close(self): closed.append(True)
    monkeypatch.setattr("navi.transport.http.client.HTTPConnection", Connection)
    with pytest.raises(ScanStopped, match="deadline"):
        Transport("http://127.0.0.1", control=control, interval=0).request("/")
    assert closed


def test_cancel_preserves_completed_runtime_evidence(shop, tmp_path):
    control = ScanControl()
    def on_event(event):
        if event["type"] == "runtime_finding": control.cancel()
    report = scan(ROOT / "examples/shop", "http://127.0.0.1:5050", load_config(str(ROOT / "examples/shop/policy.json")),
                  tmp_path, browser=False, control=control, callback=on_event)
    assert report["stop_reason"] == "cancelled" and report["status"] == "partial"
    assert any(f["origin"] == "dast" for f in report["findings"])
    assert json.loads((tmp_path / "report.json").read_text())["stop_reason"] == "cancelled"
    assert not json.loads((tmp_path / "report.sarif").read_text())["runs"][0]["invocations"][0]["executionSuccessful"]
    assert any(g["component"] == "control" for g in report["coverage"]["gaps"])


def test_cancel_during_sast_retains_prior_candidates(tmp_path):
    from navi.static import analyze
    (tmp_path / "app.py").write_text('from flask import Flask, request\napp=Flask(__name__)\n@app.get("/hello")\ndef hello():\n value=request.args.get("x")\n return f"<p>{value}</p>"\n@app.get("/second")\ndef second():\n return request.args.get("y")\n')
    class Control(ScanControl):
        def __init__(self): super().__init__(); self.calls = 0
        def check(self):
            self.calls += 1
            if self.calls == 6: self.cancel()
            super().check()
    result = analyze(tmp_path, control=Control())
    assert result.findings
    assert any(g["component"] == "control" for g in result.gaps)


def test_clean_git_revision_and_runtime_header(tmp_path):
    for args in [("init",), ("config", "user.email", "fixture@example.invalid"), ("config", "user.name", "Fixture")]:
        subprocess.run(["git", "-C", str(tmp_path), *args], check=True, capture_output=True)
    source = tmp_path / "app.py"; source.write_text("print('fixture')\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "app.py"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-m", "fixture"], check=True, capture_output=True)
    revision = git_revision(tmp_path)
    class TransportStub:
        def request(self, path): return Response(200, {"x-build-revision": revision}, b"", "", 0)
    runtime = Runtime(Analysis("digest", [], [], [], 1), "http://127.0.0.1", {"build": {"path": "/health", "kind": "git", "header": "X-Build-Revision"}},
                      transport=TransportStub(), browser=False, source=tmp_path)
    runtime.check_build()
    assert runtime.build["status"] == "matched"
    source.write_text("print('changed')\n")
    with pytest.raises(ValueError, match="clean checkout"): git_revision(tmp_path)
    runtime.check_build()
    assert runtime.build["status"] != "matched"


def test_api_token_protects_evidence_docs_and_writes(tmp_path):
    token = "cf-test-" + "a" * 40
    with local_client(create_app(Settings(output=str(tmp_path), api_token=token, allowed_hosts=("workspace.example",)))) as client:
        host = {"Host": "workspace.example"}
        assert client.get("/", headers=host).status_code == 200
        for path in ("/api/state", "/api/report.json", "/docs", "/openapi.json"):
            assert client.get(path, headers=host).status_code == 401
        assert client.get("/api/state", headers={**host, "Authorization": "Bearer wrong"}).status_code == 401
        result = client.get("/api/state", headers={**host, "Authorization": "Bearer " + token})
        assert result.status_code == 200 and token not in result.text
        assert client.post("/api/scans", json={}, headers={**host, "Authorization": "Bearer " + token}).status_code == 403
    with pytest.raises(ValueError, match="require"): create_app(Settings(allowed_hosts=("workspace.example",)))


def test_api_cancel_reaches_active_scan_control(tmp_path, monkeypatch):
    ready = threading.Event()
    def scanner(*args, control, **kwargs):
        ready.set()
        assert control.event.wait(3)
        raise ScanStopped("cancelled", "cancelled in test")
    monkeypatch.setattr("navi.api.scan", scanner)
    with local_client(create_app(Settings(source=str(ROOT / "examples/shop"), output=str(tmp_path)))) as client:
        headers = {"X-Navi": "local-scan"}
        result = client.post("/api/scans", json={}, headers=headers)
        assert ready.wait(1)
        assert client.post(f'/api/scans/{result.json()["id"]}/cancel', headers=headers).status_code == 202
        assert client.post('/api/scans/unrelated/cancel', headers=headers).status_code == 409


def test_stored_xss_cancel_after_write_still_cleans_disposable_record(connect_app, monkeypatch):
    from flask import Flask, request
    app = Flask(__name__); records = []; stages = []; control = ScanControl()
    @app.post('/write')
    def write():
        records.append(request.form['text']); stages.append('write'); return 'ok'
    @app.get('/read')
    def read(): return ''.join(records)
    @app.post('/clean')
    def clean():
        records.clear(); stages.append('clean'); return '', 204
    connect_app(app)
    runtime = Runtime(Analysis('digest', [], [], [], 0), 'http://127.0.0.1', {'allowed_methods': ['GET', 'POST'],
        'stored_xss': [{'write': {'route': '/write', 'parameter': 'text'}, 'read': {'route': '/read'}, 'cleanup': {'route': '/clean', 'form': {}}}]}, control=control)
    monkeypatch.setattr(runtime.browser, 'start', lambda: None)
    def interrupt(response, token):
        control.cancel(); control.check()
    monkeypatch.setattr(runtime.browser, 'verify', interrupt)
    with pytest.raises(ScanStopped): runtime.stored_xss()
    assert stages == ['write', 'clean'] and not records
    assert runtime.control is control and runtime.transport.control is control
    assert runtime.checks[0].outcome == 'inconclusive'
    assert any(e['label'] == 'cleanup readback' for e in runtime.checks[0].evidence)


def test_target_initialization_failure_retains_sast(tmp_path, monkeypatch):
    def fail(*a, **k): raise TargetError('not accessible')
    monkeypatch.setattr('navi.runtime.Transport', fail)
    report = scan(ROOT / 'examples/shop', 'http://127.0.0.1', {}, tmp_path, browser=False)
    assert report['status'] == 'partial' and report['summary']['code_only'] == 5
    assert (tmp_path / 'report.html').exists()
