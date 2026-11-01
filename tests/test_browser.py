import html
import secrets

import pytest

from navi.browser import BrowserUnavailable, BrowserVerifier
from navi.transport import Response


@pytest.fixture(scope="module")
def browser():
    verifier = BrowserVerifier()
    try:
        verifier.start()
    except BrowserUnavailable as error:
        pytest.skip(f"Actual browser execution requires a working Chromium: {error}")
    yield verifier
    verifier.close()


def response(payload, csp=None):
    headers = {"content-type":"text/html"}
    if csp:
        headers["content-security-policy"] = csp
    return Response(200,headers,f"<html><body>{payload}</body></html>".encode(),"http://127.0.0.1:5050/test",0)


def test_browser_observes_execution(browser):
    token = secrets.token_hex(12)
    payload = f'<svg onload="document.documentElement.setAttribute(\'data-navi-proof\',\'{token}\')"></svg>'
    result = browser.verify(response(payload),token)
    assert result["executed"] is True


def test_escaped_reflection_is_not_execution(browser):
    token = secrets.token_hex(12)
    payload = f'<script>document.documentElement.setAttribute("data-navi-proof","{token}")</script>'
    assert browser.verify(response(html.escape(payload)),token)["executed"] is False


def test_csp_is_preserved_in_replay(browser):
    token = secrets.token_hex(12)
    payload = f'<script>document.documentElement.setAttribute("data-navi-proof","{token}")</script>'
    assert browser.verify(response(payload,"default-src 'none'; script-src 'none'"),token)["executed"] is False


def test_other_network_requests_are_blocked(browser):
    result = browser.verify(response('<img src="https://example.invalid/pixel">'),"not-present")
    assert result["network_requests_blocked"] >= 1


def test_opt_in_same_origin_script_executes_with_transport(browser, monkeypatch):
    from navi.browser import options
    token = secrets.token_hex(12)
    calls = []
    class Transport:
        target = 'http://127.0.0.1:5050'
        def request(self, path, method, query=None):
            calls.append(path)
            return Response(200, {'content-type': 'application/javascript'},
                f'document.documentElement.setAttribute("data-navi-proof","{token}")'.encode(), self.target + path, 0)
    monkeypatch.setattr(browser, 'options', options({'external_scripts': True}))
    monkeypatch.setattr(browser, 'transport', Transport())
    result = browser.verify(response('<script src="/application.js"></script>'), token)
    assert result['executed'] and calls == ['/application.js']


@pytest.mark.parametrize('url', ['https://outside.invalid/script.js', 'http://127.0.0.1/other/script.js'])
def test_external_script_fetch_stays_inside_target_base(url):
    from navi.browser import script_response
    class Transport:
        target = 'http://127.0.0.1/application'
        def request(self, *args, **kwargs): pytest.fail('Out-of-scope script must not be requested')
    assert script_response(Transport(), url) is None


def test_inline_dom_payload_executes_from_url_not_response_text(browser):
    from urllib.parse import quote
    token = secrets.token_hex(6)
    payload = f'</select><svg onload="document.firstElementChild.dataset.naviProof=\'{token}\'">'
    page = response('<select><script>document.write(decodeURIComponent(location.search.substring(3)))</script></select>')
    page.url += '?x=' + quote(payload)
    assert token not in page.text
    assert browser.verify(page, token)['executed']


@pytest.mark.parametrize('escaped', [False, True])
def test_stored_xss_requires_execution_on_separate_read(browser, connect_app, escaped):
    from flask import Flask, request
    from navi.model import Analysis
    from navi.runtime import Runtime
    app = Flask(__name__); records = []
    @app.post('/write')
    def write(): records.append(request.form['text']); return request.form['text']
    @app.get('/read')
    def read(): return '<html><body>' + ''.join(html.escape(record) if escaped else record for record in records) + '</body></html>'
    @app.post('/cleanup')
    def cleanup(): records.clear(); return '', 204
    connect_app(app)
    runtime = Runtime(Analysis('', [], [], [], 0), 'http://127.0.0.1', {'allowed_methods': ['GET', 'POST'], 'stored_xss': [
        {'write': {'route': '/write', 'parameter': 'text'}, 'read': {'route': '/read'}, 'cleanup': {'route': '/cleanup'}}]})
    runtime.browser = browser
    runtime.stored_xss()
    assert runtime.checks[0].outcome == ('not_reproduced' if escaped else 'verified')
    assert not records


def test_portable_report_displays_source_reasoning_and_fixes_without_executing_evidence(browser, tmp_path):
    from navi.engine import scan
    from navi.report import portable_html
    from conftest import ROOT
    report = scan(ROOT / "examples/shop", None, output=tmp_path, browser=False)
    report['issues'][0]['source']['snippet'] = '<script>window.evidenceExecuted = true</script>'
    page = browser._browser.new_page(viewport={"width":1440,"height":1000})
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    try:
        page.set_content(portable_html(report), wait_until="domcontentloaded")
        assert page.locator('h1').inner_text().startswith('Navi')
        assert page.locator('article').count() == 5
        assert 'Reasoning:' in page.locator('article').first.inner_text()
        assert 'Suggested fix:' in page.locator('article').first.inner_text()
        assert page.evaluate('window.evidenceExecuted === undefined')
        page.set_viewport_size({"width":390,"height":844})
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        assert not errors
    finally:
        page.close()
