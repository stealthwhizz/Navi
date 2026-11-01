"""Execute the generated controller through minimal test-only PHP facades.

This exercises actual PHP/shell/file/redirect behavior and scanner integration;
it is not a booted Laravel framework or a live HTTP-server integration test.
"""
import json
import shutil
import subprocess
from urllib.parse import urlencode

import pytest

from navi.engine import scan
from navi.transport import Response
from test_laravel import laravel

pytestmark = pytest.mark.skipif(not shutil.which('php'), reason='PHP CLI required')

BRIDGE = r'''<?php
namespace Illuminate\Http {
    class Request {
        public function query($key, $default=null) { return $_GET[$key] ?? $default; }
    }
}
namespace {
    class FixtureResponse {
        public function __construct(public $body='', public $status=200, public $headers=['content-type'=>'text/html']) {}
    }
    class ResponseFactory {
        public function download($file) {
            return is_file($file) ? new FixtureResponse(file_get_contents($file), 200, ['content-type'=>'application/octet-stream']) : new FixtureResponse('missing', 404);
        }
        public function json($value) { return new FixtureResponse(json_encode($value), 200, ['content-type'=>'application/json']); }
    }
    class RedirectFactory {
        public function away($url) { return new FixtureResponse('', 302, ['location'=>$url]); }
    }
    function request($key=null) { $r = new \Illuminate\Http\Request; return $key === null ? $r : $r->query($key); }
    function response($body=null) { return func_num_args() ? new FixtureResponse($body) : new ResponseFactory; }
    function redirect($url=null) { return $url === null ? new RedirectFactory : (new RedirectFactory)->away($url); }
    $input=json_decode(stream_get_contents(STDIN), true);
    $_GET=$input['query'];
    require $input['controller'];
    ob_start();
    $result=(new \App\Http\Controllers\CheckController)->check(new \Illuminate\Http\Request);
    $printed=ob_get_clean();
    if (!$result instanceof FixtureResponse) $result=new FixtureResponse((string)$result);
    $result->body=$printed.$result->body;
    echo json_encode($result);
}
'''


class ControllerTransport:
    def __init__(self, bridge, controller):
        self.bridge, self.controller = bridge, controller
        self.target, self.count, self.max_requests = 'http://127.0.0.1:9321', 0, 250

    def request(self, route, method='GET', *, query=None, **kwargs):
        self.count += 1
        url = self.target + route + ('?' + urlencode(query) if query else '')
        metadata = {'method': method, 'url': url, 'query': query or {}, 'headers': {}}
        if route != '/check': return Response(404, {}, b'missing', url, 0, metadata)
        process = subprocess.run(['php', str(self.bridge)], input=json.dumps({'controller': str(self.controller), 'query': query or {}}), capture_output=True, text=True, timeout=3)
        assert process.returncode == 0, process.stderr
        data = json.loads(process.stdout)
        return Response(data['status'], data['headers'], data['body'].encode(), url, 0, metadata)


@pytest.mark.parametrize('cwe', ['CWE-78', 'CWE-22', 'CWE-601', 'CWE-79'])
def test_controller_to_runtime_proof_report_and_repeat_identity(laravel, tmp_path, cwe):
    browser = cwe == 'CWE-79'
    if browser:
        from navi.browser import BrowserVerifier, BrowserUnavailable
        verifier = BrowserVerifier()
        try: verifier.start()
        except BrowserUnavailable as error: pytest.skip(str(error))
        finally: verifier.close()
    public = tmp_path / 'files/public'; public.mkdir(parents=True)
    (public / 'welcome.txt').write_text('public welcome')
    marker = 'NAVI_TEST_PRIVATE_FILE_8a3f3c9d'
    (public.parent / 'private.txt').write_text(marker)
    bodies = {
        'CWE-78': "return shell_exec('printf %s '.$request->query('q'));",
        'CWE-22': f"return response()->download('{public}/'.$request->query('q'));",
        'CWE-601': "return redirect()->away($request->query('q'));",
        'CWE-79': "return response('<p>'.$request->query('q').'</p>');",
    }
    root = laravel(bodies[cwe])
    bridge = tmp_path / 'bridge.php'; bridge.write_text(BRIDGE)
    config = {'scanners': {'mode': 'templates'}, 'discovery': {'enabled': False}, 'ai': {'enabled': False},
              'requests': {'GET /check': {'query': {'q': 'welcome.txt' if cwe == 'CWE-22' else 'sample'}}},
              'traversal_fixtures': [{'route': '/check', 'parameter': 'q', 'payload': '../private.txt', 'marker': marker}]}
    reports = []
    for number in range(2):
        transport = ControllerTransport(bridge, root / 'app/Http/Controllers/CheckController.php')
        report = scan(root, transport.target, config, tmp_path / 'reports/scans' / str(number), browser=browser, transport=transport)
        issues = [i for i in report['issues'] if i['cwe'] == cwe and i['verification'] == 'verified']
        assert len(issues) == 1 and issues[0]['source_link']['status'] == 'Confirmed source link'
        issue = issues[0]
        assert issue['source']['line'] == 9 and issue['source']['snippet']
        assert issue['source']['file'] == 'app/Http/Controllers/CheckController.php'
        assert issue['runtime'] and any(o['payload'] is not None for o in issue['runtime'])
        assert all(o['url'].startswith(transport.target) and o['method'] == 'GET' for o in issue['runtime'])
        assert any(c['name'] == 'Source flow' and c['result'] == 'pass' for c in issue['correlation_checks'])
        assert issue['fix'] and issue['triage']['rank'] == 1
        assert (tmp_path / 'reports/scans' / str(number) / 'report.html').is_file()
        reports.append(report)
    assert not reports[1]['comparison']['new']
    assert {i['id'] for i in reports[0]['issues']} == {i['id'] for i in reports[1]['issues']}
