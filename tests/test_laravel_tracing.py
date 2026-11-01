"""Execute the PHP signer with request/response doubles, without booting Laravel."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from navi.tracing import verify

pytestmark = pytest.mark.skipif(not shutil.which('php'), reason='PHP required for signer interop')


def test_php_middleware_signs_request_local_operation_evidence(tmp_path):
    source = Path(__file__).resolve().parents[1] / 'navi/integrations/laravel/NaviTrace.php'
    bridge = tmp_path / 'sign.php'
    bridge.write_text(r'''<?php
namespace Illuminate\Http {
    class Bag {
        public array $data = [];
        public function get($key, $default = null) { return $this->data[$key] ?? $default; }
        public function set($key, $value) { $this->data[$key] = $value; }
        public function has($key) { return array_key_exists($key, $this->data); }
    }
    class Request {
        public Bag $attributes;
        public function __construct() { $this->attributes = new Bag; }
        public function header($key, $default = '') { return str_repeat('a', 32); }
        public function getMethod() { return 'GET'; }
        public function getRequestUri() { return '/lookup?id=1'; }
    }
}
namespace Symfony\Component\HttpFoundation {
    class Response {
        public \Illuminate\Http\Bag $headers;
        public function __construct() { $this->headers = new \Illuminate\Http\Bag; }
    }
}
namespace {
    function config($name, $default = '') {
        return $name === 'navi.trace_key' ? str_repeat('k', 32) : str_repeat('d', 64);
    }
    require $argv[1];
    $middleware = new \App\Http\Middleware\NaviTrace;
    $results = [];
    foreach ([1, 0, 33] as $count) {
        $request = new \Illuminate\Http\Request;
        $response = $middleware->handle($request, function ($req) use ($count) {
            for ($i = 0; $i < $count; $i++) {
                \App\Http\Middleware\NaviTrace::record($req, str_pad(dechex($i), 20, '0', STR_PAD_LEFT),
                    'app/Services/Lookup.php', 42, 'CWE-89', [['location' => 'query', 'parameter' => 'id']]);
            }
            return new \Symfony\Component\HttpFoundation\Response;
        });
        $results[] = $response->headers->data;
    }
    echo json_encode($results);
}
''')
    result = subprocess.run(['php', str(bridge), str(source)], capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stderr
    first, second, overflow = json.loads(result.stdout)
    def check(headers):
        return verify(headers['X-Navi-Trace'], headers['X-Navi-Trace-Signature'], b'k' * 32,
                      'a' * 32, 'GET', 'http://localhost/lookup?id=1', 'd' * 64)
    trace = check(first)
    assert trace['status'] == 'verified' and trace['version'] == 2
    assert trace['operations'][0]['operation_id'] == '0' * 20
    assert check(second)['operations'] == []  # reused middleware, fresh request state
    assert check(overflow)['status'] == 'rejected'
    assert first['Cache-Control'] == 'private, no-store'
