"""Laravel source fixtures; no Composer/bootstrap or controller execution by SAST."""
import json
import shutil
from copy import deepcopy

import pytest

from navi.static import analyze
from navi.correlate import correlate
from navi.model import Finding

pytestmark = pytest.mark.skipif(not shutil.which('php'), reason='PHP tokenizer required')


@pytest.fixture
def laravel(tmp_path):
    def write(body, route="Route::get('/check', [CheckController::class, 'check']);", signature='Request $request', views=None):
        root = tmp_path / 'app'
        (root / 'app/Http/Controllers').mkdir(parents=True, exist_ok=True)
        (root / 'routes').mkdir(exist_ok=True)
        (root / 'composer.json').write_text(json.dumps({'require': {'laravel/framework': '^12.0'}}))
        (root / 'routes/web.php').write_text(r'''<?php
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\CheckController;
''' + route)
        (root / 'app/Http/Controllers/CheckController.php').write_text(r'''<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Process;
class CheckController {
''' + f'public function check({signature}) {{\n{body}\n}}\n}}')
        for name, text in (views or {}).items():
            path = root / 'resources/views' / (name + '.blade.php')
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        return root
    return write


CASES = [
    ('CWE-89', True, "$v=$request->query('q'); return DB::select('SELECT name FROM users WHERE id='.$v);"),
    ('CWE-89', False, "return DB::select('SELECT name FROM users WHERE id=?', [$request->query('q')]);"),
    ('CWE-89', True, "return DB::table('users')->whereRaw('id='.request('q'))->get();"),
    ('CWE-89', False, "return DB::table('users')->where('id', request('q'))->get();"),
    ('CWE-89', True, "$query=DB::table('users'); return $query->whereRaw('id='.request('q'))->get();"),
    ('CWE-89', True, "return DB::table('users')->select(DB::raw(request('q')))->get();"),
    ('CWE-89', False, "return DB::table('users')->insert(['name' => request('q')]);"),
    ('CWE-89', False, "return DB::table('users')->update(['name' => request('q')]);"),
    ('CWE-89', True, "return DB::select(DB::raw('SELECT name FROM users WHERE id='.request('q')));"),
    ('CWE-79', True, "return '<p>'.$request->query('q').'</p>';"),
    ('CWE-79', True, "return response($request->query('q'));"),
    ('CWE-79', False, "return response()->json(['name' => $request->query('q')]);"),
    ('CWE-79', False, "return response(request('q'), 200, ['Content-Type' => 'text/plain']);"),
    ('CWE-79', True, "$alias=$request; return $alias->query('q');"),
    ('CWE-79', False, "return '<p>'.e($request->query('q')).'</p>';"),
    ('CWE-79', True, "return '<input value='.e($request->query('q')).'>';"),
    ('CWE-78', True, "system('printf %s '.$request->query('q'));"),
    ('CWE-78', True, "Process::run('printf %s '.request('q'));"),
    ('CWE-78', False, "system('printf %s '.escapeshellarg(request('q')));"),
    ('CWE-78', False, "Process::run(['printf', request('q')]);"),
    ('CWE-78', True, "shell_exec('sh -c '.escapeshellarg(request('q')));"),
    ('CWE-22', True, "return response()->download(storage_path($request->query('q')));"),
    ('CWE-22', False, "return Storage::disk('local')->get(request('q'));"),
    ('CWE-22', True, "return response()->download(Storage::path(request('q')));"),
    ('CWE-22', False, "return response()->download(storage_path('app/public/readme.txt'));"),
    ('CWE-601', True, "return redirect($request->query('q'));"),
    ('CWE-601', True, "return redirect()->away(request('q'));"),
    ('CWE-601', False, "return redirect('/account?next='.request('q'));"),
    ('CWE-601', False, "return redirect()->route('account', ['id' => request('q')]);"),
]


@pytest.mark.parametrize('scanner', ['templates', 'native'])
@pytest.mark.parametrize('cwe,vulnerable,body', CASES)
def test_laravel_vulnerable_and_protected_variants(laravel, cwe, vulnerable, body, scanner):
    root = laravel(body)
    result = analyze(root, {'scanners': {'mode': scanner}})
    found = [f for f in result.findings if f.cwe == cwe]
    assert bool(found) is vulnerable, [f.to_dict() for f in result.findings]
    if vulnerable:
        assert len(found) == 1
        assert found[0].scanner == 'navi-laravel'
        assert found[0].source['file'] == 'app/Http/Controllers/CheckController.php'
        assert found[0].source['line'] == 9
        assert {b.route for b in found[0].bindings} == {'/check'}
        assert {b.parameter for b in found[0].bindings} == {'q'}


@pytest.mark.parametrize('template,vulnerable', [
    ('<p>{!! $name !!}</p>', True), ('<p>{{ $name }}</p>', False),
    ('<input value={{ $name }}>', True), ('<input value="{{ $name }}">', False),
    ('<script>let name = {{ $name }};</script>', True),
])
def test_blade_view_taint_and_escaping(laravel, template, vulnerable):
    root = laravel("return view('greeting', ['name' => $request->query('q')]);", views={'greeting': template})
    result = analyze(root)
    found = [f for f in result.findings if f.cwe == 'CWE-79']
    assert bool(found) is vulnerable
    if vulnerable:
        assert found[0].source['file'] == 'resources/views/greeting.blade.php'
        assert found[0].bindings[0].route == '/check'
        assert any(e['kind'] == 'Blade view' and e['resolved'] for e in result.function_map['edges'])


def test_nested_route_groups_request_methods_and_path_inputs(laravel):
    root = laravel("return DB::select('SELECT name FROM users WHERE id='.$id);", signature='Request $request, $id', route="""
Route::prefix('v1')->middleware('auth')->group(function () {
    Route::group(['prefix' => 'orders'], function () {
        Route::match(['GET', 'PATCH'], '/{id}', [CheckController::class, 'check']);
    });
});
""")
    result = analyze(root)
    finding = next(f for f in result.findings if f.cwe == 'CWE-89')
    assert {(b.route, b.method, b.location, b.parameter) for b in finding.bindings} == {
        ('/v1/orders/<id>', 'GET', 'path', 'id'), ('/v1/orders/<id>', 'PATCH', 'path', 'id')}


def test_controller_helper_flow_and_api_prefix(laravel):
    root = laravel("return $this->lookup($request->query('q'));\n}\nprivate function lookup($id) {\nreturn DB::select('SELECT x FROM t WHERE id='.$id);")
    (root / 'routes/web.php').rename(root / 'routes/api.php')
    result = analyze(root, {'laravel': {'api_prefix': '/service'}})
    finding = next(f for f in result.findings if f.cwe == 'CWE-89')
    assert finding.source['function'].endswith('::lookup')
    assert finding.bindings[0].route == '/service/check'
    assert any(e['kind'] == 'controller method' and e['resolved'] for e in result.function_map['edges'])


def test_route_closure_and_aliased_facades(laravel):
    root = laravel('return "safe";', route=r"""
Route::get('/inline', function (\Illuminate\Http\Request $input) {
    return \Illuminate\Support\Facades\DB::select('SELECT x FROM t WHERE id='.$input->query('id'));
});
""")
    result = analyze(root)
    finding = next(f for f in result.findings if f.cwe == 'CWE-89')
    assert finding.source['file'] == 'routes/web.php'
    assert finding.bindings[0].route == '/inline'


@pytest.mark.parametrize('cwe,body', [(c, b) for c, v, b in CASES if v][:1] + [
    ('CWE-79', "return $request->query('q');"),
    ('CWE-78', "system($request->query('q'));"),
    ('CWE-22', "readfile($request->query('q'));"),
    ('CWE-601', "return redirect($request->query('q'));"),
])
def test_all_requested_cwes_correlate_only_with_matching_verified_input(laravel, cwe, body):
    analysis = analyze(laravel(body))
    source = next(f for f in analysis.findings if f.cwe == cwe)
    runtime = Finding('runtime', 'dast', cwe, source.title, source.severity,
                      bindings=deepcopy(source.bindings), verification='verified')
    issues = correlate(analysis, [runtime], {'status': 'unverified'})
    issue = next(i for i in issues if i['cwe'] == cwe)
    assert issue['status'] == 'Runtime only' and issue['findings'] == ['runtime']
    assert issue['source_link']['status'] == 'Probable source link'
    assert issue['candidate_source_ids'] == [source.id]
    runtime.bindings[0].parameter = 'different'
    assert not any(i['status'] == 'Confirmed' for i in correlate(analysis, [runtime], {'status': 'unverified'}))


def test_dynamic_and_missing_actions_are_gaps_not_guessed_links(laravel):
    root = laravel("system(request('q'));", route="Route::get($dynamic, [CheckController::class, 'check']); Route::get('/missing', [MissingController::class, 'check']);")
    result = analyze(root)
    assert not result.routes
    assert any('no URL/source link' in g['reason'] for g in result.gaps)
    assert any(f.cwe == 'CWE-78' and not f.bindings for f in result.findings)


def test_randomized_application_names_do_not_change_detection(laravel):
    import secrets
    parameter, path, method, class_name = ['p' + secrets.token_hex(6) for _ in range(4)]
    root = laravel(f"return DB::select('SELECT x FROM t WHERE id='.$request->query('{parameter}'));", route=f"Route::get('/{path}', [CheckController::class, 'check']);")
    controller = root / 'app/Http/Controllers/CheckController.php'
    controller.write_text(controller.read_text().replace('CheckController', class_name).replace('function check(', 'function ' + method + '('))
    controller.rename(controller.with_name(class_name + '.php'))
    routes = root / 'routes/web.php'
    routes.write_text(routes.read_text().replace('CheckController', class_name).replace("'check'", "'" + method + "'"))
    result = analyze(root)
    finding = next(f for f in result.findings if f.cwe == 'CWE-89')
    assert finding.source['file'].endswith(class_name + '.php')
    assert finding.bindings[0].route == '/' + path and finding.bindings[0].parameter == parameter
