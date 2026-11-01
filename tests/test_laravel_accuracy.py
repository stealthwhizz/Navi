"""Broader Laravel paths with protected controls and explicit attribution limits."""
from navi.static import analyze
from test_laravel import laravel, pytestmark
import pytest


def write(root, name, content):
    path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(content)


@pytest.mark.parametrize('protected', [False, True])
def test_injected_service_and_inherited_action(laravel, protected):
    root = laravel('return "unused";', route="Route::get('/check', [CheckController::class, 'show']);")
    write(root, 'app/Services/Lookup.php', r'''<?php namespace App\Services;
use Illuminate\Support\Facades\DB;
class Lookup { public function run($value) { return DB::select('SELECT x FROM t WHERE id='.'''
          + ('intval($value)' if protected else '$value') + '); } }')
    write(root, 'app/Http/Controllers/BaseController.php', r'''<?php namespace App\Http\Controllers;
use Illuminate\Http\Request;
use App\Services\Lookup;
class BaseController {
  public function __construct(protected Lookup $lookup) {}
  public function show(Request $request) { return $this->lookup->run($request->query('id')); }
}''')
    write(root, 'app/Http/Controllers/CheckController.php', r'''<?php namespace App\Http\Controllers;
class CheckController extends BaseController {}''')
    result = analyze(root)
    found = [f for f in result.findings if f.cwe == 'CWE-89']
    assert bool(found) is not protected
    if found:
        assert found[0].source['file'] == 'app/Services/Lookup.php'
        assert found[0].source_flows[0]['complete']
        assert any(n.get('file') == 'app/Http/Controllers/BaseController.php' for n in found[0].source_flows[0]['nodes'])


@pytest.mark.parametrize('rule,unsafe', [('required|string', True), ('required|integer', False), ('numeric', False)])
def test_formrequest_validated_values_are_contextual(laravel, rule, unsafe):
    root = laravel("$values=$request->validated(); return DB::select('SELECT x FROM t WHERE id='.$values['id']);", signature=r'\App\Http\Requests\SearchRequest $request')
    write(root, 'app/Http/Requests/SearchRequest.php', r'''<?php namespace App\Http\Requests;
use Illuminate\Foundation\Http\FormRequest;
class SearchRequest extends FormRequest { public function rules() { return ['id' => ''' + repr(rule) + ']; } }')
    result = analyze(root)
    assert any(f.cwe == 'CWE-89' for f in result.findings) is unsafe


def test_resource_route_filters_and_parameter_names(laravel):
    root = laravel("return 'unused';", route="Route::apiResource('people', CheckController::class)->only(['show'])->parameters(['people' => 'person_key']);")
    path = root / 'app/Http/Controllers/CheckController.php'
    path.write_text(path.read_text().replace('check(Request $request)', 'show($person_key)').replace("return 'unused';", 'system($person_key);'))
    result = analyze(root)
    assert {(r.path, tuple(r.methods)) for r in result.routes} == {('/people/<person_key>', ('GET',))}
    source = next(f for f in result.findings if f.cwe == 'CWE-78')
    assert source.bindings[0].parameter == 'person_key'


def test_controller_group_and_eloquent_raw_expression(laravel):
    root = laravel(r"return \App\Models\Product::whereRaw('id='.$request->query('id'))->get();", route="Route::controller(CheckController::class)->prefix('catalog')->group(function () { Route::get('/lookup', 'check'); });")
    write(root, 'app/Models/Product.php', r'<?php namespace App\Models; class Product extends \Illuminate\Database\Eloquent\Model {}')
    source = next(f for f in analyze(root).findings if f.cwe == 'CWE-89')
    assert source.bindings[0].route == '/catalog/lookup'


@pytest.mark.parametrize('escaped', [True, False])
def test_anonymous_blade_component_input_flow(laravel, escaped):
    root = laravel("return view('page', ['name' => $request->query('name')]);", views={
        'page': '<x-card :label="$name" />', 'components/card': '<p>' + ('{{ $label }}' if escaped else '{!! $label !!}') + '</p>'})
    found = [f for f in analyze(root).findings if f.cwe == 'CWE-79']
    assert bool(found) is not escaped
    if found:
        assert found[0].source['file'] == 'resources/views/components/card.blade.php'
        assert found[0].source_flows[0]['complete']
