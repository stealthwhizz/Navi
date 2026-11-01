"""Generalization checks; no application-specific paths or route mappings."""
from pathlib import Path
import secrets
import shutil

import pytest

from navi.static import analyze
from navi.correlate import correlate
from navi.model import Binding, Finding

pytestmark = pytest.mark.skipif(not shutil.which('php'), reason='PHP tokenizer required')


def write(root, file, code):
    path = root / file
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('<?php\n' + code)
    return path


def test_nested_includes_preserve_scope_and_return_values(tmp_path):
    endpoint, parameter, helper = (secrets.token_hex(5) for _ in range(3))
    write(tmp_path, f'public/{endpoint}.php', f'''
define('APP_ROOT', dirname(__DIR__));
require APP_ROOT . '/bootstrap.php';
$input = $_GET['{parameter}'];
require __DIR__ . '/../components/action.php';
echo $output;
''')
    write(tmp_path, 'bootstrap.php', "$library = __DIR__ . '/components/library.php'; require_once $library;")
    write(tmp_path, 'components/library.php', f"function f_{helper}($argument) {{ return shell_exec('printf %s ' . $argument); }}")
    write(tmp_path, 'components/action.php', f"$output = f_{helper}($input);")
    result = analyze(tmp_path, {'php_document_root': 'public'})
    assert {r.path for r in result.routes} == {f'/{endpoint}.php'}
    findings = [f for f in result.findings if f.cwe == 'CWE-78']
    assert len(findings) == 1
    finding = findings[0]
    assert finding.source['file'] == 'components/library.php'
    assert finding.source['function'] == f'f_{helper}'
    assert all(b.parameter == parameter and b.route == f'/{endpoint}.php' for b in finding.bindings)
    assert all(b.provenance == 'php-script' for b in finding.bindings)
    assert any('components/action.php:<entry>' in b.flow for b in finding.bindings)
    assert any(e['kind'] == 'literal include' for e in result.function_map['edges'])


def test_unimported_same_named_helper_is_not_a_source_link(tmp_path):
    write(tmp_path, 'index.php', "$x=$_GET['name']; dispatch($x);")
    write(tmp_path, 'unrelated.php', "function dispatch($x) { system($x); }")
    result = analyze(tmp_path)
    assert not any(f.cwe == 'CWE-78' for f in result.findings)
    assert any(g.get('call') == 'dispatch' for g in result.gaps)


@pytest.mark.parametrize('path_expression', ["__DIR__ . '/lib.php'", "dirname(__FILE__) . '/lib.php'", "BASE . '/lib.php'", "$location"])
def test_constant_include_forms_and_shared_output_scope(tmp_path, path_expression):
    write(tmp_path, 'index.php', f"const BASE = __DIR__; $location = BASE . '/lib.php'; $value=$_GET['value']; require {path_expression}; echo $html;")
    write(tmp_path, 'lib.php', "$html = '<p>' . $value . '</p>';")
    result = analyze(tmp_path)
    finding = next(f for f in result.findings if f.cwe == 'CWE-79')
    assert finding.source['file'] == 'index.php'
    assert {b.route for b in finding.bindings} == {'/', '/index.php'}
    assert not any(r.file == 'lib.php' for r in result.routes)


def test_unknown_include_never_uses_prefix_as_exact_path(tmp_path):
    write(tmp_path, 'index.php', "require __DIR__ . $_GET['page']; action($_GET['value']);")
    write(tmp_path, 'lib.php', "function action($x) { system($x); }")
    result = analyze(tmp_path)
    assert not any(f.cwe == 'CWE-78' for f in result.findings)
    assert any('Include path is dynamic' in g['reason'] for g in result.gaps)
    assert any(f.cwe == 'CWE-22' for f in result.findings)


def test_ambiguous_relative_include_is_not_guessed(tmp_path):
    write(tmp_path, 'index.php', "require __DIR__ . '/part/wrapper.php';")
    write(tmp_path, 'part/wrapper.php', "require 'helper.php'; action($_GET['x']);")
    write(tmp_path, 'part/helper.php', "function action($x) { system($x); }")
    write(tmp_path, 'helper.php', "function action($x) { return intval($x); }")
    result = analyze(tmp_path)
    assert not any(b.route in {'/', '/index.php'} for f in result.findings if f.cwe == 'CWE-78' for b in f.bindings)
    assert any('ambiguous' in g['reason'] for g in result.gaps)


def test_mapping_is_supplemental_and_cannot_confirm_a_hypothesis(tmp_path):
    write(tmp_path, 'one.php', "system('printf %s '.$_GET['x']);")
    write(tmp_path, 'two.php', "echo $_GET['name'];")
    result = analyze(tmp_path, {'php_routes': [{'file': 'one.php', 'route': '/invented'}]})
    assert {f.cwe for f in result.findings} == {'CWE-78', 'CWE-79'}
    runtime = Finding('proof', 'dast', 'CWE-78', 'Command', 'critical',
                      bindings=[Binding('/invented', 'GET', 'x', 'query', 'form')], verification='verified')
    issues = correlate(result, [runtime], {'status': 'matched'})
    assert not any(i['status'] == 'Confirmed' for i in issues)
    assert next(i for i in issues if i['id'] == 'proof')['candidate_source_ids']
    runtime.bindings[0].route = '/one.php'
    assert any(i['status'] == 'Confirmed' for i in correlate(result, [runtime], {'status': 'matched'}))
    assert not any(i['status'] == 'Confirmed' for i in correlate(result, [runtime], {'status': 'matched'}, policy='strict'))


def test_shared_helper_deduplicates_but_distinct_operations_remain_ambiguous(tmp_path):
    write(tmp_path, 'first.php', "require __DIR__.'/helper.php'; action($_GET['x']);")
    write(tmp_path, 'second.php', "require __DIR__.'/helper.php'; action($_GET['x']);")
    library = write(tmp_path, 'helper.php', "function action($x) { system('printf %s '.$x); }")
    analysis = analyze(tmp_path)
    assert len(analysis.findings) == 1
    assert {b.route for b in analysis.findings[0].bindings} == {'/first.php', '/second.php'}
    original_id = analysis.findings[0].id
    library.write_text('\n\n' + library.read_text())
    assert analyze(tmp_path).findings[0].id == original_id
    write(tmp_path, 'helper.php', "function action($x) { system('printf %s '.$x); passthru('printf %s '.$x); }")
    runtime = Finding('proof', 'dast', 'CWE-78', 'Command', 'critical', bindings=[Binding('/first.php', 'GET', 'x', 'query', '')], verification='verified')
    issues = correlate(analyze(tmp_path), [runtime], {'status': 'matched'})
    assert not any(i['status'] == 'Confirmed' for i in issues)
    assert next(i for i in issues if i['id'] == 'proof')['link_confidence'] == 'ambiguous'


@pytest.mark.parametrize('code,cwe,expected', [
    ("system('printf %s '.filter_input(INPUT_GET, 'query'));", 'CWE-78', True),
    ("system('printf %s '.filter_input(INPUT_GET, 'query', FILTER_VALIDATE_INT));", 'CWE-78', False),
    ("$values=$_GET; system('printf %s '.$values['query']);", 'CWE-78', True),
    ("return; system('printf %s '.$_GET['query']);", 'CWE-78', False),
])
def test_additional_php_sources_and_straight_line_termination(tmp_path, code, cwe, expected):
    write(tmp_path, 'index.php', code)
    findings = [f for f in analyze(tmp_path).findings if f.cwe == cwe]
    assert bool(findings) == expected
    if findings: assert all(b.parameter == 'query' for b in findings[0].bindings)


def test_protected_helper_and_unprotected_return_are_distinct(tmp_path):
    write(tmp_path, 'index.php', "require __DIR__.'/helpers.php'; echo protected_value($_GET['safe']); echo raw_value($_GET['unsafe']);")
    write(tmp_path, 'helpers.php', "function protected_value($x) {return htmlspecialchars($x, ENT_QUOTES); } function raw_value($x) {return $x;}")
    findings = [f for f in analyze(tmp_path).findings if f.cwe == 'CWE-79']
    assert len(findings) == 1
    assert {b.parameter for b in findings[0].bindings} == {'unsafe'}


def test_html_and_short_echo_tags_do_not_hide_php_statements(tmp_path):
    (tmp_path / 'index.php').write_text('''<h1>Example</h1>
<?php $x = $_GET['raw']; ?>
<p><?= $x ?></p>
<?php $safe = htmlspecialchars($_GET['safe'], ENT_QUOTES); ?>
<p><?= $safe ?></p>
''')
    findings = [f for f in analyze(tmp_path).findings if f.cwe == 'CWE-79']
    assert len(findings) == 1
    assert findings[0].source['line'] == 3
    assert {b.parameter for b in findings[0].bindings} == {'raw'}


def test_php_inc_library_is_analyzed_but_has_no_assumed_public_route(tmp_path):
    write(tmp_path, 'view.phtml', "require __DIR__.'/helper.inc'; echo render($_GET['name']);")
    write(tmp_path, 'helper.inc', "function render($value) {return $value;}")
    analysis = analyze(tmp_path)
    assert {r.path for r in analysis.routes} == {'/view.phtml'}
    assert len(analysis.findings) == 1
    assert analysis.findings[0].bindings[0].parameter == 'name'


def test_recursive_include_group_is_not_silently_lost(tmp_path):
    write(tmp_path, 'a.php', "require_once __DIR__.'/b.php'; echo $_GET['name'];")
    write(tmp_path, 'b.php', "require_once __DIR__.'/a.php';")
    analysis = analyze(tmp_path)
    assert any(f.cwe == 'CWE-79' for f in analysis.findings)
    assert any('No public entry path' in g['reason'] for g in analysis.gaps)
