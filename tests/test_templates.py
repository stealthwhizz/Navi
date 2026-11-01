"""Template execution uses Navi's engines and generic independent applications."""
from copy import deepcopy
import json
import subprocess

from flask import Flask, request
import pytest
import yaml

from navi.correlate import correlate
from navi.engine import scan
from navi.model import Binding, Finding, no_source_analysis
from navi.runtime import Runtime
from navi.static import analyze
from navi.templates import php, http
from navi.templates.load import documents, Unsupported


def write_yaml(tmp_path, value, name='rules.yaml'):
    path = tmp_path / name
    path.write_text(yaml.safe_dump(value, sort_keys=False))
    return str(path)


def rule(**changes):
    return {'id': 'test.source-rule', 'languages': ['php'], 'mode': 'taint',
            'message': 'Input reaches a custom operation', 'severity': 'ERROR',
            'metadata': {'cwe': 'CWE-89'}, 'pattern-sources': [{'pattern': "$_GET['needle']"}],
            'pattern-sinks': [{'patterns': [{'pattern': 'custom_query($DB, $QUERY)'}, {'focus-metavariable': '$QUERY'}]}],
            **changes}


def template(block=None, **changes):
    return {'id': 'test.http-rule', 'info': {'name': 'Test response', 'severity': 'medium', 'classification': {'cwe-id': 'CWE-89'}},
            'http': [block or {'path': ['{{BaseURL}}'], 'matchers': [{'type': 'word', 'words': ['marker']}]}], **changes}


def runtime_config(path):
    return {'scanners': {'mode': 'templates', 'nuclei_templates': [path]}, 'interval': 0,
            'allowed_methods': ['GET', 'POST'], 'discovery': {'enabled': True, 'max_pages': 6, 'max_candidates': 10},
            'ai': {'enabled': False}}


def test_php_rule_sources_focus_sanitizer_and_real_function_flow(tmp_path, monkeypatch):
    # PHP's syntax tokenizer is allowed; no other process is needed.
    original_run = subprocess.run
    def only_php(command, *args, **kwargs):
        assert str(command[0]).split('/')[-1] == 'php'
        return original_run(command, *args, **kwargs)
    monkeypatch.setattr(subprocess, 'run', only_php)
    source = tmp_path / 'app'; source.mkdir()
    (source / 'index.php').write_text("""<?php
function delegate($x) { custom_query('db', $x); }
delegate($_GET['needle']);
custom_query('db', $_GET['other']);
custom_query($_GET['needle'], 'constant query');
custom_query('db', clean_value($_GET['needle']));
""")
    selected = rule(**{'pattern-sanitizers': [{'pattern': 'clean_value($VALUE)'}]})
    path = write_yaml(tmp_path, {'rules': [selected]})
    config = {'scanners': {'mode': 'templates', 'semgrep_rules': [path]}}
    result = analyze(source, config)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.source['line'] == 2 and finding.source['function'] == 'delegate'
    assert finding.rule_id == 'test.source-rule' and finding.scanner == 'navi-php-template'
    assert finding.bindings[0].parameter == 'needle'
    assert result.templates['sast']['files'][0]['sha256']
    selected.pop('pattern-sanitizers')
    write_yaml(tmp_path, {'rules': [selected]})
    assert len(analyze(source, config).findings) == 2
    selected['pattern-sources'] = [{'pattern': "$_GET['other']"}]
    write_yaml(tmp_path, {'rules': [selected]})
    changed = analyze(source, config)
    assert len(changed.findings) == 1 and changed.findings[0].source['line'] == 4


@pytest.mark.parametrize('changes', [
    {'pattern-not': 'safe(...)'}, {'mode': 'search'}, {'languages': ['javascript']},
    {'pattern-sinks': [{'pattern': 'custom_query($X, $X)'}]},
    {'pattern-sources': [{'patterns': ['invalid', None]}]},
    {'pattern-sanitizers': [{'patterns': [{'pattern': 'sanitize($X)'}, {'focus-metavariable': '$X'}]}]},
])
def test_unsupported_php_rule_is_wholly_skipped(tmp_path, changes):
    rules, gaps, manifest = php.load([write_yaml(tmp_path, {'rules': [rule(**changes)]})])
    assert not rules and gaps and manifest['unsupported']


def test_duplicate_php_rules_keep_one_operation_with_both_rule_ids(tmp_path):
    (tmp_path / 'index.php').write_text("<?php custom_query('db', $_GET['needle']);")
    path = write_yaml(tmp_path, {'rules': [rule(), rule(id='second')]})
    result = analyze(tmp_path, {'scanners': {'mode': 'templates', 'semgrep_rules': [path]}})
    assert len(result.findings) == 1
    assert {e['rule_id'] for e in result.findings[0].evidence} == {'test.source-rule', 'second'}


@pytest.mark.parametrize('text', ['rules: &a [*a]', 'rules: []\nrules: []', '!!python/object/apply:os.system [false]'])
def test_yaml_aliases_duplicate_keys_and_constructors_are_rejected(tmp_path, text):
    path = tmp_path / 'unsafe.yaml'; path.write_text(text)
    docs, gaps, _ = documents([str(path)], 'test')
    assert not docs and gaps


def test_empty_packs_have_no_native_fallback(tmp_path, connect_app):
    (tmp_path / 'index.php').write_text("<?php system($_GET['arg']);")
    config = {'scanners': {'mode': 'templates', 'semgrep_rules': [], 'nuclei_templates': []}}
    analysis = analyze(tmp_path, config)
    assert not analysis.findings and any(g['component'] == 'sast-templates' for g in analysis.gaps)
    app = Flask(__name__); app.add_url_rule('/', view_func=lambda: 'plain')
    connect_app(app)
    runtime = Runtime(analysis, 'http://127.0.0.1', config, browser=False)
    assert not runtime.run() and not runtime.transport.count
    assert any(g['component'] == 'dast-templates' for g in runtime.gaps)


def test_http_fuzzing_keeps_form_controls_and_reports_unverified_evidence(tmp_path, connect_app, monkeypatch):
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: pytest.fail('HTTP templates need no scanner process'))
    app = Flask(__name__)
    @app.get('/')
    def home():
        return '<form action="/search" method="post"><input name="term" value="seed"><input type="hidden" name="token" value="required"><button name="go" value="Search">Search</button></form>'
    @app.post('/search')
    def search():
        if request.form.get('token') != 'required' or request.form.get('go') != 'Search': return 'blocked', 403
        return 'marker:' + request.form.get('term', '')
    connect_app(app)
    block = {'path': ['{{BaseURL}}'], 'payloads': {'probe': ['PAYLOAD']},
             'fuzzing': [{'part': 'body', 'type': 'postfix', 'mode': 'single', 'keys': ['term'], 'fuzz': ['{{probe}}']}],
             'matchers-condition': 'and', 'matchers': [{'type': 'status', 'status': [200]},
                 {'type': 'word', 'words': ['marker:seedPAYLOAD']}, {'type': 'regex', 'regex': ['MARKER:'], 'case-insensitive': True}]}
    config = runtime_config(write_yaml(tmp_path, template(block)))
    report = scan(None, 'http://127.0.0.1', config, tmp_path / 'out', browser=False)
    assert report['summary']['confirmed'] == 0 and report['summary']['runtime_only'] == 1
    finding = next(f for f in report['findings'] if f['origin'] == 'dast')
    assert finding['verification'] == 'template_match'
    issue = report['issues'][0]
    observation = issue['runtime'][0]
    assert observation['payload'] == 'seedPAYLOAD' and observation['parameter'] == 'term'
    assert observation['request']['form']['token'] == 'required'
    assert report['templates']['dast']['loaded'] == ['test.http-rule']
    assert 'not been independently verified' in issue['reasoning']['native']
    assert 'seedPAYLOAD' in (tmp_path / 'out/report.txt').read_text()
    from navi.ui import issue_view
    assert issue_view(issue, report)['dast']['payload'] == 'seedPAYLOAD'


def test_http_raw_and_multirequest_dsl(tmp_path, connect_app):
    app = Flask(__name__)
    app.add_url_rule('/before', endpoint='before', view_func=lambda: ('first', 201))
    app.add_url_rule('/after', endpoint='after', methods=['POST'], view_func=lambda: ('second:' + request.get_data(as_text=True), 202))
    connect_app(app)
    block = {'raw': ['GET /before HTTP/1.1\nHost: {{Hostname}}\n\n',
                     'POST /after HTTP/1.1\nHost: {{Hostname}}\nContent-Type: text/plain\n\n{{randstr}}'],
             'req-condition': True, 'matchers': [{'type': 'dsl', 'dsl': [
                 'status_code_1 == 201 && status_code_2 == 202 && contains(body_2, randstr) && !contains(body_1, "second")']} ]}
    config = runtime_config(write_yaml(tmp_path, template(block))); config['discovery'] = {'enabled': False}
    runtime = Runtime(no_source_analysis(), 'http://127.0.0.1', config, browser=False)
    findings = runtime.run()
    assert len(findings) == 1 and len(findings[0].evidence) == 2
    assert findings[0].evidence[1]['request']['body'].startswith('navi_')
    assert runtime.transport.count == 2


@pytest.mark.parametrize('bad', [
    {'flow': 'http(1)'}, {'http': [{'path': ['{{BaseURL}}'], 'cookie-reuse': True}]},
    {'variables': {'BaseURL': 'https://elsewhere.invalid'}},
    {'http': [{'path': ['{{BaseURL}}'], 'fuzzing': 'wrong'}]},
    {'http': [{'path': ['{{BaseURL}}'], 'matchers': [{'type': 'status', 'status': ['200']}]}]},
    {'http': [{'path': ['{{BaseURL}}'], 'matchers': [{'type': 'dsl', 'dsl': ['__import__("os")']}]}]},
    {'http': [{'path': ['{{BaseURL}}'], 'matchers': [{'type': 'regex', 'regex': ['(a+)+$']}]}]},
])
def test_unsupported_http_templates_are_not_executed(tmp_path, bad):
    templates, gaps, _ = http.load([write_yaml(tmp_path, template(**bad))])
    assert not templates and gaps


def test_http_scope_escape_and_budget_are_reported(tmp_path, connect_app):
    app = Flask(__name__); app.add_url_rule('/mounted/', view_func=lambda: 'marker')
    connect_app(app)
    block = {'path': ['{{RootURL}}../outside'], 'matchers': [{'type': 'word', 'words': ['marker']}]}
    config = runtime_config(write_yaml(tmp_path, template(block))); config['discovery'] = {'enabled': False}
    runtime = Runtime(no_source_analysis(), 'http://127.0.0.1/mounted', config, browser=False)
    assert not runtime.run() and runtime.transport.count == 0
    assert any('leaves target' in g['reason'] for g in runtime.gaps)
    block['path'] = ['{{BaseURL}}', '{{BaseURL}}']; write_yaml(tmp_path, template(block))
    config['max_requests'] = 1
    runtime = Runtime(no_source_analysis(), 'http://127.0.0.1/mounted', config, browser=False)
    runtime.run()
    assert runtime.transport.count == 1 and any('budget exhausted' in g['reason'] for g in runtime.gaps)


def test_template_match_cannot_confirm_but_attaches_to_independent_proof():
    analysis = no_source_analysis()
    binding = Binding('/lookup', 'GET', 'id', 'query', 'lookup', provenance='php-script')
    source = Finding('source', 'sast', 'CWE-89', 'SQL injection', 'high', source={'file': 'lookup.php', 'line': 7, 'snippet': 'query'}, bindings=[binding])
    analysis.findings = [source]
    signal = Finding('match', 'dast', 'CWE-89', 'SQL injection', 'high', bindings=[binding], verification='template_match', evidence=[{'label': 'matcher'}])
    issues = correlate(analysis, [signal], {'status': 'unverified'})
    assert len(issues) == 2 and all(i['status'] != 'Confirmed' for i in issues)
    assert next(i for i in issues if i['status'] == 'Runtime only')['link_confidence'] == 'runtime proof missing'
    proof = deepcopy(signal); proof.id = 'proof'; proof.verification = 'verified'; proof.evidence = [{'label': 'native proof'}]
    joined = correlate(analysis, [signal, proof], {'status': 'unverified'})
    assert len(joined) == 2 and joined[0]['status'] == 'Runtime only'
    assert set(joined[0]['findings']) == {'match', 'proof'}
    assert joined[0]['source_link']['status'] == 'Probable source link'
    assert joined == correlate(analysis, [proof, signal, proof, signal], {'status': 'unverified'})


def test_template_no_match_is_an_observed_check(tmp_path, connect_app):
    app = Flask(__name__); app.add_url_rule('/', view_func=lambda: 'does not match')
    connect_app(app)
    config = runtime_config(write_yaml(tmp_path, template())); config['discovery'] = {'enabled': False}
    runtime = Runtime(no_source_analysis(), 'http://127.0.0.1', config, browser=False)
    assert runtime.run() == []
    assert any(c.outcome == 'not_reproduced' and c.evidence for c in runtime.checks)


def test_plan_resolves_pack_paths_and_omissions_without_http(tmp_path, monkeypatch):
    from navi.project import plan
    from navi.runtime import load_config
    from navi.transport import Transport
    source = tmp_path / 'app'; source.mkdir()
    (source / 'index.php').write_text("<?php custom_query('db', $_GET['needle']);")
    write_yaml(tmp_path, {'rules': [rule()]}, 'php.yaml')
    write_yaml(tmp_path, template(), 'http.yaml')
    config_file = tmp_path / 'scan.json'
    config_file.write_text(json.dumps({'scanners': {'mode': 'templates', 'semgrep_rules': ['php.yaml'], 'nuclei_templates': ['http.yaml', 'missing.yaml']}}))
    config = load_config(str(config_file))
    monkeypatch.setattr(Transport, 'request', lambda *a, **k: pytest.fail('Plan sends no requests'))
    result = plan(source, 'http://127.0.0.1', config, browser=False)
    assert result['templates']['sast']['loaded'] == ['test.source-rule']
    assert result['templates']['dast']['loaded'] == ['test.http-rule']
    assert result['templates']['dast']['unsupported'] == 1
    assert result['http_template_tests'][0]['state'] == 'planned'
    assert not result['tests']  # A plain HTTP template did not enable native proof drivers.


def test_custom_cwe_uses_source_input_and_survives_reports(tmp_path, connect_app):
    source = tmp_path / 'app'; source.mkdir()
    (source / 'index.php').write_text("<?php custom_query('db', $_GET['needle']);")
    sast = write_yaml(tmp_path, {'rules': [rule(metadata={'cwe': 'CWE-94'})]}, 'php.yaml')
    block = {'path': ['{{BaseURL}}'], 'fuzzing': [{'part': 'query', 'fuzz': ['marker']}],
             'matchers': [{'type': 'word', 'words': ['marker']}]}
    spec = template(block); spec['info']['classification']['cwe-id'] = 'CWE-94'
    config = runtime_config(write_yaml(tmp_path, spec)); config['discovery'] = {'enabled': False}
    config['scanners']['semgrep_rules'] = [sast]
    app = Flask(__name__); app.add_url_rule('/', view_func=lambda: request.args.get('needle', ''))
    app.add_url_rule('/index.php', endpoint='script', view_func=lambda: request.args.get('needle', ''))
    connect_app(app)
    result = scan(source, 'http://127.0.0.1', config, tmp_path / 'out', browser=False)
    assert {f['origin'] for f in result['findings']} == {'sast', 'dast'}
    assert result['summary']['confirmed'] == 0
    assert any(f['cwe'] == 'CWE-94' for f in result['coverage']['cwe_matrix'])
    assert 'CWE-94' in result['coverage']['supported_static']
    assert 'CWE-94' in result['coverage']['supported_runtime']
    assert 'CWE-94' not in result['coverage']['runtime_proof_cwes']
    sarif = json.loads((tmp_path / 'out/report.sarif').read_text())
    assert any(r['id'] == 'CWE-94' for r in sarif['runs'][0]['tool']['driver']['rules'])
