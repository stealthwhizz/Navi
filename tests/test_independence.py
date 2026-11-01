"""Independent PHP fixtures; no target profiles, provider calls or scanner binaries."""
from pathlib import Path
import secrets
import shutil

import pytest

from navi.engine import scan
from navi.static import analyze
from test_php_acceptance import PHPBodyTransport


@pytest.mark.skipif(not shutil.which('php'), reason='Actual PHP fixture needs PHP CLI')
@pytest.mark.parametrize('method', ['GET', 'POST'])
@pytest.mark.parametrize('with_source', [True, False], ids=['combined', 'dast-only'])
def test_unknown_php_form_seed_and_safe_control(tmp_path, method, with_source, monkeypatch):
    # These names and required values are created after scanner implementation.
    root = tmp_path / ('app_' + secrets.token_hex(5))
    public = root / ('www_' + secrets.token_hex(5)); public.mkdir(parents=True)
    entry, parameter, seed, function, gate, submit = ['p' + secrets.token_hex(6) for _ in range(6)]
    library = 'lib_' + secrets.token_hex(5) + '.php'
    (root / library).write_text(f'''<?php
function {function}($value) {{ return shell_exec('printf "%s" ' . $value); }}
function {function}_safe($value) {{ return shell_exec('printf "%s" ' . escapeshellarg($value)); }}
''')
    forms = []
    for protected in [False, True]:
        filename = entry + ('_safe' if protected else '') + '.php'
        call = function + ('_safe' if protected else '')
        forms.append(f'<form action="{filename}" method="{method}"><input name="{parameter}" value="{seed}"><input type="hidden" name="mode" value="{gate}"><button name="{submit}" value="Run">Run</button></form>')
        container = '$_GET' if method == 'GET' else '$_POST'
        (public / filename).write_text(f'''<?php
require dirname(__DIR__) . '/{library}';
$value = {container}['{parameter}'] ?? '';
if (({container}['mode'] ?? '') !== '{gate}' || !isset({container}['{submit}']) || !str_starts_with($value, '{seed}')) {{
    http_response_code(400); echo 'Invalid request'; return;
}}
echo {call}($value);
''')
    (public / 'index.php').write_text('\n'.join(forms))
    # The policy supplies only the web root/method, not endpoints or parameter values.
    config = {'php_document_root': public.name, 'allowed_methods': ['GET', 'POST'],
              'scanners': {'mode': 'templates'}, 'interval': 0, 'ai': {'enabled': False}}
    analysis = analyze(root, config)
    assert len([f for f in analysis.findings if f.cwe == 'CWE-78']) == 1
    if not with_source:
        monkeypatch.setattr('navi.engine.analyze', lambda *a, **k: pytest.fail('DAST-only scan must not inspect source'))
    reports = []
    for run in range(2):
        bridge = PHPBodyTransport(public)
        report = scan(root if with_source else None, bridge.target, config, tmp_path / 'reports' / 'scans' / str(run), browser=False, transport=bridge)
        verified = [i for i in report['issues'] if i['cwe'] == 'CWE-78' and i['verification'] == 'verified']
        assert len(verified) == 1
        issue = verified[0]
        assert issue['status'] == 'Runtime only'
        if with_source:
            assert issue['source_link']['status'] == 'Probable source link'
            candidate = next(i for i in report['issues'] if i['id'] in issue['candidate_source_ids'])
            assert candidate['source']['file'] == library and candidate['source']['function'] == function
        else:
            assert issue['source'] is None and report['source_files'] == 0
        assert all(b['parameter'] == parameter for b in issue['bindings'])
        probes = [e for e in issue['evidence'] if e.get('execution_proof', {}).get('observed')]
        assert len(probes) == 2
        assert all(e['request']['tested_input']['value'].startswith(seed) for e in probes)
        assert any(c['route'] == '/' + entry + '_safe.php' and c['cwe'] == 'CWE-78' and c['outcome'] == 'not_reproduced' for c in report['checks'])
        assert report['ai']['requests'] == 0
        reports.append(report)
    assert {i['id'] for i in reports[0]['issues']} == {i['id'] for i in reports[1]['issues']}


def test_missing_php_reports_a_gap_without_inventing_source_findings(tmp_path, monkeypatch):
    (tmp_path / 'index.php').write_text("<?php system($_GET['value']);")
    monkeypatch.setattr('navi.php.shutil.which', lambda name: None)
    report = scan(tmp_path, None, {'scanners': {'mode': 'templates'}, 'ai': {'enabled': False}}, tmp_path / 'out', browser=False)
    assert not report['issues']
    assert any('PHP CLI/tokenizer is unavailable' in g['reason'] for g in report['coverage']['gaps'])
    assert report['ai']['requests'] == 0 and report['http_requests'] == 0
