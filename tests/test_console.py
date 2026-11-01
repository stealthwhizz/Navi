import json
from copy import deepcopy

import pytest

from navi.cli import main
from navi.console import ConsoleProgress, clean, summarize
from navi.engine import scan
from conftest import ROOT


@pytest.fixture
def saved_report(tmp_path):
    report = scan(ROOT / 'examples/shop', None, {}, tmp_path, browser=False)
    return report, tmp_path


def test_default_progress_names_the_weakness_and_input_and_summarizes_other_checks(capsys):
    progress = ConsoleProgress()
    base = {'cwe': 'CWE-89', 'method': 'GET', 'route': '/products', 'parameter': 'id', 'location': 'query', 'reason': 'Boolean controls verified.'}
    progress({'type': 'check', 'data': {**base, 'outcome': 'verified'}})
    progress({'type': 'check', 'data': {**base, 'outcome': 'not_reproduced'}})
    output = capsys.readouterr()
    assert output.err.count('[2/6]') == 1 and 'SQL injection' not in output.err
    assert '[NOT REPRODUCED]' not in output.err and output.out == ''
    ConsoleProgress(verbose=True)({'type': 'check', 'data': {**base, 'outcome': 'not_reproduced', 'reason': 'No proof; safety is not established.'}})
    assert 'No proof; safety is not established.' in capsys.readouterr().err


def test_saved_report_explains_code_only_limits_and_ai_failures_without_scanning(saved_report, monkeypatch, capsys):
    report, path = saved_report
    report['ai'] = {'enabled': True, 'status': 'partial', 'requests': 3, 'request_limit': 5,
                    'correlation_reviews': [], 'fixes': [], 'stages': {
                        'remediation': {'status': 'unavailable', 'reason': 'OpenAI returned HTTP 413; no AI result accepted.'},
                        'coverage': {'status': 'unavailable', 'reason': 'OpenAI rate limit reached.'}}}
    file = path / 'report.json'; file.write_text(json.dumps(report)); before = file.read_bytes()
    def forbidden(*a, **k): pytest.fail('Saved report must not scan or call OpenAI')
    monkeypatch.setattr('navi.cli.scan', forbidden)
    monkeypatch.setattr('navi.ai.client.OpenAIClient.complete', forbidden)
    assert main(['report', str(file)]) == 0
    output = capsys.readouterr()
    assert output.err.count('Reasoning:') == 5
    assert 'Suggested change:' not in output.err and 'WHAT THE TEST OUTCOMES MEAN' not in output.err
    assert 'Partial coverage' in output.err and '0/5 findings reviewed' in output.err
    assert [output.err.index(f'[{n}/6]') for n in range(1,7)] == sorted(output.err.index(f'[{n}/6]') for n in range(1,7))
    assert 'S001' in output.err and 'Common format and route map' in output.err
    assert file.read_bytes() == before and output.out == ''


def test_report_uses_project_output_without_loading_scan_secrets(saved_report, monkeypatch, capsys):
    _, output = saved_report
    (output / 'navi.json').write_text(json.dumps({'version': 1, 'key': 'test', 'source': str(ROOT/'examples/shop'), 'output': '.', 'config': 'missing-secret-policy.json'}))
    monkeypatch.chdir(output)
    assert main(['report']) == 0
    assert '5 source findings' in capsys.readouterr().err


def test_json_events_remain_machine_readable(tmp_path, capsys):
    assert main(['scan', '--source', str(ROOT/'examples/shop'), '--output', str(tmp_path), '--no-ai', '--no-browser', '--json-events']) == 0
    output = capsys.readouterr()
    events = [json.loads(row) for row in output.out.splitlines()]
    assert events[0]['type'] == 'scan_started' and events[-1]['type'] == 'scan_finished'
    assert output.err.count('Reasoning:') == 5


def test_terminal_control_sequences_cannot_execute():
    assert '\x1b' not in clean('\x1b[31mUntrusted model output\x00')
    assert '\x00' not in clean('\x00')


def test_live_scan_prints_scanner_evidence_in_order_without_repeating_phases(shop, tmp_path, capsys):
    from navi.runtime import load_config
    progress = ConsoleProgress()
    report = scan(ROOT/'examples/shop', 'http://127.0.0.1:5050', load_config(str(ROOT/'examples/shop/policy.json')),
                  tmp_path, browser=False, callback=progress)
    summarize(report, tmp_path, phases_printed=True)
    output = capsys.readouterr().err
    offsets = [output.index(f'[{n}/6]') for n in range(1,7)]
    assert offsets == sorted(offsets)
    assert all(output.count(f'[{n}/6]') == 1 for n in range(1,7))
    assert 'S002 | high | CWE-89 SQL injection | app.py:' in output
    assert output.index('S002 |') < offsets[1]
    assert 'D001 | high | CWE-89' in output and offsets[1] < output.index('D001 |') < offsets[2]
    assert 'Payload:' in output and 'Evidence:' in output
    assert 'Probable source link' in output and '0 Confirmed' in output
    assert 'exact attribution remains provisional' in output
    assert output.count('Reasoning:') == len(report['issues'])
    assert 'AI analysis: disabled' in output
    # Portable reports retain all routes, including those omitted from the terminal preview.
    text = (tmp_path/'report.txt').read_text()
    assert 'Showing 12/' not in text
    for route in report['routes']: assert route['path'] in text
    html = (tmp_path/'report.html').read_text()
    assert [html.index(f'[{n}/6]') for n in range(1,7)] == sorted(html.index(f'[{n}/6]') for n in range(1,7))


def test_code_only_reason_explains_the_actual_runtime_prerequisite():
    from navi.reasoning import explain
    issue = {'status':'Code only','verification':'unverified','cwe':'CWE-78',
             'bindings':[{'route':'/run','method':'POST','location':'form','parameter':'ip'}]}
    report = {'target':'http://127.0.0.1', 'checks':[{'cwe':'CWE-78','route':'/run','method':'POST','location':'form','parameter':'ip',
              'outcome':'skipped', 'reason':'HTTP method is not enabled in allowed_methods.'}]}
    assert 'HTTP method is not enabled' in explain(issue, report)['native']
