"""Synthetic model responses exercise AI contracts; no test claims real OpenAI inference."""
from copy import deepcopy
import json
from pathlib import Path
import runpy
from types import SimpleNamespace

import pytest

from navi.ai import AISession
from navi.ai.client import OpenAIClient, AIUnavailable
from navi.ai.config import options
from navi.ai.context import Redactor, source_context
from navi.ai.review import valid_patch
from navi.control import ScanControl
from navi.engine import scan
from navi.runtime import load_config
from navi.static import analyze
from navi.transport import Response
from conftest import ROOT


class SyntheticModel:
    """Contract fixture which reads IDs from real context, never a trained model."""
    def __init__(self): self.prompts = []; self.stages = []
    def complete(self, messages, control):
        value = json.loads(messages[1]['content']); self.prompts.append(value)
        name, ctx = value['schema']['title'], value['context']; self.stages.append(name)
        if name == 'SourceReview':
            source = ctx['source_windows'][0]
            result = {'summary': 'Synthetic source reviewer fixture.', 'hypotheses': [{'source_id': source['id'], 'line': source['start'], 'cwe': 'CWE-89', 'title': 'Inspect query construction', 'reasoning': 'A mapped function requires source review.', 'missing_evidence': 'A native SQL verifier must establish runtime behavior.'}]}
        elif name == 'TestPlan':
            chosen = next((i for i in ctx['inputs'] if i['parameter'] == 'id'), None)
            result = {'summary': 'Synthetic test planner fixture.', 'tests': [{'input_id': chosen['id'], 'cwe': 'CWE-89', 'hypothesis_id': ctx['hypotheses'][0]['id'] if ctx['hypotheses'] else None, 'rationale': 'Run native boolean comparisons for the mapped ID input.'}] if chosen else []}
        elif name == 'CorrelationReview':
            result = {'summary': 'Synthetic correlation fixture.', 'reviews': [{'issue_id': i['id'], 'assessment': 'uncertain', 'explanation': 'Native build and candidate evidence remains the authority.', 'candidate_ranking': [{'finding_id': f, 'reason': 'Candidate provided by the native engine.'} for f in i['candidate_source_ids']], 'evidence_refs': [e['id'] for e in i['evidence'][:1]], 'next_step': 'Inspect the exact source operation and repeat the native verifier.'} for i in ctx['issues']]}
        elif name == 'RemediationReview':
            fixes = []
            for issue in ctx['issues']:
                window = next((w for w in ctx['source_windows'] if w['file'] == issue['source'].get('file') and w['start'] <= issue['source'].get('line', 0) <= w['end']), None)
                patch = None
                if window:
                    line = issue['source']['line']; original = next(l['text'] for l in window['lines'] if l['number'] == line)
                    patch = f"--- a/{window['file']}\n+++ b/{window['file']}\n@@ -{line},1 +{line},1 @@\n-{original}\n+    # Synthetic proposal; review before implementation.\n"
                fixes.append({'issue_id': issue['id'], 'source_id': window['id'] if window else None, 'explanation': 'Use the appropriate supported boundary protection and preserve legitimate behavior.', 'patch': patch, 'regression_tests': [{'name': 'Protected and legitimate requests', 'scenario': 'Repeat the relevant native probes and a valid baseline.', 'expected': 'Reject unauthorized behavior while preserving legitimate output.'}], 'evidence_refs': [e['id'] for e in issue['evidence'][:1]]})
            result = {'summary': 'Synthetic remediation fixture; patches are deliberately not applied.', 'fixes': fixes}
        else:
            result = {'summary': 'Synthetic coverage fixture.', 'priorities': [{'gap_ids': [g['id']], 'priority': 'high', 'reason': 'Coverage remains incomplete in this area.', 'action': 'Supply the documented prerequisite and rerun.'} for g in ctx['gaps'][:3]]}
        return result, {'prompt_tokens': 100, 'completion_tokens': 100, 'total_tokens': 200}


@pytest.fixture
def synthetic(monkeypatch):
    model = SyntheticModel()
    monkeypatch.setattr(OpenAIClient, 'complete', lambda self, messages, control: model.complete(messages, control))
    return model


def test_all_five_capabilities_preserve_native_results_and_propose_only(synthetic, shop, tmp_path):
    config = load_config(str(ROOT / 'examples/shop/policy.json'))
    baseline = scan(ROOT / 'examples/shop', 'http://127.0.0.1:5050', config, tmp_path / 'native', browser=False)
    config['ai'] = {'enabled': True, 'workflow': 'full'}
    before = (ROOT / 'examples/shop/app.py').read_bytes()
    result = scan(ROOT / 'examples/shop', 'http://127.0.0.1:5050', config, tmp_path / 'ai', browser=False)
    ai = result['ai']
    assert synthetic.stages == ['SourceReview', 'TestPlan', 'CorrelationReview', 'RemediationReview', 'CoverageReview']
    assert ai['status'] == 'completed'
    assert ai['call_attempts'] == ai['request_limit'] == 5
    assert ai['hypotheses'] and ai['tests'] and ai['correlation_reviews'] and ai['fixes'] and ai['coverage_priorities']
    assert ai['tests'][0]['state'] == 'already_scheduled'
    assert any(f['patch'] for f in ai['fixes'])
    assert before == (ROOT / 'examples/shop/app.py').read_bytes()
    assert {(i['id'], i['status'], i['severity']) for i in baseline['issues']} == {(i['id'], i['status'], i['severity']) for i in result['issues']}
    assert result['coverage']['gaps'] == baseline['coverage']['gaps']
    assert json.loads((tmp_path / 'ai/report.json').read_text())['ai']['status'] == 'completed'
    assert 'AI review' in (tmp_path / 'ai/report.html').read_text()


def test_ai_can_add_native_test_for_input_without_static_sink(synthetic, connect_app, tmp_path):
    source = tmp_path / 'source'; source.mkdir()
    (source / 'app.py').write_text('''from flask import Flask, request, jsonify
import sqlite3
app = Flask(__name__)
@app.get('/lookup')
def lookup():
    value = request.args.get('id', '1')
    with sqlite3.connect(':memory:') as db:
        db.execute('CREATE TABLE items(id INTEGER, name TEXT)')
        db.execute("INSERT INTO items VALUES (1,'Notebook')")
        executor = {'query': db.execute}['query']
        try:
            rows = executor(f"SELECT name FROM items WHERE id='{value}'").fetchall()
        except sqlite3.Error:
            return 'Invalid query', 400
    return jsonify(rows)
''')
    analysis = analyze(source)
    assert not any(f.cwe == 'CWE-89' for f in analysis.findings)
    connect_app(runpy.run_path(str(source / 'app.py'))['app'])
    result = scan(source, 'http://127.0.0.1', {'ai': {'enabled': True, 'workflow': 'full'}, 'interval': 0}, tmp_path / 'report', browser=False)
    assert result['ai']['tests'][0]['state'] == 'scheduled'
    assert result['ai']['tests'][0]['execution']['outcome'] == 'verified'
    finding = next(i for i in result['issues'] if i['cwe'] == 'CWE-89')
    assert finding['status'] == 'Runtime only' and finding['verification'] == 'verified'
    assert result['ai']['hypotheses'][0]['status'] == 'hypothesis'


def test_missing_key_keeps_native_scan_available(tmp_path, monkeypatch):
    monkeypatch.delenv('OPENAI_API_KEY', raising=False)
    monkeypatch.delenv('GROQ_API_KEY', raising=False)
    def forbidden(*args, **kwargs): pytest.fail('No network when API key is absent.')
    monkeypatch.setattr('navi.ai.client.Transport', forbidden)
    result = scan(ROOT / 'examples/shop', None, {'ai': {'enabled': True, 'workflow': 'full'}}, tmp_path, browser=False)
    assert result['summary']['code_only'] == 5 and result['ai']['status'] == 'unavailable'
    assert all(s['status'] == 'unavailable' for s in result['ai']['stages'].values())
    assert not any(g['component'] == 'ai' for g in result['coverage']['gaps'])
    assert 'GROQ_API_KEY' in result['ai']['stages']['source_review']['reason']


def test_disabled_ai_makes_no_model_calls(tmp_path, monkeypatch):
    monkeypatch.setattr(OpenAIClient, 'complete', lambda *a, **k: pytest.fail('AI disabled'))
    assert scan(ROOT / 'examples/shop', None, {}, tmp_path)['ai']['status'] == 'disabled'


def test_context_redacts_secrets_and_preserves_source_line_numbers(tmp_path, monkeypatch):
    key = 'sk-test_' + 'OpenAICredentialOnly' * 3; monkeypatch.setenv('OPENAI_API_KEY', key)
    (tmp_path / 'app.py').write_text(f'''from flask import Flask, request
API_PASSWORD = "literal-private-password"
app=Flask(__name__)
@app.get('/hello')
def hello():
    return request.args.get('name')
# {key}
''')
    config = {'ai': {'enabled': True, 'workflow': 'full'}, 'requests': {'GET /hello': {'headers': {'Authorization': 'Bearer private-header-token'}, 'query': {'name': 'DO_NOT_UPLOAD_SEED'}}}}
    context = source_context(analyze(tmp_path), tmp_path, config, options(config['ai']), Redactor(config, tmp_path))
    text = json.dumps(context)
    assert all(secret not in text for secret in [key, 'literal-private-password', 'private-header-token', 'DO_NOT_UPLOAD_SEED', str(tmp_path)])
    assert any(line['number'] == 2 and 'REDACTED' in line['text'] for s in context['source_windows'] for line in s['lines'])
    assert len(text) < config.get('max_context_chars', 20000)


def test_only_metadata_from_http_evidence_reaches_model(synthetic, shop, tmp_path):
    config = load_config(str(ROOT / 'examples/shop/policy.json')); config['ai'] = {'enabled': True, 'workflow': 'full'}
    scan(ROOT / 'examples/shop', 'http://127.0.0.1:5050', config, tmp_path, browser=False)
    for payload in synthetic.prompts:
        text = json.dumps(payload['context'])
        assert 'body_excerpt' not in text and 'response_headers' not in text
        assert 'ALICE-PRIVATE-ORDER' not in text and 'BOB-PRIVATE-ORDER' not in text
        for issue in payload['context'].get('issues', []):
            assert all('request' not in e and 'body_excerpt' not in e for e in issue['evidence'])


def test_untrusted_unknown_references_and_payloads_are_rejected(tmp_path):
    class Hostile(SyntheticModel):
        def complete(self, messages, control):
            name = json.loads(messages[1]['content'])['schema']['title']
            if name == 'SourceReview':
                return {'summary': 'bad citation', 'hypotheses': [{'source_id': '../../.env', 'line': 1, 'cwe': 'CWE-89', 'title': 'invented', 'reasoning': 'invented', 'missing_evidence': 'none'}]}, {}
            if name == 'TestPlan': return {'summary': 'bad payload', 'tests': [{'input_id': 'invented', 'cwe': 'CWE-78', 'hypothesis_id': None, 'rationale': 'attempt', 'payload': 'arbitrary shell command'}]}, {}
            return super().complete(messages, control)
    session = AISession({'ai': {'enabled': True, 'workflow': 'full'}}, ScanControl(), client=Hostile())
    assert session.before(analyze(ROOT / 'examples/shop'), ROOT / 'examples/shop') == []
    assert not session.report['hypotheses']
    assert session.report['stages']['test_planning']['status'] == 'invalid'
    assert session.report['rejected'][0]['stage'] == 'source_review'


def test_test_plans_do_not_execute_when_auto_test_disabled(tmp_path):
    class Planner(SyntheticModel):
        def complete(self, messages, control):
            value, usage = super().complete(messages, control)
            ctx = json.loads(messages[1]['content'])
            if ctx['schema']['title'] == 'TestPlan':
                chosen = next(i for i in ctx['context']['inputs'] if i['route'] == '/safe/products')
                value['tests'] = [{'input_id': chosen['id'], 'cwe': 'CWE-89', 'hypothesis_id': None, 'rationale': 'test protection'}]
            return value, usage
    session = AISession({'ai': {'enabled': True, 'workflow': 'full', 'auto_test': False}}, ScanControl(), client=Planner())
    assert session.before(analyze(ROOT / 'examples/shop'), ROOT / 'examples/shop') == []
    assert session.report['tests'][0]['state'] == 'suggested'


def test_openai_uses_requested_model_and_fixed_https_destination(monkeypatch):
    captured = {}; key = 'sk-test_test_key_secret'; monkeypatch.setenv('OPENAI_API_KEY', key)
    class Transport:
        def __init__(self, target, **kwargs): captured.update(target=target, **kwargs)
        def request(self, path, method, **kwargs):
            captured.update(path=path, method=method, **kwargs)
            return Response(200, {}, json.dumps({'choices': [{'finish_reason': 'stop', 'message': {'content': '{"ready":true}'}}], 'usage': {'total_tokens': 5}}).encode(), '', 0)
    monkeypatch.setattr('navi.ai.client.Transport', Transport)
    result, usage = OpenAIClient({'enabled': True, 'workflow': 'full'}).complete([{'role': 'user', 'content': 'JSON please'}], ScanControl())
    assert result == {'ready': True} and usage['total_tokens'] == 5
    assert captured['target'] == 'https://api.openai.com/v1' and captured['path'] == '/chat/completions'
    assert captured['headers']['Authorization'] == 'Bearer ' + key
    assert captured['json_body']['model'] == 'gpt-4.1-mini'
    assert captured['json_body']['response_format'] == {'type': 'json_object'}
    assert 'tools' not in captured['json_body'] and key not in json.dumps(captured['json_body'])


@pytest.mark.parametrize('status', [401, 403, 429, 500])
def test_provider_failures_do_not_echo_response_secrets_and_stop_repeated_calls(monkeypatch, status):
    monkeypatch.setenv('OPENAI_API_KEY', 'sk-test_do_not_echo')
    attempts = []
    class Transport:
        def __init__(self, *a, **k): pass
        def request(self, *a, **k): attempts.append(1); return Response(status, {}, b'sk-test_do_not_echo private server details', '', 0)
    monkeypatch.setattr('navi.ai.client.Transport', Transport)
    client = OpenAIClient({})
    for _ in range(2):
        with pytest.raises(AIUnavailable) as e: client.complete([], ScanControl())
        assert 'sk-test_do_not_echo' not in str(e.value) and 'private server' not in str(e.value)
    assert len(attempts) == 1


def test_model_wait_has_separate_budget_and_cannot_reset_cancellation(monkeypatch):
    import navi.ai.review as review
    clock = iter([0., 4.]); monkeypatch.setattr(review, 'time', SimpleNamespace(monotonic=lambda: next(clock)))
    class Failed:
        def complete(self, *args): raise AIUnavailable('temporary failure')
    control = ScanControl(); original_deadline = control.deadline
    session = AISession({'ai': {'enabled': True, 'workflow': 'full'}}, control, client=Failed())
    assert session.call('source_review', {}) is None
    assert control.deadline == original_deadline + 4 and session.remaining == 116
    control.cancel()
    assert control.event.is_set()


@pytest.mark.parametrize('config', [{'endpoint': 'https://elsewhere.invalid'}, {'api_key': 'secret'}, {'provider': 'other'}, {'enabled': 'true'}, {'max_tests': 500}])
def test_configuration_cannot_embed_keys_or_redirect_provider(config):
    with pytest.raises(ValueError): options(config)


def test_patch_scope_validation():
    window = {'file': 'app.py', 'start': 10, 'end': 20}
    assert valid_patch('--- a/app.py\n+++ b/app.py\n@@ -12,1 +12,1 @@\n-old\n+new\n', window)
    assert not valid_patch('--- a/app.py\n+++ b/../../outside\n@@ -12 +12 @@\n-old\n+new', window)
    assert not valid_patch('--- a/app.py\n+++ b/app.py\n@@ -99 +99 @@\n-old\n+new', window)


def test_model_cannot_invent_correlations_patches_or_gap_ids(shop, tmp_path, monkeypatch):
    class Hostile(SyntheticModel):
        def complete(self, messages, control):
            result, usage = super().complete(messages, control)
            name = json.loads(messages[1]['content'])['schema']['title']
            if name == 'CorrelationReview':
                for item in result['reviews']: item['candidate_ranking'] = [{'finding_id': 'invented-source-id', 'reason': 'model assertion'}]
            if name == 'RemediationReview':
                for item in result['fixes']: item['patch'] = '--- a/../../outside\n+++ b/../../outside\n@@ -1 +1 @@\n-old\n+new'
            if name == 'CoverageReview':
                for item in result['priorities']: item['gap_ids'] = ['nonexistent-gap']
            return result, usage
    model = Hostile()
    monkeypatch.setattr(OpenAIClient, 'complete', lambda self, m, c: model.complete(m, c))
    config = load_config(str(ROOT / 'examples/shop/policy.json')); config['ai'] = {'enabled': True, 'workflow': 'full'}
    result = scan(ROOT / 'examples/shop', 'http://127.0.0.1:5050', config, tmp_path, browser=False)
    assert result['summary']['confirmed'] == 3 and result['summary']['probable_source_links'] == 0
    assert not result['ai']['correlation_reviews'] and not result['ai']['fixes'] and not result['ai']['coverage_priorities']
    assert {r['stage'] for r in result['ai']['rejected']} >= {'correlation', 'remediation', 'coverage'}


def test_api_ai_results_are_protected_and_saved_with_scan(synthetic, shop, tmp_path, monkeypatch):
    from navi.api import create_app, Settings
    from test_api_reports import local_client
    import time
    token = 'test-workspace-access-' + 'x' * 32
    key = 'sk-test_never_render_this'; monkeypatch.setenv('OPENAI_API_KEY', key)
    app = create_app(Settings(source=str(ROOT / 'examples/shop'), target='http://127.0.0.1:5050',
                              config_path=str(ROOT / 'examples/shop/policy.json'), output=str(tmp_path), browser=False,
                              api_token=token, ai={'enabled': True, 'workflow': 'full'}))
    headers = {'Authorization': 'Bearer ' + token, 'X-Navi': 'local-scan'}
    with local_client(app) as client:
        assert client.get('/api/ai').status_code == 401
        assert client.get('/api/worklist').status_code == 401
        assert client.post('/api/scans', json={}, headers=headers).status_code == 202
        for _ in range(200):
            state = client.get('/api/state', headers=headers)
            if not state.json()['running']: break
            time.sleep(.02)
        assert not state.json()['running'] and state.json()['error'] is None
        result = client.get('/api/ai', headers=headers)
        assert result.status_code == 200 and result.json()['status'] == 'completed'
        worklist = client.get('/api/worklist', headers=headers)
        assert worklist.status_code == 200 and worklist.json()['summary']['source_runtime_pairs'] == 3
        assert key not in worklist.text
        assert key not in state.text and key not in result.text
        assert 'AI review' in client.get('/api/report.html', headers=headers).text


def test_ai_cli_overrides_saved_project_without_mutating_it(tmp_path, monkeypatch):
    from navi.project import initialize, resolve
    project = tmp_path / 'project.json'
    initialize(project, ROOT / 'examples/shop')
    value = json.loads(project.read_text()); value['ai'] = {'enabled': True, 'workflow': 'full'}; project.write_text(json.dumps(value))
    before = project.read_bytes()
    args = SimpleNamespace(project=str(project), source=None, ai=False, ai_model=None)
    assert resolve(args)['config']['ai']['enabled'] is False
    assert project.read_bytes() == before


def test_patch_rejects_mismatched_hunk_counts():
    assert not valid_patch('--- a/app.py\n+++ b/app.py\n@@ -10,3 +10,1 @@\n-old\n+new\n', {'file': 'app.py', 'start': 1, 'end': 20})


def test_context_budget_reports_windows_and_items_not_supplied():
    from navi.ai.context import pack
    cfg = {'ai': {'enabled': True, 'workflow': 'full', 'max_source_windows': 1, 'max_context_chars': 4000}}
    ctx = source_context(analyze(ROOT / 'examples/shop'), ROOT / 'examples/shop', cfg, options(cfg['ai']), Redactor(cfg))
    assert len(json.dumps(ctx)) <= 4000
    assert ctx['omitted']['source_windows'] > 0
    second = pack(ctx, 4000)
    assert second['omitted']['source_windows'] >= ctx['omitted']['source_windows']


def test_planner_enforces_methods_controls_and_additional_test_budget(tmp_path):
    (tmp_path / 'app.py').write_text('''from flask import Flask, request
app=Flask(__name__)
@app.route('/lookup', methods=['GET','POST'])
def lookup():
    request.args.get('id')
    request.args.get('password')
    request.args.get('csrf')
    request.args.get('custom_protection')
    request.args.get('extra')
    return 'ok'
''')
    class Planner(SyntheticModel):
        def complete(self, messages, control):
            prompt = json.loads(messages[1]['content'])
            if prompt['schema']['title'] == 'SourceReview': return {'summary': 'Synthetic source review', 'hypotheses': []}, {}
            assert prompt['schema']['title'] == 'TestPlan'
            return {'summary': 'Synthetic proposed tests', 'tests': [
                {'input_id': i['id'], 'cwe': 'CWE-89', 'hypothesis_id': None, 'rationale': 'Synthetic proposal'} for i in prompt['context']['inputs']]}, {}
    config = {'ai': {'enabled': True, 'workflow': 'full', 'max_tests': 1}, 'allowed_methods': ['GET'],
              'requests': {'GET /lookup': {'csrf': {'path': '/lookup', 'field': 'custom_protection', 'location': 'query'}}}}
    session = AISession(config, ScanControl(), client=Planner())
    tests = session.before(analyze(tmp_path), tmp_path)
    assert len(tests) == 1 and tests[0][1].parameter == 'id' and tests[0][1].method == 'GET'
    for test in session.report['tests']:
        if test['parameter'] in {'password', 'csrf', 'custom_protection'} or test['method'] == 'POST':
            assert test['state'] == 'needs_review'
    assert any(t['state'] == 'budget_limited' for t in session.report['tests'])


def test_cancelled_ai_does_not_call_provider_or_extend_native_deadline():
    class NeverCalled:
        def complete(self, *args): pytest.fail('Cancelled review contacted provider')
    control = ScanControl(); control.cancel(); deadline = control.deadline
    session = AISession({'ai': {'enabled': True, 'workflow': 'full'}}, control, client=NeverCalled())
    assert session.call('source_review', {}) is None
    assert session.report['stages']['source_review']['status'] == 'cancelled'
    assert control.deadline == deadline


@pytest.mark.parametrize('choice', [
    {'finish_reason': 'length', 'message': {'content': '{"ready":true}'}},
    {'finish_reason': 'stop', 'message': {'content': '```json\n{"ready":true}\n```'}},
    {'finish_reason': 'stop', 'message': {'content': None}},
])
def test_incomplete_or_non_json_provider_answers_are_rejected(monkeypatch, choice):
    monkeypatch.setenv('OPENAI_API_KEY', 'sk-test_synthetic_test_only')
    class Transport:
        def __init__(self, *a, **k): pass
        def request(self, *a, **k): return Response(200, {}, json.dumps({'choices': [choice]}).encode(), '', 0)
    monkeypatch.setattr('navi.ai.client.Transport', Transport)
    with pytest.raises(AIUnavailable): OpenAIClient({}).complete([], ScanControl())
