"""Correlation-focused AI contracts and hard provider budgets; synthetic responses only."""
import json

import pytest

from navi.ai.client import OpenAIClient, AIUnavailable
from navi.ai.config import options
from navi.ai.review import AISession
from navi.control import ScanControl
from navi.engine import scan
from navi.runtime import load_config
from navi.transport import Response
from conftest import ROOT
from test_ai import SyntheticModel


class CorrelationModel(SyntheticModel):
    def complete(self, messages, control):
        result, usage = super().complete(messages, control)
        prompt = json.loads(messages[1]['content'])
        ctx = prompt['context']
        windows = {w['id']: w for w in ctx.get('source_windows', [])}
        if prompt['schema']['title'] == 'CorrelationReview':
            issues = {i['id']: i for i in ctx['issues']}
            for review in result['reviews']:
                issue = issues[review['issue_id']]
                target = next((t for t in issue['fix_targets'] if t['source_id'] in windows), None)
                review.update(noise_assessment='actionable' if issue['verification'] == 'verified' else 'possible_false_positive',
                    noise_reason='Synthetic triage opinion, not a safety proof.', priority_hint='later',
                    priority_reason='Synthetic prioritization opinion.', fix_target_id=target['id'] if target else None,
                    fix_line=target['start'] if target else None, fix_reason='Inspect the supplied mapped operation or function.')
        if prompt['schema']['title'] == 'RemediationReview':
            issues = {i['id']: i for i in ctx['issues']}
            for fix in result['fixes']:
                target = issues[fix['issue_id']].get('reviewed_fix_target')
                if not target or target['source_id'] not in windows: continue
                window = windows[target['source_id']]
                line = target['line']; original = next(l['text'] for l in window['lines'] if l['number'] == line)
                fix.update(source_id=window['id'], patch=f"--- a/{window['file']}\n+++ b/{window['file']}\n@@ -{line},1 +{line},1 @@\n-{original}\n+# Synthetic review proposal only\n")
        return result, usage


def install_model(monkeypatch, model):
    monkeypatch.setattr(OpenAIClient, 'complete', lambda self, messages, control: model.complete(messages, control))


def test_one_call_reconciles_signals_noise_fix_locations_and_priority(shop, tmp_path, monkeypatch):
    model = CorrelationModel(); install_model(monkeypatch, model)
    config = load_config(str(ROOT / 'examples/shop/policy.json')); config['ai'] = {'enabled': True, 'max_prompt_tokens': 12000}
    report = scan(ROOT / 'examples/shop', 'http://127.0.0.1:5050', config, tmp_path, browser=False)
    assert model.stages == ['CorrelationReview']
    assert report['ai']['workflow'] == 'correlation' and report['ai']['call_attempts'] == 1
    assert report['ai']['request_limit'] == 5 and report['ai']['status'] == 'completed'
    assert report['ai']['stages']['source_review']['status'] == 'skipped'
    worklist = report['worklist']; items = worklist['items']
    assert len(items) == len({i['issue_id'] for i in items}) == report['summary']['total'] == 9
    assert worklist['summary']['source_runtime_pairs'] == 0
    assert worklist['summary']['combined_signals'] == 0
    assert worklist['summary']['possible_noise'] == 5  # visible hypotheses, never removed
    assert sum(i['priority'] == 'P2' for i in items) == 4
    assert sum(i['priority'] == 'P3' for i in items) == 5
    assert all(i['ai_priority_hint'] == 'normal' for i in items if i['priority'] in {'P1', 'P2'})
    assert all(i['signals_combined'] == 2 for i in items if i['priority'] == 'P1')
    runtime = next(i for i in items if i['status'] == 'Runtime only')
    assert runtime['fix_locations'][0]['basis'] == 'AI suggested location; runtime cause unproven'
    assert not report['ai']['fixes']
    assert all(i['reasoning']['native'] for i in report['issues'])
    assert runtime['reasoning']['ai']
    assert len(json.loads((tmp_path / 'report.json').read_text())['worklist']['items']) == 9
    assert 'Prioritized issue queue' in (tmp_path / 'report.html').read_text()


@pytest.mark.parametrize('failure', [False, True])
def test_client_never_attempts_a_sixth_request_including_network_failures(monkeypatch, failure):
    monkeypatch.setenv('OPENAI_API_KEY', 'sk-test_synthetic_budget')
    attempts = []
    class Transport:
        def __init__(self, *a, **k):
            attempts.append(1)
            if failure: raise OSError('synthetic connection failure')
        def request(self, *a, **k):
            return Response(200, {}, json.dumps({'choices': [{'finish_reason': 'stop', 'message': {'content': '{}'}}]}).encode(), '', 0)
    monkeypatch.setattr('navi.ai.client.Transport', Transport)
    client = OpenAIClient({})
    for _ in range(9):
        try: client.complete([], ScanControl())
        except AIUnavailable: pass
    assert len(attempts) == client.requests == 5
    with pytest.raises(AIUnavailable, match='request limit'): client.complete([], ScanControl())


def test_request_ceiling_cannot_be_configured_above_five():
    for invalid in (6, 50, 0, True):
        with pytest.raises(ValueError): options({'max_requests': invalid})


def test_stage_cannot_be_retried_or_exceed_smaller_scan_budget(shop, tmp_path, monkeypatch):
    model = CorrelationModel(); install_model(monkeypatch, model)
    config = load_config(str(ROOT / 'examples/shop/policy.json')); config['ai'] = {'enabled': True, 'max_requests': 1}
    report = scan(ROOT / 'examples/shop', 'http://127.0.0.1:5050', config, tmp_path, browser=False)
    assert model.stages == ['CorrelationReview']
    assert report['ai']['stages']['remediation']['status'] == 'skipped'
    assert report['summary']['confirmed'] == 0 and report['summary']['probable_source_links'] == 3
    session = AISession({'ai': {'enabled': True}}, ScanControl(), client=model)
    session.call('coverage', {'gaps': []})
    attempts = session.report['call_attempts']
    assert session.call('coverage', {'gaps': []}) is None
    assert session.report['call_attempts'] == attempts


def test_verified_noise_dismissal_and_unrelated_fix_targets_are_rejected(shop, tmp_path, monkeypatch):
    class Hostile(CorrelationModel):
        def complete(self, messages, control):
            result, usage = super().complete(messages, control)
            if json.loads(messages[1]['content'])['schema']['title'] == 'CorrelationReview':
                for row in result['reviews']:
                    row['noise_assessment'] = 'possible_false_positive'
                    if row['issue_id'] == result['reviews'][-1]['issue_id']:
                        row['fix_target_id'] = 'invented-or-other-issue-target'
            return result, usage
    model = Hostile(); install_model(monkeypatch, model)
    config = load_config(str(ROOT / 'examples/shop/policy.json')); config['ai'] = {'enabled': True}
    result = scan(ROOT / 'examples/shop', 'http://127.0.0.1:5050', config, tmp_path, browser=False)
    assert result['summary']['confirmed'] == 0 and len(result['worklist']['items']) == 9
    reasons = ' '.join(r['reason'] for r in result['ai']['rejected'])
    assert 'verified runtime finding' in reasons and 'Fix target' in reasons
    assert all(i['noise_assessment'] != 'possible_false_positive' for i in result['worklist']['items'] if i['priority'] in {'P1', 'P2'})


@pytest.mark.parametrize('boundary', ['ambiguous', 'mismatched_build'])
def test_ai_opinion_never_promotes_an_unsupported_source_link(shop, tmp_path, monkeypatch, boundary):
    from copy import deepcopy
    from flask import jsonify
    from navi.static import analyze
    if boundary == 'ambiguous':
        analysis = analyze(ROOT / 'examples/shop')
        operation = deepcopy(next(f for f in analysis.findings if f.cwe == 'CWE-89'))
        operation.id = 'synthetic-second-operation'; operation.source['line'] += 1
        analysis.findings.append(operation)
        monkeypatch.setattr('navi.engine.analyze', lambda *a, **k: analysis)
    else:
        shop.view_functions['build'] = lambda: jsonify(source_digest='different-build')
    class Overconfident(CorrelationModel):
        def complete(self, messages, control):
            result, usage = super().complete(messages, control)
            if json.loads(messages[1]['content'])['schema']['title'] == 'CorrelationReview':
                for row in result['reviews']: row['assessment'] = 'supported'
            return result, usage
    model = Overconfident(); install_model(monkeypatch, model)
    cfg = load_config(str(ROOT / 'examples/shop/policy.json'))
    cfg['ai'] = {'enabled': True, 'max_context_chars': 60000, 'max_prompt_tokens': 16000}
    result = scan(ROOT / 'examples/shop', 'http://127.0.0.1:5050', cfg, tmp_path, browser=False)
    sql = [i for i in result['issues'] if i['cwe'] == 'CWE-89']
    runtime = next(i for i in sql if i['status'] == 'Runtime only')
    assert not any(i['status'] == 'Confirmed' for i in sql)
    assert runtime['triage']['priority'] == 'P2'
    assert runtime['triage']['ai_link_assessment'] == 'supported'  # opinion, not proof
    assert runtime['link_confidence'] == ('ambiguous' if boundary == 'ambiguous' else 'build unverified')
    assert len(sql) == (3 if boundary == 'ambiguous' else 2)
