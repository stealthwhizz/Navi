"""PRD matching, strict opt-in, and honest export of optional attribution evidence."""
from argparse import Namespace
from copy import deepcopy
import json

import pytest

from navi.correlate import correlate
from navi.project import resolve, plan
from navi.runtime import validate_scan_options
from navi.static import analyze
from test_source_evidence import flow_app, proof


@pytest.mark.parametrize('missing', ['trace', 'legacy_trace', 'flow', 'complete_flow', 'build'])
def test_prd_accepts_optional_evidence_gaps_but_strict_does_not(flow_app, missing):
    analysis = analyze(flow_app)
    source = analysis.findings[0]
    runtime = proof(analysis, source)
    build = {'status': 'matched'}
    if missing == 'trace': runtime.evidence[0].pop('trace')
    if missing == 'legacy_trace': runtime.evidence[0]['trace']['version'] = 1
    if missing == 'flow': source.source_flows = []
    if missing == 'complete_flow': source.source_flows[0]['complete'] = False
    if missing == 'build': build = {'status': 'unverified'}
    prd = correlate(analysis, [runtime], build)
    linked = next(i for i in prd if i['status'] == 'Confirmed')
    assert linked['source_link']['policy'] == 'prd'
    assert linked['source_link']['basis'] == 'PRD route and input match'
    assert len(linked['findings']) == 2
    assert not any(i['status'] == 'Confirmed' for i in correlate(analysis, [runtime], build, policy='strict'))


@pytest.mark.parametrize('policy', ['prd', 'strict'])
@pytest.mark.parametrize('boundary', ['bad_trace', 'other_operation', 'other_input', 'request_replay', 'build_mismatch', 'template_only', 'operator_mapping', 'ambiguous'])
def test_both_policies_reject_contradictions_and_unsupported_matches(flow_app, policy, boundary):
    analysis = analyze(flow_app)
    source = analysis.findings[0]
    runtime = proof(analysis, source)
    build = {'status': 'matched'}
    trace = runtime.evidence[0]['trace']
    if boundary == 'bad_trace': trace['status'] = 'rejected'
    if boundary == 'other_operation': trace['operations'][0]['operation_id'] = 'f' * 20
    if boundary == 'other_input': trace['operations'][0]['inputs'][0]['parameter'] = 'other'
    if boundary == 'request_replay': trace['request_id'] = 'b' * 32
    if boundary == 'build_mismatch': build['status'] = 'mismatch'
    if boundary == 'template_only': runtime.verification = 'template_match'
    if boundary == 'operator_mapping':
        for binding in source.bindings: binding.provenance = 'configured'
    if boundary == 'ambiguous':
        other = deepcopy(source); other.id = 'f' * 20
        analysis.findings.append(other)
        runtime.evidence[0].pop('trace')
    assert not any(i['status'] == 'Confirmed' for i in correlate(analysis, [runtime], build, policy=policy))


@pytest.mark.parametrize('requirement', ['build', 'trace'])
def test_explicit_evidence_requirements_are_honored_in_prd(flow_app, requirement):
    analysis = analyze(flow_app)
    source = analysis.findings[0]
    runtime = proof(analysis, source)
    runtime.evidence[0].pop('trace')
    kwargs = {'require_build_match': True} if requirement == 'build' else {'trace_required': True}
    issues = correlate(analysis, [runtime], {'status': 'unverified'}, **kwargs)
    assert not any(i['status'] == 'Confirmed' for i in issues)


@pytest.mark.parametrize('value', ['strict', [], {'policy': 'guess'}, {'policy': []}, {'enabled': True}])
def test_invalid_policy_config_is_rejected(value):
    with pytest.raises(ValueError, match='correlation'):
        validate_scan_options({'correlation': value})


def test_policy_config_and_cli_override_are_not_target_specific(tmp_path):
    (tmp_path / 'app.py').write_text('from flask import Flask\napp=Flask(__name__)\n')
    config = tmp_path / 'scan.json'
    config.write_text(json.dumps({'correlation': {'policy': 'strict'}}))
    args = Namespace(source=str(tmp_path), config=str(config))
    selected = resolve(args)
    assert selected['config']['correlation']['policy'] == 'strict'
    args.correlation_policy = 'prd'
    selected = resolve(args)
    assert plan(selected['source'], None, selected['config'])['correlation']['policy'] == 'prd'
    assert json.loads(config.read_text())['correlation']['policy'] == 'strict'
