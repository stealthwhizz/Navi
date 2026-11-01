"""Ordered scanner results, route links and a deduplicated worklist."""
from collections import Counter
from pathlib import Path
import json
import sys
import textwrap

from .model import RULES
from .evidence import runtime_observations, primary_observation

NAMES = {cwe: rule[0] for cwe, rule in RULES.items()}
OUTCOMES = {'verified': 'REPRODUCED', 'not_reproduced': 'NOT REPRODUCED', 'inconclusive': 'INCONCLUSIVE',
            'skipped': 'NOT TESTED', 'error': 'TEST ERROR', 'template_match': 'TEMPLATE MATCH (UNVERIFIED)'}
PHASES = ['SAST — source findings', 'DAST — runtime findings', 'Common format and route map',
          'Correlation and AI analysis', 'Merge duplicates', 'Prioritized issues']


def clean(value):
    return ' '.join(''.join(c for c in str(value) if ord(c) >= 32 and ord(c) != 127).split())


def short(value, width=240):
    return textwrap.shorten(clean(value), width=width, placeholder='…')


def line(value='', indent=''):
    for part in textwrap.wrap(clean(value), width=118, initial_indent=indent, subsequent_indent=indent,
                              break_long_words=False, break_on_hyphens=False) or ['']:
        print(part, file=sys.stderr, flush=True)


def show(lines):
    for value in lines: line(value, indent='  ' if value.startswith('  ') else '')


def counted(number, noun):
    return f"{number} {noun}{'' if number == 1 else 's'}"


def heading(number):
    return f'[{number}/6] {PHASES[number - 1]}'


def input_label(binding):
    if not binding.get('route'): return 'Configured access-control policy'
    return f"{binding.get('method', 'GET')} {binding['route']} | {binding.get('location', 'input')}.{binding.get('parameter', '?')}"


def references(findings):
    counters = Counter(); result = {}
    for finding in findings:
        if finding['id'] in result: continue
        prefix = 'S' if finding['origin'] == 'sast' else 'D'
        counters[prefix] += 1
        result[finding['id']] = f'{prefix}{counters[prefix]:03}'
    return result


def source_lines(findings, refs):
    for finding in findings:
        if finding['origin'] != 'sast': continue
        source = finding.get('source') or {}
        yield f"{refs[finding['id']]} | {finding['severity']} | {finding['cwe']} {finding['title']} | {source.get('file', '?')}:{source.get('line', '?')}"
        yield '  Code: ' + short(source.get('snippet', 'No snippet recorded.'), 160)


def template_lines(manifest):
    if manifest:
        name = 'Navi Laravel rules' if manifest.get('interpreter') == 'navi-laravel-native-v1' else 'Navi templates'
        yield f"{name}: {len(manifest.get('loaded', []))} supported | {manifest.get('unsupported', 0)} coverage limitations."


def runtime_lines(findings, refs):
    found = False
    for finding in findings:
        if finding['origin'] != 'dast': continue
        found = True
        observations = finding.get('runtime') or runtime_observations(finding.get('evidence', []), finding.get('bindings', []))
        observation = primary_observation(observations)
        yield f"{refs[finding['id']]} | {finding['severity']} | {finding['cwe']} {finding['title']} | runtime {finding['verification']}"
        if observation:
            yield f"  URL: {observation['method']} {observation['url']}"
            yield f"  Parameter: {observation['location']}.{observation['parameter']} | Payload: {json.dumps(observation['payload'], ensure_ascii=True)}"
            statuses = ', '.join(str(s) for s in sorted({o['response']['status'] for o in observations if isinstance(o['response'].get('status'), int)}))
            yield f"  Evidence: {short(finding.get('note', ''), 190)} ({len(observations)} observations; HTTP {statuses})"
        else:
            yield '  Evidence: ' + short(finding.get('note') or 'See retained evidence.')
    if not found: yield 'No runtime vulnerabilities reproduced in the tested scope.'


def route_lines(routes, full=False):
    rows = [(method, r) for r in routes for method in r['methods']]
    yield f"Both scanners use the same CWE finding format. {counted(len(rows), 'method/route mapping')}."
    selected = rows if full else rows[:12]
    for method, route in selected:
        origin = {'php-script': ' [inferred script path]', 'configured': ' [operator mapping; unverified]'}.get(route.get('provenance'), '')
        yield f"{method} {route['path']} -> {route['function']}() | {route['file']}:{route['line']}-{route.get('end_line', route['line'])}{origin}"
    if len(selected) < len(rows): yield f"Showing {len(selected)}/{len(rows)} mappings; report.txt and report.html contain the complete map."
    if not rows: yield 'No supported source routes mapped; runtime-only inputs cannot establish a code cause.'


def correlation_lines(issues, findings, ai):
    refs = references(findings)
    policies = sorted({i.get('source_link', {}).get('policy') for i in issues if i.get('source_link', {}).get('policy')})
    if policies: yield 'Correlation policy: ' + ', '.join(policies) + '.'
    linked = [i for i in issues if i['status'] == 'Confirmed']
    yield f"Native correlation: {counted(len(linked), 'source/runtime link')}."
    for issue in linked:
        members = ' + '.join(refs[f] for f in issue['findings'] if f in refs)
        yield f"{members} -> one Confirmed {issue['cwe']} issue"
        for reason in issue.get('link_reasons', []):
            yield '  Link: ' + reason
    if not ai.get('enabled'):
        yield 'AI analysis: disabled. Native correlation is retained.'
    else:
        yield f"AI analysis: {ai.get('status', 'pending')} | {len(ai.get('correlation_reviews', []))}/{len(issues)} findings reviewed | {ai.get('requests', 0)}/5 requests"
        reason = ai.get('stages', {}).get('correlation', {}).get('reason') or ai.get('error')
        if reason: yield '  ' + reason


def prerequisite_lines(checks):
    counts = Counter(c['outcome'] for c in checks)
    yield 'Checks: ' + (' | '.join(f"{n} {OUTCOMES.get(k, k).lower()}" for k, n in counts.items()) or 'none')
    reasons = Counter(c['reason'] for c in checks if c['outcome'] in {'inconclusive', 'skipped', 'error'})
    for reason, count in reasons.most_common(3): yield f"  {counted(count, 'check')}: {short(reason, 180)}"


def merge_lines(report):
    issues = report['issues']; signals = len({f['id'] for f in report.get('findings', [])})
    yield f"{counted(signals, 'scanner finding')} -> {counted(len(issues), 'issue')}; all supporting evidence stays attached."
    previous = report.get('comparison', {})
    if previous.get('previous_scan'):
        yield f"Previous scan: {len(previous['new'])} new | {len(previous['still_observed'])} recurring with unchanged IDs | {len(previous['not_observed'])} not observed."
    else: yield 'Stable fingerprints identify recurring bugs across scans; no previous scan for comparison.'


def issue_lines(report):
    from .reasoning import explain
    refs = references(report.get('findings', []))
    reviews = {r['issue_id']: r for r in report.get('ai', {}).get('correlation_reviews', [])}
    counts = report['summary']
    yield f"{counted(counts['total'], 'issue')} | {counts['confirmed']} Confirmed | {counts['runtime_only']} Runtime only | {counts['code_only']} Code only"
    if counts.get('probable_source_links'):
        yield f"{counts['probable_source_links']} verified runtime issues have Probable source link attribution; their source candidates remain separate."
    yield 'Order: Confirmed first, then descending risk. P1/P2/P3 indicate evidence strength; S/D references identify the scanner evidence.'
    for index, issue in enumerate(report['issues'], 1):
        yield ''
        members = ', '.join(refs[f] for f in issue['findings'] if f in refs)
        priority = issue.get('triage', {}).get('priority', '')
        yield f"{index}. {priority} {issue['status']} | {issue['severity']} | risk {issue['risk_score']}/10 | {issue['cwe']} {issue['title']} [{members}]"
        source = issue.get('source')
        if source: yield f"  File: {source['file']}:{source['line']}"
        observations = issue.get('runtime') or runtime_observations(issue.get('evidence', []), issue.get('bindings', []))
        observation = primary_observation(observations)
        if observation:
            yield f"  URL: {observation['method']} {observation['url']}"
            yield f"  Parameter: {observation['location']}.{observation['parameter']} | Payload: {json.dumps(observation['payload'], ensure_ascii=True)}"
        if issue['status'] == 'Confirmed' and source: yield '  Code: ' + short(source.get('snippet', ''), 160)
        reasoning = explain(issue, report, reviews.get(issue['id']))
        yield '  Reasoning: ' + reasoning['native']
        if reasoning.get('ai'): yield '  AI analysis: ' + reasoning['ai']
        yield '  Fix: ' + issue['fix']
    if not report['issues']: yield 'No issues found in the tested scope.'


def sections(report, full=False):
    findings = report.get('findings', []); refs = references(findings)
    source = [heading(1), *template_lines(report.get('templates', {}).get('sast')), f"{counted(report.get('source_files', 0), 'file')}; {counted(sum(f['origin'] == 'sast' for f in findings), 'source finding')}.", *source_lines(findings, refs)]
    runtime = [heading(2), *template_lines(report.get('templates', {}).get('dast')), *runtime_lines(findings, refs), *prerequisite_lines(report.get('checks', []))]
    routes = [heading(3), *route_lines(report.get('routes', []), full)]
    correlation = [heading(4), *correlation_lines(report['issues'], findings, report.get('ai', {}))]
    return [source, runtime, routes, correlation, [heading(5), *merge_lines(report)], [heading(6), *issue_lines(report)]]


def text_report(report):
    return '\n\n'.join('\n'.join(('  ' if value.startswith('  ') else '') + clean(value) for value in section) for section in sections(report, full=True)) + '\n'


class ConsoleProgress:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.findings = {}
        self.routes = []
        self.issues = {}
        self.checks = []
        self.live = False

    def __call__(self, event):
        kind, data = event['type'], event['data']
        if kind == 'scan_started':
            line('Navi | ' + (data.get('target') or data.get('source') or 'scan'))
            setup = data.get('configuration', {})
            if setup:
                line(f"Session login: {'configured' if setup.get('session_configured') else 'not configured'} | HTTP methods: {', '.join(setup.get('allowed_methods', ['GET']))} | Explicit PHP route mappings: {setup.get('php_route_mappings', 0)}")
            line(heading(1))
        elif kind == 'analysis':
            line(f"{counted(data['files'], 'file')}; {counted(data['findings'], 'source finding')}.")
        elif kind == 'static_finding': self.findings[data['id']] = data
        elif kind == 'analysis_complete':
            self.routes = data['routes']
            show(template_lines(data.get('templates')))
            show(source_lines(list(self.findings.values()), references(self.findings.values())))
        if kind in {'build', 'test_started', 'check', 'runtime_complete'} and not self.live:
            self.live = True; line(); line(heading(2))
        if kind == 'runtime_finding': self.findings[data['id']] = data
        elif kind == 'check':
            self.checks.append(data)
            if self.verbose:
                line(f"{OUTCOMES.get(data['outcome'], data['outcome'])} | {data['cwe']} | {input_label(data)}")
                line(data.get('reason', ''), '  ')
        elif kind == 'runtime_complete':
            show(template_lines(data.get('templates')))
            show(runtime_lines(list(self.findings.values()), references(self.findings.values())))
            show(prerequisite_lines(self.checks))
            line(f"{data['requests']} HTTP requests.")
            line(); line(heading(3)); show(route_lines(self.routes, self.verbose))
        elif kind == 'correlation_started': line(); line(heading(4)); line('Matching source operations to runtime evidence…')
        elif kind == 'issue': self.issues[data['id']] = data
        elif kind == 'correlation_complete':
            ai = {'enabled': data['enabled'], 'status': data['status'], 'requests': data['requests'],
                  'correlation_reviews': [None] * data['reviewed'], 'stages': {'correlation': {'reason': data.get('reason')}}}
            show(correlation_lines(list(self.issues.values()), list(self.findings.values()), ai))
        elif kind == 'ai_wait': line(f"Waiting {data['seconds']:.0f}s for AI provider quota.")
        elif kind == 'ai_stage' and self.verbose: line(f"AI {data['stage']}: {data['status']}")
        elif kind == 'scan_stopped': line('Stopping; saving completed evidence.')


def summarize(report, output, source_file=None, phases_printed=False, full=False):
    for section in sections(report, full=full)[4 if phases_printed else 0:]:
        line(); show(section)
    gaps = len(report.get('coverage', {}).get('gaps', []))
    line()
    line(f"{'Partial coverage (' + str(gaps) + ' limitations)' if gaps else 'Declared checks completed'} | {report.get('duration_seconds', '?')}s | {report.get('persistence', 'files only')}")
    if report.get('stop_reason'): line('Stopped: ' + report['stop_reason'])
    destination = Path(output).resolve()
    line('Full report: ' + str(destination / 'report.html'))
    line('Text report: ' + str(destination / 'report.txt'))
    line('JSON evidence: ' + str(Path(source_file).resolve() if source_file else destination / 'report.json'))
