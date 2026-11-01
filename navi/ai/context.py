"""Bounded, referenced context. No credentials, request values, or response bodies by default."""
import ast
from dataclasses import asdict
import json
import os
from pathlib import Path
import re

from ..model import fingerprint

SENSITIVE = re.compile(r'password|passwd|secret|token|api.?key|credential|authorization|cookie|private.?key', re.I)


class Redactor:
    def __init__(self, config, root=None):
        self.values = set()
        self.root = str(Path(root).resolve()) if root else None
        for name in (config.get('ai', {}).get('api_key_env', 'GROQ_API_KEY'), 'OPENAI_API_KEY', 'GROQ_API_KEY', 'NAVI_API_TOKEN', 'DATABASE_URL'):
            value = os.getenv(name)
            if value: self.values.add(value)
        def collect(value, protected=False, container=''):
            if isinstance(value, dict):
                for name, item in value.items():
                    if name == 'api_key_env': continue
                    secret = bool(SENSITIVE.search(name))
                    if container == 'cookies': secret = name.lower() not in {'id', 'security'} and isinstance(item, str) and len(item) >= 12
                    if container == 'headers': secret = name.lower() in {'authorization', 'cookie', 'x-api-key'}
                    collect(item, protected or container == 'json_match' or (secret and not isinstance(item, (dict, list))), name)
            elif isinstance(value, list):
                for item in value: collect(item, protected, container)
            elif protected and isinstance(value, str) and value:
                self.values.add(value)
                if value.lower().startswith('bearer '): self.values.add(value[7:])
        collect(config)
        self.values = sorted(self.values, key=len, reverse=True)

    def text(self, value, code=False):
        for secret in self.values: value = value.replace(secret, '[REDACTED]')
        if self.root: value = value.replace(self.root, '[source root]')
        value = re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----',
                       lambda m: '[REDACTED PRIVATE KEY]' + '\n' * m[0].count('\n'), value, flags=re.S)
        value = re.sub(r'\b(?:gsk_[A-Za-z0-9_-]{12,}|sk-[A-Za-z0-9_-]{12,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)', '[REDACTED]', value)
        value = re.sub(r'(https?://)[^\s/@]+:[^\s/@]+@', r'\1[REDACTED]@', value)
        if code:
            value = '\n'.join('[REDACTED credential-related line]' if SENSITIVE.search(line) and re.search(r'[=:].*[\'"]', line) else line for line in value.split('\n'))
        return value

    def clean(self, value):
        if isinstance(value, str): return self.text(value)
        if isinstance(value, dict): return {k: self.clean(v) for k, v in value.items()}
        if isinstance(value, list): return [self.clean(v) for v in value]
        return value


def pack(context, limit):
    """Keep complete JSON items with fair representation of each context category."""
    lists = {k: v for k, v in context.items() if isinstance(v, list)}
    result = {k: v for k, v in context.items() if not isinstance(v, list)}
    result.update({k: [] for k in lists})
    size = len(json.dumps(result, ensure_ascii=True))
    for index in range(max((len(v) for v in lists.values()), default=0)):
        for name, values in lists.items():
            if index >= len(values): continue
            item = values[index]
            cost = len(json.dumps(item, ensure_ascii=True)) + 2
            if size + cost < limit - 600:
                result[name].append(item); size += cost
    result['omitted'] = {name: context.get('omitted', {}).get(name, 0) + len(values) - len(result[name]) for name, values in lists.items()}
    return result


def source_context(analysis, root, config, opts, redactor):
    root = Path(root).resolve(); base = root.parent if root.is_file() else root
    cache, windows, inputs = {}, {}, {}
    requested_windows = set()
    def read(file):
        path = base / file
        if path.is_symlink() or not path.resolve().is_relative_to(base) or path.suffix not in {'.py', '.php', '.inc', '.phtml'}: return []
        if file not in cache:
            try:
                if path.stat().st_size > 2_000_000: return []
                cache[file] = path.read_text(errors='replace').splitlines()
            except OSError: return []
        return cache[file]
    def add_input(route, method, parameter, location, reason):
        if not isinstance(parameter, str) or not parameter or parameter == '*' or len(parameter) > 120: return
        if location not in {'query', 'form', 'json', 'path', 'header', 'cookie', 'session'}: return
        if not any(r.path == route and method in r.methods for r in analysis.routes): return
        identifier = 'input-' + fingerprint(route, method, parameter, location)
        inputs[identifier] = {'id': identifier, 'route': route, 'method': method, 'parameter': parameter, 'location': location, 'basis': reason}
    def window(file, start, end, routes, function=None):
        requested_windows.add((file, max(1, start), end))
        if len(windows) >= opts['max_source_windows']: return
        lines = read(file)
        start, end = max(1, start), min(end, len(lines), start + 49)
        if end < start: return
        identifier = 'source-' + fingerprint(file, start, end)
        if identifier in windows: return
        selected, length = [], 0
        cleaned = redactor.text('\n'.join(lines[start-1:end]), code=True).split('\n')
        for number, line in enumerate(cleaned, start):
            text = line[:400]
            if length + len(text) > 4500: break
            selected.append({'number': number, 'text': text}); length += len(text)
        if selected: windows[identifier] = {'id': identifier, 'file': file, 'start': start, 'end': selected[-1]['number'],
                                           'function': function, 'routes': routes, 'lines': selected}
    for finding in analysis.findings:
        for binding in finding.bindings: add_input(binding.route, binding.method, binding.parameter, binding.location, 'native source binding')
        if finding.source:
            s = finding.source
            window(s['file'], s['line']-15, s['line']+20,
                   [{'route': b.route, 'methods': [b.method]} for b in finding.bindings], s.get('function'))
    nodes = sorted(analysis.function_map.get('nodes', []), key=lambda n: (not n.get('reachable_from'), n['file'], n['line']))
    for node in nodes:
        window(node['file'], node['line'], node.get('end_line', node['line']+25), node.get('reachable_from', []), node.get('name'))
    for gap in analysis.gaps:
        if gap.get('file'): window(gap['file'], max(1, gap.get('line', 1)-5), gap.get('line', 1)+30, [])
    # Independently enumerate literal Python request selectors. This does not
    # assert a taint-to-sink flow; AI may select a native test for these inputs.
    for file, lines in list(cache.items()):
        if not file.endswith('.py'): continue
        try: tree = ast.parse('\n'.join(lines))
        except (SyntaxError, ValueError): continue
        for node in ast.walk(tree):
            key = receiver = None
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'get' and node.args:
                receiver, key = node.func.value, node.args[0]
            elif isinstance(node, ast.Subscript): receiver, key = node.value, node.slice
            if not isinstance(key, ast.Constant) or not isinstance(key.value, str): continue
            if not isinstance(receiver, ast.Attribute) or not isinstance(receiver.value, ast.Name) or receiver.value.id != 'request': continue
            location = {'args': 'query', 'form': 'form', 'json': 'json', 'headers': 'header', 'cookies': 'cookie'}.get(receiver.attr)
            if not location: continue
            for function in nodes:
                if function['file'] == file and function['line'] <= node.lineno <= function.get('end_line', function['line']):
                    for route in function.get('reachable_from', []):
                        for method in route['methods']: add_input(route['route'], method, key.value, location, 'literal Python request selector in a mapped function')
    for item in config.get('runtime_inputs', []): add_input(item['route'], item.get('method', 'GET'), item['parameter'], item.get('location', 'query'), 'explicit configured runtime input')
    for route in analysis.routes:
        for method in route.methods:
            for param in route.parameters: add_input(route.path, method, param['name'], param['location'], 'route parameter')
            settings = config.get('requests', {}).get(f'{method} {route.path}', {})
            for component, location in {'query': 'query', 'form': 'form', 'json': 'json', 'path': 'path'}.items():
                for name in settings.get(component, {}): add_input(route.path, method, name, location, 'configured seed name; value withheld')
    findings = [{'id': f.id, 'cwe': f.cwe, 'source': {k: v for k, v in (f.source or {}).items() if k in {'file', 'line', 'function', 'operation'}},
                 'bindings': [{k: v for k, v in asdict(b).items() if k != 'provenance' or v != 'source'} for b in f.bindings]} for f in analysis.findings]
    context = {'source_digest': analysis.digest, 'source_windows': list(windows.values()), 'inputs': list(inputs.values()),
               'static_findings': findings, 'call_edges': analysis.function_map.get('edges', [])[:80],
               'gaps': [{'id': 'source-gap-' + str(i), **g} for i, g in enumerate(analysis.gaps[:40])],
               'omitted': {'source_windows': max(0, len(requested_windows) - len(windows)),
                           'call_edges': max(0, len(analysis.function_map.get('edges', [])) - 80),
                           'gaps': max(0, len(analysis.gaps) - 40)},
               'disclosure': 'Redacted bounded source excerpts and metadata. No request values, headers, cookies, or raw response bodies.'}
    return redactor.clean(context) if opts['workflow'] == 'correlation' else pack(redactor.clean(context), opts['max_context_chars'])


def fix_targets(issue, report, windows):
    """Candidate editing locations grounded in operations or mapped functions.

    A runtime-only handler is investigation context, not a native source cause.
    """
    result = {}
    findings = {f['id']: f for f in report['findings']}
    operations = []
    if issue.get('source'):
        operations.append((issue['source'], 'native source operation', None))
    else:
        for identifier in issue.get('candidate_source_ids', []):
            source = findings.get(identifier, {}).get('source')
            if source: operations.append((source, 'candidate operation; cause unresolved', identifier))
    def add(window, start, end, basis, function, finding_id=None):
        identifier = 'target-' + fingerprint(issue['id'], window['id'], start, end, basis)
        result[identifier] = {'id': identifier, 'source_id': window['id'], 'file': window['file'],
                              'start': start, 'end': end, 'basis': basis, 'function': function,
                              'finding_id': finding_id}
    for source, basis, identifier in operations:
        candidates = [w for w in windows if w['file'] == source['file'] and w['start'] <= source['line'] <= w['end']]
        if candidates:
            w = min(candidates, key=lambda w: w['end'] - w['start'])
            add(w, source['line'], source['line'], basis, source.get('function'), identifier)
    if not issue.get('source'):
        bindings = {(b['route'], b['method']) for b in issue.get('bindings', [])}
        for node in report.get('function_map', {}).get('nodes', []):
            if not any((r['route'], method) in bindings for r in node.get('reachable_from', []) for method in r['methods']): continue
            candidates = [w for w in windows if w['file'] == node['file'] and max(w['start'], node['line']) <= min(w['end'], node.get('end_line', node['line']))]
            if candidates:
                w = min(candidates, key=lambda w: w['end'] - w['start'])
                start, end = max(w['start'], node['line']), min(w['end'], node.get('end_line', node['line']))
                add(w, start, end, 'mapped function context; cause unresolved', node['name'])
    return list(result.values())[:3]


def report_context(report, sources, opts, redactor):
    issues = []
    for issue in report['issues'][:24]:
        finding_ids = set(issue.get('findings', []))
        allowed = set(issue.get('candidate_source_ids', [])) | {f['id'] for f in report['findings'] if f['id'] in finding_ids and f['origin'] == 'sast'}
        evidence = []
        for index in range(max(0, len(issue['evidence']) - 4), len(issue['evidence'])):
            e = issue['evidence'][index]
            evidence.append({'id': f"evidence-{issue['id']}-{index}", 'label': e.get('label'), 'status': e.get('status'),
                             'body_sha256': e.get('body_sha256'), 'body_bytes': e.get('body_bytes'),
                             'browser_executed': e.get('browser', {}).get('executed'),
                             'shell_marker_observed': e.get('execution_proof', {}).get('observed'),
                             'shell_marker_in_payload': e.get('execution_proof', {}).get('marker_in_payload'),
                             'has_explicit_access_policy': bool(e.get('policy'))})
        issues.append({'id': issue['id'], 'cwe': issue['cwe'], 'status': issue['status'], 'verification': issue['verification'],
                       'source_link': issue.get('source_link'),
                       'source': {k: v for k, v in (issue.get('source') or {}).items() if k in {'file', 'line', 'function', 'operation'}},
                       'bindings': issue.get('bindings', []), 'candidate_source_ids': sorted(allowed),
                       'link_reasons': issue.get('link_reasons', []), 'evidence': evidence,
                       'severity': issue['severity'], 'risk_score': issue['risk_score'],
                       'signals_combined': len(issue.get('findings', [])),
                       'reachability': 'mapped input flow' if issue.get('bindings') else 'unknown; no mapped flow does not prove dead code',
                       'fix_targets': fix_targets(issue, report, sources.get('source_windows', []))})
    selected_windows = {t['source_id'] for i in issues for t in i['fix_targets']}
    windows = [w for w in sources.get('source_windows', []) if w['id'] in selected_windows]
    context = {'build': {k: report['build'].get(k) for k in ('status', 'reason')}, 'issues': issues,
               'source_windows': windows, 'static_findings': [{k: f[k] for k in ('id', 'cwe', 'source')} for f in sources.get('static_findings', [])],
               'checks': [{'id': 'check-' + str(i), **{k: c.get(k) for k in ('cwe', 'route', 'method', 'parameter', 'location', 'outcome', 'reason')}} for i, c in enumerate(report['checks'])],
               'gaps': [{'id': 'gap-' + str(i), **g} for i, g in enumerate(report['coverage']['gaps'])],
               'native_scope': report['coverage']['scope'], 'limitations': report['coverage']['limitations'],
               'omitted': {'issues': max(0, len(report['issues']) - 24),
                           **{k: sources.get('omitted', {}).get(k, 0) for k in ('source_windows', 'static_findings')}},
               'evidence_disclosure': 'Metadata only. Response bodies, request values, headers, identity values, and cookies were withheld.'}
    # Stage-specific filtering and packing happen at the actual request boundary.
    return redactor.clean(context)


def compact_post_context(context):
    """Keep issue-specific evidence and short cited excerpts instead of repetition."""
    from copy import deepcopy
    result = deepcopy(context)
    checks = result.pop('checks', [])
    result.pop('static_findings', None)
    evidence_omitted = 0
    anchors = {}
    for issue in result.get('issues', []):
        evidence = issue.get('evidence', [])
        evidence_omitted += max(0, len(evidence) - 2)
        issue['evidence'] = [{k: v for k, v in e.items() if v is not None} for e in evidence[-2:]]
        keys = {(b['route'], b['method'], b['parameter'], b['location']) for b in issue.get('bindings', [])}
        issue['runtime_checks'] = [{k: c.get(k) for k in ('outcome', 'reason')} for c in checks
                                   if c.get('cwe') == issue['cwe'] and (c.get('route'), c.get('method'), c.get('parameter'), c.get('location')) in keys][:3]
        issue['bindings'] = [{k: b[k] for k in ('route', 'method', 'parameter', 'location', 'flow') if k in b} for b in issue.get('bindings', [])]
        for target in issue.get('fix_targets', []):
            # Candidate operations have an exact line; mapped functions expose
            # their beginning as investigation context, never their entire body.
            anchors.setdefault(target['source_id'], []).append(target['start'])
        if issue.get('reviewed_fix_target'):
            target = issue['reviewed_fix_target']
            anchors.setdefault(target['source_id'], []).append(target['line'])
    windows = {}
    lines_omitted = 0
    for window in result.get('source_windows', []):
        centers = anchors.get(window['id'], [])
        lines = [l for l in window['lines'] if any(abs(l['number'] - c) <= 4 for c in centers)]
        lines_omitted += len(window['lines']) - len(lines)
        if lines:
            windows[window['id']] = {'id': window['id'], 'file': window['file'], 'start': lines[0]['number'],
                                    'end': lines[-1]['number'], 'lines': lines}
    result['source_windows'] = list(windows.values())
    for issue in result.get('issues', []):
        targets = []
        for target in issue.get('fix_targets', []):
            window = windows.get(target['source_id'])
            if window:
                start, end = max(target['start'], window['start']), min(target['end'], window['end'])
                if start <= end: targets.append({**target, 'start': start, 'end': end})
        issue['fix_targets'] = targets
    result['context_compaction'] = {'source_lines_omitted': lines_omitted, 'evidence_records_omitted': evidence_omitted,
                                    'note': 'Short code excerpts may omit guards or surrounding context; missing code is unknown.'}
    return result
