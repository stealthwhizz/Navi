"""Present native reports to the supplied static UI without inventing evidence."""
import json

from .reasoning import explain
from .evidence import runtime_observations, primary_observation

STATUS = {'Confirmed': 'confirmed', 'Code only': 'code_only', 'Runtime only': 'runtime_only'}


def issue_view(issue, report):
    source = issue.get('source')
    binding = next(iter(issue.get('bindings', [])), {})
    review = next((r for r in report.get('ai', {}).get('correlation_reviews', []) if r['issue_id'] == issue['id']), None)
    reason = issue.get('reasoning') or explain(issue, report, review)
    location = {'file': source['file'], 'line': source['line']} if source else None
    evidence = issue.get('evidence', [])
    observations = issue.get('runtime') or runtime_observations(evidence, issue.get('bindings', []))
    observation = primary_observation(observations)
    sast = None
    if source:
        sast = {'rule_id': issue['cwe'], 'file': source['file'], 'line_start': source['line'], 'line_end': source['line'],
                'snippet': {'start_line': source['line'], 'code': source.get('snippet', '')}, 'highlight_line': source['line'],
                'source': {'expr': binding.get('parameter', 'Code literal'), 'type': binding.get('location', 'static'), 'location': f"{source['file']}:{source['line']}"},
                'sink': {'name': source.get('function', 'Source operation'), 'type': issue['cwe'], 'location': f"{source['file']}:{source['line']}"},
                'path': [{'label': step, 'location': '', 'resolved': None} for step in binding.get('flow', [])], 'sanitizers': []}
    dast = None
    if observation:
        request = observation['request']
        dast = {'rule_id': issue['cwe'], 'method': observation['method'],
                'url': observation['url'], 'parameter': observation['parameter'], 'location': observation['location'], 'payload': observation['payload'],
                'request': json.dumps(request, indent=2), 'response': observation['response'],
                'evidence': (observation.get('execution_proof') or {}).get('expected_marker'),
                'oracle': reason['native'], 'observations': observations}
    native = reason['native']
    return {'id': issue['id'], 'fingerprint': issue['id'], 'status': STATUS[issue['status']], 'severity': issue['severity'],
            'risk': issue['risk_score'], 'cwe': int(issue['cwe'].split('-')[1]), 'title': issue['title'],
            'route': {'method': binding['method'], 'path': binding['route']} if binding.get('route') else None,
            'location': location, 'scan_id': report['id'], 'first_seen': issue.get('first_seen', report['started']), 'last_seen': issue.get('last_seen', report['finished']),
            'sast': sast, 'dast': dast, 'reasoning': reason, 'fix': issue.get('fix'),
            'priority': issue.get('triage', {}).get('priority'), 'risk_basis': issue.get('risk_basis'),
            'evidence_count': len(evidence), 'signals_combined': len(issue.get('findings', [])),
            'correlation': {'accepted': issue['status'] == 'Confirmed', 'source_link': issue.get('source_link'),
                'evidence_graph': issue.get('evidence_graph'), 'rationale': ' '.join(issue.get('link_reasons', [])) or native, 'checks': issue.get('correlation_checks') or [
                {'name': 'Runtime proof', 'result': 'pass' if issue['verification'] == 'verified' else 'unknown', 'detail': native},
                {'name': 'Source link', 'result': 'pass' if issue['status'] == 'Confirmed' else 'unknown', 'detail': ' '.join(issue.get('link_reasons', [])) or 'No supported runtime/source link.'}]}}


def routes_view(report):
    routes = {}
    for route in report.get('routes', []):
        for method in route['methods']:
            routes[(method, route['path'])] = {'method': method, 'path': route['path'], 'declared_at': f"{route['file']}:{route['line']}",
                'handler': {'name': route['function'], 'file': route['file'], 'line_start': route['line'], 'line_end': route.get('end_line', route['line'])},
                'params': [], 'provenance': 'native', 'confidence': 'medium', 'tested': False, 'issue_count': 0}
    for binding in [*report.get('discovery', {}).get('inputs', []), *report.get('checks', [])]:
        if not binding.get('route'): continue
        key = (binding['method'], binding['route'])
        row = routes.setdefault(key, {'method': key[0], 'path': key[1], 'declared_at': None, 'handler': None,
            'params': [], 'provenance': 'unresolved', 'confidence': 'low', 'tested': False, 'issue_count': 0})
        if binding.get('parameter') and binding['parameter'] not in row['params']: row['params'].append(binding['parameter'])
        if binding.get('outcome') not in {None, 'skipped'}: row['tested'] = True
    for key, row in routes.items():
        row['issue_count'] = sum(any((b['method'], b['route']) == key for b in issue['bindings']) for issue in report['issues'])
    return list(routes.values())


def scan_view(report, state=None):
    state = state or {}
    active = state.get('running') and state.get('scan_id') == report['id']
    failed = bool((state.get('error') and state.get('scan_id') == report['id']) or report.get('stop_reason'))
    failure = state.get('error') or ('Scan stopped: ' + report['stop_reason'] if report.get('stop_reason') else None)
    routes = routes_view(report)
    gaps = report.get('coverage', {}).get('gaps', [])
    checks = report.get('checks', [])
    phase = state.get('phase') if active or failed else None
    return {'id': report['id'], 'state': 'running' if active else 'failed' if failed else 'completed',
            'source_root': report.get('source') or '', 'target_origin': report.get('target') or '',
            'created_at': report['started'], 'started_at': report['started'], 'finished_at': None if active else report.get('finished'),
            'phase': phase, 'progress': None, 'error': failure if failed else None,
            'counts': {k: report.get('summary', {}).get(k, 0) for k in ('confirmed', 'code_only', 'runtime_only')},
            'ai': {'status': report.get('ai', {}).get('status', 'pending' if active else 'disabled'), 'reviewed': len(report.get('ai', {}).get('correlation_reviews', [])), 'requests': report.get('ai', {}).get('requests', 0)},
            'coverage': None if active else {'frameworks': ['Native source mapping'] if report.get('routes') else [], 'files_parsed': report.get('source_files', 0), 'files_skipped': [],
                'routes_total': len(routes), 'routes_unmapped': sum(not r['handler'] for r in routes),
                'unresolved': [{'kind': g['component'], 'location': g.get('file', g.get('route', '')), 'detail': g['reason']} for g in gaps],
                'rules_not_run': [], 'dast': {'requests': report.get('http_requests', 0), 'routes_tested': sum(r['tested'] for r in routes),
                    'params_tested': len({(c['method'], c['route'], c['location'], c['parameter']) for c in checks if c['outcome'] != 'skipped'}), 'blocked': 0, 'timeouts': 0},
                'errors': [{'stage': phase or 'scan', 'message': failure}] if failed else []}}


def install_api(app, settings, project, state, lock, get_scan, history):
    """Read-only projections; starting/cancelling scans uses the existing guarded API."""
    from pathlib import Path
    import re
    from fastapi import HTTPException
    from fastapi.responses import JSONResponse

    def archive(scan_id):
        if not re.fullmatch(r'[a-f0-9]{32}', scan_id): raise HTTPException(404, 'Scan not found.')
        try:
            result = get_scan(scan_id)
            if isinstance(result, dict): return result
        except HTTPException as error:
            if error.status_code != 404: raise
        path = Path(settings.output) / 'scans' / scan_id / 'report.json'
        try: report = json.loads(path.read_text())
        except (OSError, ValueError): raise HTTPException(404, 'Scan not found.') from None
        if report.get('project') != project: raise HTTPException(404, 'Scan not found in this workspace.')
        return report

    def working_report():
        return {'id': state['scan_id'], 'source': settings.source, 'target': settings.target, 'started': state.get('started'),
                'issues': [], 'checks': [], 'summary': {}}

    @app.get('/api/ui/scans')
    def ui_scans():
        rows = {}
        # File history remains usable in exports-only operation and after restart.
        paths = list((Path(settings.output) / 'scans').glob('*/report.json'))
        def modified(path):
            try: return path.stat().st_mtime
            except OSError: return 0
        for path in sorted(paths, key=modified, reverse=True)[:100]:
            try:
                report = json.loads(path.read_text())
                if report.get('project') == project: rows[report['id']] = scan_view(report)
            except (OSError, ValueError, KeyError): continue
        for row in history():
            rows[row['id']] = scan_view(archive(row['id']))
        with lock:
            if state['scan_id'] and (state['running'] or state['error']): rows[state['scan_id']] = scan_view(working_report(), state)
        return sorted(rows.values(), key=lambda r: r['created_at'] or '', reverse=True)[:100]

    @app.get('/api/ui/scans/{scan_id}')
    def ui_scan(scan_id: str):
        with lock:
            if state['scan_id'] == scan_id and (state['running'] or state['error']): return scan_view(working_report(), state)
        return scan_view(archive(scan_id))

    @app.get('/api/ui/issues')
    def ui_issues(scan_id: str, status: str | None = None, cwe: int | None = None):
        with lock:
            if state['scan_id'] == scan_id and (state['running'] or state['error']): return []
        report = archive(scan_id)
        rows = [issue_view(i, report) for i in report['issues']]
        return [i for i in rows if (not status or i['status'] == status) and (cwe is None or i['cwe'] == cwe)]

    @app.get('/api/ui/issues/{issue_id}')
    def ui_issue(issue_id: str, scan_id: str):
        report = archive(scan_id)
        for issue in report['issues']:
            if issue['id'] == issue_id: return issue_view(issue, report)
        raise HTTPException(404, 'Issue not found in this scan.')

    @app.get('/api/ui/routes')
    def ui_routes(scan_id: str):
        with lock:
            if state['scan_id'] == scan_id and (state['running'] or state['error']): return []
        return routes_view(archive(scan_id))

    @app.get('/api/ui/reports/{scan_id}')
    def ui_report(scan_id: str):
        return JSONResponse(archive(scan_id), headers={'Content-Disposition': f'attachment; filename="navi-{scan_id}.json"'})
