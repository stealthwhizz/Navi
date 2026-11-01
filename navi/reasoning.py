"""Short, evidence-grounded explanations shared by CLI, API, and reports."""
PROOFS = {
    'CWE-89': 'Repeated true/false SQL probes changed the result while true controls matched the baseline.',
    'CWE-79': 'The test marker executed as JavaScript in browser verification.',
    'CWE-78': 'Two encoded shell markers were executed; reflection and non-command controls did not reproduce them.',
    'CWE-22': 'A boundary-crossing request returned the configured private-file marker, absent from the baseline.',
    'CWE-601': 'The response redirected to the supplied external destination.',
    'CWE-639': 'A verified identity outside the access policy received the expected protected object fields.',
}
CANDIDATES = {
    'CWE-89': 'Request input may reach a SQL query without modeled parameterization.',
    'CWE-79': 'Request input may reach HTML output without adequate contextual escaping.',
    'CWE-78': 'Request input may influence a shell command without sufficient protection.',
    'CWE-22': 'Request input may select a file outside the intended boundary.',
    'CWE-601': 'Request input may control a redirect destination without an effective allowlist.',
    'CWE-798': 'A credential-like literal was found in code; its validity has not been tested.',
}


def explain(issue, report, review=None):
    review = review or {}
    if issue['verification'] == 'template_match':
        native = 'The HTTP template matched the recorded response. Exploitability and a unique source cause have not been independently verified.'
    elif issue['verification'] == 'verified':
        native = PROOFS.get(issue['cwe'], 'The native runtime verifier reproduced the weakness.')
        if issue['status'] == 'Confirmed':
            link = issue.get('source_link', {})
            if link.get('basis') == 'PRD route and input match':
                native += ' Confirmed under PRD correlation: one source-derived candidate matches the CWE, route, method, input location and parameter.'
                if not any(c['name'] == 'Runtime trace' and c['result'] == 'pass'
                           for c in issue.get('correlation_checks', [])):
                    native += ' Signed execution attribution is unavailable.'
            else:
                native += ' A modeled input-to-sink path and signed operation/input traces identify the source operation on the matching deployed build.'
            if issue.get('deployment_identity', report.get('build', {}).get('status')) != 'matched':
                native += ' Deployment identity is unverified.'
        elif issue.get('source_link', {}).get('status') == 'Probable source link':
            native += ' Probable source link: a source candidate matches, but exact attribution remains provisional. '
            native += ' '.join(issue['source_link'].get('missing_evidence', []))
        elif issue.get('link_confidence') == 'ambiguous':
            native += ' Multiple source operations match; the cause is unresolved.'
        elif issue.get('link_confidence') == 'operator mapping only':
            native += ' Only an operator mapping suggests a source location; no analyzed route/include path supports that link.'
        elif issue.get('candidate_source_ids'):
            native += ' Source candidates exist, but the evidence does not establish an exact source link.'
        else:
            native += ' No unique source cause was established.'
    else:
        native = CANDIDATES.get(issue['cwe'], 'Source analysis identified a potentially unsafe operation.')
        if issue['cwe'] != 'CWE-798':
            keys = {(b['route'], b['method'], b['location'], b['parameter']) for b in issue.get('bindings', [])}
            checks = [c for c in report.get('checks', []) if c['cwe'] == issue['cwe']
                      and (c['route'], c['method'], c['location'], c['parameter']) in keys]
            if checks:
                # A verified input can still be unlinked due to ambiguity/build identity.
                if any(c['outcome'] == 'verified' for c in checks):
                    native += ' Runtime proof exists for this input, but no unique permitted source link was established.'
                else:
                    reasons = list(dict.fromkeys(c['reason'] for c in checks if c.get('reason')))
                    if reasons: native += ' Validation: ' + reasons[0]
            elif not report.get('target'):
                native += ' No running application was supplied for validation.'
            else:
                native += ' No runtime check completed for this source input.'
    ai = report.get('ai', {})
    stage = ai.get('stages', {}).get('correlation', {})
    status = 'reviewed' if review else 'disabled' if not ai.get('enabled') else 'unavailable' if stage.get('status') in {'unavailable', 'rejected'} or ai.get('status') == 'unavailable' else 'not_reviewed'
    return {'native': native, 'ai': review.get('explanation') or None,
            'ai_status': status, 'ai_provider': ai.get('provider'), 'ai_model': ai.get('model'),
            'ai_reason': None if review else ('AI is disabled for this scan.' if status == 'disabled' else stage.get('reason') or ai.get('error') or 'This finding was not reviewed within the bounded AI context and request budget.'),
            'evidence_refs': review.get('evidence_refs', [])}
