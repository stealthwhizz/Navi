"""One evidence-prioritized queue with grounded AI review attached to native issues."""


def build_worklist(report):
    ai = report.get('ai', {})
    reviews = {r['issue_id']: r for r in ai.get('correlation_reviews', [])}
    fixes = {f['issue_id']: index for index, f in enumerate(ai.get('fixes', []))}
    origins = {f['id']: f['origin'] for f in report['findings']}
    items = []
    for issue in report['issues']:
        review = reviews.get(issue['id'], {})
        from .reasoning import explain
        issue['reasoning'] = explain(issue, report, review)
        verified = issue['verification'] == 'verified'
        tier = 0 if verified and issue['status'] == 'Confirmed' else 1 if verified else 2
        reasons = [
            'Runtime behavior reproduced and linked to one supported source operation; see the deployment identity check.',
            'Runtime behavior reproduced; the source cause still needs investigation.',
            'Source candidate without runtime verification; confirm exploitability before treating it as proven.',
        ]
        if issue['verification'] == 'template_match':
            reasons[2] = 'HTTP template match without independent runtime proof; validate exploitability and locate the source cause.'
        noise = review.get('noise_assessment', 'not_reviewed')
        # A model opinion can never defer a proven issue into the code-only tier.
        hint = review.get('priority_hint', 'normal')
        if verified and hint == 'later': hint = 'normal'
        locations = []
        if issue.get('source'):
            source = issue['source']
            locations.append({k: source.get(k) for k in ('file', 'line', 'function')})
            locations[-1]['basis'] = 'linked source operation' if issue['status'] == 'Confirmed' else 'static candidate; runtime unverified'
        elif review.get('fix_target'):
            target = review['fix_target']
            locations.append({k: target.get(k) for k in ('file', 'line', 'function')})
            locations[-1]['basis'] = 'AI suggested location; runtime cause unproven'
        else:
            locations = [{**h, 'basis': 'handler context only; cause unresolved'} for h in issue.get('handler_locations', [])]
        combined = len(set(issue['findings']))
        item = {'issue_id': issue['id'], 'title': issue['title'], 'cwe': issue['cwe'], 'status': issue['status'],
                'priority': f'P{tier + 1}', 'evidence_tier': tier, 'priority_reason': reasons[tier],
                'risk_score': issue['risk_score'], 'risk_basis': issue['risk_basis'],
                'signals_combined': combined,
                'signal_origins': sorted({origins[f] for f in issue['findings'] if f in origins}),
                'evidence_count': len(issue['evidence']), 'inputs': issue['bindings'],
                'fix_locations': locations, 'fix_index': fixes.get(issue['id']),
                'noise_assessment': noise, 'noise_reason': review.get('noise_reason', ''),
                'reachability': 'mapped input flow' if issue['bindings'] else 'unknown; not proof of unreachable code',
                'ai_priority_hint': hint, 'ai_priority_reason': review.get('priority_reason', ''),
                'ai_link_assessment': review.get('assessment'), 'ai_link_explanation': review.get('explanation', ''),
                'ai_next_step': review.get('next_step', ''), 'ai_fix_reason': review.get('fix_reason', ''),
                'candidate_ranking': review.get('candidate_ranking', []),
                'reviewed': bool(review), 'reasoning': issue['reasoning']}
        items.append(item)
    # Requested order: Confirmed first, then risk. P1/P2/P3 describe evidence
    # strength; the numeric rank is the priority order.
    items.sort(key=lambda i: (i['status'] != 'Confirmed', -i['risk_score'],
                             {'urgent': 0, 'normal': 1, 'later': 2}[i['ai_priority_hint']], i['issue_id']))
    issues = {i['id']: i for i in report['issues']}
    for rank, item in enumerate(items, 1):
        item['rank'] = rank
        issues[item['issue_id']]['triage'] = item
    report['issues'] = [issues[i['issue_id']] for i in items]
    return {'items': items, 'summary': {'issues': len(items),
            'signals': sum(i['signals_combined'] for i in items),
            'combined_signals': sum(max(0, i['signals_combined'] - 1) for i in items),
            'source_runtime_pairs': sum(i['signal_origins'] == ['dast', 'sast'] for i in items),
            'ai_reviewed': sum(i['reviewed'] for i in items),
            'possible_noise': sum(i['noise_assessment'] == 'possible_false_positive' for i in items)},
            'note': 'One entry per native correlated issue. P1: verified and source-linked; P2: verified with unresolved cause; P3: unverified code. AI reviews never hide findings, prove unreachability, or establish an ambiguous source cause.'}
