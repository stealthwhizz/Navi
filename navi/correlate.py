"""Keep runtime proof independent from exact source attribution."""

from __future__ import annotations

from dataclasses import asdict

from .model import Analysis, Finding, RULES
from .source_flow import matching
from .tracing import narrow


def binding_key(binding):
    return binding.route, binding.method, binding.location, binding.parameter


def correlate(analysis: Analysis, runtime: list[Finding], build: dict, require_build_match=False, trace_required=False) -> list[dict]:
    issues = {}

    def make(key, finding, status):
        return {"id": key, "title": finding.title, "cwe": finding.cwe, "severity": finding.severity,
                "status": status, "verification": finding.verification, "link_confidence": "unlinked",
                "source": finding.source, "bindings": [], "findings": [], "evidence": [], "link_reasons": [],
                "candidate_source_ids": [], "handler_locations": [], "fix": RULES.get(finding.cwe, ('', '', 'Review the scanner evidence and address the reported weakness at its source.'))[2], "notes": [],
                "deployment_identity": build.get('status', 'unverified'), "correlation_checks": [],
                "source_link": {"status": "Code only" if status == "Code only" else "Runtime only",
                                "operation_id": None, "missing_evidence": []},
                "evidence_graph": {"version": 1, "source_flows": list(finding.source_flows), "runtime_nodes": [], "edges": []}}

    def attach(issue, finding):
        if finding.id not in issue["findings"]:
            issue["findings"].append(finding.id)
        for binding in finding.bindings:
            item = asdict(binding)
            if item not in issue["bindings"]:
                issue["bindings"].append(item)
        for evidence in finding.evidence:
            if evidence not in issue["evidence"]:
                issue["evidence"].append(evidence)
        if finding.note and finding.note not in issue["notes"]:
            issue["notes"].append(finding.note)

    for finding in analysis.findings:
        key = finding.id
        issue = issues.setdefault(key, make(key, finding, "Code only"))
        attach(issue, finding)

    # Supporting matches attach independently of incoming scanner result order.
    for finding in sorted(runtime, key=lambda f: f.verification != 'verified'):
        keys = {binding_key(b) for b in finding.bindings}
        if finding.verification == 'template_match' and any(b.parameter for b in finding.bindings):
            established = [i for i in issues.values() if i['cwe'] == finding.cwe and i['verification'] == 'verified'
                           and any((b['route'], b['method'], b['location'], b['parameter']) in keys for b in i['bindings'])]
            if len(established) == 1:
                attach(established[0], finding)
                continue
        candidates = list({f.id: f for f in analysis.findings if f.cwe == finding.cwe and f.source
                           and keys.intersection(binding_key(b) for b in f.bindings)}.values())
        asserted = [f for f in candidates if not any(binding_key(b) in keys and b.provenance not in {"configured", "unmapped"} for b in f.bindings)]
        candidates = [f for f in candidates if f not in asserted]
        stored_flow = any(b.handler == "configured stored-XSS workflow" for b in finding.bindings)
        if stored_flow:
            candidates = []  # A write-time echo is not the stored read's source operation.
        original_candidates = candidates
        candidates, traced, trace_reason = narrow(candidates, finding, analysis.digest, trace_required)
        native = finding.verification == 'verified' and finding.scanner in {'native', 'navi-template-proof'}
        unique = candidates[0] if len(candidates) == 1 else None
        flows = matching(unique, keys) if unique else []
        complete = bool(flows) and all(g.get('complete') for g in flows)
        # require_build_match is retained for callers of the old API; false no
        # longer permits an unverified deployment to establish a source link.
        confirmed = bool(unique and complete and traced and native and build.get('status') == 'matched')
        missing = []
        if not native: missing.append('Independent native runtime proof is missing.')
        if not unique: missing.append('The executed source operation is unresolved or ambiguous.')
        if not complete: missing.append('A complete modeled input-to-sink path is missing.')
        if not traced: missing.append(trace_reason or 'Authenticated operation/input execution evidence is missing.')
        if build.get('status') != 'matched': missing.append('Deployment identity is unverified or mismatches the scanned source.')
        if confirmed:
            issue = issues[unique.id]
            issue['status'] = 'Confirmed'
            issue['verification'] = 'verified'
            issue['link_confidence'] = 'authenticated runtime trace and source flow'
            issue['source_link'] = {'status': 'Confirmed source link', 'operation_id': unique.id, 'missing_evidence': []}
            binding = next(b for b in finding.bindings if binding_key(b) in {binding_key(s) for s in unique.bindings})
            checks = [
                ('Same CWE', f"Both scanners report {finding.cwe}."),
                ('Same route and method', f"{binding.method} {binding.route} maps to {binding.handler}."),
                ('Same parameter', f"Both findings concern {binding.location} parameter {binding.parameter}."),
                ('Source flow', f"Modeled value propagation reaches exact operation {unique.id} at {unique.source['file']}:{unique.source['line']}."),
                ('Runtime proof', 'Native test requests independently reproduced the vulnerability.'),
                ('Runtime trace', 'Signed request-bound traces attribute the tested input to this exact operation throughout the recorded probe requests.'),
                ('Deployment identity', 'The running application reported an identity matching the scanned source.')]
            for name, detail in checks:
                check = {'name': name, 'result': 'pass', 'detail': detail}
                if check not in issue['correlation_checks']: issue['correlation_checks'].append(check)
            issue['link_reasons'] = [c['detail'] for c in issue['correlation_checks']]
            attach(issue, finding)
        else:
            issue = issues.setdefault(finding.id, make(finding.id, finding, 'Runtime only'))
            attach(issue, finding)
            issue['candidate_source_ids'] = [f.id for f in [*original_candidates, *asserted]]
            probable = bool(unique and native and build.get('status') != 'mismatch')
            issue['source_link'] = {'status': 'Probable source link' if probable else 'Runtime only',
                                    'operation_id': unique.id if probable else None, 'missing_evidence': missing}
            issue['link_reasons'] = list(missing)
            if len(candidates) > 1:
                issue['link_confidence'] = 'ambiguous'
                issue['link_reasons'].insert(0, f'{len(candidates)} source operations match this input; no source cause was selected.')
            elif original_candidates and not native: issue['link_confidence'] = 'runtime proof missing'
            elif original_candidates and build.get('status') != 'matched': issue['link_confidence'] = 'build unverified'
            elif unique and not complete: issue['link_confidence'] = 'incomplete source flow'
            elif original_candidates: issue['link_confidence'] = 'execution trace unresolved'
            elif asserted:
                issue['link_confidence'] = 'operator mapping only'
                issue['link_reasons'] = ['Only an operator mapping matches; no source-derived route/input path establishes the cause.']
            else:
                issue['link_reasons'] = ['No supported static vulnerability candidate matches this runtime result.']
            if stored_flow: issue['link_reasons'] = ['Stored-XSS behavior was verified across a write and separate read; the storage-to-output source path is not modeled.']
            issue['correlation_checks'] = [
                {'name': 'Runtime proof', 'result': 'pass' if native else 'unknown', 'detail': 'Native vulnerability verification is independent of source attribution.'},
                {'name': 'Source flow', 'result': 'pass' if complete else 'unknown', 'detail': 'A unique complete modeled input-to-sink path is required.'},
                {'name': 'Runtime trace', 'result': 'pass' if traced else 'unknown', 'detail': trace_reason or 'Authenticated operation/input attribution was recorded.'},
                {'name': 'Deployment identity', 'result': 'pass' if build.get('status') == 'matched' else 'fail' if build.get('status') == 'mismatch' else 'unknown', 'detail': build.get('reason') or 'The deployed identity must match the scanned source.'}]
            for route in analysis.routes:
                if any(b.route == route.path and b.method in route.methods for b in finding.bindings):
                    location = {"file": route.file, "function": route.function, "line": route.line, "role": "handler context only"}
                    if location not in issue["handler_locations"]:
                        issue["handler_locations"].append(location)
        graph = issue['evidence_graph']
        for candidate in original_candidates:
            for flow in matching(candidate, keys):
                if flow not in graph['source_flows']: graph['source_flows'].append(flow)
        for index, evidence in enumerate(finding.evidence):
            if not evidence.get('request', {}).get('tested_input'): continue
            node = {'id': f'{finding.id}:observation:{index}', 'kind': 'runtime_observation',
                    'finding_id': finding.id, 'evidence_index': index,
                    'tested_input': {k: v for k, v in evidence['request']['tested_input'].items() if k != 'value'},
                    'native_verified': native, 'trace_status': (evidence.get('trace') or {}).get('status', 'missing')}
            if node not in graph['runtime_nodes']: graph['runtime_nodes'].append(node)
            if confirmed:
                edge = {'from': node['id'], 'to_operation': unique.id, 'kind': 'authenticated_input_attribution'}
                if edge not in graph['edges']: graph['edges'].append(edge)
    for issue in issues.values():
        from .evidence import runtime_observations
        issue['fingerprint'] = issue['id']
        issue['runtime'] = runtime_observations(issue['evidence'], issue['bindings'])
        base = {"critical": 9.0, "high": 7.0, "medium": 4.5, "low": 2.0}.get(issue["severity"], 2.0)
        issue["risk_score"] = min(10.0, base + (2.0 if issue["verification"] == "verified" else 0.0))
        issue["risk_basis"] = "Heuristic severity weight + 2 for verified runtime behavior; this is not CVSS."
    return sorted(issues.values(), key=lambda i: (i["status"] != "Confirmed", -i["risk_score"], i["cwe"], i["id"]))
