"""PRD source/runtime correlation with optional strict execution attribution."""

from __future__ import annotations

from dataclasses import asdict

from .model import Analysis, Finding, RULES
from .source_flow import matching
from .tracing import narrow


def binding_key(binding):
    return binding.route, binding.method, binding.location, binding.parameter


def options(value=None):
    value = {} if value is None else value
    if not isinstance(value, dict) or value.keys() - {'policy'} or value.get('policy', 'prd') not in ('prd', 'strict'):
        raise ValueError('correlation accepts policy: prd or strict.')
    return {'policy': value.get('policy', 'prd')}


def correlate(analysis: Analysis, runtime: list[Finding], build: dict, require_build_match=False, trace_required=False,
              policy='prd') -> list[dict]:
    policy = options({'policy': policy})['policy']
    strict = policy == 'strict'
    build_required = strict or require_build_match
    execution_required = strict or trace_required
    issues = {}

    def make(key, finding, status):
        return {"id": key, "title": finding.title, "cwe": finding.cwe, "severity": finding.severity,
                "status": status, "verification": finding.verification, "link_confidence": "unlinked",
                "source": finding.source, "bindings": [], "findings": [], "evidence": [], "link_reasons": [],
                "candidate_source_ids": [], "handler_locations": [], "fix": RULES.get(finding.cwe, ('', '', 'Review the scanner evidence and address the reported weakness at its source.'))[2], "notes": [],
                "deployment_identity": build.get('status', 'unverified'), "correlation_checks": [],
                "source_link": {"status": "Code only" if status == "Code only" else "Runtime only",
                                "operation_id": None, "policy": policy, "basis": None, "missing_evidence": []},
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
        # PRD matching needs a unique source-derived input binding and native
        # runtime proof. Extra evidence is reported honestly, not fabricated.
        # Explicitly required checks and contradictory evidence still veto links.
        build_ok = build.get('status') == 'matched' if build_required else build.get('status') != 'mismatch'
        confirmed = bool(unique and native and build_ok and (not strict or complete)
                         and (not execution_required or traced))
        missing = []
        if not native: missing.append('Independent native runtime proof is missing.')
        if not unique: missing.append('A unique source-derived route/input candidate is missing or ambiguous.')
        if strict and not complete: missing.append('A complete modeled input-to-sink path is missing.')
        if execution_required and not traced: missing.append(trace_reason or 'Authenticated operation/input execution evidence is missing.')
        elif not candidates and trace_reason: missing.append(trace_reason)
        if not build_ok: missing.append('Deployment identity is unverified or mismatches the scanned source.')
        evidence_checks = [
            {'name': 'Runtime proof', 'result': 'pass' if native else 'unknown', 'required': True,
             'detail': 'Native test requests independently reproduced the vulnerability.' if native else 'Independent native runtime proof is missing.'},
            {'name': 'Source flow', 'result': 'pass' if complete else 'unknown', 'required': strict,
             'detail': 'A complete modeled input-to-sink path is recorded.' if complete else 'A complete flow graph is required by strict policy.' if strict else 'A complete flow graph is unavailable; PRD matching uses the source-derived route/input binding.'},
            {'name': 'Runtime trace', 'result': 'pass' if traced else 'unknown', 'required': execution_required,
             'detail': 'Signed request-bound traces attribute the tested input to this operation.' if traced else trace_reason or 'No authenticated operation/input trace was supplied.'},
            {'name': 'Deployment identity', 'result': 'pass' if build.get('status') == 'matched' else 'fail' if build.get('status') == 'mismatch' else 'unknown',
             'required': build_required, 'detail': build.get('reason') or 'Deployment identity was not verified.'}]
        if confirmed:
            issue = issues[unique.id]
            issue['status'] = 'Confirmed'
            issue['verification'] = 'verified'
            attributed = complete and traced and build.get('status') == 'matched'
            basis = 'authenticated runtime trace and source flow' if attributed else 'PRD route and input match'
            issue['link_confidence'] = basis
            issue['source_link'] = {'status': 'Confirmed source link', 'operation_id': unique.id,
                                    'policy': policy, 'basis': basis, 'missing_evidence': []}
            binding = next(b for b in finding.bindings if binding_key(b) in {binding_key(s) for s in unique.bindings})
            checks = [
                ('Same CWE', f"Both scanners report {finding.cwe}."),
                ('Same route and method', f"{binding.method} {binding.route} maps to {binding.handler}."),
                ('Same parameter', f"Both findings concern {binding.location} parameter {binding.parameter}."),
                ('Unique source candidate', f"One source-derived candidate matches: {unique.source['file']}:{unique.source['line']} ({unique.id}).")]
            for name, detail in checks:
                check = {'name': name, 'result': 'pass', 'detail': detail, 'required': True}
                if check not in issue['correlation_checks']: issue['correlation_checks'].append(check)
            for check in evidence_checks:
                if check not in issue['correlation_checks']: issue['correlation_checks'].append(check)
            issue['link_reasons'] = [c['detail'] for c in issue['correlation_checks']]
            attach(issue, finding)
        else:
            issue = issues.setdefault(finding.id, make(finding.id, finding, 'Runtime only'))
            attach(issue, finding)
            issue['candidate_source_ids'] = [f.id for f in [*original_candidates, *asserted]]
            probable = bool(unique and native and build.get('status') != 'mismatch')
            issue['source_link'] = {'status': 'Probable source link' if probable else 'Runtime only',
                                    'operation_id': unique.id if probable else None, 'policy': policy,
                                    'basis': 'unique source candidate; confirmation requirements incomplete' if probable else None,
                                    'missing_evidence': missing}
            issue['link_reasons'] = list(missing)
            if len(candidates) > 1:
                issue['link_confidence'] = 'ambiguous'
                issue['link_reasons'].insert(0, f'{len(candidates)} source operations match this input; no source cause was selected.')
            elif original_candidates and not native: issue['link_confidence'] = 'runtime proof missing'
            elif original_candidates and not build_ok: issue['link_confidence'] = 'build unverified'
            elif strict and unique and not complete: issue['link_confidence'] = 'incomplete source flow'
            elif original_candidates: issue['link_confidence'] = 'execution trace unresolved'
            elif asserted:
                issue['link_confidence'] = 'operator mapping only'
                issue['link_reasons'] = ['Only an operator mapping matches; no source-derived route/input path establishes the cause.']
            else:
                issue['link_reasons'] = ['No supported static vulnerability candidate matches this runtime result.']
            if stored_flow: issue['link_reasons'] = ['Stored-XSS behavior was verified across a write and separate read; the storage-to-output source path is not modeled.']
            issue['correlation_checks'] = evidence_checks
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
                edge = {'from': node['id'], 'to_operation': unique.id,
                        'kind': 'authenticated_input_attribution' if traced else 'prd_input_correlation'}
                if edge not in graph['edges']: graph['edges'].append(edge)
    for issue in issues.values():
        from .evidence import runtime_observations
        issue['fingerprint'] = issue['id']
        issue['runtime'] = runtime_observations(issue['evidence'], issue['bindings'])
        base = {"critical": 9.0, "high": 7.0, "medium": 4.5, "low": 2.0}.get(issue["severity"], 2.0)
        issue["risk_score"] = min(10.0, base + (2.0 if issue["verification"] == "verified" else 0.0))
        issue["risk_basis"] = "Heuristic severity weight + 2 for verified runtime behavior; this is not CVSS."
    return sorted(issues.values(), key=lambda i: (i["status"] != "Confirmed", -i["risk_score"], i["cwe"], i["id"]))
