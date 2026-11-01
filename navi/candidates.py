"""Shared native DAST candidate selection for inspection and execution."""
from .model import Binding
from dataclasses import replace

NATIVE_CWES = ("CWE-89", "CWE-79", "CWE-22", "CWE-601", "CWE-78")


def binding_skip_reason(binding, config):
    if binding.method not in config.get('allowed_methods', ['GET']):
        return 'HTTP method is not enabled in allowed_methods.'
    if binding.parameter == '*':
        return 'The source uses a dynamic request key; no concrete parameter was resolved.'
    if binding.location in {'cookie', 'session'} and not any(
        i['route'] == binding.route and i.get('method', 'GET') == binding.method
        and i.get('location') == binding.location and i['parameter'] == binding.parameter
        for i in config.get('runtime_inputs', [])):
        return 'Cookie/session mutation requires an explicit runtime_inputs scenario.'
    return None


def native_candidates(analysis, config, discovered=()):
    seen = set()
    discovered = list(discovered)
    observed = {(b.route, b.method, b.location, b.parameter) for b in discovered}
    # Discovery already applies explicit request overrides. An OpenAPI/configured
    # input pointing at that same request must not schedule it a second time.
    additional = [*discovered, *(Binding(i["route"], i.get("method", "GET"), i["parameter"],
                    i.get("location", "query"), "configured runtime input", provenance="configured")
                    for i in config.get("runtime_inputs", [])
                    if (i['route'], i.get('method', 'GET'), i.get('location', 'query'), i['parameter']) not in observed)]
    candidates = []
    for finding in analysis.findings:
        if finding.cwe not in NATIVE_CWES: continue
        for binding in finding.bindings:
            matches = [b for b in discovered if (b.route, b.method, b.location, b.parameter) == (binding.route, binding.method, binding.location, binding.parameter)]
            candidates.extend((finding.cwe, replace(binding, scenario=b.scenario)) for b in matches)
            if not matches: candidates.append((finding.cwe, binding))
    # Known live forms/links supply valid controls, so try their source flows
    # before unobserved script paths. This ordering contains no app knowledge.
    candidates.sort(key=lambda pair: (pair[1].route, pair[1].method, pair[1].location, pair[1].parameter) not in observed)
    candidates.extend((cwe, b) for cwe in NATIVE_CWES for b in additional)
    for cwe, binding in candidates:
        key = (cwe, binding.route, binding.method, binding.location, binding.parameter, binding.scenario)
        if key in seen: continue
        seen.add(key)
        reason = binding_skip_reason(binding, config)
        yield cwe, binding, reason
