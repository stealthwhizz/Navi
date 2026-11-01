"""Bounded Nuclei-style HTTP requests and matchers executed by Navi itself."""
import ast
from dataclasses import dataclass
import hashlib
import json
import re
import secrets
from urllib.parse import urlsplit, parse_qsl, quote

from .load import Unsupported, documents, cwe
from ..model import Binding, Check, Finding, RULES, fingerprint, gap
from ..discovery import local_reference

VERIFIERS = {'sql': 'CWE-89', 'xss': 'CWE-79', 'command': 'CWE-78', 'traversal': 'CWE-22', 'redirect': 'CWE-601'}


def regex(pattern, value, flags=0):
    # Avoid backreferences, lookarounds and repeated groups; request bodies are
    # bounded too. Unsupported expressions are never silently treated as false.
    if not isinstance(pattern, str) or len(pattern) > 300 or re.search(r'\\[1-9]|\(\?(?!:|[ims]+\))|\)\s*[*+{]', pattern):
        raise Unsupported('Regex exceeds the supported bounded matcher subset.')
    quantifiers = re.sub(r'\(\?(?::|[ims]+\))', '(', pattern)
    if len(re.findall(r'(?<!\\)[*+?]', quantifiers)) > 1: raise Unsupported('Regex supports at most one quantifier; split alternatives into separate matchers.')
    if re.search(r'(?<!\\)\{\d', pattern): raise Unsupported('Counted regex repetitions are unsupported.')
    try: return re.search(pattern, str(value)[:8192], flags=flags) is not None
    except re.error: raise Unsupported('Invalid matcher regex.') from None


FUNCTIONS = {'contains': lambda text, word: str(word) in str(text),
             'contains_all': lambda text, *words: all(str(word) in str(text) for word in words),
             'contains_any': lambda text, *words: any(str(word) in str(text) for word in words),
             'len': len, 'to_lower': lambda value: str(value).lower(), 'to_upper': lambda value: str(value).upper(),
             'regex': regex}


def dsl(expression, context, validate=False):
    if not isinstance(expression, str) or len(expression) > 2000: raise Unsupported('Invalid/oversized DSL expression.')
    # Rewrite operators outside quoted literals, then interpret an allowlisted AST.
    parts = re.split(r'("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')', expression)
    for index in range(0, len(parts), 2):
        parts[index] = re.sub(r'!(?!=)', ' not ', parts[index].replace('&&', ' and ').replace('||', ' or '))
        parts[index] = re.sub(r'\btrue\b', 'True', re.sub(r'\bfalse\b', 'False', parts[index]))
    try: tree = ast.parse(''.join(parts).strip(), mode='eval')
    except SyntaxError: raise Unsupported('Unsupported matcher DSL syntax.') from None
    allowed = (ast.Expression, ast.Constant, ast.Name, ast.Load, ast.Call, ast.BoolOp, ast.And, ast.Or,
               ast.UnaryOp, ast.Not, ast.Compare, ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE)
    for node in ast.walk(tree):
        if not isinstance(node, allowed): raise Unsupported('Unsupported matcher DSL operation.')
        if isinstance(node, ast.Call) and (not isinstance(node.func, ast.Name) or node.func.id not in FUNCTIONS or node.keywords):
            raise Unsupported('Unsupported matcher DSL function.')
        if isinstance(node, ast.Name) and node.id not in FUNCTIONS and node.id not in context:
            if not (validate and re.fullmatch(r'(body|status_code|all_headers|content_length|duration)(?:_\d+)?|randstr', node.id)):
                raise Unsupported(f'Unknown matcher variable: {node.id}.')
    if validate: return
    def evaluate(node):
        if isinstance(node, ast.Constant): return node.value
        if isinstance(node, ast.Name): return context[node.id]
        if isinstance(node, ast.Call): return FUNCTIONS[node.func.id](*(evaluate(a) for a in node.args))
        if isinstance(node, ast.UnaryOp): return not evaluate(node.operand)
        if isinstance(node, ast.BoolOp): return (all if isinstance(node.op, ast.And) else any)(bool(evaluate(v)) for v in node.values)
        if isinstance(node, ast.Compare):
            left = evaluate(node.left)
            for operation, right_node in zip(node.ops, node.comparators):
                right = evaluate(right_node)
                if not {ast.Eq: lambda: left == right, ast.NotEq: lambda: left != right, ast.Lt: lambda: left < right,
                        ast.LtE: lambda: left <= right, ast.Gt: lambda: left > right, ast.GtE: lambda: left >= right}[type(operation)](): return False
                left = right
            return True
        raise Unsupported('Unsupported matcher DSL node.')
    try: return bool(evaluate(tree.body))
    except (TypeError, KeyError): raise Unsupported('Matcher DSL values are incompatible or unavailable.') from None


def render(text, context):
    if not isinstance(text, str) or len(text) > 65536: raise Unsupported('Invalid/oversized request text.')
    def substitute(match):
        key = match[1].strip()
        if key in context: return str(context[key])
        call = re.fullmatch(r'url_encode\((\w+)\)', key)
        if call and call[1] in context: return quote(str(context[call[1]]), safe='')
        raise Unsupported(f'Unsupported request variable/expression: {key}.')
    return re.sub(r'{{\s*(.*?)\s*}}', substitute, text)


def matcher_result(spec, response, context):
    values = {'body': response.text, 'header': '\n'.join(f'{k}: {v}' for k, v in response.headers.items()),
              'all': '\n'.join(f'{k}: {v}' for k, v in response.headers.items()) + '\n\n' + response.text}
    kind = spec['type']; part = values.get(spec.get('part', 'body'), '')
    if spec.get('case-insensitive'): part = part.lower()
    if kind == 'status': matches = [response.status == number for number in spec['status']]
    elif kind == 'word':
        words = [render(word, context) for word in spec['words']]
        matches = [(word.lower() if spec.get('case-insensitive') else word) in part for word in words]
    elif kind == 'regex': matches = [regex(render(pattern, context), part, re.I if spec.get('case-insensitive') else 0) for pattern in spec['regex']]
    elif kind == 'dsl': matches = [dsl(expression, context) for expression in spec['dsl']]
    else: raise Unsupported('Unsupported matcher type.')
    result = (all if spec.get('condition', 'or') == 'and' else any)(matches)
    return not result if spec.get('negative') else result


@dataclass
class Template:
    id: str
    cwe: str
    title: str
    severity: str
    http: list
    variables: dict
    verifier: str | None = None


def load(paths):
    docs, gaps, manifest = documents(paths, 'dast-templates')
    templates, seen = [], set()
    for raw, file in docs:
        try:
            if raw.keys() - {'id', 'info', 'http', 'variables'}: raise Unsupported('Only HTTP templates are supported; flow/code/headless/network/extractors are not executed.')
            identifier, info, requests = raw.get('id'), raw.get('info', {}), raw.get('http')
            if not isinstance(identifier, str) or not re.fullmatch(r'[\w.:-]{1,160}', identifier) or identifier in seen: raise Unsupported('Invalid or duplicate template ID.')
            weakness = cwe(info.get('classification', {}).get('cwe-id'))
            variables = raw.get('variables', {})
            builtins = {'BaseURL', 'RootURL', 'Hostname', 'Host', 'Port', 'Scheme', 'Path', 'randstr'}
            if not isinstance(variables, dict) or set(variables) & builtins or any(not isinstance(k, str) or not re.fullmatch(r'[A-Za-z_]\w*', k) for k in variables) or any(not isinstance(v, (str, int)) for v in variables.values()): raise Unsupported('Invalid variables or an attempt to override scope variables.')
            if not isinstance(requests, list) or not 1 <= len(requests) <= 10: raise Unsupported('Expected 1–10 HTTP request blocks.')
            for request in requests:
                if not isinstance(request, dict) or request.keys() - {'method', 'path', 'headers', 'body', 'raw', 'matchers', 'matchers-condition', 'payloads', 'fuzzing', 'redirects', 'stop-at-first-match', 'req-condition'}:
                    raise Unsupported('Unsupported HTTP fields; the complete template was skipped.')
                for flag in ['redirects', 'stop-at-first-match', 'req-condition']:
                    if flag in request and type(request[flag]) is not bool: raise Unsupported('HTTP flags must be booleans.')
                if request.get('redirects'): raise Unsupported('Following template redirects is unsupported; requests stay in target scope.')
                if request.get('method', 'GET') not in {'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'}: raise Unsupported('Unsupported HTTP method.')
                paths_, raw_ = request.get('path', []), request.get('raw', [])
                if bool(paths_) == bool(raw_) or not isinstance(paths_, list) or not isinstance(raw_, list) or len(paths_ or raw_) > 10 or not all(isinstance(v, str) for v in paths_ + raw_): raise Unsupported('Supply bounded path or raw request lists, not both.')
                if raw_ and any(key in request for key in ['method', 'headers', 'body']): raise Unsupported('Raw HTTP cannot be combined with path-mode request fields.')
                for path in paths_:
                    if not isinstance(path, str) or not path.startswith(('{{BaseURL}}', '{{RootURL}}', '/')): raise Unsupported('Paths must be relative to this application.')
                if not isinstance(request.get('headers', {}), dict) or any(not isinstance(k, str) or not isinstance(v, str) or k.lower() in {'host', 'content-length', 'transfer-encoding', 'connection'} for k, v in request.get('headers', {}).items()): raise Unsupported('Template control headers cannot override the transport; names/values must be strings.')
                if 'body' in request and not isinstance(request['body'], str): raise Unsupported('HTTP body must be text.')
                payloads = request.get('payloads', {})
                if not isinstance(payloads, dict) or len(payloads) > 1 or any(not isinstance(v, list) or not 1 <= len(v) <= 30 or not all(isinstance(x, str) for x in v) for v in payloads.values()): raise Unsupported('Only one inline payload list of at most 30 strings is supported.')
                if any(not isinstance(k, str) or not re.fullmatch(r'[A-Za-z_]\w*', k) for k in payloads) or set(payloads) & (builtins | set(variables)): raise Unsupported('Payload variable names must be unique and cannot override scope variables.')
                if not isinstance(request.get('fuzzing', []), list) or len(request.get('fuzzing', [])) > 10: raise Unsupported('Expected at most ten fuzzing entries.')
                for fuzz in request.get('fuzzing', []):
                    if not isinstance(fuzz, dict) or fuzz.keys() - {'part', 'type', 'mode', 'keys', 'fuzz'}: raise Unsupported('Unsupported fuzzing fields.')
                    if fuzz.get('part') not in {'query', 'body'} or fuzz.get('type', 'replace') not in {'replace', 'prefix', 'postfix'} or fuzz.get('mode', 'single') != 'single': raise Unsupported('Fuzzing supports single query/body parameters with replace/prefix/postfix only.')
                    if not isinstance(fuzz.get('fuzz'), list) or not 1 <= len(fuzz['fuzz']) <= 20 or not all(isinstance(v, str) for v in fuzz['fuzz']): raise Unsupported('Invalid fuzz value list.')
                    if fuzz.get('keys') is not None and (not isinstance(fuzz['keys'], list) or not all(isinstance(k, str) for k in fuzz['keys'])): raise Unsupported('Invalid fuzz keys.')
                if request.get('fuzzing') and (paths_ != ['{{BaseURL}}'] or raw_ or request.get('body') or request.get('headers')): raise Unsupported('Fuzzing uses the discovered request unchanged except for one input; path/body/header overrides are unsupported.')
                matchers = request.get('matchers')
                if not isinstance(matchers, list) or not 1 <= len(matchers) <= 20: raise Unsupported('Templates need bounded matchers.')
                if request.get('matchers-condition', 'or') not in {'and', 'or'}: raise Unsupported('Invalid matcher combination.')
                for matcher in matchers:
                    allowed = {'type', 'part', 'status', 'words', 'regex', 'dsl', 'condition', 'negative', 'case-insensitive', 'name'}
                    if not isinstance(matcher, dict) or matcher.keys() - allowed or matcher.get('type') not in {'status', 'word', 'regex', 'dsl'}: raise Unsupported('Unsupported matcher.')
                    kind = matcher['type']; key = {'word': 'words'}.get(kind, kind)
                    if not isinstance(matcher.get(key), list) or not 1 <= len(matcher[key]) <= 30: raise Unsupported('Invalid matcher values.')
                    invalid_values = (any(type(v) is not int or not 100 <= v <= 599 for v in matcher[key]) if kind == 'status'
                                      else any(not isinstance(v, str) for v in matcher[key]))
                    if invalid_values: raise Unsupported('Invalid matcher value type.')
                    for flag in ['negative', 'case-insensitive']:
                        if flag in matcher and type(matcher[flag]) is not bool: raise Unsupported('Matcher flags must be booleans.')
                    if (set(matcher) & {'status', 'words', 'regex', 'dsl'}) != {key}: raise Unsupported('Matcher values must agree with matcher type.')
                    if matcher.get('part', 'body') not in {'body', 'header', 'all'} or matcher.get('condition', 'or') not in {'and', 'or'}: raise Unsupported('Unsupported matcher part/condition.')
                    if kind == 'dsl':
                        for expression in matcher[key]: dsl(expression, variables, validate=True)
                    if kind == 'regex':
                        for expression in matcher[key]: regex(expression, '')
            verifier = info.get('metadata', {}).get('navi-verifier')
            if verifier and (verifier not in VERIFIERS or VERIFIERS[verifier] != weakness): raise Unsupported('Invalid Navi proof verifier/CWE combination.')
            severity = info.get('severity', 'medium')
            if severity not in {'critical', 'high', 'medium', 'low', 'info'}: raise Unsupported('Invalid severity.')
            templates.append(Template(identifier, weakness, str(info.get('name', weakness)), severity, requests, variables, verifier)); seen.add(identifier)
        except (Unsupported, TypeError, AttributeError, KeyError) as error:
            gaps.append(gap('dast-templates', str(error) if isinstance(error, Unsupported) else 'Invalid template structure.', file=file['file'], rule_id=raw.get('id')))
    if not templates: gaps.append(gap('dast-templates', 'No supported HTTP templates loaded; no template runtime coverage.'))
    return templates, gaps, {'interpreter': 'navi-http-v1', 'loaded': [t.id for t in templates], 'files': manifest, 'unsupported': len(gaps),
                            'cwes': sorted({t.cwe for t in templates}), 'proof_cwes': sorted({t.cwe for t in templates if t.verifier}),
                            'limits': {'regex_response_characters': 8192, 'regex_pattern_characters': 300, 'discovered_endpoints': 60}}


def context_for(runtime, route, variables):
    target = runtime.transport.target.rstrip('/')
    parsed = urlsplit(target)
    context = {'BaseURL': target + route, 'RootURL': target + '/', 'Hostname': parsed.netloc,
               'Host': parsed.hostname, 'Port': parsed.port or (443 if parsed.scheme == 'https' else 80),
               'Scheme': parsed.scheme, 'Path': route, 'randstr': 'navi_' + secrets.token_hex(8)}
    for key, value in variables.items(): context[key] = render(str(value), context)
    return context


def observations(context, response, index):
    values = {'body': response.text, 'status_code': response.status, 'content_length': len(response.body),
              'all_headers': '\n'.join(f'{k}: {v}' for k, v in response.headers.items()), 'duration': response.elapsed_ms / 1000}
    context.update(values); context.update({f'{key}_{index}': value for key, value in values.items()})


def record_match(runtime, template, response, binding, evidence):
    key = fingerprint('template-runtime', template.cwe, template.id, binding.route, binding.method, binding.location, binding.parameter)
    finding = runtime.findings.setdefault(key, Finding(key, 'dast', template.cwe, RULES.get(template.cwe, (template.title,))[0], template.severity,
        bindings=[binding], verification='template_match', confidence='template matcher only',
        note='The HTTP template matched. This is a detection signal; exploitability and a unique source cause have not been verified.', scanner='navi-http-template', rule_id=template.id))
    finding.evidence.extend(item for item in evidence if item not in finding.evidence)
    runtime.emit('runtime_finding', finding.to_dict())
    runtime.record(Check(template.cwe, binding.route, binding.method, binding.parameter, binding.location,
                         'template_match', finding.note, evidence))


def execute(runtime, templates):
    from ..candidates import native_candidates, binding_skip_reason
    bindings = {}
    for _, binding, skipped in native_candidates(runtime.analysis, runtime.config, runtime.discovered_inputs):
        if not skipped: bindings[(binding.route, binding.method, binding.location, binding.parameter)] = binding
    for finding in runtime.analysis.findings:
        for binding in finding.bindings:
            if not binding_skip_reason(binding, runtime.config):
                bindings[(binding.route, binding.method, binding.location, binding.parameter)] = binding
    endpoints = list(dict.fromkeys(['/', *(b.route for b in bindings.values()), *(p['route'] for p in runtime.discovered_pages)]))[:60]
    for template in templates:
        if template.verifier: continue  # Explicit extension: native multi-request proof is scheduled separately.
        for block in template.http:
            scenarios = list(bindings.values()) if block.get('fuzzing') else [None]
            for binding in scenarios:
                routes = [binding.route] if binding else ['/']
                # BaseURL templates can be applied to discovered endpoints. RootURL
                # remains the configured application base, never an origin escape.
                if not binding and block.get('path') == ['{{BaseURL}}']: routes = endpoints
                for route in routes:
                    try:
                        base_context = context_for(runtime, route, template.variables)
                        payloads = block.get('payloads', {})
                        key = next(iter(payloads), None)
                        for payload in payloads.get(key, ['']):
                            context = dict(base_context)  # No stale indexed response values from an earlier payload.
                            if key: context[key] = render(payload, context)
                            requests = []
                            if binding:
                                for fuzz in block['fuzzing']:
                                    if fuzz['part'] != ('body' if binding.location in {'form', 'json'} else binding.location): continue
                                    if fuzz.get('keys') and binding.parameter not in fuzz['keys']: continue
                                    settings = runtime.config.get('requests', {}).get(f'{binding.method} {binding.route}', {})
                                    seed = str(settings.get(binding.location, {}).get(binding.parameter, '1'))
                                    for value in fuzz['fuzz']:
                                        value = render(value, context)
                                        value = seed + value if fuzz.get('type') == 'postfix' else value + seed if fuzz.get('type') == 'prefix' else value
                                        requests.append(('fuzz', value))
                            else: requests = [('raw' if block.get('raw') else 'path', value) for value in block.get('raw', block.get('path', []))]
                            evidence = []
                            for index, (kind, value) in enumerate(requests, 1):
                                runtime.control.check()
                                if runtime.transport.count >= runtime.transport.max_requests:
                                    runtime.gaps.append(gap('dast-templates', 'HTTP request budget exhausted; remaining template requests were not run.', rule_id=template.id))
                                    return
                                if kind == 'fuzz': response = runtime.request(binding, value); actual = binding
                                else:
                                    headers, body = {}, None
                                    method = block.get('method', 'GET')
                                    value = render(value, context)
                                    if kind == 'raw':
                                        head, _, body = value.replace('\r\n', '\n').partition('\n\n')
                                        lines = head.splitlines(); method, path, version = lines[0].split()
                                        if version != 'HTTP/1.1': raise Unsupported('Raw requests support HTTP/1.1 only.')
                                        for line in lines[1:]:
                                            name, separator, content = line.partition(':')
                                            if not separator: raise Unsupported('Malformed raw header.')
                                            if name.lower() == 'host':
                                                if content.strip() != context['Hostname']: raise Unsupported('Raw Host differs from the selected target.')
                                            elif name.lower() == 'transfer-encoding': raise Unsupported('Raw transfer-encoding is unsupported.')
                                            elif name.lower() not in {'content-length', 'connection'}: headers[name] = content.strip()
                                    else:
                                        path = value
                                        headers = {name: render(content, context) for name, content in block.get('headers', {}).items()}
                                        if 'body' in block: body = render(block['body'], context)
                                    if method not in runtime.config.get('allowed_methods', ['GET']): raise Unsupported(f'{method} is not enabled in allowed_methods.')
                                    local = local_reference(runtime.transport.target, runtime.transport.target.rstrip('/') + '/', path)
                                    if not local: raise Unsupported('Template request leaves target origin or application base path.')
                                    response = runtime.transport.request(local[0], method, query=local[1], raw_body=body, headers=headers)
                                    actual = Binding(local[0], method, '', 'query', 'HTTP template', provenance='http-template')
                                observations(context, response, index)
                                evidence.append({**response.evidence('HTTP template response'), 'template_id': template.id, 'matcher_basis': 'template match; not independent proof'})
                                if block.get('req-condition') and index < len(requests): continue
                                tests = [matcher_result(matcher, response, context) for matcher in block['matchers']]
                                if not response.truncated and (all if block.get('matchers-condition', 'or') == 'and' else any)(tests):
                                    record_match(runtime, template, response, actual, evidence)
                                    if block.get('stop-at-first-match'): break
                                else:
                                    runtime.record(Check(template.cwe, actual.route, actual.method, actual.parameter, actual.location,
                                        'inconclusive' if response.truncated else 'not_reproduced',
                                        'Template response was truncated.' if response.truncated else f'Template {template.id} did not match; this does not establish safety.', evidence))
                    except (Unsupported, ValueError, OSError, TypeError, IndexError) as error:
                        runtime.gaps.append(gap('dast-templates', str(error), rule_id=template.id, route=route))
