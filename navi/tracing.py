"""Authenticated, request-bound execution evidence; never vulnerability proof."""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
from urllib.parse import urlsplit

CWES = {'CWE-89','CWE-79','CWE-78','CWE-22','CWE-601'}


def options(value=None):
    value = {} if value is None else value
    if not isinstance(value, dict) or value.keys() - {'enabled','required','key_env'}:
        raise ValueError('trace accepts enabled, required and key_env.')
    result = {'enabled': False, 'required': True, 'key_env': 'NAVI_TRACE_KEY', **value}
    if any(type(result[k]) is not bool for k in ['enabled','required']): raise ValueError('Trace flags must be booleans.')
    if not isinstance(result['key_env'], str) or not re.fullmatch(r'[A-Za-z_]\w*', result['key_env']): raise ValueError('trace.key_env must name an environment variable.')
    return result


def verify(encoded, signature, key, request_id, method, url, digest):
    def rejected(reason): return {'status': 'rejected', 'reason': reason}
    if not encoded or not signature: return {'status': 'missing', 'reason': 'Target did not return a signed execution trace.'}
    if len(encoded) > 6000 or not re.fullmatch(r'[A-Za-z0-9_-]+', encoded) or not re.fullmatch(r'[0-9a-f]{64}', signature):
        return rejected('Malformed or oversized execution trace.')
    expected = hmac.new(key, encoded.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature): return rejected('Execution trace signature does not match.')
    try:
        data = json.loads(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
        if not isinstance(data, dict) or type(data.get('version')) is not int or data['version'] not in {1, 2}: return rejected('Unsupported execution trace format.')
        if data.get('request_id') != request_id or data.get('method') != method or data.get('path') != urlsplit(url).path:
            return rejected('Execution trace belongs to a different request.')
        if type(data.get('truncated')) is not bool or data['truncated']: return rejected('Execution trace is incomplete.')
        actual = data.get('source_digest')
        if not isinstance(actual, str) or not re.fullmatch(r'[0-9a-f]{64}', actual) or digest is not None and not hmac.compare_digest(actual, digest):
            return rejected('Execution trace source snapshot differs from the analyzed source.')
        operations = data.get('operations')
        if not isinstance(operations, list) or len(operations) > 32: return rejected('Invalid execution operation list.')
        cleaned = []
        for operation in operations:
            if not isinstance(operation, dict): return rejected('Invalid execution operation.')
            file, line, cwe = operation.get('file'), operation.get('line'), operation.get('cwe')
            if not isinstance(file, str) or not file or len(file) > 512 or file.startswith('/') or '\\' in file or any(p in {'', '.', '..'} for p in file.split('/')) or any(ord(c) < 32 for c in file):
                return rejected('Invalid execution source path.')
            if type(line) is not int or not 1 <= line <= 10_000_000 or cwe not in CWES: return rejected('Invalid execution source location or CWE.')
            item = {'file': file, 'line': line, 'cwe': cwe}
            if data['version'] == 2:
                identifier, inputs = operation.get('operation_id'), operation.get('inputs')
                if not isinstance(identifier, str) or not re.fullmatch(r'[0-9a-f]{20}', identifier): return rejected('Invalid operation identity.')
                if not isinstance(inputs, list) or not inputs or len(inputs) > 16: return rejected('Missing operation input attribution.')
                for inp in inputs:
                    if not isinstance(inp, dict) or set(inp) != {'location', 'parameter'} or inp['location'] not in {'query','form','json','path','header','cookie','session'} or not isinstance(inp['parameter'], str) or not 0 < len(inp['parameter']) <= 200:
                        return rejected('Invalid operation input attribution.')
                item.update(operation_id=identifier, inputs=inputs)
            cleaned.append(item)
        return {'status': 'verified', 'version': data['version'], 'request_id': request_id, 'source_digest': actual, 'operations': cleaned,
                'reason': 'Authenticated trace matches this request and analyzed source snapshot.'}
    except (ValueError, TypeError, UnicodeError):
        return rejected('Execution trace could not be decoded.')


class TraceTransport:
    def __init__(self, raw, config, digest):
        self.raw, self.options, self.digest = raw, options(config), digest
        self.key = os.getenv(self.options['key_env'], '').encode()
        if len(self.key) < 32: raise ValueError('Tracing requires a shared key of at least 32 bytes in its configured environment variable.')
        self.trace_summary = {'verified': 0, 'missing': 0, 'rejected': 0, 'required': self.options['required']}

    def __getattr__(self, name): return getattr(self.raw, name)

    def request(self, route, method='GET', **kwargs):
        request_id = secrets.token_hex(16)
        headers = {k:v for k,v in (kwargs.pop('headers', None) or {}).items() if k.lower() != 'x-navi-request-id'}
        response = self.raw.request(route, method, headers={**headers, 'X-Navi-Request-ID': request_id}, **kwargs)
        response.trace = verify(response.headers.get('x-navi-trace'), response.headers.get('x-navi-trace-signature'),
                                self.key, request_id, method, response.url, self.digest)
        response.request['trace_request_id'] = request_id
        self.trace_summary[response.trace['status']] += 1
        return response


def narrow(candidates, finding, digest, required=False):
    observations = [e for e in finding.evidence if e.get('request', {}).get('tested_input')]
    present = any(e.get('trace') for e in observations)
    if not present and not required: return candidates, False, 'No authenticated operation/input execution trace; the source link remains provisional.'
    if not observations or any(e.get('trace', {}).get('status') != 'verified' or e['trace'].get('source_digest') != digest for e in observations):
        if not required and all(e.get('trace', {}).get('status', 'missing') == 'missing' for e in observations): return candidates, False, 'No authenticated operation/input execution trace; the source link remains provisional.'
        return [], False, 'Missing, rejected or mismatched execution traces; the source link was withheld.'
    if any(e['trace'].get('version') != 2 for e in observations):
        return candidates, False, 'Legacy traces record execution locations without exact operation/input attribution.'
    def matches(f, e):
        tested = e['request']['tested_input']
        if not any(b.route == tested.get('route') and b.method == e['request'].get('method') and b.location == tested.get('location') and b.parameter == tested.get('parameter') for b in f.bindings): return False
        relevant = [op for op in e['trace']['operations'] if op['cwe'] == f.cwe and
                    {'location': tested.get('location'), 'parameter': tested.get('parameter')} in op.get('inputs', [])]
        # A second consuming operation remains a competing cause even when the
        # static analyzer could not model it. Execution alone is not causality.
        return bool(relevant) and e['trace'].get('request_id') == e['request'].get('trace_request_id') and all(
            op.get('operation_id') == f.id and op['file'] == f.source['file'] and op['line'] == f.source['line']
            for op in relevant)
    supported = [f for f in candidates if all(matches(f, e) for e in observations)]
    if not supported: return [], False, 'Signed traces did not consistently execute a matching candidate operation during the proof requests.'
    return supported, True, None
