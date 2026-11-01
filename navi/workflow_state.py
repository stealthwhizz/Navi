"""Bounded create/extract/test/cleanup workflows with per-check state."""
from contextlib import contextmanager
from copy import deepcopy
import re

from .control import ScanControl
from .model import gap
from .transport import TargetError


def bind_values(value, state):
    """Carry discovered object IDs forward to the next setup, without stale IDs."""
    if isinstance(value, dict): return {k: bind_values(v, state) for k, v in value.items()}
    if isinstance(value, list): return [bind_values(v, state) for v in value]
    names = [k for k, v in state.items() if str(v) == str(value)]
    return {'$var': names[0]} if len(names) == 1 else value


def bind_path(path, state):
    from urllib.parse import unquote
    parts = path.split('/')
    for index, part in enumerate(parts):
        names = [k for k, v in state.items() if str(v) == unquote(part)]
        if len(names) == 1: parts[index] = '<' + names[0] + '>'
    return '/'.join(parts)


def variables(value, state):
    if isinstance(value, dict):
        if set(value) == {'$var'}:
            name = value['$var']
            if not isinstance(name, str) or name not in state:
                raise TargetError('A required workflow variable is unavailable; request withheld.')
            return state[name]
        return {k: variables(v, state) for k, v in value.items()}
    if isinstance(value, list): return [variables(v, state) for v in value]
    return value


def validate(workflows, methods, local, validate_refresh):
    if not isinstance(workflows, list) or len(workflows) > 10: raise ValueError('workflows accepts at most ten flows.')
    ids = set()
    for flow in workflows:
        if (not isinstance(flow, dict) or flow.keys() - {'id', 'steps', 'page', 'cleanup'}
                or not isinstance(flow.get('id'), str) or not re.fullmatch(r'[A-Za-z_]\w{0,79}', flow['id']) or flow['id'] in ids
                or not local(flow.get('page'))):
            raise ValueError('Each workflow needs a unique ID, local page and preparation steps.')
        ids.add(flow['id'])
        if not isinstance(flow.get('steps'), list) or not 1 <= len(flow['steps']) <= 10: raise ValueError('Workflow needs 1–10 preparation steps.')
        cleanup = flow.get('cleanup', [])
        if not isinstance(cleanup, list) or len(cleanup) > 4: raise ValueError('Workflow cleanup accepts at most four steps.')
        names = set()
        for step in [*flow['steps'], *cleanup]:
            if (not isinstance(step, dict) or step.keys() - {'path', 'path_values', 'method', 'query', 'form', 'json', 'headers', 'form_refresh', 'expect_status', 'success_contains', 'extract'}
                    or not local(step.get('path')) or step.get('method', 'GET') not in methods):
                raise ValueError('Workflow requests need local paths and explicitly enabled methods.')
            if any(not isinstance(step[k], dict) for k in ['path_values','query','form','json','headers'] if k in step) or 'form' in step and 'json' in step:
                raise ValueError('Invalid workflow request values.')
            if 'form_refresh' in step: validate_refresh(step['form_refresh'])
            statuses = step.get('expect_status', [200, 201, 204, 302, 303])
            if not isinstance(statuses, list) or not statuses or any(type(s) is not int or not 100 <= s <= 599 for s in statuses): raise ValueError('Invalid workflow response statuses.')
            if 'success_contains' in step and not isinstance(step['success_contains'], str): raise ValueError('Invalid workflow success text.')
            extracts = step.get('extract', {})
            if not isinstance(extracts, dict) or len(extracts) > 10: raise ValueError('Workflow steps accept at most ten extracted variables.')
            for name, spec in extracts.items():
                if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z_]\w{0,79}', name) or name in names:
                    raise ValueError('Workflow variable names must be unique identifiers.')
                if not isinstance(spec, dict) or len(spec) != 1 or not set(spec) <= {'json','header','hidden'} or not all(isinstance(v, str) and 0 < len(v) <= 200 for v in spec.values()):
                    raise ValueError('Extractors accept one json field path, header name, or hidden form field.')
                names.add(name)
    return ids


def step_request(transport, step, state, allowed_methods):
    from .workflows import refresh_form
    from .route_inputs import concrete_route
    settings = variables(step, state)
    method = settings.get('method', 'GET')
    if method not in allowed_methods: raise TargetError('Workflow method is not enabled.')
    path_values = {**state, **settings.get('path_values', {})}
    path = concrete_route(settings['path'], path_values)
    if settings.get('form_refresh'):
        settings['form_refresh']['path'] = concrete_route(settings['form_refresh']['path'], path_values)
    settings = refresh_form(transport, settings, path, method)
    response = transport.request(path, method, query=settings.get('query'), form=settings.get('form'),
                                 json_body=settings.get('json'), headers=settings.get('headers'))
    if response.truncated or response.status not in step.get('expect_status', [200, 201, 204, 302, 303]):
        raise TargetError('Workflow request did not return a complete expected response.')
    if step.get('success_contains') and step['success_contains'] not in response.text:
        raise TargetError('Workflow success check failed.')
    for name, spec in step.get('extract', {}).items():
        kind, selector = next(iter(spec.items()))
        try:
            if kind == 'json':
                value = response.json()
                for field in selector.split('.'):
                    value = value[int(field)] if isinstance(value, list) and field.isdigit() else value[field]
            elif kind == 'header': value = response.headers[selector.lower()]
            else:
                from .discovery import Page
                value = Page(response.text).hidden[selector]
        except (KeyError, IndexError, TypeError, ValueError):
            raise TargetError('Workflow extraction failed; dependent requests were not sent.') from None
        if type(value) not in {str, int, float} or len(str(value)) > 4096 or any(c in str(value) for c in '\r\n'):
            raise TargetError('Extracted workflow values must be bounded scalar values without newlines.')
        state[name] = value
    return response


@contextmanager
def cleanup_budget(transport):
    raw = transport
    while hasattr(raw, 'raw'): raw = raw.raw
    previous = {k: getattr(raw, k) for k in ('control', 'max_requests') if hasattr(raw, k)}
    raw.control = ScanControl(15)
    raw.max_requests = getattr(raw, 'count', 0) + 4
    try: yield
    finally:
        for key in ('control', 'max_requests'):
            if key in previous: setattr(raw, key, previous[key])
            else: delattr(raw, key)


class WorkflowRunner:
    def __init__(self, transport, config, gaps, emit=lambda *args: None):
        self.transport, self.config, self.gaps, self.emit = transport, config, gaps, emit
        self.active = {}

    def start(self, identifier):
        if identifier in self.active: return self.active[identifier][1]
        flow = next((w for w in self.config.get('workflows', []) if w['id'] == identifier), None)
        if flow is None: raise TargetError('Unknown request workflow.')
        state = {}
        self.active[identifier] = (flow, state)
        try:
            for step in flow['steps']: step_request(self.transport, step, state, self.config.get('allowed_methods', ['GET']))
        except BaseException:
            self.close()
            raise
        self.emit('workflow_ready', {'id': identifier, 'variables': sorted(state)})
        return state

    def resolve(self, settings):
        if not settings.get('workflow'): return deepcopy(settings)
        state = self.start(settings['workflow']['id'])
        result = variables(settings, state)
        if result.get('form_refresh'):
            from .route_inputs import concrete_route
            result['form_refresh']['path'] = concrete_route(result['form_refresh']['path'], state)
        return result

    def close(self):
        active, self.active = self.active, {}
        for identifier, (flow, state) in reversed(list(active.items())):
            if not flow.get('cleanup'): continue
            try:
                with cleanup_budget(self.transport):
                    for step in flow['cleanup']: step_request(self.transport, step, state, self.config.get('allowed_methods', ['GET']))
                self.emit('workflow_cleanup', {'id': identifier, 'status': 'completed'})
            except Exception as error:
                self.gaps.append(gap('workflow-cleanup', f'Cleanup did not complete ({type(error).__name__}); inspect the configured test resources.', workflow=identifier))
                self.emit('workflow_cleanup', {'id': identifier, 'status': 'incomplete'})
