"""Scoped request preparation, fresh form controls and bounded session renewal."""
from copy import deepcopy

from .model import fingerprint
from .transport import TargetError


def form_signature(form):
    return fingerprint(form['action'], form['method'], form.get('id'), sorted(form['fields']))


def select_form(response, selector):
    from .discovery import Page
    if response.status != 200 or response.truncated:
        raise TargetError('A successful complete form page is required; request was not submitted.')
    forms = Page(response.text).forms
    selected = None
    if selector.get('id'):
        matching = [f for f in forms if f.get('id') == selector['id']]
        if len(matching) == 1: selected = matching[0]
    else:
        index = selector.get('index', 0)
        if 0 <= index < len(forms): selected = forms[index]
    if selected is None or (selector.get('signature') and form_signature(selected) != selector['signature']):
        raise TargetError('The selected form disappeared or changed structure; no request was submitted.')
    return selected


def refresh_form(transport, settings, route, method):
    """Reload all hidden/submit controls; preserve explicit values and the tested input."""
    from .discovery import local_reference
    settings = deepcopy(settings)
    spec = settings.get('form_refresh')
    if not spec: return settings
    response = transport.request(spec['path'], query=spec.get('query'))
    form = select_form(response, spec)
    local = local_reference(transport.target, response.url, form['action'])
    from .route_inputs import concrete_route
    expected = concrete_route(route, settings.get('path', {}))
    if not local or local[0] != expected or form['method'] != method:
        raise TargetError('Refreshed form action/method differs from the selected request.')
    location = 'query' if method == 'GET' else 'form'
    settings[location] = {**form['fields'], **settings.get(location, {})}
    for name in form.get('hidden', []):
        settings[location][name] = form['fields'][name]
    # Explicit operator overrides are applied after refreshing controls.
    for component, values in spec.get('overrides', {}).items():
        if component in {'query', 'form', 'json', 'headers', 'cookies', 'path'}:
            settings.setdefault(component, {}).update(values)
    return settings


def replay(transport, workflow, allowed_methods):
    """Execute only explicitly supplied, bounded navigation/preparation steps."""
    for step in workflow.get('steps', []):
        method = step.get('method', 'GET')
        if method not in allowed_methods:
            raise TargetError('Workflow method is not enabled in allowed_methods.')
        settings = refresh_form(transport, step, step['path'], method)
        response = transport.request(step['path'], method, query=settings.get('query'), form=settings.get('form'),
                                     json_body=settings.get('json'), headers=settings.get('headers'))
        if response.truncated or response.status not in step.get('expect_status', [200, 201, 204, 302, 303]):
            raise TargetError('Workflow preparation did not return its expected status; tests were not run.')
        if step.get('success_contains') and step['success_contains'] not in response.text:
            raise TargetError('Workflow preparation failed its success check; tests were not run.')


class SessionGuard:
    """Verify identity before requests; never blindly retry a mutation after failure."""
    def __init__(self, transport, config, emit):
        self.raw, self.config, self.emit = transport, config, emit
        self.active = False
        self.renewals = 0

    def __getattr__(self, name): return getattr(self.raw, name)

    def request(self, *args, **kwargs):
        if self.active:
            from .discovery import authenticate
            login = self.config['session']['login']
            verified = self.raw.request(login['verify_path'])
            if verified.status != 200 or verified.truncated or login['success_contains'] not in verified.text:
                if self.renewals >= self.config['session'].get('max_reauth', 2):
                    raise TargetError('Session renewal budget exhausted; authenticated request withheld.')
                self.renewals += 1
                authenticate(self.raw, self.config)
                self.emit('session_renewed', {'renewals': self.renewals})
        return self.raw.request(*args, **kwargs)
