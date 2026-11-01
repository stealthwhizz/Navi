"""Request identity, rotating controls and source-derived path candidates."""
from flask import Flask, request, session

from navi.candidates import native_candidates
from navi.discovery import discover
from navi.model import Analysis, Binding, Route
from navi.runtime import Runtime
from navi.transport import Transport


def test_equivalent_forms_and_openapi_inputs_schedule_once(connect_app):
    app = Flask(__name__)
    form = '<form action="/lookup"><input name="id" value="1"></form>'
    app.add_url_rule('/', 'index', lambda: form)
    app.add_url_rule('/index.php', 'alias', lambda: form)
    connect_app(app)
    config = {'discovery': {'enabled': True}, 'runtime_inputs': [{'route': '/lookup', 'parameter': 'id'}]}
    inputs, _, _ = discover(Transport('http://127.0.0.1', interval=0), config, ['/index.php'])
    assert len(inputs) == 1
    scheduled = list(native_candidates(Analysis(None, [], [], [], 0), config, inputs))
    assert len(scheduled) == 5
    assert len({(cwe, b.scenario) for cwe, b, _ in scheduled}) == 5


def test_distinct_submission_modes_are_tested_but_share_runtime_issue(connect_app):
    app = Flask(__name__)
    app.add_url_rule('/', 'index', lambda: ''.join(
        f'<form action="/lookup"><input name="q" value="1"><input type="hidden" name="mode" value="{mode}"></form>'
        for mode in ['first', 'second']))
    connect_app(app)
    config = {'discovery': {'enabled': True}}
    inputs, _, _ = discover(Transport('http://127.0.0.1', interval=0), config)
    assert len(inputs) == 2 and inputs[0].scenario != inputs[1].scenario
    runtime = Runtime(Analysis(None, [], [], [], 0), 'http://127.0.0.1', config, browser=False)
    for b in inputs: runtime.finding('CWE-89', b, [{'scenario': b.scenario}], 'proof')
    assert len(runtime.findings) == 1
    finding = next(iter(runtime.findings.values()))
    assert len(finding.bindings) == 2 and len(finding.evidence) == 2


def test_discovered_form_refreshes_unknown_rotating_hidden_field(connect_app):
    app = Flask(__name__); app.secret_key = 'test-only-cookie-signing'
    @app.get('/')
    def index():
        session['counter'] = session.get('counter', 0) + 1
        return f'<form action="/submit" method="post"><input name="name" value="seed"><input type="hidden" name="challenge" value="{session["counter"]}"></form>'
    @app.post('/submit')
    def submit():
        return ('accepted', 200) if request.form.get('challenge') == str(session.get('counter')) else ('stale', 403)
    connect_app(app)
    config = {'discovery': {'enabled': True}, 'allowed_methods': ['GET','POST'], 'interval': 0}
    transport = Transport('http://127.0.0.1', interval=0)
    inputs, _, _ = discover(transport, config)
    runtime = Runtime(Analysis(None, [], [], [], 0), transport.target, config, browser=False, transport=transport)
    assert runtime.request(inputs[0], 'first').status == 200
    assert runtime.request(inputs[0], 'second').status == 200


def test_concrete_form_action_supplies_path_seed_for_source_route(connect_app):
    app = Flask(__name__)
    app.add_url_rule('/', 'index', lambda: '<form action="/orders/42" method="post"><input name="name" value="sample"></form>')
    app.add_url_rule('/orders/<id>', 'orders', lambda id: request.form.get('name', '') + ':' + id, methods=['POST'])
    connect_app(app)
    routes = [Route('/orders/<id>', ['POST'], 'Controller.php', 'update', 1, 4, provenance='laravel-route')]
    config = {'discovery': {'enabled': True}, 'allowed_methods': ['GET','POST'], 'interval': 0}
    transport = Transport('http://127.0.0.1', interval=0)
    inputs, _, _ = discover(transport, config, routes=routes)
    assert {(b.route,b.location,b.parameter) for b in inputs} == {
        ('/orders/<id>', 'path', 'id'), ('/orders/<id>', 'form', 'name')}
    runtime = Runtime(Analysis(None, routes, [], [], 0), transport.target, config, browser=False, transport=transport)
    binding = next(b for b in inputs if b.location == 'form')
    assert runtime.request(binding, 'changed').text == 'changed:42'


def test_ambiguous_source_route_patterns_are_not_assigned_to_observed_path():
    from navi.route_inputs import route_match
    routes = [Route('/orders/<id>', ['GET'], 'one.py', 'one', 1, 2), Route('/orders/<name>', ['GET'], 'two.py', 'two', 1, 2)]
    assert route_match(routes, '/orders/42', 'GET') == ('/orders/42', {})


def test_openapi_path_types_keep_source_bindings_and_valid_seeds():
    from navi.route_inputs import align_config
    routes = [Route('/orders/<id>', ['GET'], 'Controller.php', 'show', 1, 5, provenance='laravel-route')]
    original = {'requests': {'GET /orders/<int:id>': {'path': {'id': 42}, 'query': {'filter': 'open'}}},
                'runtime_inputs': [{'route': '/orders/<int:id>', 'parameter': 'id', 'location': 'path'}]}
    aligned = align_config(routes, original)
    assert aligned['requests']['GET /orders/<id>']['path']['id'] == 42
    assert aligned['runtime_inputs'][0]['route'] == '/orders/<id>'
    assert original['runtime_inputs'][0]['route'] == '/orders/<int:id>'
