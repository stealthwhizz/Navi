from copy import deepcopy

import pytest
from flask import Flask, request

from navi.model import Analysis, Binding
from navi.runtime import Runtime, validate_scan_options
from navi.transport import TargetError


def config():
    return {'allowed_methods': ['GET', 'POST', 'DELETE'], 'interval': 0,
            'workflows': [{'id': 'order', 'page': '/orders/<order_id>', 'steps': [
                {'path': '/orders', 'method': 'POST', 'json': {'name': 'test'},
                 'extract': {'order_id': {'json': 'data.id'}, 'csrf': {'header': 'x-token'}}}],
                'cleanup': [{'path': '/orders/<order_id>', 'method': 'DELETE', 'headers': {'X-Token': {'$var': 'csrf'}}}]}],
            'requests': {'GET /orders/<id>': {'workflow': {'id': 'order'}, 'path': {'id': {'$var': 'order_id'}},
                        'headers': {'X-Token': {'$var': 'csrf'}}, 'query': {'q': 'valid'}}}}


@pytest.fixture
def app(connect_app):
    app = Flask(__name__)
    state = {'orders': {}, 'counter': 0, 'deleted': []}
    @app.post('/orders')
    def create():
        state['counter'] += 1
        id = state['counter']; state['orders'][id] = 'token-' + str(id)
        return {'data': {'id': id}}, 201, {'X-Token': state['orders'][id]}
    @app.route('/orders/<int:id>', methods=['GET', 'DELETE'])
    def order(id):
        if state['orders'].get(id) != request.headers.get('X-Token'): return 'invalid setup', 403
        if request.method == 'DELETE':
            state['deleted'].append(id); del state['orders'][id]
            return '', 204
        return str(id) + ':' + request.args.get('q', '')
    connect_app(app)
    return state


def test_extract_reuse_and_cleanup_are_per_check(app):
    cfg = config(); validate_scan_options(cfg); original = deepcopy(cfg)
    runtime = Runtime(Analysis(None, [], [], [], 0), 'http://127.0.0.1', cfg, browser=False)
    b = Binding('/orders/<id>', 'GET', 'q', 'query', 'order')
    assert runtime.request(b, 'one').text == '1:one'
    assert runtime.request(b, 'two').text == '1:two'
    runtime.workflows.close()
    assert not app['orders'] and app['deleted'] == [1]
    assert runtime.request(b, 'three').text == '2:three'
    runtime.workflows.close()
    assert app['deleted'] == [1, 2] and cfg == original


def test_failed_extraction_withholds_probe_and_cleans_known_id(app):
    cfg = config()
    cfg['workflows'][0]['steps'].append({'path': '/missing', 'extract': {'more': {'json': 'absent'}}})
    runtime = Runtime(Analysis(None, [], [], [], 0), 'http://127.0.0.1', cfg, browser=False)
    with pytest.raises(TargetError): runtime.request(Binding('/orders/<id>', 'GET', 'q', 'query', 'order'), 'probe')
    assert app['deleted'] == [1] and not app['orders'] and not runtime.workflows.active


def test_cleanup_runs_after_cancellation_and_preserves_control(app):
    runtime = Runtime(Analysis(None, [], [], [], 0), 'http://127.0.0.1', config(), browser=False)
    runtime.workflows.start('order')
    previous = runtime.transport.control
    runtime.control.cancel()
    runtime.workflows.close()
    assert app['deleted'] == [1]
    assert runtime.transport.control is previous and runtime.control.event.is_set()


@pytest.mark.parametrize('mutation', [lambda c: c['workflows'][0]['steps'][0].update(path='https://outside.example/create'),
    lambda c: c.update(allowed_methods=['GET']),
    lambda c: c['requests']['GET /orders/<id>'].update(workflow={'id': 'unknown'})])
def test_workflow_validation_rejects_unusable_or_unscoped_setup(mutation):
    cfg = config(); mutation(cfg)
    with pytest.raises(ValueError): validate_scan_options(cfg)


def test_discovered_form_replaces_deleted_setup_id(connect_app):
    from navi.discovery import discover
    from navi.model import Route
    app = Flask(__name__); state = {'next': 0, 'live': set()}
    @app.post('/create')
    def create():
        state['next'] += 1; state['live'].add(state['next'])
        return {'id': state['next']}, 201
    @app.route('/items/<int:id>', methods=['GET', 'POST', 'DELETE'])
    def item(id):
        if id not in state['live']: return 'missing', 404
        if request.method == 'DELETE': state['live'].remove(id); return '', 204
        if request.method == 'POST': return str(id) + ':' + request.form['q']
        return f'<form method="post" action="/items/{id}"><input name="q" value="seed"></form>'
    connect_app(app)
    cfg = {'interval': 0, 'allowed_methods': ['GET','POST','DELETE'], 'discovery': {'enabled': True},
           'workflows': [{'id': 'item', 'page': '/items/<item_id>',
              'steps': [{'path': '/create', 'method': 'POST', 'extract': {'item_id': {'json': 'id'}}}],
              'cleanup': [{'path': '/items/<item_id>', 'method': 'DELETE'}]}]}
    routes = [Route('/items/<id>', ['POST'], 'Item.php', 'update', 1, 4)]
    runtime = Runtime(Analysis(None, routes, [], [], 0), 'http://127.0.0.1', cfg, browser=False)
    initial = runtime.workflows.start('item')
    inputs, _, _ = discover(runtime.transport, runtime.config, workflow={**cfg['workflows'][0], 'page': '/items/1', '_state': initial}, routes=routes)
    runtime.workflows.close()
    binding = next(b for b in inputs if b.parameter == 'q')
    assert runtime.request(binding, 'probe').text == '2:probe'
    runtime.workflows.close()
    assert not state['live']
