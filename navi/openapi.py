"""Import local OpenAPI 3 JSON into native input candidates, never target scope."""
from copy import deepcopy
import json
from pathlib import Path
import re

from .model import gap

SENSITIVE = re.compile(r'password|passwd|secret|token|api.?key|authorization|cookie|csrf|xsrf', re.I)


def import_spec(path, config):
    path = Path(path)
    if path.stat().st_size > 2_000_000: raise ValueError('OpenAPI JSON exceeds the 2 MB limit.')
    document = json.loads(path.read_text())
    if not isinstance(document, dict) or not str(document.get('openapi', '')).startswith('3.') or not isinstance(document.get('paths'), dict):
        raise ValueError('Use a local OpenAPI 3 JSON document with a paths object.')
    from .runtime import validate_scan_options
    validate_scan_options(config)
    result = deepcopy(config)
    notes = result.setdefault('import_gaps', [])
    requests = result.setdefault('requests', {})
    inputs = result.setdefault('runtime_inputs', [])
    seen = {(i['route'], i.get('method', 'GET'), i['parameter'], i.get('location', 'query')) for i in inputs}
    methods = result.get('allowed_methods', ['GET'])
    count = 0

    def note(reason, route=None):
        item = gap('openapi', reason, **({'route': route} if route else {}))
        if item not in notes: notes.append(item)

    def resolve(value):
        visited = set()
        for _ in range(12):
            if not isinstance(value, dict): raise ValueError('OpenAPI object must be a JSON object.')
            ref = value.get('$ref')
            if not ref: return value
            if not isinstance(ref, str) or not ref.startswith('#/') or ref in visited:
                raise ValueError('External or cyclic OpenAPI references are not imported; provide resolved local schemas.')
            visited.add(ref); value = document
            try:
                for part in ref[2:].split('/'): value = value[part.replace('~1', '/').replace('~0', '~')]
            except (KeyError, TypeError): raise ValueError('OpenAPI local reference could not be resolved.') from None
        raise ValueError('OpenAPI reference depth limit reached.')

    def value_for(schema, example=None):
        schema = resolve(schema)
        if any(k in schema for k in ('allOf', 'oneOf', 'anyOf')) or schema.get('type') in {'array', 'object'}:
            raise ValueError('Nested, array, or composed schemas need explicit request seeds; this importer supports scalar inputs.')
        enum = schema.get('enum')
        if enum is not None and not isinstance(enum, list): raise ValueError('OpenAPI enum must be an array.')
        for value in (example, schema.get('example'), schema.get('default'), (enum or [None])[0]):
            if value is not None and isinstance(value, (str, int, float, bool)): return value
        if schema.get('type') == 'integer': return 1
        if schema.get('type') == 'number': return 1.0
        if schema.get('type') == 'boolean': return True
        return 'test'

    for raw_route, raw_item in list(document['paths'].items())[:300]:
        if not isinstance(raw_route, str) or not raw_route.startswith('/') or raw_route.startswith('//') or any(c in raw_route for c in '?\\#\r\n'):
            note('Invalid API route skipped.'); continue
        try: item = resolve(raw_item)
        except ValueError as error: note(str(error), raw_route); continue
        for verb, raw_operation in item.items():
            if verb.upper() not in {'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'}: continue
            method = verb.upper()
            if method not in methods:
                note(f'{method} is not enabled in allowed_methods; operation not imported.', raw_route); continue
            count += 1
            if count > 500:
                note('OpenAPI operation limit reached.'); validate_scan_options(result); return result
            try:
                operation = resolve(raw_operation)
                declared = [resolve(p) for p in [*item.get('parameters', []), *operation.get('parameters', [])]]
                parameters = {(p.get('in'), p.get('name')): p for p in declared}
                def path_parameter(match):
                    name = match[1]
                    parameter = parameters.get(('path', name), {})
                    schema = resolve(parameter.get('schema', {}))
                    return '<' + ('int:' if schema.get('type') == 'integer' else '') + name + '>'
                route = re.sub(r'\{([A-Za-z_][A-Za-z0-9_]*)\}', path_parameter, raw_route)
                if '{' in route or '}' in route: raise ValueError('Unsupported API path-parameter syntax.')
                settings = requests.setdefault(f'{method} {route}', {})
                if operation.get('security', document.get('security')) and not (result.get('session') or settings.get('headers') or settings.get('cookies')):
                    note('Operation declares authentication. Configure a login session or request headers for valid baselines.', route)
                def add(name, location, schema, example=None):
                    if not isinstance(name, str) or not name: raise ValueError('API parameter name is missing.')
                    if SENSITIVE.search(name) or name.lower() in {'submit', 'security'}:
                        note('Authentication/security controls need explicit configuration and are not automatically fuzzed.', route); return
                    component = {'query': 'query', 'path': 'path', 'json': 'json', 'form': 'form'}[location]
                    seed = settings.setdefault(component, {})
                    if name not in seed:
                        seed[name] = value_for(schema, example)
                    key = (route, method, name, location)
                    if key not in seen:
                        if len(inputs) >= 500: raise ValueError('OpenAPI input limit reached.')
                        inputs.append({'route': route, 'method': method, 'parameter': name, 'location': location}); seen.add(key)
                for (where, name), parameter in parameters.items():
                    if where not in {'query', 'path'}:
                        note('Header/cookie parameters need explicit runtime_inputs; no automatic mutation was added.', route); continue
                    try: add(name, where, parameter.get('schema', {}), parameter.get('example'))
                    except ValueError as error: note(str(error), route)
                if operation.get('requestBody'):
                    body = resolve(operation['requestBody'])
                    content = body.get('content', {})
                    media = next((m for m in ('application/json', 'application/x-www-form-urlencoded') if m in content), None)
                    if media is None: note('Request body format unsupported; configure explicit request data. File uploads are not generated.', route); continue
                    schema = resolve(content[media].get('schema', {}))
                    if schema.get('type') != 'object' or not isinstance(schema.get('properties'), dict):
                        note('Request body must be a scalar-field object; configure other shapes explicitly.', route); continue
                    location = 'json' if media == 'application/json' else 'form'
                    if ('form' if location == 'json' else 'json') in settings:
                        note('Explicit body format takes precedence over the API document.', route); continue
                    example = content[media].get('example', schema.get('example', {}))
                    for name, definition in schema['properties'].items():
                        try: add(name, location, definition, example.get(name) if isinstance(example, dict) else None)
                        except ValueError as error: note(str(error), route)
                missing = [m.split(':')[-1] for m in re.findall(r'<([^<>]+)>', route) if m.split(':')[-1] not in settings.get('path', {})]
                if missing: note('Supply valid path seeds for unresolved API path parameters before scanning this operation.', route)
            except (ValueError, TypeError, AttributeError) as error:
                note(str(error) if isinstance(error, ValueError) else 'Unsupported OpenAPI structure; configure this operation explicitly.', raw_route)
    if len(document['paths']) > 300: note('OpenAPI path limit reached; remaining paths were not imported.')
    note('API-derived defaults are starting values, not guaranteed valid baselines. Override them in requests. OpenAPI servers never change the configured target or allowed scope.')
    from .runtime import validate_scan_options
    validate_scan_options(result)
    return result
