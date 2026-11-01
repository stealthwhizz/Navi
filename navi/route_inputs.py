"""Map observed concrete paths to a unique source-declared route."""
import re
from urllib.parse import quote, unquote


def route_match(routes, path, method):
    eligible = [r for r in routes if method in r.methods and r.provenance not in {'configured', 'unmapped'}]
    if any(r.path == path for r in eligible): return path, {}
    matches = {}
    for route in eligible:
        pieces, names, start = [], [], 0
        for segment in re.finditer(r'<(?:(\w+):)?(\w+)>', route.path):
            pieces.append(re.escape(route.path[start:segment.start()]))
            pieces.append('(.+)' if segment[1] == 'path' else '([^/]+)')
            names.append(segment[2]); start = segment.end()
        if not names: continue
        pieces.append(re.escape(route.path[start:]))
        found = re.fullmatch(''.join(pieces), path)
        if found:
            matches[route.path] = {name: unquote(value) for name, value in zip(names, found.groups())}
    return next(iter(matches.items())) if len(matches) == 1 else (path, {})


def concrete_route(route, values):
    def replace(match):
        name = match[1].split(':')[-1]
        return quote(str(values[name]), safe='') if name in values else match[0]
    return re.sub(r'<([^<>]+)>', replace, route)


def align_config(routes, config):
    """Align OpenAPI converter annotations to one source-declared route.

    /orders/<int:id> and /orders/<id> describe the same URL template. Keep the
    actual source spelling when unambiguous, including in request seed keys.
    """
    from copy import deepcopy
    result = deepcopy(config)
    def shape(path): return re.sub(r'<\w+:(\w+)>', r'<\1>', path)
    def canonical(path, method):
        choices = {r.path for r in routes if method in r.methods and r.provenance not in {'configured','unmapped'} and shape(r.path) == shape(path)}
        return next(iter(choices)) if len(choices) == 1 else path
    requests = {}
    entries = list(result.get('requests', {}).items())
    # Exact source keys win if both spellings are explicitly configured.
    entries.sort(key=lambda item: item[0].partition(' ')[2] == canonical(item[0].partition(' ')[2], item[0].partition(' ')[0]))
    for key, settings in entries:
        method, separator, path = key.partition(' ')
        normalized = method + separator + canonical(path, method)
        selected = requests.setdefault(normalized, {})
        for component, values in settings.items(): selected[component] = {**selected.get(component, {}), **values}
    if entries: result['requests'] = requests
    for field in ['runtime_inputs', 'traversal_fixtures']:
        for item in result.get(field, []):
            if 'route' in item: item['route'] = canonical(item['route'], item.get('method', 'GET'))
    return result
