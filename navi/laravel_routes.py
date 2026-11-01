"""Conventional Laravel resource routes with explicit customization support."""
import re
from .model import Route


def singular(name):
    irregular = {'people':'person', 'children':'child', 'men':'man', 'women':'woman', 'mice':'mouse', 'statuses':'status', 'news':'news', 'series':'series'}
    if name in irregular: return irregular[name]
    if name.endswith('ies'): return name[:-3] + 'y'
    if name.endswith(('ches','shes','sses','xes')): return name[:-2]
    if name.endswith('s') and not name.endswith('ss'): return name[:-1]
    return name


def resources(analyzer, file, args, calls, prefix, api, token):
    from .laravel import literal
    if len(args) < 2: return False
    resource = literal(args[0])
    cls = args[1]
    if not resource or not re.fullmatch(r'[\w.-]+', resource) or len(cls) != 3 or cls[1][1] != '::' or cls[2][1].lower() != 'class': return False
    class_name = analyzer.resolve_name(cls[0][1], file)
    parameters, only, excluded = {}, None, set()
    for method, groups, _ in calls:
        if method in {'resource','apiresource','prefix','middleware','name','names','withoutmiddleware'}: continue
        if method == 'parameters' and groups:
            values = analyzer.array_values(groups[0])
            if values is None: return False
            parameters = {key: literal(value) for key, value in values.items()}
            if any(not value or not re.fullmatch(r'\w+', value) for value in parameters.values()): return False
        elif method in {'only','except'} and groups:
            from .php import split_args
            selected = [literal(v) for v in split_args(groups[0][1:-1])] if groups[0] and groups[0][0][1] == '[' else [literal(g) for g in groups]
            if any(v is None for v in selected): return False
            if method == 'only': only = set(selected)
            else: excluded = set(selected)
        else: return False
    parts = resource.split('.')
    base = prefix.rstrip('/')
    for part in parts[:-1]: base += '/' + part + '/<' + parameters.get(part, singular(part).replace('-', '_')) + '>'
    last = parts[-1]
    collection = base + '/' + last
    item = collection + '/<' + parameters.get(last, singular(last).replace('-', '_')) + '>'
    methods = [('index','GET',collection), ('store','POST',collection), ('show','GET',item),
               ('update','PUT',item), ('update','PATCH',item), ('destroy','DELETE',item)]
    if not api: methods += [('create','GET',collection+'/create'), ('edit','GET',item+'/edit')]
    added = False
    for action, verb, path in methods:
        if (only is not None and action not in only) or action in excluded: continue
        fn = analyzer.method(class_name, action)
        if not fn:
            analyzer.warn('Resource controller action could not be resolved: ' + action, file, token[2]); continue
        analyzer.actions.append((Route(path, [verb], fn['file'], fn['name'], fn['line'], fn['end_line'], provenance='laravel-route'),
                                 {**fn, 'receiver_class': class_name}))
        added = True
    return added
