"""Source-derived Laravel routes and bounded controller/Blade data flow.

Uses PHP tokens only: Composer, Artisan, controllers and application bootstraps
are never executed. Framework operations are native rules, independent of the
procedural PHP template pack.
"""
import json
import re
from dataclasses import replace
from .source_flow import step

from .model import Analysis, Input, Route, fingerprint, gap
from .php import PHPAnalyzer, Value, closing, split_args, text_literal, NUMERIC_SAFE
from .laravel_types import LaravelTypes


def is_laravel(root):
    if not root.is_dir(): return False
    if (root / 'routes').is_dir() and (root / 'app/Http/Controllers').is_dir(): return True
    manifest = root / 'composer.json'
    try:
        return manifest.stat().st_size < 1_000_000 and 'laravel/framework' in json.loads(manifest.read_text()).get('require', {})
    except (OSError, ValueError, AttributeError):
        return False


def literal(tokens):
    return text_literal(tokens[0]) if len(tokens) == 1 and tokens[0][0] == 'T_CONSTANT_ENCAPSED_STRING' else None


def chain(tokens, start):
    """Read a static/object call and its immediately chained method calls."""
    calls, i = [], start
    while i + 1 < len(tokens) and tokens[i+1][1] == '(':
        end = closing(tokens, i+1)
        calls.append((tokens[i][1].lower(), split_args(tokens[i+2:end]), tokens[i]))
        i = end + 1
        if i + 2 < len(tokens) and tokens[i][1] in {'->', '?->'} and tokens[i+2][1] == '(':
            i += 1
        else: break
    return calls, i


class LaravelAnalyzer(LaravelTypes, PHPAnalyzer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.classes, self.aliases, self.namespaces = {}, {}, {}
        self.actions = []
        self._warnings = set()
        self.parents, self.properties, self.validation_sets = {}, {}, {}

    def warn(self, reason, file='', line=None):
        key = (reason, file, line)
        if key not in self._warnings:
            self._warnings.add(key)
            self.gaps.append(gap('laravel', reason, file=file, **({'line': line} if line else {})))

    def resolve_name(self, name, file):
        if name.startswith('\\'): return name.lstrip('\\')
        head, _, tail = name.partition('\\')
        alias = self.aliases.get(file, {}).get(head.lower())
        if alias: return alias + ('\\' + tail if tail else '')
        namespace = self.namespaces.get(file, '')
        return (namespace + '\\' if namespace else '') + name

    def imports(self, file, tokens):
        aliases, namespace, depth, i = {}, '', 0, 0
        while i < len(tokens):
            token = tokens[i]
            if depth == 0 and token[0] in {'T_NAMESPACE', 'T_USE'}:
                end = i+1
                while end < len(tokens) and tokens[end][1] not in {';', '{'}: end += 1
                text = ''.join(t[1] if t[0] != 'T_AS' else ' as ' for t in tokens[i+1:end])
                if end < len(tokens) and tokens[end][1] == '{':
                    self.warn('Grouped imports or bracketed namespaces are not resolved.', file, token[2])
                elif token[0] == 'T_NAMESPACE': namespace = text.strip('\\')
                else:
                    for item in text.split(','):
                        parts = item.split(' as ')
                        full = parts[0].strip('\\')
                        aliases[(parts[-1] if len(parts) > 1 else full.split('\\')[-1]).lower()] = full
                i = end
            if i < len(tokens):
                if tokens[i][1] == '{': depth += 1
                elif tokens[i][1] == '}': depth -= 1
            i += 1
        self.aliases[file], self.namespaces[file] = aliases, namespace

    def function(self, file, tokens, index, name, class_name=None):
        begin = index + 1
        while begin < len(tokens) and tokens[begin][1] != '(': begin += 1
        if begin >= len(tokens): return None, len(tokens)
        end = closing(tokens, begin)
        groups = split_args(tokens[begin+1:end])
        params, requests, types, promoted = [], set(), {}, {}
        for group in groups:
            variable = next((t for t in group if t[0] == 'T_VARIABLE'), None)
            if not variable: continue
            params.append(variable[1])
            declaration = group[:group.index(variable)]
            type_name = ''.join(t[1] for t in declaration if t[1] not in {'?', '&', '...'} and t[0] not in {'T_PUBLIC','T_PROTECTED','T_PRIVATE','T_READONLY'})
            types[variable[1]] = self.resolve_name(type_name, file) if type_name else None
            if any(t[0] in {'T_PUBLIC','T_PROTECTED','T_PRIVATE'} for t in declaration): promoted[variable[1][1:]] = types[variable[1]]
            if self.resolve_name(type_name, file) == 'Illuminate\\Http\\Request': requests.add(variable[1])
        body = end + 1
        while body < len(tokens) and tokens[body][1] not in {'{', ';'}: body += 1
        if body >= len(tokens) or tokens[body][1] != '{': return None, body + 1
        last = closing(tokens, body, '{', '}')
        fn = {'name': name, 'file': file, 'line': tokens[index][2], 'end_line': tokens[last][2],
              'parameters': params, 'request_parameters': requests, 'body': tokens[body+1:last],
              'class': class_name, 'framework': 'laravel', 'parameter_types': types, 'promoted': promoted}
        self.add_node(fn)
        return fn, last+1

    def load(self):
        self.load_tokens()
        for file, tokens in self.token_streams.items():
            self.control.check()
            self.imports(file, tokens)
            i = 0
            while i < len(tokens):
                if tokens[i][0] != 'T_CLASS' or i+1 >= len(tokens) or tokens[i+1][0] != 'T_STRING':
                    i += 1; continue
                class_name = ((self.namespaces[file] + '\\') if self.namespaces[file] else '') + tokens[i+1][1]
                begin = i+2
                while begin < len(tokens) and tokens[begin][1] != '{': begin += 1
                parent = next((tokens[n+1][1] for n in range(i+2, begin-1) if tokens[n][0] == 'T_EXTENDS'), None)
                self.parents[class_name.lower()] = self.resolve_name(parent, file) if parent else None
                end = closing(tokens, begin, '{', '}')
                methods, properties, j = {}, {}, begin+1
                while j < end:
                    if tokens[j][0] == 'T_FUNCTION' and j+1 < end and tokens[j+1][0] == 'T_STRING':
                        method = tokens[j+1][1]
                        fn, j = self.function(file, tokens, j, class_name + '::' + method, class_name)
                        if fn:
                            methods[method.lower()] = fn
                            if method.lower() == '__construct':
                                properties.update(fn['promoted'])
                                body = fn['body']
                                for n in range(len(body)-4):
                                    if body[n][1] == '$this' and body[n+1][1] == '->' and body[n+3][1] == '=':
                                        property_type = fn['parameter_types'].get(body[n+4][1])
                                        if property_type: properties[body[n+2][1]] = property_type
                    else:
                        if tokens[j][0] == 'T_VARIABLE' and j > begin+1 and tokens[j-1][0] in {'T_STRING','T_NAME_QUALIFIED','T_NAME_FULLY_QUALIFIED'}:
                            properties[tokens[j][1][1:]] = self.resolve_name(tokens[j-1][1], file)
                        j += 1
                self.classes[class_name.lower()] = methods
                self.properties[class_name.lower()] = properties
                i = end+1
        for methods in self.classes.values():
            for fn in methods.values():
                fn['request_parameters'] = {p for p,t in fn['parameter_types'].items() if self.request_type(t)}
        for file in ('routes/web.php', 'routes/api.php'):
            if file in self.token_streams:
                prefix = self.options.get('laravel', {}).get('api_prefix', '/api') if file.endswith('api.php') else ''
                self.read_routes(file, self.token_streams[file], prefix)
        if not self.actions: self.warn('No supported Laravel routes resolved. Supply conventional routes/web.php or routes/api.php with literal controller actions or closures.')
        self.warn('Laravel coverage is bounded: dynamic container bindings, middleware/policies, model relationships, runtime route registration and arbitrary Blade control flow are not fully modeled. Runtime proof remains required.')

    def facade(self, name, file, short):
        return self.resolve_name(name, file) == 'Illuminate\\Support\\Facades\\' + short or name == short and not self.namespaces.get(file)

    def read_routes(self, file, tokens, prefix='', depth=0, controller=None):
        if depth > 12:
            self.warn('Laravel route group depth limit reached.', file); return
        i = 0
        while i + 3 < len(tokens):
            self.control.check()
            if tokens[i][1] == '{':
                # Do not infer unconditional routes inside arbitrary PHP logic.
                end = closing(tokens, i, '{', '}')
                self.warn('Routes inside unmodeled PHP blocks were not inferred.', file, tokens[i][2])
                i = end+1; continue
            if tokens[i+1][1] != '::' or not self.facade(tokens[i][1], file, 'Route'):
                i += 1; continue
            calls, end = chain(tokens, i+2)
            local_prefix, handled, local_controller = prefix, False, controller
            for method, args, token in calls:
                if method == 'prefix' and args and literal(args[0]) is not None:
                    local_prefix += '/' + literal(args[0]).strip('/')
                elif method in {'middleware', 'name', 'withoutmiddleware'}:
                    continue
                elif method == 'controller' and args:
                    cls = args[0]
                    if len(cls) != 3 or cls[1][1] != '::' or cls[2][1].lower() != 'class': break
                    local_controller = self.resolve_name(cls[0][1], file)
                elif method in {'resource', 'apiresource'}:
                    from .laravel_routes import resources
                    handled = resources(self, file, args, calls, local_prefix, method == 'apiresource', token)
                    break
                elif method == 'group' and args:
                    closure = args[-1]
                    if len(args) > 1:
                        attributes = self.array_values(args[0])
                        if attributes is None or set(attributes) - {'prefix', 'middleware', 'as'}:
                            self.warn('Unsupported route group attributes; source links withheld.', file, token[2]); break
                        if 'prefix' in attributes:
                            p = literal(attributes['prefix'])
                            if p is None: break
                            local_prefix += '/' + p.strip('/')
                    opening = next((j for j,t in enumerate(closure) if t[1] == '{'), None)
                    if opening is not None:
                        last = closing(closure, opening, '{', '}')
                        self.read_routes(file, closure[opening+1:last], local_prefix, depth+1, local_controller)
                        handled = True
                    break
                elif method in {'get', 'post', 'put', 'patch', 'delete', 'head', 'any', 'match'}:
                    methods = [method.upper()]
                    if method == 'any': methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD']
                    if method == 'match':
                        if not args: break
                        methods = [literal(g) for g in split_args(args[0][1:-1])] if args[0] and args[0][0][1] == '[' else []
                        args = args[1:]
                    if len(args) < 2 or not methods or any(m not in {'GET','POST','PUT','PATCH','DELETE','HEAD'} for m in methods): break
                    path = literal(args[0])
                    if path is None or re.search(r'\{[^}]*[?:][^}]*\}', path): break
                    path = '/' + '/'.join(part for part in (local_prefix + '/' + path).split('/') if part)
                    path = re.sub(r'\{([A-Za-z_]\w*)\}', r'<\1>', path)
                    if any(c in path for c in '{}?#'): break
                    fn = self.action(file, args[1], token, local_controller)
                    if fn:
                        for verb in methods:
                            route = Route(path, [verb], fn['file'], fn['name'], fn['line'], fn['end_line'], provenance='laravel-route')
                            if not any(r.path == path and r.methods == [verb] and f['id'] == fn['id'] for r,f in self.actions):
                                self.actions.append((route, fn))
                        handled = True
                    break
                else: break
            if not handled: self.warn('Laravel route declaration could not be resolved; no URL/source link was invented.', file, tokens[i][2])
            i = max(end, i+1)

    def action(self, file, tokens, token, controller=None):
        if tokens and tokens[0][0] in {'T_FUNCTION', 'T_STATIC'}:
            index = next((j for j,t in enumerate(tokens) if t[0] == 'T_FUNCTION'), None)
            if index is not None:
                fn, _ = self.function(file, tokens, index, '<route:' + str(token[2]) + ':' + fingerprint(tokens)[:8] + '>')
                return fn
        action = literal(tokens)
        method = '__invoke'
        if action:
            if controller and '@' not in action:
                fn = self.method(controller, action)
                return {**fn, 'receiver_class': controller} if fn else None
            if '@' in action: action, method = action.rsplit('@', 1)
            class_name = action.lstrip('\\')
            if '\\' not in class_name: class_name = 'App\\Http\\Controllers\\' + class_name
        else:
            pieces = split_args(tokens[1:-1]) if tokens and tokens[0][1] == '[' else [tokens]
            if not pieces: return None
            cls = pieces[0]
            if len(cls) != 3 or cls[1][1] != '::' or cls[2][1].lower() != 'class': return None
            class_name = self.resolve_name(cls[0][1], file)
            if len(pieces) > 1:
                method = literal(pieces[1])
                if not method: return None
        fn = self.method(class_name, method)
        return {**fn, 'receiver_class': class_name} if fn else None

    @staticmethod
    def array_values(tokens):
        if not tokens or tokens[0][1] != '[' or tokens[-1][1] != ']': return None
        result = {}
        for part in split_args(tokens[1:-1]):
            if len(part) < 3 or part[1][1] != '=>' or literal(part[:1]) is None: return None
            result[literal(part[:1])] = part[2:]
        return result

    def input_value(self, kind, name, route):
        if not isinstance(name, str):
            self.warn('A Laravel request key was dynamic; provide runtime inputs for complete testing.', route.file)
            name = '*'
        locations = {'query': ['query'], 'post': ['form'], 'cookie': ['cookie'], 'header': ['header'], 'json': ['json'], 'route': ['path']}.get(kind)
        if locations is None:
            locations = ['query'] if route.methods == ['GET'] or route.methods == ['HEAD'] else ['query', 'form', 'json']
        for location in locations:
            param = {'name': name, 'location': location}
            if param not in route.parameters: route.parameters.append(param)
        return Value({Input(location, name): frozenset() for location in locations})

    def special_expression(self, tokens, i, env, fn, route, stack):
        token = tokens[i]
        name = token[1]
        # Typed Request parameters and the request() helper have request semantics.
        request_kind = env.get(name, Value()).kind or ''
        request_variable = name in fn.get('request_parameters', set()) or request_kind.startswith('request')
        if request_kind.startswith('validated:') and i+3 < len(tokens) and tokens[i+1][1] == '[' and tokens[i+3][1] == ']':
            return self.validated(self.validation_sets.get(request_kind.split(':',1)[1], {}), literal(tokens[i+2:i+3]), route), i+4
        if request_variable and i+2 < len(tokens) and tokens[i+1][1] in {'->', '?->'}:
            member = tokens[i+2][1]
            if i+3 < len(tokens) and tokens[i+3][1] == '(':
                calls, end = chain(tokens, i+2)
                kind, args, _ = calls[0]
                validated = self.request_call(kind, args, request_kind, fn, route, token)
                if len(calls) == 1 and validated is not None: return validated, end
                if len(calls) == 1 and kind in {'input','get','query','post','cookie','header','json','route','integer','string'}:
                    value = self.input_value(kind, literal(args[0]) if args else None, route)
                    return (value.protected(*NUMERIC_SAFE) if kind == 'integer' else value), end
                self.warn('Unsupported Request method chain; input semantics are incomplete.', fn['file'], token[2])
            else: return self.input_value('input', member, route), i+3
        if token[0] == 'T_NEW' and i+2 < len(tokens) and tokens[i+2][1] == '(':
            class_name = self.resolve_name(tokens[i+1][1], fn['file'])
            end = closing(tokens, i+2)
            if class_name.lower() in self.classes:
                constructor = self.method(class_name, '__construct')
                if constructor: self.invoke(constructor, split_args(tokens[i+3:end]), env, fn, route, stack, token, class_name)
                return Value(kind='object:' + class_name), end+1
        receiver, member = env.get(name, Value()).kind or '', i+2
        if i+4 < len(tokens) and tokens[i+1][1] == '->' and tokens[i+3][1] == '->':
            receiver = env.get(name + '->' + tokens[i+2][1], Value()).kind or ''
            member = i+4
        if receiver.startswith('object:') and member+1 < len(tokens) and tokens[member+1][1] == '(':
            calls, end = chain(tokens, member)
            if len(calls) == 1:
                method, groups, _ = calls[0]
                class_name = receiver.split(':', 1)[1]
                helper = self.method(class_name, method)
                if helper: return self.invoke(helper, groups, env, fn, route, stack, token, class_name), end
                self.warn('Object method could not be resolved to source.', fn['file'], token[2])
        facade = None
        builder = False
        if i+3 < len(tokens) and tokens[i+1][1] == '::':
            class_name = (fn.get('class') if name == 'self' else self.parents.get((fn.get('class') or '').lower()) if name == 'parent' else self.resolve_name(name, fn['file']))
            facade = next((f for f in ['DB','Storage','File','Redirect','Response','Process','Input','Request'] if self.facade(name, fn['file'], f)), None)
            if not facade and class_name and self.subclass(class_name, 'Illuminate\\Database\\Eloquent\\Model'):
                facade, builder = 'DB', True
            if not facade and class_name and class_name.lower() in self.classes:
                calls, end = chain(tokens, i+2)
                helper = self.method(class_name, calls[0][0]) if calls else None
                if helper and len(calls) == 1: return self.invoke(helper, calls[0][1], env, fn, route, stack, token, class_name), end
            calls, end = chain(tokens, i+2) if facade else ([], i)
        elif i+3 < len(tokens) and tokens[i+1][1] in {'->', '?->'} and env.get(name, Value()).kind in {'query_builder', 'storage', 'response', 'redirect'}:
            kind = env[name].kind
            facade = {'query_builder': 'DB', 'storage': 'Storage', 'response': 'Response', 'redirect': 'Redirect'}[kind]
            builder = kind == 'query_builder'
            calls, end = chain(tokens, i+2)
        elif name.lower() in {'request','response','redirect','view','e','storage_path','public_path','base_path'} and i+1 < len(tokens) and tokens[i+1][1] == '(':
            facade = 'helper'
            calls, end = chain(tokens, i)
        else: calls, end = [], i
        if not calls: return None
        request_helper = facade == 'helper' and calls[0][0] == 'request'
        value = Value()
        for method, groups, call_token in calls:
            args = [self.expression(g, env, fn, route, stack) for g in groups]
            first = args[0] if args else Value()
            if (facade in {'Input','Request'} or request_helper) and method in {'request','input','get','query','post','cookie','header','route','integer','string','json'}:
                if method == 'request' and not groups:
                    value = Value(kind='request'); continue
                value = self.input_value(method, literal(groups[0]) if groups else None, route)
                if method == 'integer': value = value.protected(*NUMERIC_SAFE)
            elif facade == 'DB':
                if method in {'table', 'query', 'newquery'}:
                    builder = True
                    value = Value(kind='query_builder')
                elif method in {'whereraw','orwhereraw','havingraw','orderbyraw','groupbyraw','selectraw'} or not builder and method in {'select','selectone','cursor','statement','unprepared','insert','update','delete'}:
                    self.mark(fn, 'DB::' + method, call_token, first, route, stack, cwe='CWE-89')
                    value = Value(kind='query_builder' if builder else None)
                elif method == 'raw':
                    value = replace(first, kind='raw_sql')
                elif builder and method in {'where','orwhere','select','orderby','groupby','having'}:
                    for arg in args:
                        if arg.kind == 'raw_sql': self.mark(fn, 'DB::' + method, call_token, arg, route, stack, cwe='CWE-89')
                    value = Value(kind='query_builder')
                elif method not in {'table','connection','where','orwhere','get','first','find','value','pluck','count','limit','take','orderby','groupby','select','join'}:
                    if method not in {'insert', 'update', 'delete'}: self.warn('Unsupported database method in Laravel data flow.', fn['file'], call_token[2])
                if builder and method in {'get','first','find','value','pluck','count','insert','update','delete'}: value = Value()
            elif facade == 'Storage':
                if method == 'disk': value = Value(kind='storage')
                elif method == 'path': value = first
                elif method in {'get','read','readstream','download','response','contents'}:
                    # Flysystem-backed reads reject traversal outside the disk.
                    # Access to private objects is a separate policy question.
                    value = Value()
                else: self.warn('Unsupported Storage operation; custom disk behavior is not modeled.', fn['file'], call_token[2])
            elif facade == 'File' and method in {'get','read','download','response','contents'}:
                self.mark(fn, facade + '::' + method, call_token, first, route, stack, cwe='CWE-22')
            elif facade == 'Process' and method == 'run':
                if not groups or not groups[0] or groups[0][0][1] != '[':
                    self.mark(fn, 'Process::run', call_token, first, route, stack, cwe='CWE-78')
            elif facade == 'Redirect' or facade == 'helper' and (method in {'redirect','to','away'}):
                value = Value(kind='redirect')
                if groups and method in {'redirect','to','away'}:
                    if not (first.context_known and re.match(r'^/[^/\\]', first.prefix)):
                        self.mark(fn, 'redirect', call_token, first, route, stack, cwe='CWE-601')
            elif facade == 'Response' or facade == 'helper' and method in {'response','json','file','download','make'}:
                value = Value(kind='response')
                if method in {'file','download'}:
                    self.mark(fn, 'response()->' + method, call_token, first, route, stack, cwe='CWE-22')
                elif method != 'json' and groups:
                    headers = self.array_values(groups[2]) if len(groups) > 2 else {}
                    content_type = next((literal(v) for k,v in (headers or {}).items() if k.lower() == 'content-type'), None)
                    if content_type is None or 'text/html' in content_type.lower():
                        self.mark(fn, 'HTML response', call_token, first, route, stack, cwe='CWE-79')
            elif facade == 'helper' and method == 'view':
                self.view(groups, env, fn, route, stack, call_token)
            elif facade == 'helper' and method == 'e': value = first.protected('CWE-79')
            elif facade == 'helper' and method in {'storage_path','public_path','base_path'}: value = first
        return value, end

    def template_call(self, name, method, args, fn, token, route, stack, shape=''):
        # Framework input sources include path/JSON/header parameters absent from
        # procedural superglobal templates. Native Laravel rules own this flow.
        return

    def mark(self, fn, call, token, value, route, stack, shape='', cwe='CWE-78', rule=None):
        finding = super().mark(fn, call, token, value, route, stack, shape, cwe, rule)
        if finding:
            finding.scanner = 'navi-laravel'
            finding.rule_id = 'navi.laravel.' + finding.cwe.lower()
        return finding

    def on_return(self, fn, token, value, route, stack, statement):
        if fn['name'] == route.function:
            self.mark(fn, 'HTML return', token, value, route, stack, cwe='CWE-79')

    def view(self, args, env, fn, route, stack, token):
        name = literal(args[0]) if args else None
        if not name or not re.fullmatch(r'[\w.-]+', name) or '..' in name:
            self.warn('Dynamic Laravel view name; Blade source links are unavailable.', fn['file'], token[2]); return
        file = 'resources/views/' + name.replace('.', '/') + '.blade.php'
        if file not in self.sources:
            self.warn('Laravel view source was not found.', file); return
        data = self.array_values(args[1]) if len(args) > 1 else {}
        if data is None and len(args) > 1 and args[1] and args[1][0][1] == 'compact':
            data = {literal(g): [['T_VARIABLE', '$' + literal(g), token[2]]] for g in split_args(args[1][2:-1]) if literal(g)}
        if data is None:
            self.warn('Unsupported view data mapping; Blade taint is incomplete.', fn['file'], token[2]); return
        values = {key: self.expression(group, env, fn, route, stack) for key,group in data.items()}
        self.render_blade(file, name, values, fn, route, stack, token)

    def render_blade(self, file, name, values, fn, route, stack, token):
        if file in stack or len(stack) >= 12:
            self.warn('Blade component recursion/depth limit reached.', file); return
        text = self.sources[file]
        components = list(re.finditer(r'<x-([\w.-]+)\b([^<>]*?)/>', text, re.S))
        for component in components:
            component_name, attributes = component[1], component[2]
            target = 'resources/views/components/' + component_name.replace('.', '/') + '.blade.php'
            class_file = 'app/View/Components/' + ''.join(p.title() for p in re.split('[.-]', component_name)) + '.php'
            if target not in self.sources or class_file in self.sources or '..' in component_name:
                self.warn('Blade component resolution is dynamic or class-based; its flow is incomplete.', file); continue
            props = {}
            for attribute in re.finditer(r':([\w-]+)\s*=\s*([\'"])(\$\w+)\2', attributes):
                prop = re.sub(r'-([a-z])', lambda m: m[1].upper(), attribute[1])
                props[prop] = values.get(attribute[3][1:], Value())
            self.render_blade(target, 'components.' + component_name, props, fn, route, [*stack, file], token)
        if len(re.findall(r'<x-[\w.-]+', text)) != len(components):
            self.warn('Blade component slots and dynamic attributes are not fully modeled.', file)
        for match in re.finditer(r'\{!!(.*?)!!\}|\{\{(.*?)\}\}', text, re.S):
            expression = (match[1] if match[1] is not None else match[2]).strip()
            escaped = match[1] is None
            variable = re.fullmatch(r'\$(\w+)', expression)
            if not variable:
                self.warn('Blade expressions beyond direct view variables are not resolved.', file); continue
            value = values.get(variable[1], Value())
            if escaped: value = value.protected('CWE-79')
            before = text[:match.start()]
            prefix = before[before.rfind('<'):] if before.rfind('<') > before.rfind('>') else ''
            if before.lower().rfind('<script') > before.lower().rfind('</script'): prefix = '<script>'
            value = replace(value, prefix=prefix)
            line = text.count('\n', 0, match.start())+1
            value = step(value, file, line, expression, match.start(), 'template_output')
            point = ['T_ECHO', 'Blade output', line]
            view_fn = {'name': '<view:' + name + '>', 'file': file, 'line': 1, 'end_line': len(text.splitlines()), 'parameters': list(values), 'body': [point], 'framework': 'laravel'}
            if fingerprint('function', file, view_fn['name']) not in self.nodes: self.add_node(view_fn)
            else: view_fn['id'] = fingerprint('function', file, view_fn['name'])
            self.nodes[view_fn['id']]['reachable_from'].append({'route': route.path, 'methods': route.methods})
            edge = {'caller': fn['id'], 'callee': view_fn['id'], 'call': 'view', 'file': fn['file'], 'line': token[2], 'resolved': True, 'kind': 'Blade view', 'potential_cwe': 'CWE-79'}
            if edge not in self.edges: self.edges.append(edge)
            self.mark(view_fn, 'Blade output', point, value, route, [*stack, file], shape=str(match.start()), cwe='CWE-79')

    def run(self):
        from .static import source_digest
        digest = source_digest(self.root)
        self.load()
        self.scan_secrets()
        for route, fn in self.actions:
            self.control.check()
            self.routes.append(route)
            self.reset_flow(fn)
            entry = {'route': route.path, 'methods': route.methods}
            self.nodes[fn['id']]['entry_points'].append(entry)
            self.nodes[fn['id']]['reachable_from'].append(entry)
            self.nodes[fn['id']]['reachability'] = 'Laravel route declaration'
            env = self.environment(fn)
            for name in re.findall(r'<(\w+)>', route.path):
                env['$' + name] = self.input_value('route', name, route)
            self.block(fn, env, route, [fn['file'] + ':' + fn['name']])
        # Unresolved registration must not discard a controller's source-only
        # candidates. These flows deliberately have no URL binding.
        for methods in self.classes.values():
            for fn in methods.values():
                if '/Controllers/' not in fn['file'] or self.nodes[fn['id']]['reachable_from']: continue
                self.control.check()
                self.reset_flow(fn)
                route = Route('', ['GET', 'POST'], fn['file'], fn['name'], fn['line'], fn['end_line'], provenance='unmapped')
                env = self.environment(fn)
                self.block(fn, env, route, [fn['file'] + ':' + fn['name']])
        for node in self.nodes.values():
            node['operations'] = [{'finding_id': f.id, 'cwe': f.cwe, 'line': f.source['line']} for f in self.findings.values() if f.source['file'] == node['file'] and f.source['function'] == node['name']]
            node['reachable_from'] = list({json.dumps(v, sort_keys=True): v for v in node['reachable_from']}.values())
        return Analysis(digest, self.routes, list(self.findings.values()), self.gaps, len(self.sources),
                        {'nodes': list(self.nodes.values()), 'edges': self.edges, 'scope': 'Laravel literal routes, controller methods, direct Request inputs, framework operations and direct Blade view variables.'},
                        {'sast': {'interpreter': 'navi-laravel-native-v1', 'loaded': ['navi.laravel.' + c.lower() for c in ['CWE-89','CWE-79','CWE-78','CWE-22','CWE-601']], 'cwes': ['CWE-89','CWE-79','CWE-78','CWE-22','CWE-601'], 'files': [], 'unsupported': len(self.gaps)}})
