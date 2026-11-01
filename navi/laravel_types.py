"""Bounded PHP class dispatch and Laravel validated-value semantics."""
from .php import Value, NUMERIC_SAFE, split_args, closing


class LaravelTypes:
    def subclass(self, name, parent):
        seen = set()
        while name and name.lower() not in seen and len(seen) < 16:
            if name.lower() == parent.lower(): return True
            seen.add(name.lower())
            name = self.parents.get(name.lower())
        return False

    def request_type(self, name):
        return self.subclass(name, 'Illuminate\\Http\\Request') or self.subclass(name, 'Illuminate\\Foundation\\Http\\FormRequest')

    def method(self, class_name, method):
        seen = set()
        while class_name and class_name.lower() not in seen and len(seen) < 16:
            seen.add(class_name.lower())
            fn = self.classes.get(class_name.lower(), {}).get(method.lower())
            if fn: return fn
            class_name = self.parents.get(class_name.lower())
        return None

    def properties_for(self, class_name):
        result, seen = {}, set()
        while class_name and class_name.lower() not in seen and len(seen) < 16:
            seen.add(class_name.lower())
            for name, kind in self.properties.get(class_name.lower(), {}).items(): result.setdefault(name, kind)
            class_name = self.parents.get(class_name.lower())
        return result

    def type_value(self, name):
        if self.request_type(name): return Value(kind='request:' + name)
        if name and name.lower() in self.classes: return Value(kind='object:' + name)
        return Value()

    def environment(self, fn, arguments=(), receiver=None):
        env = {name: arguments[index] if index < len(arguments) else self.type_value(fn.get('parameter_types', {}).get(name))
               for index, name in enumerate(fn['parameters'])}
        receiver = receiver or fn.get('receiver_class') or fn.get('class')
        if receiver:
            env['$this'] = Value(kind='object:' + receiver)
            for prop, type_name in self.properties_for(receiver).items(): env['$this->' + prop] = self.type_value(type_name)
        return env

    def invoke(self, helper, groups, env, fn, route, stack, token, receiver):
        if helper['id'] in self.call_stack or len(self.call_stack) >= 12:
            self.warn('Recursive/service call depth limit reached; source flow is incomplete.', fn['file'], token[2])
            return Value()
        arguments = [self.expression(g, env, fn, route, stack) for g in groups]
        edge = {'caller': fn['id'], 'callee': helper['id'], 'call': helper['name'], 'file': fn['file'], 'line': token[2],
                'resolved': True, 'kind': 'controller method' if '/Controllers/' in helper['file'] else 'service method', 'potential_cwe': None}
        if edge not in self.edges: self.edges.append(edge)
        node = self.nodes[helper['id']]
        reached = {'route': route.path, 'methods': route.methods}
        if reached not in node['reachable_from']: node['reachable_from'].append(reached)
        if fn['id'] not in node['callers']: node['callers'].append(fn['id'])
        self.call_stack.append(helper['id'])
        try: return self.block(helper, self.environment(helper, arguments, receiver), route, [*stack, helper['name']])
        finally: self.call_stack.pop()

    def rules_for(self, class_name):
        fn = self.method(class_name, 'rules')
        if not fn or self.method(class_name, 'validationData'): return {}
        body = fn['body']
        # A single literal return is required; conditional/dynamic rules cannot
        # establish a sanitizer for every execution path.
        if not body or body[0][0] != 'T_RETURN': return {}
        return self.validation_rules(body[1:-1] if body[-1][1] == ';' else body[1:])

    def validation_rules(self, tokens):
        from .laravel import literal
        values = self.array_values(tokens)
        if values is None: return {}
        rules = {}
        for name, value in values.items():
            text = literal(value)
            if text is not None: rules[name] = text.split('|')
            elif value and value[0][1] == '[':
                items = [literal(part) for part in split_args(value[1:-1])]
                if all(v is not None for v in items): rules[name] = items
        return rules

    def validated(self, rules, key, route):
        value = self.input_value('input', key, route)
        protections = {r.split(':', 1)[0] for r in rules.get(key, [])}
        if protections & {'integer', 'numeric', 'boolean'}: value = value.protected(*NUMERIC_SAFE)
        return value

    def request_call(self, kind, groups, request_kind, fn, route, token):
        from .laravel import literal
        if kind not in {'validated', 'validate', 'safe'}: return None
        if kind == 'validate':
            rules = self.validation_rules(groups[0]) if groups else {}
            identifier = fn['id'] + ':' + str(token[2])
        else:
            class_name = request_kind.split(':', 1)[1] if ':' in request_kind else ''
            rules = self.rules_for(class_name)
            identifier = class_name
        self.validation_sets[identifier] = rules
        if kind == 'validated' and groups:
            return self.validated(rules, literal(groups[0]), route)
        return Value(kind='validated:' + identifier)
