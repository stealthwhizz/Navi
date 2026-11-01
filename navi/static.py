"""A deliberately bounded Flask AST/data-flow analyzer; never imports target code."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field, replace
import hashlib
import os
from .control import ScanControl, ScanStopped
from pathlib import Path
import re

from .model import Analysis, Binding, Finding, Input, RULES, Route, fingerprint, gap
from .source_flow import step, incomplete, combine_flows, record


IGNORED = {".git", ".venv", "venv", "node_modules", "vendor", "__pycache__", "artifacts", ".navi", "site-packages"}
PHP_SUFFIXES = {".php", ".phtml", ".inc"}


def source_files(root: Path) -> list[Path]:
    return [p for p in project_files(root) if p.suffix == ".py"]


def project_files(root: Path) -> list[Path]:
    root = root.resolve()
    base = root.parent if root.is_file() else root
    paths = []
    if root.is_file(): paths = [root]
    else:
        for directory, dirs, names in os.walk(root, followlinks=False):
            dirs[:] = [d for d in dirs if d not in IGNORED and not d.startswith(".") and not (Path(directory) / d).is_symlink()]
            paths.extend(Path(directory) / name for name in names if Path(name).suffix in {".py", *PHP_SUFFIXES})
            if len(paths) > 5000: raise ValueError("Source exceeds the 5000-file limit; choose a smaller application directory.")
    selected = sorted(p for p in paths if p.suffix in {".py", *PHP_SUFFIXES} and p.is_file() and not p.is_symlink()
                      and not any(part in IGNORED or part.startswith(".") for part in p.relative_to(base).parts)
                      and p.resolve().is_relative_to(base))
    sizes = [p.stat().st_size for p in selected]
    if any(size > 2_000_000 for size in sizes) or sum(sizes) > 50_000_000:
        raise ValueError("Source exceeds the 2 MB/file or 50 MB/application limit; narrow the source scope.")
    return selected


def source_digest(root: Path) -> str:
    root = root.resolve()
    base = root.parent if root.is_file() else root
    digest = hashlib.sha256()
    for path in project_files(root):
        digest.update(path.relative_to(base).as_posix().encode() + b"\0")
        digest.update(path.read_bytes() + b"\0")
    return digest.hexdigest()


def dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{dotted(node.value)}.{node.attr}"
    return ""


def literal(node: ast.AST | None, default=None):
    try:
        return ast.literal_eval(node) if node is not None else default
    except (ValueError, TypeError, SyntaxError):
        return default


@dataclass
class Value:
    inputs: dict[Input, frozenset[str]] = field(default_factory=dict)
    container: str | None = None
    flows: dict = field(default_factory=dict)

    def protected(self, *cwes: str) -> Value:
        return replace(self, inputs={key: safe.union(cwes) for key, safe in self.inputs.items()})

    def vulnerable(self, cwe: str) -> list[Input]:
        return [key for key, safe in self.inputs.items() if cwe not in safe]


def combine(*values: Value) -> Value:
    result = Value()
    for value in values:
        for key, safe in value.inputs.items():
            result.inputs[key] = result.inputs[key].intersection(safe) if key in result.inputs else safe
    result.flows = combine_flows(values)
    return result


@dataclass
class Module:
    path: str
    name: str
    tree: ast.Module
    text: str
    aliases: dict[str, str]
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef]


class Analyzer:
    def __init__(self, root: str | Path, control=None):
        self.control = control or ScanControl()
        self.root = Path(root).resolve()
        if not self.root.exists():
            raise ValueError(f"Source path does not exist: {self.root}")
        self.base = self.root.parent if self.root.is_file() else self.root
        self.modules: dict[str, Module] = {}
        self.findings: dict[str, Finding] = {}
        self.routes: list[Route] = []
        self.gaps: list[dict] = []
        self._gap_keys: set[tuple] = set()
        self.call_targets = {}
        self.function_map = {"nodes": [], "edges": []}

    def warn(self, reason: str, file: str = "", **details):
        key = (reason, file, repr(details))
        if key not in self._gap_keys:
            self.gaps.append(gap("static", reason, file=file, **details))
            self._gap_keys.add(key)

    def load(self):
        for path in source_files(self.root):
            self.control.check()
            relative = path.relative_to(self.base).as_posix()
            try:
                text = path.read_text(encoding="utf-8")
                tree = ast.parse(text, filename=relative)
            except (SyntaxError, UnicodeError, OSError) as error:
                self.warn(f"Could not parse Python source: {error}", relative)
                continue
            aliases = {}
            module_name = relative.removesuffix(".py").replace("/", ".").removesuffix(".__init__")
            for node in tree.body:
                if isinstance(node, ast.ImportFrom):
                    name = node.module or ""
                    if node.level:
                        package = module_name.split(".")[:-1]
                        if node.level > 1:
                            package = package[:1 - node.level]
                        name = ".".join([*package, name]).strip(".")
                    for alias in node.names:
                        aliases[alias.asname or alias.name] = f"{name}.{alias.name}".strip(".")
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        aliases[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]
            if any(value.split(".")[0] in {"fastapi", "starlette", "django", "litestar"} for value in aliases.values()):
                self.warn("Framework input/response semantics are unsupported by the Flask adapter; use configured runtime_inputs and review source manually.", relative)
            funcs = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
            self.modules[module_name] = Module(relative, module_name, tree, text, aliases, funcs)

    def resolve(self, module: Module, name: str) -> str:
        head, _, tail = name.partition(".")
        return module.aliases.get(head, head) + (f".{tail}" if tail else "")

    def helper(self, module: Module, name: str):
        if name in module.functions:
            return module, module.functions[name]
        resolved = self.resolve(module, name)
        for module_name, candidate in self.modules.items():
            for fn_name, fn in candidate.functions.items():
                target = f"{module_name}.{fn_name}"
                if resolved == target or resolved.endswith("." + target):
                    return candidate, fn
        return None

    def discover_routes(self):
        blueprint_names: dict[str, str] = {}
        registrations: dict[str, list[str]] = {}
        for module in self.modules.values():
            for node in module.tree.body:
                if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                    if self.resolve(module, dotted(node.value.func)) == "flask.Blueprint":
                        prefix = next((literal(k.value) for k in node.value.keywords if k.arg == "url_prefix"), "")
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                blueprint_names[f"{module.name}.{target.id}"] = prefix
                if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and dotted(node.value.func).endswith(".register_blueprint"):
                    call = node.value
                    if call.args:
                        raw = dotted(call.args[0])
                        name = self.resolve(module, raw)
                        if name == raw and "." not in name:
                            name = f"{module.name}.{name}"
                        prefix = next((literal(k.value) for k in call.keywords if k.arg == "url_prefix"), None)
                        registrations.setdefault(name, []).append(prefix)
        for module in self.modules.values():
            for function in module.functions.values():
                for deco in function.decorator_list:
                    if not isinstance(deco, ast.Call) or not isinstance(deco.func, ast.Attribute):
                        continue
                    verb = deco.func.attr
                    if verb not in {"route", "get", "post", "put", "patch", "delete"}:
                        continue
                    path = literal(deco.args[0]) if deco.args else next((literal(k.value) for k in deco.keywords if k.arg == "rule"), None)
                    methods = next((literal(k.value) for k in deco.keywords if k.arg == "methods"), ["GET"] if verb == "route" else [verb.upper()])
                    if not isinstance(path, str) or not isinstance(methods, (list, tuple)) or not all(isinstance(x, str) for x in methods):
                        self.warn("Dynamic route or HTTP methods could not be resolved", module.path, line=deco.lineno)
                        continue
                    owner = f"{module.name}.{dotted(deco.func.value)}"
                    if owner in blueprint_names:
                        prefixes = registrations.get(owner)
                        if prefixes is None:
                            # Imported blueprint names may carry an outer package prefix.
                            prefixes = next((v for k, v in registrations.items() if k.endswith("." + owner)), None)
                        if prefixes is None:
                            self.warn("Blueprint registration not found; route prefix is unverified", module.path, line=deco.lineno)
                            continue
                        prefixes = [blueprint_names[owner] if p is None else p for p in prefixes]
                    else:
                        prefixes = [""]
                    for prefix in prefixes:
                        if not isinstance(prefix, str):
                            self.warn("Dynamic blueprint prefix could not be resolved", module.path, line=deco.lineno)
                            continue
                        route = Route(prefix.rstrip("/") + "/" + path.lstrip("/"), [m.upper() for m in methods], module.path,
                                      function.name, function.lineno, function.end_lineno or function.lineno)
                        self.routes.append(route)
            for node in ast.walk(module.tree):
                if isinstance(node, ast.Call) and dotted(node.func).endswith((".add_url_rule", ".register_blueprint")) and not any(isinstance(s, ast.Expr) and s.value is node for s in module.tree.body):
                    self.warn("Application-factory route registration is outside the supported subset", module.path, line=node.lineno)

    def build_function_map(self):
        """A map of source functions is an analysis clue, not a reachability proof."""
        nodes = {}
        edges = []
        identities = {}
        for module in self.modules.values():
            for name, function in module.functions.items():
                key = fingerprint("function", module.path, name)
                identities[(module.path, name)] = key
                entry_points = [{"route": r.path, "methods": r.methods} for r in self.routes if r.file == module.path and r.function == name]
                nodes[key] = {"id": key, "name": name, "file": module.path, "line": function.lineno,
                              "end_line": function.end_lineno, "parameters": [a.arg for a in [*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs]],
                              "entry_points": entry_points, "reachable_from": [], "callers": [], "operations": [],
                              "reachability": "unknown", "note": "No resolved route path is not evidence that a function is unreachable."}
        for module in self.modules.values():
            for name, function in module.functions.items():
                caller = identities[(module.path, name)]
                # Nested function bodies have their own lexical scope; do not attribute their calls to the outer function.
                def calls(node):
                    for child in ast.iter_child_nodes(node):
                        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                            continue
                        if isinstance(child, ast.Call):
                            yield child
                        yield from calls(child)
                for call in calls(function):
                    label = dotted(call.func)
                    resolved = self.helper(module, label)
                    target = identities[(resolved[0].path, resolved[1].name)] if resolved else None
                    full_name = self.resolve(module, label)
                    cwe = None
                    if label.endswith((".execute", ".executemany", ".executescript")):
                        cwe = "CWE-89"
                    elif full_name == "flask.redirect":
                        cwe = "CWE-601"
                    elif full_name == "flask.send_file" or label == "open" or label.endswith((".read_text", ".read_bytes")):
                        cwe = "CWE-22"
                    elif full_name == "flask.render_template_string":
                        cwe = "CWE-79"
                    elif full_name in {"os.system", "os.popen", "subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output", "subprocess.check_call", "subprocess.getoutput", "subprocess.getstatusoutput"}:
                        cwe = "CWE-78"
                    kind = "request input" if full_name.startswith("flask.request.") else "sensitive operation" if cwe else "application call" if target else "external or unresolved"
                    if resolved:
                        self.call_targets[(module.path, call.lineno, call.col_offset)] = resolved
                        if caller not in nodes[target]["callers"]:
                            nodes[target]["callers"].append(caller)
                    edges.append({"caller": caller, "callee": target, "call": full_name or "<dynamic>",
                                  "file": module.path, "line": call.lineno, "resolved": target is not None,
                                  "kind": kind, "potential_cwe": cwe})
        adjacency = {key: set() for key in nodes}
        for edge in edges:
            if edge["callee"]:
                adjacency[edge["caller"]].add(edge["callee"])
        for key, node in nodes.items():
            for entry in node["entry_points"]:
                queue = [key]; seen = set()
                while queue:
                    current = queue.pop()
                    if current in seen:
                        continue
                    seen.add(current)
                    if entry not in nodes[current]["reachable_from"]:
                        nodes[current]["reachable_from"].append(entry)
                    nodes[current]["reachability"] = "resolved route path"
                    queue.extend(adjacency[current])
        self.function_map = {"nodes": list(nodes.values()), "edges": edges,
                             "scope": "Module-level functions and statically resolved calls. Dynamic calls and external functions remain unresolved; no-path nodes remain unknown."}

    def add(self, module: Module, function: ast.AST, node: ast.AST, cwe: str, value: Value,
            route: Route | None, stack: list[str], secret: bool = False):
        inputs = value.vulnerable(cwe)
        if not inputs and not secret:
            return
        # AST + occurrence within the containing function keeps identity stable when lines move.
        shape = ast.dump(node, include_attributes=False)
        same = [n for n in ast.walk(function) if ast.dump(n, include_attributes=False) == shape]
        ordinal = same.index(node) if node in same else 0
        function_name = getattr(function, "name", "<module>")
        key = fingerprint("static", cwe, module.path, function_name, shape, ordinal)
        snippet = ast.get_source_segment(module.text, node) or ""
        if secret:
            snippet = re.sub(r"([\"']).*?\1", "'[redacted literal]'", snippet)
        title, severity, _ = RULES[cwe]
        finding = self.findings.setdefault(key, Finding(key, "sast", cwe, title, severity,
            source={"file": module.path, "line": node.lineno, "end_line": getattr(node, "end_lineno", node.lineno),
                    "function": function_name, "snippet": snippet[:1400], "operation": type(node).__name__},
            note="Literal credential candidate; value redacted." if secret else "Input reaches an operation without a modeled protection. Runtime verification is separate."))
        if route:
            for inp in inputs:
                for method in route.methods:
                    binding = Binding(route.path, method, inp.name, inp.location, route.function,
                                      [f"{inp.location}:{inp.name}", *stack, f"{module.path}:{node.lineno}"])
                    if binding not in finding.bindings:
                        finding.bindings.append(binding)
                    record(finding, binding, value, inp)

    def expression(self, node: ast.AST | None, env: dict[str, Value], module: Module, fn: ast.AST,
                   route: Route, stack: list[str]) -> Value:
        value = self._expression(node, env, module, fn, route, stack)
        if node is None or not value.inputs: return value
        label = ast.get_source_segment(module.text, node) or type(node).__name__
        return step(value, module.path, getattr(node, 'lineno', fn.lineno), label, getattr(node, 'col_offset', 0))

    def _expression(self, node, env, module, fn, route, stack):
        if node is None:
            return Value()
        if isinstance(node, ast.Name):
            return env.get(node.id, Value())
        if isinstance(node, ast.Attribute):
            name = self.resolve(module, dotted(node))
            locations = {"flask.request.args": "query", "flask.request.values": "query", "flask.request.form": "form", "flask.request.json": "json", "flask.request.headers": "header"}
            if name in locations:
                return Value(container=locations[name])
            return self.expression(node.value, env, module, fn, route, stack)
        if isinstance(node, ast.Subscript):
            container = self.expression(node.value, env, module, fn, route, stack)
            name = literal(node.slice)
            if container.container and isinstance(name, str):
                return Value({Input(container.container, name): frozenset()})
            return combine(container, self.expression(node.slice, env, module, fn, route, stack))
        if isinstance(node, ast.Call):
            name = dotted(node.func)
            resolved = self.resolve(module, name)
            receiver = self.expression(node.func.value, env, module, fn, route, stack) if isinstance(node.func, ast.Attribute) else Value()
            args = [self.expression(a, env, module, fn, route, stack) for a in node.args]
            keywords = {k.arg: self.expression(k.value, env, module, fn, route, stack) for k in node.keywords}
            values = combine(receiver, *args, *keywords.values())
            first = args[0] if args else next(iter(keywords.values()), Value())
            if resolved == "flask.request.get_json":
                return Value(container="json")
            if receiver.container and name.endswith((".get", ".getlist")):
                parameter = literal(node.args[0]) if node.args else None
                if isinstance(parameter, str):
                    return Value({Input(receiver.container, parameter): frozenset()})
                self.warn("Dynamic request parameter name could not be resolved", module.path, line=node.lineno)
                return Value({Input(receiver.container, "*"): frozenset()})
            if resolved in {"markupsafe.escape", "html.escape", "flask.escape"}:
                return first.protected("CWE-79")
            if name in {"int", "float"}:
                return first.protected("CWE-89", "CWE-79", "CWE-22", "CWE-601", "CWE-78")
            if resolved in {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"}:
                self.add(module, fn, node, "CWE-78", first, route, stack)
                return Value()
            if resolved in {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_call", "subprocess.check_output"}:
                shell = next((literal(k.value) for k in node.keywords if k.arg == "shell"), False)
                if shell is True: self.add(module, fn, node, "CWE-78", first, route, stack)
                elif shell is not False: self.warn("Dynamic subprocess shell option cannot be resolved", module.path, line=node.lineno)
                return Value()
            if name.endswith((".execute", ".executemany", ".executescript")):
                self.add(module, fn, node, "CWE-89", args[0] if args else keywords.get("sql", Value()), route, stack)
                return Value()
            if resolved == "flask.redirect":
                self.add(module, fn, node, "CWE-601", args[0] if args else keywords.get("location", Value()), route, stack)
                return Value()
            if resolved == "flask.send_from_directory":
                return Value()
            if resolved == "flask.send_file" or name == "open" or name.endswith((".read_text", ".read_bytes")):
                mode = literal(node.args[1], "r") if name == "open" and len(node.args) > 1 else next((literal(k.value, "r") for k in node.keywords if k.arg == "mode"), "r")
                if not isinstance(mode, str) or not any(c in mode for c in "wa+"):
                    self.add(module, fn, node, "CWE-22", first if name == "open" or resolved == "flask.send_file" else receiver, route, stack)
                return Value()
            if resolved == "flask.render_template_string":
                self.add(module, fn, node, "CWE-79", first, route, stack)
                return Value()
            if resolved in {"flask.jsonify", "flask.abort"}:
                return Value()
            if resolved == "flask.render_template":
                if values.inputs:
                    self.warn("Jinja template context analysis is not implemented; autoescaping is not treated as universal proof of safety", module.path, line=node.lineno)
                return Value()
            if resolved == "flask.Response":
                mime = next((literal(k.value) for k in node.keywords if k.arg in {"mimetype", "content_type"}), "text/html")
                if isinstance(mime, str) and (mime.startswith("text/plain") or mime.startswith("application/json")):
                    return Value()
                self.add(module, fn, node, "CWE-79", first, route, stack)
                return Value()
            helper = self.call_targets.get((module.path, node.lineno, node.col_offset))
            if helper:
                target_module, target_fn = helper
                label = f"{target_module.path}:{target_fn.name}"
                if label in stack or len(stack) >= 8:
                    self.warn("Call depth or recursion limit reached", module.path, line=node.lineno)
                    return incomplete(values)
                target_env = {}
                for position, parameter in enumerate([*target_fn.args.posonlyargs, *target_fn.args.args]):
                    target_env[parameter.arg] = args[position] if position < len(args) else keywords.get(parameter.arg, Value())
                for parameter in target_fn.args.kwonlyargs:
                    target_env[parameter.arg] = keywords.get(parameter.arg, Value())
                return self.block(target_fn.body, target_env, target_module, target_fn, route, [*stack, label], False)
            if values.inputs and name not in {"str", "repr", "len"} and not name.endswith((".format", ".join", ".strip", ".lower", ".upper", ".replace", ".encode", ".decode")):
                self.warn("Unmodeled call with request input; taint is conservatively retained", module.path, line=node.lineno, call=name or "<dynamic>")
                # An unknown transformation can undo an upstream sanitizer.
                return incomplete(replace(values, inputs={key: frozenset() for key in values.inputs}))
            if name.endswith(".replace"):
                return replace(values, inputs={key: frozenset() for key in values.inputs})
            return values
        value = combine(*(self.expression(child, env, module, fn, route, stack) for child in ast.iter_child_nodes(node)))
        if isinstance(node, (ast.JoinedStr, ast.BinOp)):
            literals = " ".join(n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str))
            if re.search(r"<script\b|\bon\w+\s*=|\b(?:href|src|style)\s*=", literals, re.I):
                # HTML escaping alone does not protect JS, CSS, or URL contexts.
                value = replace(value, inputs={key: safe - {"CWE-79"} for key, safe in value.inputs.items()})
        return value

    def assign(self, target: ast.AST, value: Value, env: dict[str, Value]):
        if isinstance(target, ast.Name):
            env[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            for child in target.elts:
                self.assign(child, value, env)

    def block(self, statements, env, module, fn, route, stack, endpoint):
        returns = []
        for statement in statements:
            self.control.check()
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value = self.expression(statement.value, env, module, fn, route, stack)
                for target in statement.targets if isinstance(statement, ast.Assign) else [statement.target]:
                    self.assign(target, value, env)
            elif isinstance(statement, ast.AugAssign):
                value = combine(self.expression(statement.target, env, module, fn, route, stack), self.expression(statement.value, env, module, fn, route, stack))
                self.assign(statement.target, value, env)
            elif isinstance(statement, ast.Return):
                value = self.expression(statement.value, env, module, fn, route, stack)
                # Flask serializes dict/list responses as JSON, not HTML.
                if endpoint and not isinstance(statement.value, (ast.Dict, ast.List)):
                    self.add(module, fn, statement, "CWE-79", value, route, stack)
                returns.append(value)
                break
            elif isinstance(statement, ast.If):
                self.expression(statement.test, env, module, fn, route, stack)
                branches = []
                for branch in [statement.body, statement.orelse]:
                    child_env = env.copy()
                    returns.append(self.block(branch, child_env, module, fn, route, stack, endpoint))
                    branches.append(child_env)
                for key in set().union(*(b.keys() for b in branches)):
                    env[key] = combine(*(b.get(key, Value()) for b in branches))
            elif isinstance(statement, (ast.For, ast.While, ast.With, ast.Try)):
                self.warn("Control flow is approximated; branch conditions are not proven", module.path, line=statement.lineno)
                if isinstance(statement, ast.With):
                    for item in statement.items:
                        val = self.expression(item.context_expr, env, module, fn, route, stack)
                        if item.optional_vars:
                            self.assign(item.optional_vars, val, env)
                if isinstance(statement, ast.For):
                    self.assign(statement.target, self.expression(statement.iter, env, module, fn, route, stack), env)
                before = env.copy()
                returns.append(self.block(statement.body, env, module, fn, route, stack, endpoint))
                for key, val in before.items():
                    env[key] = combine(val, env.get(key, Value()))
                for attribute in ["orelse", "finalbody"]:
                    returns.append(self.block(getattr(statement, attribute, []), env, module, fn, route, stack, endpoint))
                for handler in getattr(statement, "handlers", []):
                    returns.append(self.block(handler.body, env, module, fn, route, stack, endpoint))
            elif isinstance(statement, ast.Expr):
                self.expression(statement.value, env, module, fn, route, stack)
        return combine(*returns)

    def scan_secrets(self):
        for module in self.modules.values():
            for node in ast.walk(module.tree):
                if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                    continue
                value = literal(node.value)
                if not isinstance(value, str) or not value or re.search(r"example|placeholder|changeme|your[_-]|dummy", value, re.I):
                    continue
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if len(value) < 12 and not any(re.search(r"password|passwd", dotted(t), re.I) for t in targets):
                    continue
                if any(re.search(r"(?:secret|password|passwd|api_?key|access_?token)", dotted(t), re.I) for t in targets):
                    self.add(module, module.tree, node, "CWE-798", Value(), None, [], secret=True)

    def run(self) -> Analysis:
        initial_digest = source_digest(self.root)
        self.load()
        self.discover_routes()
        self.build_function_map()
        self.scan_secrets()
        for route in self.routes:
            self.control.check()
            module = next(m for m in self.modules.values() if m.path == route.file)
            fn = module.functions[route.function]
            env = {}
            for segment in re.findall(r"<([^<>]+)>", route.path):
                converter, _, name = segment.rpartition(":")
                safe = frozenset({"CWE-89", "CWE-79", "CWE-22", "CWE-601"}) if converter in {"int", "float", "uuid"} else frozenset()
                env[name] = Value({Input("path", name): safe})
            self.block(fn.body, env, module, fn, route, [f"{module.path}:{fn.name}"], True)
            inputs = {Input(b.location, b.parameter) for f in self.findings.values() for b in f.bindings if b.route == route.path and b.method in route.methods}
            route.parameters = [{"name": i.name, "location": i.location} for i in sorted(inputs)]
        if not self.routes:
            self.warn("No supported Flask routes discovered. App factories, class views, and other frameworks require an adapter.")
        for node in self.function_map["nodes"]:
            node["operations"] = [{"finding_id": f.id, "cwe": f.cwe, "line": f.source["line"]} for f in self.findings.values()
                                  if f.source and f.source["file"] == node["file"] and f.source["function"] == node["name"]]
        return Analysis(initial_digest, self.routes, list(self.findings.values()), self.gaps, len(self.modules), self.function_map)


def analyze(root: str | Path, options: dict | None = None, control=None) -> Analysis:
    root = Path(root).resolve()
    if not root.exists(): raise FileNotFoundError(f"Source path does not exist: {root}")
    files = project_files(root)
    if not files: raise ValueError("No supported Python or PHP source files found.")
    control = control or ScanControl((options or {}).get("limits", {}).get("max_seconds", 300))
    initial_digest = source_digest(root)
    combined = Analysis(initial_digest, [], [], [], 0, {"nodes": [], "edges": [], "scope": "Bounded Python/Flask and PHP source analysis."})
    analyzers = []
    if any(p.suffix == ".py" for p in files): analyzers.append(Analyzer(root, control=control))
    if any(p.suffix in PHP_SUFFIXES for p in files):
        from .php import PHPAnalyzer
        from .laravel import LaravelAnalyzer, is_laravel
        analyzers.append((LaravelAnalyzer if is_laravel(root) else PHPAnalyzer)(root, options, control=control))
    for analyzer in analyzers:
        try:
            control.check()
            result = analyzer.run()
        except ScanStopped as error:
            php = hasattr(analyzer, "sources")
            result = Analysis(initial_digest, analyzer.routes, list(analyzer.findings.values()),
                              [*analyzer.gaps, gap("control", str(error))],
                              len(analyzer.sources if php else analyzer.modules),
                              {"nodes": list(analyzer.nodes.values()), "edges": analyzer.edges} if php else analyzer.function_map)
        combined.routes.extend(result.routes)
        combined.findings.extend(result.findings)
        combined.gaps.extend(result.gaps)
        combined.files += result.files
        combined.function_map["nodes"].extend(result.function_map["nodes"])
        combined.function_map["edges"].extend(result.function_map["edges"])
        combined.templates.update(result.templates)
    return combined
