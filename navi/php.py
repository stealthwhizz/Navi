"""Bounded native PHP function/taint analysis using PHP's lexer, never target execution."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
import re
import shutil
import shlex
import subprocess
import json

from .model import Analysis, Binding, Finding, Input, Route, RULES, fingerprint, gap
from .source_flow import step, incomplete, combine_flows, record


LEXER = r'''$s=stream_get_contents(STDIN);$out=[];$line=1;foreach(token_get_all($s,TOKEN_PARSE) as $t){if(is_array($t)){$line=$t[2];$name=token_name($t[0]);if($name==='T_OPEN_TAG_WITH_ECHO')$out[]=['T_ECHO','echo',$line];elseif($name==='T_CLOSE_TAG')$out[]=[';',';',$line];elseif(!in_array($name,['T_WHITESPACE','T_COMMENT','T_DOC_COMMENT','T_OPEN_TAG']))$out[]=[$name,$t[1],$line];$line+=substr_count($t[1],"\n");}else{$out[]=[$t,$t,$line];}}echo json_encode($out,JSON_INVALID_UTF8_SUBSTITUTE);'''
SINKS = {"shell_exec", "exec", "system", "passthru", "popen", "proc_open"}
SQL_SINKS = {"mysqli_query": 1, "mysqli_multi_query": 1, "mysql_query": 0, "pg_query": -1,
             "query": 0, "prepare": 0, "sqlite_query": 1}
FILE_SINKS = {"file_get_contents", "readfile", "fopen", "file", "include", "include_once", "require", "require_once"}
NUMERIC_SAFE = frozenset({"CWE-89", "CWE-78", "CWE-79", "CWE-22", "CWE-601"})
MAX_STRING_CONTEXT = 4096


@dataclass
class Value:
    inputs: dict = field(default_factory=dict)
    prefix: str = ""
    constants: tuple | None = None
    literal: str | int | None = None
    context_known: bool = True
    context_limited: bool = False
    kind: str | None = None
    flows: dict = field(default_factory=dict)

    def __post_init__(self):
        if len(self.prefix) > MAX_STRING_CONTEXT:
            self.prefix = self.prefix[:MAX_STRING_CONTEXT]
            self.context_known = False
            self.context_limited = True
        if isinstance(self.literal, str) and len(self.literal) > MAX_STRING_CONTEXT:
            self.literal = None  # A truncated string must never become an include path.

    def protected(self, *cwes):
        return replace(self, inputs={inp: safe | frozenset(cwes) for inp, safe in self.inputs.items()})


def merge(values):
    """Concatenate expression components; use join() for alternative states."""
    result = Value()
    prefix_open = True
    for value in values:
        if prefix_open:
            room = MAX_STRING_CONTEXT - len(result.prefix)
            result.prefix += value.prefix[:room]
            if len(value.prefix) > room:
                result.context_known = False
                result.context_limited = True
        result.context_known = result.context_known and value.context_known
        result.context_limited = result.context_limited or value.context_limited
        if value.inputs:
            prefix_open = False
        for inp, safe in value.inputs.items():
            result.inputs[inp] = result.inputs[inp] & safe if inp in result.inputs else safe
    if values and values[0].constants is not None and all(value.constants == values[0].constants for value in values):
        result.constants = values[0].constants
    if values and all(value.literal == values[0].literal for value in values):
        result.literal = values[0].literal
    if len(values) == 1: result.kind = values[0].kind
    result.flows = combine_flows(values)
    return result


def join(values):
    """Union branch/return states without concatenating mutually exclusive text.

    Keep only a common prefix; protections on the same input must hold on all
    paths. Lost context cannot be used to dismiss an HTML/shell candidate.
    """
    if not values: return Value()
    result = Value(prefix=values[0].prefix, context_known=values[0].context_known)
    for value in values:
        if result.prefix != value.prefix:
            count = 0
            for left, right in zip(result.prefix, value.prefix):
                if left != right: break
                count += 1
            result.prefix = result.prefix[:count]
            result.context_known = False
        result.context_known = result.context_known and value.context_known
        result.context_limited = result.context_limited or value.context_limited
        for inp, safe in value.inputs.items():
            result.inputs[inp] = result.inputs[inp] & safe if inp in result.inputs else safe
    if all(v.constants == values[0].constants for v in values): result.constants = values[0].constants
    if all(v.literal == values[0].literal for v in values): result.literal = values[0].literal
    if all(v.kind == values[0].kind for v in values): result.kind = values[0].kind
    result.flows = combine_flows(values)
    return result


def closing(tokens, start, opening="(", ending=")"):
    depth = 0
    for index in range(start, len(tokens)):
        if tokens[index][1] == opening:
            depth += 1
        elif tokens[index][1] == ending:
            depth -= 1
            if depth == 0:
                return index
    return len(tokens) - 1


def split_args(tokens):
    groups, start, depth = [], 0, 0
    for i, token in enumerate(tokens):
        if token[1] in {"(", "[", "{"}: depth += 1
        elif token[1] in {")", "]", "}"}: depth -= 1
        elif token[1] == "," and depth == 0:
            groups.append(tokens[start:i]); start = i + 1
    if tokens[start:]: groups.append(tokens[start:])
    return groups


def text_literal(token):
    if token[0] == "T_CONSTANT_ENCAPSED_STRING":
        return token[1][1:-1].replace("\\'", "'").replace('\\"', '"').replace("\\\\", "\\")
    return token[1] if token[0] == "T_ENCAPSED_AND_WHITESPACE" else ""


class PHPAnalyzer:
    def __init__(self, root, options=None, control=None):
        from .control import ScanControl
        self.control = control or ScanControl()
        self.root = Path(root).resolve()
        self.base = self.root.parent if self.root.is_file() else self.root
        self.functions, self.sources, self.entries = {}, {}, []
        self.findings, self.nodes, self.edges, self.gaps, self.routes = {}, {}, [], [], []
        self.options = options or {}
        self.response_variables = []
        self.token_streams = {}
        self.loaded_files, self.include_stack, self.call_stack = set(), [], []
        self.entry_file = ""
        self.probing = False
        self.included_files = set()
        self.inferred_includes = set()
        from .templates.config import options as template_options
        settings = template_options(self.options)
        self.template_rules, self.template_manifest = None, {}
        if settings['mode'] == 'templates':
            from .templates.php import load
            self.template_rules, warnings, self.template_manifest = load(settings['semgrep_rules'])
            self.gaps.extend(warnings)

    def load_tokens(self):
        from .static import project_files, PHP_SUFFIXES
        executable = shutil.which("php")
        paths = [p for p in project_files(self.root) if p.suffix in PHP_SUFFIXES]
        if not executable:
            self.gaps.append(gap("php", "PHP CLI/tokenizer is unavailable; PHP sources were not analyzed."))
            return
        for path in paths:
            self.control.check()
            file = path.relative_to(self.base).as_posix()
            source = path.read_text()
            try:
                result = subprocess.run([executable, "-r", LEXER], input=source, text=True, capture_output=True, timeout=min(5, self.control.remaining()))
                if result.returncode:
                    raise ValueError("PHP rejected the source syntax")
                tokens = json.loads(result.stdout)
            except (ValueError, OSError, subprocess.TimeoutExpired):
                self.gaps.append(gap("php", "PHP tokenization failed; this file has incomplete coverage.", file=file))
                continue
            self.sources[file] = source
            self.token_streams[file] = tokens

    def load(self):
        self.load_tokens()
        for file, tokens in self.token_streams.items():
            if any(t[0] in {"T_CLASS", "T_TRAIT", "T_INTERFACE", "T_NAMESPACE"} for t in tokens):
                self.gaps.append(gap("php", "PHP class/namespace resolution is unsupported; this file is excluded from automatic source links.", file=file))
                continue
            if any(t[0] in {"T_IF", "T_ELSEIF", "T_FOR", "T_FOREACH", "T_WHILE", "T_SWITCH", "T_TRY", "T_FN"} for t in tokens):
                self.gaps.append(gap("php", "PHP branch, loop, and closure analysis is approximate; coverage is incomplete.", file=file))
            entry, i = [], 0
            while i < len(tokens):
                if tokens[i][0] == "T_FUNCTION" and i + 2 < len(tokens) and tokens[i+1][0] == "T_STRING":
                    name = tokens[i+1][1]
                    begin = i + 2
                    end = closing(tokens, begin)
                    params = [t[1] for t in tokens[begin+1:end] if t[0] == "T_VARIABLE"]
                    body_start = end + 1
                    while body_start < len(tokens) and tokens[body_start][1] != "{": body_start += 1
                    if body_start >= len(tokens): break
                    body_end = closing(tokens, body_start, "{", "}")
                    function = {"name": name, "file": file, "line": tokens[i][2], "end_line": tokens[body_end][2], "parameters": params,
                                "body": tokens[body_start+1:body_end]}
                    self.functions.setdefault(name.lower(), []).append(function)
                    self.add_node(function)
                    i = body_end + 1
                else:
                    entry.append(tokens[i]); i += 1
            if entry:
                function = {"name": "<entry>", "file": file, "line": entry[0][2], "end_line": entry[-1][2], "parameters": [], "body": entry}
                self.entries.append(function)
                self.add_node(function)
            if any(t[0] in {"T_CLASS", "T_TRAIT", "T_INTERFACE", "T_NAMESPACE", "T_FN"} for t in tokens):
                self.gaps.append(gap("php", "Classes, namespaces, closures, and dynamic dispatch require additional PHP modeling.", file=file))

    def add_node(self, fn):
        fn["id"] = fingerprint("function", fn["file"], fn["name"])
        self.nodes[fn["id"]] = {k: fn[k] for k in ["id", "name", "file", "line", "end_line", "parameters"]}
        self.nodes[fn["id"]].update(language="PHP", entry_points=[], reachable_from=[], callers=[], operations=[], reachability="unknown",
                                     note="No resolved path does not prove unreachability.")

    def helper(self, name, file):
        options = [fn for fn in self.functions.get(name.lower().lstrip("\\"), []) if fn["file"] in self.loaded_files]
        local = [fn for fn in options if fn["file"] == file]
        return local[0] if len(local) == 1 else options[0] if len(options) == 1 else None

    def mark(self, fn, call, token, value, route, stack, shape="", cwe="CWE-78", rule=None):
        if self.probing: return
        if self.template_rules is not None and rule is None and not fn.get('framework'): return
        if rule:
            value = replace(value, inputs={inp: safe for inp, safe in value.inputs.items() if rule.input_matches(inp) and 'rule:' + rule.id not in safe})
        line = token[2]
        has_fixed_program = value.context_known and bool(re.match(r"^\s*(?:/[\w./-]+|[\w.-]+)\s", value.prefix))
        try:
            shlex.split(value.prefix)
        except ValueError:
            has_fixed_program = False  # escapeshellarg inside an open quote is not sufficient.
        if re.search(r"\b(?:sh|bash|dash|zsh|ksh)\b.*\s-[a-z]*c(?:\s|$)|\bphp\b.*\s-r(?:\s|$)|\b(?:python\d*|perl|ruby)\b.*\s-(?:c|e)(?:\s|$)", value.prefix):
            has_fixed_program = False  # An interpreter executes even a properly quoted code argument.
        inputs = [inp for inp, safe in value.inputs.items() if cwe not in safe or (cwe == "CWE-78" and not has_fixed_program and "CWE-89" not in safe)]
        if cwe == "CWE-79":
            in_tag = value.prefix.rfind("<") > value.prefix.rfind(">")
            quoted_attribute = bool(value.prefix.count('"') % 2 or value.prefix.count("'") % 2)
            if not in_tag: inputs = [inp for inp in inputs if "HTML-TEXT" not in value.inputs[inp]]
            if re.search(r"<script\b|\bon\w+\s*=|javascript:", value.prefix, re.I) or (in_tag and not quoted_attribute):
                inputs = list(value.inputs)  # HTML encoding does not protect JS or unquoted attributes.
            if not value.context_known:
                inputs = [inp for inp, safe in value.inputs.items() if not NUMERIC_SAFE.issubset(safe)]
        if not inputs: return
        occurrence = next((index for index, item in enumerate(fn["body"]) if item is token), 0)
        key = fingerprint("php", cwe, fn["file"], fn["name"], occurrence, call, shape)
        source_line = self.sources[fn["file"]].splitlines()[line-1]
        title, severity = RULES.get(cwe, (rule.title if rule else cwe, 'medium', ''))[:2]
        finding = self.findings.setdefault(key, Finding(key, "sast", cwe, title, rule.severity if rule else severity,
            source={"file": fn["file"], "line": line, "end_line": line, "function": fn["name"], "snippet": source_line.strip(), "operation": call, "language": "PHP"},
            note="Request input reaches a PHP sensitive operation without a modeled context-appropriate protection; runtime proof is separate."))
        if rule:
            finding.scanner, finding.rule_id = 'navi-php-template', finding.rule_id or rule.id
            evidence = {'kind': 'source-rule', 'rule_id': rule.id, 'message': rule.title}
            if evidence not in finding.evidence: finding.evidence.append(evidence)
        for inp in inputs:
            methods = ["POST"] if inp.location == "form" and not fn.get('framework') else route.methods
            for method in methods:
                binding = Binding(route.path, method, inp.name, inp.location, route.function, [f"{inp.location}:{inp.name}", *stack, f"{fn['file']}:{line} {call}()"], route.provenance)
                if route.path and binding not in finding.bindings: finding.bindings.append(binding)
                if route.path: record(finding, binding, value, inp)
        return finding

    def template_call(self, name, method, args, fn, token, route, stack, shape=''):
        for rule in self.template_rules or []:
            for sink in rule.sinks:
                if not sink.accepts(name, method, len(args)): continue
                value = args[sink.focus] if sink.focus is not None else merge(args)
                if rule.cwe == 'CWE-601' and name.lower() == 'header':
                    if not re.match(r'\s*location\s*:', value.prefix, re.I): continue
                    destination = re.sub(r'^\s*location\s*:\s*', '', value.prefix, flags=re.I)
                    if value.context_known and destination.startswith('/') and len(destination) > 1 and destination[1] not in {'/', '\\'}: continue
                self.mark(fn, name, token, value, route, stack, shape if rule.cwe == 'CWE-78' else '', rule.cwe, rule)

    def include(self, tokens, env, fn, route, stack, once=False):
        from .php_paths import constant, include_target
        literal = constant(tokens, env, self.base / fn["file"])
        target = include_target(literal, self.base, Path(fn["file"]).parent, Path(self.entry_file).parent, self.sources)
        entry = next((e for e in self.entries if e["file"] == target), None)
        if target is None:
            warning = gap("php", "Include path is dynamic, ambiguous, outside the source tree, or unavailable; no source link was inferred through it.", file=fn["file"], line=tokens[0][2] if tokens else fn["line"])
            if not self.probing and warning not in self.gaps: self.gaps.append(warning)
            return Value()
        if self.probing: self.included_files.add(target)
        else: self.inferred_includes.add(target)
        if (once and target in self.loaded_files) or target in self.include_stack: return Value()
        self.loaded_files.add(target)
        if not entry: return Value()  # Function-only library: definitions are now in scope.
        if len(self.include_stack) >= 16:
            if not self.probing: self.gaps.append(gap("php", "Include depth limit reached.", file=target))
            return Value()
        edge = {"caller": fn["id"], "callee": entry["id"], "call": "include", "file": fn["file"],
                "line": tokens[0][2], "resolved": True, "kind": "literal include", "potential_cwe": None}
        if not self.probing:
            if edge not in self.edges: self.edges.append(edge)
            node = self.nodes[entry["id"]]
            reach = {"route": route.path, "methods": route.methods}
            if reach not in node["reachable_from"]: node["reachable_from"].append(reach)
            node["reachability"] = "source include path"
        self.include_stack.append(target)
        try: return self.block(entry, env, route, [*stack, f"{target}:<entry>"])
        finally: self.include_stack.pop()

    def expression(self, tokens, env, fn, route, stack):
        value = self._expression(tokens, env, fn, route, stack)
        if not tokens or not value.inputs: return value
        return step(value, fn['file'], tokens[0][2], ' '.join(t[1] for t in tokens)[:300])

    def _expression(self, tokens, env, fn, route, stack):
        self.control.check()
        values, i = [], 0
        while i < len(tokens):
            self.control.check()
            token = tokens[i]; name = token[1]
            special = self.special_expression(tokens, i, env, fn, route, stack)
            if special is not None:
                value, i = special
                values.append(step(value, fn['file'], token[2], ' '.join(t[1] for t in tokens[:i])[:300]))
                continue
            if token[0] in {"T_INT_CAST", "T_DOUBLE_CAST", "T_BOOL_CAST"}:
                start, end = i+1, i+2
                if start < len(tokens) and tokens[start][1] == "(": end = closing(tokens, start)+1
                elif end < len(tokens) and tokens[end][1] in {"[", "("}:
                    opening = tokens[end][1]
                    end = closing(tokens, end, opening, "]" if opening == "[" else ")")+1
                values.append(self.expression(tokens[start:end], env, fn, route, stack).protected(*NUMERIC_SAFE)); i=end; continue
            if token[0] in {"T_INCLUDE", "T_INCLUDE_ONCE", "T_REQUIRE", "T_REQUIRE_ONCE", "T_ECHO", "T_PRINT"}:
                value = self.expression(tokens[i+1:], env, fn, route, stack)
                self.mark(fn, name, token, value, route, stack, cwe="CWE-79" if token[0] in {"T_ECHO", "T_PRINT"} else "CWE-22")
                self.template_call(name, False, [value], fn, token, route, stack)
                included = self.include(tokens[i+1:], env, fn, route, stack, token[0].endswith("_ONCE")) if token[0] not in {"T_ECHO", "T_PRINT"} else Value()
                values.append(included); break
            if token[0] == "T_VARIABLE" and name in {"$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SESSION"} and i+3 < len(tokens) and tokens[i+1][1] == "[" and tokens[i+2][0] == "T_CONSTANT_ENCAPSED_STRING":
                locations = ["form"] if name == "$_POST" else ["cookie"] if name == "$_COOKIE" else ["session"] if name == "$_SESSION" else ["query"]
                if name == "$_REQUEST": locations = ["form" if method == "POST" else "query" for method in route.methods]
                parameter = text_literal(tokens[i+2])
                values.append(step(Value({Input(location, parameter): frozenset() for location in locations}), fn['file'], token[2], name + '[' + parameter + ']'))
                for location in locations:
                    item = {"name": parameter, "location": location}
                    if item not in route.parameters: route.parameters.append(item)
                i += 4; continue
            if token[0] in {"T_STRING", "T_NAME_FULLY_QUALIFIED"} and i+1 < len(tokens) and tokens[i+1][1] == "(":
                end = closing(tokens, i+1)
                arg_tokens = split_args(tokens[i+2:end])
                args = [self.expression(group, env, fn, route, stack) for group in arg_tokens]
                first = args[0] if args else Value()
                call_name = name.lower().lstrip("\\")
                is_method = i > 0 and tokens[i-1][0] in {"T_OBJECT_OPERATOR", "T_NULLSAFE_OBJECT_OPERATOR", "T_DOUBLE_COLON"}
                self.template_call(call_name, is_method, args, fn, token, route, stack, ' '.join(t[1] for t in tokens[i:end+1]))
                shell_call = call_name in SINKS and not is_method
                sql_index = 0 if is_method and call_name == "exec" else SQL_SINKS.get(call_name)
                helper = None if is_method else self.helper(call_name, fn["file"])
                edge = {"caller": fn["id"], "callee": helper["id"] if helper else None, "call": name, "file": fn["file"], "line": token[2], "resolved": bool(helper),
                        "kind": "sensitive operation" if shell_call or sql_index is not None or call_name in FILE_SINKS else "application call" if helper else "external or unresolved", "potential_cwe": "CWE-78" if shell_call else "CWE-89" if sql_index is not None else "CWE-22" if call_name in FILE_SINKS else None}
                if not self.probing and edge not in self.edges: self.edges.append(edge)
                if call_name == "filter_input" and len(arg_tokens) >= 2:
                    from .php_paths import constant
                    location = {"INPUT_GET": "query", "INPUT_POST": "form", "INPUT_COOKIE": "cookie"}.get("".join(t[1] for t in arg_tokens[0]))
                    parameter = constant(arg_tokens[1], env, self.base / fn["file"])
                    value = Value({Input(location, parameter): frozenset()}) if location and isinstance(parameter, str) else Value()
                    value = step(value, fn['file'], token[2], 'filter_input(' + str(parameter) + ')')
                    if value.inputs:
                        item = {"name": parameter, "location": location}
                        if item not in route.parameters: route.parameters.append(item)
                        mode = "".join(t[1] for t in arg_tokens[2]) if len(arg_tokens) > 2 else ""
                        if mode in {"FILTER_VALIDATE_INT", "FILTER_VALIDATE_FLOAT", "FILTER_VALIDATE_BOOLEAN"}: value = value.protected(*NUMERIC_SAFE)
                elif shell_call:
                    array_command = bool(arg_tokens and arg_tokens[0] and arg_tokens[0][0][1] in {"[", "array"})
                    if not (call_name == "proc_open" and array_command):
                        self.mark(fn, name, token, first, route, stack, " ".join(t[1] for t in tokens[i:end+1]))
                    value = Value()
                elif sql_index is not None:
                    index = sql_index
                    query = args[index] if args and -len(args) <= index < len(args) else Value()
                    self.mark(fn, name, token, query, route, stack, cwe="CWE-89")
                    value = Value()
                elif call_name in FILE_SINKS:
                    self.mark(fn, name, token, first, route, stack, cwe="CWE-22")
                    value = Value()
                elif call_name == "header":
                    if re.match(r"\s*location\s*:", first.prefix, re.I):
                        destination = re.sub(r"^\s*location\s*:\s*", "", first.prefix, flags=re.I)
                        if not (first.context_known and destination.startswith("/") and len(destination) > 1 and destination[1] not in {"/", "\\"}):
                            self.mark(fn, name, token, first, route, stack, cwe="CWE-601")
                    value = Value()
                elif call_name in {"printf", "vprintf"}:
                    self.mark(fn, name, token, merge(args), route, stack, cwe="CWE-79")
                    value = Value()
                elif call_name == "escapeshellarg":
                    value = first.protected("CWE-78")
                elif call_name in {"intval", "floatval", "doubleval", "abs", "strlen", "count", "is_numeric", "is_int", "ctype_digit"}:
                    value = first.protected(*NUMERIC_SAFE)
                elif call_name in {"htmlspecialchars", "htmlentities"}:
                    flags = "".join(t[1] for t in arg_tokens[1]) if len(arg_tokens) > 1 else "ENT_QUOTES"
                    value = first.protected("CWE-79" if "ENT_QUOTES" in flags else "HTML-TEXT")
                elif call_name == "define" and len(arg_tokens) >= 2:
                    from .php_paths import constant
                    key = constant(arg_tokens[0], env, self.base / fn["file"])
                    literal = constant(arg_tokens[1], env, self.base / fn["file"])
                    if isinstance(key, str): env[key] = Value(literal=literal)
                    value = Value()
                elif helper and helper["id"] not in self.call_stack and len(self.call_stack) < 8:
                    if not self.probing:
                        if fn["id"] not in self.nodes[helper["id"]]["callers"]: self.nodes[helper["id"]]["callers"].append(fn["id"])
                        reach = {"route": route.path, "methods": route.methods}
                        if reach not in self.nodes[helper["id"]]["reachable_from"]: self.nodes[helper["id"]]["reachable_from"].append(reach)
                        self.nodes[helper["id"]]["reachability"] = "source function path"
                    child = {param: args[index] if index < len(args) else Value() for index, param in enumerate(helper["parameters"])}
                    child.update({key: value for key, value in env.items() if not key.startswith("$")})
                    self.call_stack.append(helper["id"])
                    try: value = self.block(helper, child, route, [*stack, f"{helper['file']}:{helper['name']}"])
                    finally: self.call_stack.pop()
                else:
                    value = merge(args)
                    if helper or call_name not in {"trim", "strtolower", "strtoupper", "sprintf", "escapeshellcmd"}:
                        value = incomplete(value)
                    if call_name not in {"trim", "strtolower", "strtoupper"}:
                        value.inputs = {inp: frozenset() for inp in value.inputs}
                    if value.inputs and not helper and call_name not in {"trim", "strtolower", "strtoupper", "sprintf", "escapeshellcmd"}:
                        warning = gap("php", "A PHP call receiving request input could not be resolved; analysis is incomplete.", file=fn["file"], line=token[2], call=name)
                        if not self.probing and warning not in self.gaps: self.gaps.append(warning)
                for rule in self.template_rules or []:
                    if any(s.accepts(call_name, is_method, len(args)) for s in rule.sanitizers):
                        value = value.protected('rule:' + rule.id)
                values.append(value); i = end + 1; continue
            if name == "`":
                end = i+1
                while end < len(tokens) and tokens[end][1] != "`": end += 1
                value = self.expression(tokens[i+1:end], env, fn, route, stack)
                self.mark(fn, "backtick execution", token, value, route, stack, " ".join(t[1] for t in tokens[i:end+1]))
                self.template_call('backtick execution', False, [value], fn, token, route, stack, ' '.join(t[1] for t in tokens[i:end+1]))
                values.append(Value()); i = end + 1; continue
            if token[0] == "T_VARIABLE":
                if i+3 < len(tokens) and tokens[i+1][1] == "[" and tokens[i+3][1] == "]":
                    key = name + "[" + tokens[i+2][1] + "]"
                    value = env.get(key, env.get(name, Value()))
                    if tokens[i+2][0] == "T_CONSTANT_ENCAPSED_STRING":
                        value = incomplete(replace(value, inputs={Input(inp.location, text_literal(tokens[i+2]) if inp.name == "*" else inp.name): safe for inp, safe in value.inputs.items()}))
                    values.append(value); i += 4; continue
                globals_ = {"$_GET": "query", "$_POST": "form", "$_COOKIE": "cookie", "$_SESSION": "session"}
                value = Value({Input(globals_[name], "*"): frozenset()}) if name in globals_ else env.get(name, Value())
                values.append(step(value, fn['file'], token[2], name))
            elif token[0] in {"T_CONSTANT_ENCAPSED_STRING", "T_ENCAPSED_AND_WHITESPACE"}: values.append(Value(prefix=text_literal(token)))
            i += 1
        result = merge(values)
        from .php_paths import constant
        result.literal = constant(tokens, env, self.base / fn["file"])
        if result.context_limited and not self.probing:
            warning = gap("php", "PHP string context limit reached; contextual protections are uncertain and retained candidates need runtime validation.", file=fn["file"])
            if warning not in self.gaps: self.gaps.append(warning)
        return result

    def special_expression(self, tokens, index, env, fn, route, stack):
        return None

    def on_return(self, fn, token, value, route, stack, statement):
        pass

    def block(self, fn, env, route, stack, tokens=None):
        tokens = fn["body"] if tokens is None else tokens
        returned, i = [], 0
        while i < len(tokens):
            self.control.check()
            token = tokens[i]
            if token[0] == "T_INLINE_HTML":
                i += 1
                continue
            if token[1] == "{":
                end = closing(tokens, i, "{", "}")
                branch = dict(env)
                returned.append(self.block(fn, branch, route, stack, tokens[i+1:end]))
                for key, value in branch.items(): env[key] = join([env.get(key, Value()), value])
                i = end + 1; continue
            if token[0] in {"T_IF", "T_ELSEIF", "T_WHILE", "T_FOR", "T_FOREACH", "T_SWITCH", "T_CATCH"} and i+1 < len(tokens) and tokens[i+1][1] == "(":
                end = closing(tokens, i+1)
                selector = "".join(t[1] for t in tokens[i+2:end]).replace('"', "'")
                if token[0] == "T_IF" and end+1 < len(tokens) and tokens[end+1][1] == "{":
                    last = closing(tokens, end+1, "{", "}")
                    body = tokens[end+2:last]
                    branch = dict(env)
                    if "!" not in selector and "||" not in selector and "or" not in selector.lower():
                        for match in re.finditer(r"is_numeric\((\$\w+(?:\[\d+\])?)\)", selector):
                            key = match[1]
                            branch[key] = branch.get(key, branch.get(key.split("[")[0], Value())).protected(*NUMERIC_SAFE)
                    self.expression(tokens[i+2:end], env, fn, route, stack)
                    returned.append(self.block(fn, branch, route, stack, body))
                    for key, value in branch.items(): env[key] = join([env.get(key, Value()), value])
                    rejection = re.fullmatch(r"!in_array\((\$\w+),(\$\w+)(?:,true)?\)", selector)
                    tail = [item for item in body if item[1] != ";"]
                    if rejection and tail and tail[-1][0] == "T_EXIT" and env.get(rejection[2], Value()).constants:
                        env[rejection[1]] = env.get(rejection[1], Value()).protected(*NUMERIC_SAFE)
                    i = last+1; continue
                self.expression(tokens[i+2:end], env, fn, route, stack)
                i = end + 1; continue
            if token[0] in {"T_CASE", "T_DEFAULT"}:
                while i < len(tokens) and tokens[i][1] != ":": i += 1
                i += 1; continue
            if token[0] in {"T_ELSE", "T_TRY", "T_FINALLY"} or token[1] in {";", "}"}: i += 1; continue
            end, depth, quoted = i, 0, False
            while end < len(tokens):
                item = tokens[end]
                if item[1] == '"': quoted = not quoted
                if not quoted:
                    if item[1] in {"(", "["}: depth += 1
                    elif item[1] in {")", "]"}: depth -= 1
                    elif depth == 0 and item[1] == ";": break
                end += 1
            statement = tokens[i:end]
            if len(statement) > 3 and statement[0][0] == "T_CONST" and statement[2][1] == "=":
                from .php_paths import constant
                env[statement[1][1]] = Value(literal=constant(statement[3:], env, self.base / fn["file"]))
            elif len(statement) > 2 and statement[0][0] == "T_VARIABLE" and statement[1][1] in {"=", ".="}:
                value = self.expression(statement[2:], env, fn, route, stack)
                variable = statement[0][1]
                literal_tokens = statement[2:]
                if literal_tokens and literal_tokens[0][1] == "[" and all(t[0] == "T_CONSTANT_ENCAPSED_STRING" or t[1] in {"[", "]", ","} for t in literal_tokens):
                    value.constants = tuple(text_literal(t) for t in literal_tokens if t[0] == "T_CONSTANT_ENCAPSED_STRING")
                env[variable] = merge([env.get(variable, Value()), value]) if statement[1][1] == ".=" else value
                if statement[1][1] == ".=": env[variable].literal = None
                if variable in self.response_variables:
                    self.mark(fn, "HTML response fragment", statement[0], value, route, stack, cwe="CWE-79")
            elif statement:
                value = self.expression(statement, env, fn, route, stack)
                if statement[0][0] == "T_RETURN":
                    self.on_return(fn, statement[0], value, route, stack, statement)
                    returned.append(value)
                    break
                if statement[0][0] == "T_EXIT": break
            i = end + 1
        return join(returned)

    def scan_secrets(self):
        for file, tokens in self.token_streams.items():
            candidates = []
            for index, token in enumerate(tokens):
                if token[0] == "T_VARIABLE":
                    end = index+1
                    if end < len(tokens) and tokens[end][1] == "[": end = closing(tokens, end, "[", "]")+1
                    if end+1 < len(tokens) and tokens[end][1] == "=" and tokens[end+1][0] == "T_CONSTANT_ENCAPSED_STRING":
                        candidates.append(("".join(t[1] for t in tokens[index:end]), tokens[end+1], token[2]))
                if token[1].lower() == "define" and index+4 < len(tokens) and tokens[index+2][0] == tokens[index+4][0] == "T_CONSTANT_ENCAPSED_STRING":
                    candidates.append((text_literal(tokens[index+2]), tokens[index+4], token[2]))
            for name, literal, line in candidates:
                secret = text_literal(literal)
                if not re.search(r"secret|password|passwd|api_?key|access_?token", name, re.I): continue
                if not secret or (len(secret) < 12 and not re.search(r"password|passwd", name, re.I)) or re.search(r"example|placeholder|changeme|your[_-]|dummy", secret, re.I): continue
                key = fingerprint("php-secret", file, name, secret)
                self.findings[key] = Finding(key, "sast", "CWE-798", RULES["CWE-798"][0], "high",
                    source={"file": file, "line": line, "end_line": line, "function": "<entry>",
                            "snippet": name + " = '[redacted literal]'", "operation": "credential literal", "language": "PHP"},
                    note="Literal credential candidate; value redacted. Password names include short defaults; other key/secret names require at least 12 characters.")

    def run(self):
        from .static import source_digest
        digest = source_digest(self.root)
        self.load()
        self.scan_secrets()
        configured = self.options.get("php_routes")
        document_root = (self.base / self.options.get("php_document_root", ".")).resolve()
        if not document_root.is_relative_to(self.base) or not document_root.is_dir():
            raise ValueError("php_document_root must be an existing directory within the source tree.")
        if self.options.get("php_switches") or self.options.get("php_platform"):
            self.gaps.append(gap("php", "Legacy PHP branch/platform selectors are ignored; all modeled branches are analyzed."))
        # A dry static pass resolves includes before choosing entry scripts. It
        # never executes application code and does not emit vulnerability links.
        self.probing = True
        for entry in self.entries:
            self.control.check()
            route = Route("/" + entry["file"], ["GET", "POST"], entry["file"], "<entry>", entry["line"], entry["end_line"])
            self.reset_flow(entry)
            self.block(entry, {}, route, [])
        self.probing = False
        if self.included_files:
            self.gaps.append(gap("php", "Included libraries are analyzed through their callers, not assumed to be public scripts. Server rewrites and direct exposure of libraries are not inferred."))
        for entry in self.entries:
            self.control.check()
            if entry["file"] in self.included_files: continue
            path = self.base / entry["file"]
            public = path.is_relative_to(document_root) and path.suffix != '.inc'
            relative = path.relative_to(document_root).as_posix() if public else ""
            routes = ["/" + relative] if public else [""]
            if public and path.name == "index.php":
                routes.append("/" + relative.removesuffix("index.php"))
            for path in routes:
                route = Route(path, ["GET", "POST"], entry["file"], "<entry>", entry["line"], entry["end_line"], provenance="php-script" if path else "unmapped")
                self.analyze_entry(entry, route, {})
        for entry in self.entries:
            if entry['file'] in self.included_files and entry['file'] not in self.inferred_includes:
                route = Route('', ['GET', 'POST'], entry['file'], '<entry>', entry['line'], entry['end_line'], provenance='unmapped')
                self.analyze_entry(entry, route, {})
                self.gaps.append(gap('php', 'No public entry path was resolved for this include group; findings retain source locations without URL bindings.', file=entry['file']))
        # External mappings are supplemental hypotheses, never a scope filter.
        # They cannot alone upgrade a runtime issue into Confirmed.
        for mapping in configured or []:
            entry = next((e for e in self.entries if e["file"] == mapping["file"]), None)
            if entry:
                route = Route(mapping["route"], mapping.get("methods", ["GET", "POST"]), entry["file"], "<entry>", entry["line"], entry["end_line"], provenance="configured")
                self.analyze_entry(entry, route, mapping)
        if configured:
            self.gaps.append(gap("php", "Configured PHP mappings are operator hypotheses; they do not establish automatic source links or exclude other source files."))
        for node in self.nodes.values():
            node["operations"] = [{"finding_id": f.id, "cwe": f.cwe, "line": f.source["line"]} for f in self.findings.values() if f.source["file"] == node["file"] and f.source["function"] == node["name"]]
            unique = {json.dumps(r,sort_keys=True):r for r in node["reachable_from"]}
            node["reachable_from"] = list(unique.values())
        return Analysis(digest, self.routes, list(self.findings.values()), self.gaps, len(self.sources),
            {"nodes": list(self.nodes.values()), "edges": self.edges, "scope": "PHP script paths under the document root, exact includes and in-scope named functions. Branches are approximate; classes, rewrite rules, dynamic includes, stored data flow and namespaces are incomplete."},
            {'sast': self.template_manifest} if self.template_manifest else {})

    def reset_flow(self, entry):
        self.loaded_files = {entry["file"]}
        self.include_stack = [entry["file"]]
        self.call_stack = []
        self.entry_file = entry["file"]

    def analyze_entry(self, entry, route, mapping):
            self.response_variables = mapping.get("response_variables", [])
            self.reset_flow(entry)
            if route.path: self.routes.append(route)
            if route.path: self.nodes[entry["id"]]["entry_points"].append({"route": route.path, "methods": route.methods})
            self.nodes[entry["id"]]["reachable_from"].append({"route": route.path, "methods": route.methods})
            self.nodes[entry["id"]]["reachability"] = route.provenance
            env = {}
            self.block(entry, env, route, [f"{entry['file']}:<entry>"])
            if mapping.get("continuation"):
                continuation = next((e for e in self.entries if e["file"] == mapping["continuation"]), None)
                if continuation:
                    self.response_variables = []
                    self.edges.append({"caller": entry["id"], "callee": continuation["id"], "call": "configured include continuation", "file": continuation["file"], "line": continuation["line"], "resolved": True, "kind": "configured include", "potential_cwe": None})
                    self.nodes[continuation["id"]]["reachable_from"].append({"route": route.path, "methods": route.methods})
                    self.nodes[continuation["id"]]["reachability"] = "configured include path"
                    self.block(continuation, env, route, [f"{entry['file']}:<entry>", f"{continuation['file']}:<entry>"])
                else: self.gaps.append(gap("php", "Configured include continuation was not analyzed.", file=mapping["continuation"]))
