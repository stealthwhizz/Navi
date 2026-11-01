"""A small Semgrep-style PHP taint-rule compiler for Navi's own value engine.

No Semgrep imports or subprocesses. Unsupported syntax rejects the entire rule.
"""
from dataclasses import dataclass
import re

from .load import documents, cwe, Unsupported
from ..model import gap


@dataclass
class Call:
    name: str
    method: bool
    arguments: list
    focus: int | None = None
    variadic: bool = False

    def accepts(self, name, method, count):
        minimum = len(self.arguments)
        return self.name == name.lower() and self.method == method and (count >= minimum if self.variadic else count == minimum)


def patterns(items):
    if not isinstance(items, list) or len(items) > 100: raise Unsupported('Expected a bounded pattern list.')
    result = []
    for item in items:
        if not isinstance(item, dict): raise Unsupported('Pattern entries must be objects.')
        if set(item) == {'pattern-either'}:
            result.extend(patterns(item['pattern-either']))
        elif set(item) == {'pattern'} and isinstance(item['pattern'], str):
            result.append((item['pattern'].strip(), None))
        elif set(item) == {'patterns'} and isinstance(item['patterns'], list) and len(item['patterns']) == 2:
            first, second = item['patterns']
            if not isinstance(first, dict) or not isinstance(second, dict): raise Unsupported('Invalid pattern conjunction.')
            if set(first) != {'pattern'} or set(second) != {'focus-metavariable'}: raise Unsupported('Only pattern + focus-metavariable conjunctions are supported.')
            result.append((first['pattern'].strip(), second['focus-metavariable']))
        else: raise Unsupported('Unsupported pattern condition; the complete rule was skipped.')
    return result


def call_pattern(pattern, focus=None):
    text = pattern.rstrip(';').strip()
    special = re.fullmatch(r'(echo|print|include|include_once|require|require_once)\s+(\$[A-Z_][A-Z_0-9]*|\.\.\.)', text)
    if special: return Call(special[1], False, ['$VALUE'], 0)
    if re.fullmatch(r'`\$[A-Z_][A-Z_0-9]*`', text): return Call('backtick execution', False, ['$VALUE'], 0)
    found = re.fullmatch(r'(?:(\$[A-Z_][A-Z_0-9]*)\s*->\s*)?([\\\w]+)\s*\(([^()]*)\)', text)
    if not found: raise Unsupported('Only direct calls, object calls and simple PHP output/include sink patterns are supported.')
    args = [p.strip() for p in found[3].split(',') if p.strip()]
    variadic = bool(args and args[-1] == '...')
    if variadic: args.pop()
    if any(not re.fullmatch(r'\$[A-Z_][A-Z_0-9]*', p) for p in args):
        raise Unsupported('Call patterns support metavariable arguments and a trailing ellipsis only.')
    if len(args) != len(set(args)): raise Unsupported('Repeated metavariable equality constraints are unsupported.')
    if focus and focus not in args: raise Unsupported('Focus metavariable does not identify a concrete argument.')
    return Call(found[2].lower().lstrip('\\'), bool(found[1]), args, args.index(focus) if focus else None, variadic)


def source_pattern(pattern):
    found = re.fullmatch(r'\$_(GET|POST|REQUEST|COOKIE|SESSION)\s*\[\s*(\.\.\.|\$[A-Z_][A-Z_0-9]*|[\'"][^\'"]+[\'"])\s*\]', pattern)
    if found:
        locations = {'GET': ['query'], 'POST': ['form'], 'REQUEST': ['query', 'form'], 'COOKIE': ['cookie'], 'SESSION': ['session']}[found[1]]
        name = found[2][1:-1] if found[2].startswith(('"', "'")) else None
        return [(location, name) for location in locations]
    found = re.fullmatch(r'filter_input\(INPUT_(GET|POST|COOKIE),\s*\$[A-Z_][A-Z_0-9]*(?:,\s*\.\.\.)?\)', pattern)
    if found: return [({'GET': 'query', 'POST': 'form', 'COOKIE': 'cookie'}[found[1]], None)]
    raise Unsupported('Source pattern is outside supported request selectors/filter_input forms.')


@dataclass
class Rule:
    id: str
    cwe: str
    title: str
    severity: str
    sources: list
    sinks: list[Call]
    sanitizers: list[Call]

    def input_matches(self, inp):
        return any(location == inp.location and (name is None or name == inp.name) for location, name in self.sources)


def load(paths):
    docs, gaps, manifests = documents(paths, 'sast-templates')
    rules, seen = [], set()
    inspected = 0
    for document, manifest in docs:
        entries = document.get('rules')
        if set(document) != {'rules'} or not isinstance(entries, list):
            gaps.append(gap('sast-templates', 'Expected a Semgrep-style rules list.', file=manifest['file'])); continue
        remaining = max(0, 500 - inspected)
        if len(entries) > remaining:
            gaps.append(gap('sast-templates', 'Rule limit reached (500 per pack); remaining rules were not loaded.', file=manifest['file']))
        for raw in entries[:remaining]:
            inspected += 1
            try:
                allowed = {'id', 'languages', 'severity', 'message', 'metadata', 'mode', 'pattern-sources', 'pattern-sinks', 'pattern-sanitizers'}
                if not isinstance(raw, dict) or raw.keys() - allowed: raise Unsupported('Unsupported rule-level fields; complete rule skipped.')
                identifier = raw.get('id')
                if not isinstance(identifier, str) or not re.fullmatch(r'[\w.:-]{1,160}', identifier): raise Unsupported('Invalid rule ID.')
                if identifier in seen: raise Unsupported('Duplicate rule ID.')
                if raw.get('languages') != ['php'] or raw.get('mode') != 'taint': raise Unsupported('This interpreter supports PHP taint rules only.')
                metadata = raw.get('metadata', {})
                weakness = cwe(metadata.get('cwe'))
                sources = []
                for pattern, focus in patterns(raw.get('pattern-sources', [])):
                    if focus: raise Unsupported('Source focus is unsupported.')
                    sources.extend(source_pattern(pattern))
                sinks = [call_pattern(p, focus) for p, focus in patterns(raw.get('pattern-sinks', []))]
                sanitizer_patterns = patterns(raw.get('pattern-sanitizers', []))
                if any(focus for _, focus in sanitizer_patterns): raise Unsupported('Focused sanitizer side effects are unsupported.')
                sanitizers = [call_pattern(p) for p, _ in sanitizer_patterns]
                if not sources or not sinks: raise Unsupported('Taint rules need supported sources and sinks.')
                severity = metadata.get('severity', {'ERROR': 'high', 'WARNING': 'medium', 'INFO': 'low'}.get(raw.get('severity'), 'medium'))
                if severity not in {'critical', 'high', 'medium', 'low'}: raise Unsupported('Invalid severity.')
                rules.append(Rule(identifier, weakness, str(raw.get('message', weakness)), severity, sources, sinks, sanitizers)); seen.add(identifier)
            except (Unsupported, TypeError, AttributeError) as error:
                gaps.append(gap('sast-templates', str(error) if isinstance(error, Unsupported) else 'Invalid rule structure.', file=manifest['file'], rule_id=raw.get('id') if isinstance(raw, dict) else None))
    if not rules: gaps.append(gap('sast-templates', 'No supported PHP taint rules were loaded; no template taint coverage.'))
    return rules, gaps, {'interpreter': 'navi-php-taint-v1', 'loaded': [r.id for r in rules], 'cwes': sorted({r.cwe for r in rules}), 'files': manifests, 'unsupported': len(gaps)}
