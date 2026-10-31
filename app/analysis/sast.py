import hashlib
import re
from pathlib import Path

from tree_sitter import Node

from app.analysis.php import PhpParseError, parse_php_file, php_files
from app.analysis.routemap import RouteEvidence, node_text, walk
from app.analysis.types import FindingInput

SOURCE_RE = re.compile(r"\$_(GET|POST|REQUEST|COOKIE|FILES)\s*\[\s*(['\"])([^'\"]+)\2\]")
VARIABLE_RE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*")
RULES = {
    89: ("SQL injection", "high", 75),
    79: ("Cross-site scripting", "high", 70),
    78: ("Command injection", "critical", 90),
    22: ("Path traversal", "high", 75),
    601: ("Open redirect", "medium", 55),
    798: ("Hard-coded secret", "high", 75),
}
PLACEHOLDERS = ("replace-me", "your-", "example", "dummy", "placeholder", "changeme", "todo")


def _scope(node: Node) -> int:
    parent = node.parent
    while parent is not None:
        if parent.type in {"function_definition", "method_declaration", "anonymous_function"}:
            return parent.start_byte
        parent = parent.parent
    return 0


def _literal(node: Node, source: str) -> str | None:
    if node.type not in {"string", "encapsed_string"}:
        return None
    raw = node_text(node, source)
    if len(raw) < 2 or raw[0] not in "'\"" or raw[-1] != raw[0]:
        return None
    if node.type == "encapsed_string" and "$" in raw:
        return None
    return raw[1:-1]


def _sanitizer_calls(node: Node, source: str) -> set[str]:
    return {
        _call_name(part, source)
        for part in walk(node)
        if part.type in {"function_call_expression", "member_call_expression"}
    }


def _source_evidence(
    node: Node, text: str, source: str, scope: int,
    tainted: dict[tuple[int, str], tuple[str, int, set[str]]], sanitizer: str | None,
) -> list[tuple[str, str, int | None]]:
    allowed = set(sanitizer.split("|")) if sanitizer else set()
    ranges = [
        (part.start_byte, part.end_byte)
        for part in walk(node)
        if part.type in {"function_call_expression", "member_call_expression"}
        and _call_name(part, source) in allowed
    ]
    evidence = set()
    for match in SOURCE_RE.finditer(text):
        start = node.start_byte + len(text[:match.start()].encode())
        if not any(left <= start < right for left, right in ranges):
            evidence.add((match.group(0), match.group(3), None))
    for match in VARIABLE_RE.finditer(text):
        variable = match.group(0)
        value = tainted.get((scope, variable))
        if not value:
            continue
        expr, source_line, sanitizers = value
        start = node.start_byte + len(text[:match.start()].encode())
        if sanitizers & allowed or any(left <= start < right for left, right in ranges):
            continue
        parameter = expr.split("[")[-1].rstrip("]'\"")
        evidence.add((expr, parameter, source_line))
    return sorted(evidence)


def _route_for(routes: list[RouteEvidence], file: str, line: int) -> dict | None:
    for route in routes:
        handler = route.handler
        if handler and handler["file"] == file and handler["line_start"] <= line <= handler["line_end"]:
            return {"method": route.method, "path": route.path}
    return None


def _snippet(source: str, line: int, redact: str | None = None) -> dict:
    code = source.splitlines()[line - 1] if source.splitlines() else ""
    if redact:
        code = code.replace(redact, "[REDACTED]")
    return {"start_line": line, "code": code[:500]}


def _finding(cwe: int, file: str, line: int, source_line: int | None, parameter: str,
             route: dict | None, source: str, expr: str, sink_name: str, sink_type: str,
             secret: str | None = None) -> FindingInput:
    title, severity, risk = RULES[cwe]
    sink_location = f"{file}:{line}"
    source_location = f"{file}:{source_line or line}"
    fingerprint = hashlib.sha256(f"{cwe}|{file}|{line}|{sink_name}|{parameter}".encode()).hexdigest()
    evidence = {
        "rule_id": f"CWE-{cwe}",
        "file": file,
        "line_start": line,
        "line_end": line,
        "snippet": _snippet(source, line, secret),
        "highlight_line": line,
        "source": {"expr": expr, "type": "literal_secret" if cwe == 798 else "request_parameter", "location": source_location},
        "sink": {"name": sink_name, "type": sink_type, "location": sink_location},
        "path": [
            {"label": "source", "location": source_location, "resolved": cwe != 798},
            {"label": "sink", "location": sink_location, "resolved": True},
        ],
        "sanitizers": [],
    }
    return FindingInput(
        source="sast", cwe=cwe, title=title, severity=severity, risk=risk,
        fingerprint=fingerprint, route=route, location={"file": file, "line": line}, sast=evidence,
    )


def _call_name(node: Node, source: str) -> str:
    name = node.child_by_field_name("function") or node.child_by_field_name("name")
    return node_text(name, source).lower().split("\\")[-1] if name is not None else ""


def _secret_assignment(node: Node, parsed, routes: list[RouteEvidence]) -> FindingInput | None:
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or right is None:
        return None
    variable = node_text(left, parsed.source)
    if not re.search(r"(?:pass(?:word)?|secret|token|api[_-]?key|private[_-]?key)", variable, re.I):
        return None
    literal_node = next((part for part in walk(right) if _literal(part, parsed.source) is not None), None)
    if literal_node is None:
        return None
    value = _literal(literal_node, parsed.source) or ""
    lowered = value.lower()
    if len(value) < 20 or any(marker in lowered for marker in PLACEHOLDERS):
        return None
    if not (re.search(r"[a-z]", value, re.I) and re.search(r"\d", value)):
        return None
    line = node.start_point.row + 1
    route = _route_for(routes, parsed.relative_path, line)
    return _finding(798, parsed.relative_path, line, line, variable, route, parsed.source, variable, "literal credential", "secret_literal", value)


def scan_source(source_root: Path, routes: list[RouteEvidence]) -> tuple[list[FindingInput], list[dict], dict]:
    root = source_root.resolve(strict=True)
    paths, skipped = php_files(root)
    findings: list[FindingInput] = []
    parsed_count = 0
    for path in paths:
        try:
            parsed = parse_php_file(path, root)
        except PhpParseError as exc:
            skipped.append({"path": path.relative_to(root).as_posix(), "reason": str(exc)})
            continue
        parsed_count += 1
        tainted: dict[tuple[int, str], tuple[str, int, set[str]]] = {}
        for node in walk(parsed.tree.root_node):
            text = node_text(node, parsed.source)
            scope = _scope(node)
            if node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left is not None and right is not None and node_text(left, parsed.source).startswith("$"):
                    target = (scope, node_text(left, parsed.source))
                    rhs = node_text(right, parsed.source)
                    sources = SOURCE_RE.findall(rhs)
                    value = None
                    if sources:
                        match = SOURCE_RE.search(rhs)
                        if match:
                            value = (
                                match.group(0), node.start_point.row + 1,
                                _sanitizer_calls(right, parsed.source),
                            )
                    else:
                        value = next((
                            tainted[(scope, variable)]
                            for variable in VARIABLE_RE.findall(rhs)
                            if (scope, variable) in tainted
                        ), None)
                    if value is None:
                        tainted.pop(target, None)
                    else:
                        tainted[target] = value
                secret = _secret_assignment(node, parsed, routes)
                if secret:
                    findings.append(secret)
                continue

            sinks: list[tuple[int, str, str, str | None]] = []
            if node.type == "echo_statement":
                sinks.append((79, "echo", "html_output", "htmlspecialchars|htmlentities"))
            elif node.type in {"function_call_expression", "member_call_expression"}:
                name = _call_name(node, parsed.source)
                if name in {"query", "mysql_query", "mysqli_query", "pg_query", "sqlite_query"}:
                    sinks.append((89, name, "sql_query", None))
                if name in {"system", "exec", "shell_exec", "passthru", "popen", "proc_open"}:
                    sinks.append((78, name, "command_execution", "escapeshellarg"))
                if name in {"file_get_contents", "fopen", "readfile", "file", "include", "require"}:
                    sinks.append((22, name, "file_path", "basename"))
                if name == "header" and "location" in text.lower():
                    sinks.append((601, name, "http_redirect", None))
            elif node.type == "include_expression":
                sinks.append((22, "include", "file_path", "basename"))

            for cwe, sink_name, sink_type, sanitizer in sinks:
                line = node.start_point.row + 1
                for expr, parameter, source_line in _source_evidence(
                    node, text, parsed.source, scope, tainted, sanitizer
                ):
                    findings.append(_finding(
                        cwe, parsed.relative_path, line, source_line, parameter,
                        _route_for(routes, parsed.relative_path, line), parsed.source,
                        expr, sink_name, sink_type,
                    ))

    findings.sort(key=lambda finding: (finding.cwe, finding.location["file"], finding.location["line"], finding.fingerprint))
    rules_not_run = []
    if skipped:
        rules_not_run = [{"rule": f"CWE-{cwe}", "reason": "some PHP files could not be parsed; coverage is partial"} for cwe in RULES]
    coverage = {
        "frameworks": [],
        "files_parsed": parsed_count,
        "files_skipped": skipped,
        "rules_not_run": rules_not_run,
    }
    return findings, [], coverage
