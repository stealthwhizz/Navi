from dataclasses import dataclass
from pathlib import Path
import re

from tree_sitter import Node

from app.analysis.php import ParsedPhpFile, PhpParseError, parse_php_file, php_files, validate_source_root


@dataclass(frozen=True)
class RouteEvidence:
    method: str
    path: str
    declared_at: str | None
    handler: dict | None
    params: list[str]
    provenance: str
    confidence: str
    tested: bool = False
    issue_count: int = 0


def walk(node: Node):
    yield node
    for child in node.named_children:
        yield from walk(child)


def node_text(node: Node | None, source: str) -> str:
    return "" if node is None else source[node.start_byte:node.end_byte]


def literal_value(node: Node, source: str) -> str | None:
    if node.type not in {"string", "encapsed_string"}:
        return None
    raw = node_text(node, source)
    if len(raw) < 2 or raw[0] not in "'\"" or raw[-1] != raw[0]:
        return None
    return raw[1:-1]


def _handler_index(files: list[ParsedPhpFile]) -> dict[tuple[str, str], dict]:
    handlers: dict[tuple[str, str], dict] = {}
    for parsed in files:
        for class_node in walk(parsed.tree.root_node):
            if class_node.type != "class_declaration":
                continue
            name = class_node.child_by_field_name("name")
            if name is None:
                continue
            class_name = node_text(name, parsed.source).split("\\")[-1]
            for method in walk(class_node):
                if method.type != "method_declaration":
                    continue
                method_name = method.child_by_field_name("name")
                if method_name is None:
                    continue
                key = (class_name, node_text(method_name, parsed.source))
                handlers[key] = _handler(parsed, node_text(method_name, parsed.source), method)
    return handlers


def _handler(parsed: ParsedPhpFile, name: str, node: Node) -> dict:
    return {
        "name": name,
        "file": parsed.relative_path,
        "line_start": node.start_point.row + 1,
        "line_end": node.end_point.row + 1,
    }


def _params(path: str, source: str) -> list[str]:
    names = set(re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", path))
    names.update(re.findall(r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]([^'\"]+)['\"]", source))
    names.update(re.findall(r"->(?:input|query|post)\s*\(\s*['\"]([^'\"]+)['\"]", source))
    return sorted(names)


def _arguments(call: Node) -> list[Node]:
    args = call.child_by_field_name("arguments")
    return [child.named_children[0] for child in args.named_children if child.named_children] if args else []


def _route_handler(handler_node: Node, parsed: ParsedPhpFile, handler_index: dict[tuple[str, str], dict]) -> tuple[dict | None, str]:
    for node in walk(handler_node):
        if node.type == "anonymous_function":
            return _handler(parsed, "closure", node), "closure"
    class_access = next((node for node in walk(handler_node) if node.type == "class_constant_access_expression"), None)
    strings = [value for node in walk(handler_node) if (value := literal_value(node, parsed.source))]
    if class_access is not None and strings:
        class_name = node_text(class_access, parsed.source).split("::", 1)[0].split("\\")[-1]
        method_name = strings[-1]
        handler = handler_index.get((class_name, method_name))
        if handler is not None:
            handler = {**handler, "name": f"{class_name}@{method_name}"}
        return handler, f"{class_name}@{method_name}"
    return None, node_text(handler_node, parsed.source)[:120]


def _laravel_routes(files: list[ParsedPhpFile], handler_index: dict[tuple[str, str], dict]):
    routes: list[RouteEvidence] = []
    unresolved: list[dict[str, str]] = []
    for parsed in files:
        if not parsed.relative_path.startswith("routes/"):
            continue
        for node in walk(parsed.tree.root_node):
            if node.type != "scoped_call_expression":
                continue
            scope = node.child_by_field_name("scope")
            method_node = node.child_by_field_name("name")
            if scope is None or method_node is None or node_text(scope, parsed.source).split("\\")[-1] != "Route":
                continue
            method = node_text(method_node, parsed.source).lower()
            if method not in {"get", "post", "put", "patch", "delete", "options", "any"}:
                continue
            args = _arguments(node)
            path = literal_value(args[0], parsed.source) if args else None
            if not path or len(args) < 2:
                continue
            handler, handler_name = _route_handler(args[1], parsed, handler_index)
            route_method = "ANY" if method == "any" else method.upper()
            line = node.start_point.row + 1
            if handler is None:
                provenance, confidence = "unresolved", "low"
                unresolved.append({"kind": "route_handler", "location": f"{parsed.relative_path}:{line}", "detail": f"Could not resolve {handler_name}"})
            else:
                provenance, confidence = "laravel", "high"
            handler_source = parsed.source
            if handler is not None:
                handler_path = next((file for file in files if file.relative_path == handler["file"]), None)
                if handler_path:
                    handler_source = handler_path.source
            routes.append(RouteEvidence(
                route_method, path, f"{parsed.relative_path}:{line}", handler,
                _params(path, handler_source), provenance, confidence,
            ))
    return routes, unresolved


def _filesystem_routes(root: Path, files: list[ParsedPhpFile]):
    public_root = root / "public"
    web_root = public_root if public_root.is_dir() else root
    routes: list[RouteEvidence] = []
    ignored = {"includes", "config", "setup", "tests", "vendor", "storage", "resources"}
    ignored_files = {"config.php"}
    for parsed in files:
        if not parsed.path.is_relative_to(web_root):
            continue
        relative = parsed.path.relative_to(web_root)
        if any(part.lower() in ignored for part in relative.parts[:-1]) or relative.name.lower() in ignored_files:
            continue
        filename = relative.as_posix()
        if filename == "index.php":
            route_path, provenance, confidence = "/", "front_controller", "low"
        else:
            route_path, provenance, confidence = f"/{filename}", "filesystem", "medium"
        line_end = max(1, len(parsed.source.splitlines()))
        handler = {
            "name": parsed.path.stem,
            "file": parsed.relative_path,
            "line_start": 1,
            "line_end": line_end,
        }
        routes.append(RouteEvidence("GET", route_path, None, handler, _params(route_path, parsed.source), provenance, confidence))
    return routes


def build_route_map(source_root: Path) -> tuple[list[RouteEvidence], list[dict[str, str]], list[dict[str, str]]]:
    root = validate_source_root(source_root, source_root)
    paths, skipped = php_files(root)
    parsed_files: list[ParsedPhpFile] = []
    for path in paths:
        try:
            parsed_files.append(parse_php_file(path, root))
        except PhpParseError as exc:
            skipped.append({"path": path.relative_to(root).as_posix(), "reason": str(exc)})

    handler_index = _handler_index(parsed_files)
    routes, unresolved = _laravel_routes(parsed_files, handler_index)
    if not routes:
        routes = _filesystem_routes(root, parsed_files)
    routes.sort(key=lambda route: (route.path, route.method, route.declared_at or ""))
    return routes, unresolved, skipped
