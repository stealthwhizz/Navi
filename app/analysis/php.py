from dataclasses import dataclass
from pathlib import Path

import tree_sitter_php
from tree_sitter import Language, Parser, Tree

MAX_PHP_BYTES = 1_000_000
_PARSER = Parser(Language(tree_sitter_php.language_php()))


class PhpParseError(ValueError):
    pass


@dataclass(frozen=True)
class ParsedPhpFile:
    path: Path
    relative_path: str
    source: str
    tree: Tree


def validate_source_root(root: Path, allowed_root: Path) -> Path:
    try:
        allowed = allowed_root.expanduser().resolve(strict=True)
        candidate = root.expanduser().resolve(strict=True)
    except OSError as exc:
        raise ValueError("source root does not exist") from exc
    if not allowed.is_dir() or not candidate.is_dir():
        raise ValueError("source root must be a directory")
    if not candidate.is_relative_to(allowed):
        raise ValueError("source root is outside the configured workspace")
    return candidate


def parse_php_file(path: Path, source_root: Path, max_bytes: int = MAX_PHP_BYTES) -> ParsedPhpFile:
    root = source_root.resolve(strict=True)
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(root):
        raise PhpParseError("file resolves outside source root")
    if not resolved.is_file():
        raise PhpParseError("not a regular file")
    if resolved.stat().st_size > max_bytes:
        raise PhpParseError("file exceeds size limit")
    try:
        raw = resolved.read_bytes()
        source = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise PhpParseError("file could not be read as UTF-8") from exc
    tree = _PARSER.parse(raw)
    if tree.root_node.has_error:
        raise PhpParseError("PHP syntax error")
    return ParsedPhpFile(resolved, resolved.relative_to(root).as_posix(), source, tree)


def php_files(root: Path) -> tuple[list[Path], list[dict[str, str]]]:
    files: list[Path] = []
    skipped: list[dict[str, str]] = []
    excluded = {".git", "vendor", "node_modules", "storage", "cache", ".venv"}
    for path in sorted(root.rglob("*.php")):
        relative = path.relative_to(root)
        if any(part in excluded for part in relative.parts):
            continue
        try:
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(root.resolve(strict=True)):
                skipped.append({"path": relative.as_posix(), "reason": "symlink resolves outside source root"})
                continue
        except OSError:
            skipped.append({"path": relative.as_posix(), "reason": "file is unavailable"})
            continue
        files.append(path)
    return files, skipped
