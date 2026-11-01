"""Small, non-executing evaluator for exact PHP include paths.

Unknown expressions stay unknown: prefixes, request values and arbitrary PHP
calls must never become guessed include edges.
"""
from pathlib import Path


def constant(tokens, env, file):
    from .php import closing, split_args, text_literal, MAX_STRING_CONTEXT
    if not tokens:
        return None
    if tokens[0][1] == "(" and closing(tokens, 0) == len(tokens) - 1:
        return constant(tokens[1:-1], env, file)
    depth, start, groups = 0, 0, []
    for i, token in enumerate(tokens):
        if token[1] in {"(", "[", "{"}: depth += 1
        elif token[1] in {")", "]", "}"}: depth -= 1
        elif token[1] == "." and depth == 0:
            groups.append(tokens[start:i]); start = i + 1
    if groups:
        values = [constant(group, env, file) for group in [*groups, tokens[start:]]]
        if any(value is None for value in values) or sum(len(str(value)) for value in values) > MAX_STRING_CONTEXT:
            return None
        return "".join(str(value) for value in values)
    if len(tokens) == 1:
        token = tokens[0]
        if token[0] == "T_CONSTANT_ENCAPSED_STRING":
            return text_literal(token) if len(token[1]) <= MAX_STRING_CONTEXT + 2 else None
        if token[0] == "T_DIR": return str(Path(file).parent)
        if token[0] == "T_FILE": return str(file)
        if token[0] == "T_LNUMBER" and token[1].isdigit(): return int(token[1])
        if token[1] == "DIRECTORY_SEPARATOR": return "/"
        value = env.get(token[1])
        return getattr(value, "literal", None)
    if tokens[0][1].lower() == "dirname" and tokens[1][1] == "(" and closing(tokens, 1) == len(tokens) - 1:
        args = [constant(group, env, file) for group in split_args(tokens[2:-1])]
        if len(args) in {1, 2} and isinstance(args[0], str):
            levels = args[1] if len(args) == 2 else 1
            if type(levels) is int and 1 <= levels <= 10:
                path = Path(args[0])
                for _ in range(levels): path = path.parent
                return str(path)
    return None


def include_target(value, base, caller, entry, known):
    if not isinstance(value, str) or not value or "\x00" in value or "://" in value:
        return None
    path = Path(value)
    paths = [path] if path.is_absolute() else [base / caller / path, base / entry / path, base / path]
    matches = set()
    for candidate in paths:
        try: relative = candidate.resolve().relative_to(base).as_posix()
        except ValueError: continue
        if relative in known: matches.add(relative)
    return next(iter(matches)) if len(matches) == 1 else None
