"""Declared test families and measured outcomes, without claiming universal recall."""

FAMILIES = {
    "CWE-89": {"name": "SQL injection", "static": "Python DB-API, PHP mysqli/PDO, Laravel DB facade and raw query-builder SQL",
               "runtime": ["single-quoted boolean", "numeric boolean", "double-quoted boolean", "session/cookie inputs", "HTML result comparison"],
               "limits": "No time-only or out-of-band oracle, second-order SQL, or general ORM/query-builder modeling."},
    "CWE-79": {"name": "Cross-site scripting", "static": "Flask/PHP HTML output, Laravel responses and direct Blade view-variable flows",
               "runtime": ["HTML event", "script element", "single/double attribute breakout", "textarea breakout", "inline DOM select breakout", "configured stored write/read/cleanup"],
               "limits": "Browser required. Same-origin scripts are opt-in; stored XSS requires an explicit workflow and stays Runtime only without a supported storage-to-output link. Not all JavaScript/CSS contexts are modeled."},
    "CWE-78": {"name": "Command injection", "static": "Python shell calls, PHP execution functions/backticks and Laravel Process strings",
               "runtime": ["semicolon", "quote breakout", "pipe", "newline", "AND/OR command chaining", "two independently encoded markers"],
               "limits": "POSIX probes only. Blind execution without returned output and program-specific argument injection are not covered."},
    "CWE-22": {"name": "Path traversal", "static": "Python/PHP file operations, Laravel File and response file/download paths",
               "runtime": ["configured relative path", "configured filter-bypass path", "configured absolute or local-file path", "repeated private marker"],
               "limits": "Requires a known disposable file outside the permitted directory. No arbitrary sensitive-file searching."},
    "CWE-601": {"name": "Open redirect", "static": "Flask/PHP redirects and Laravel redirect/to/away operations",
                "runtime": ["absolute URL", "scheme-relative URL", "observed seed path on an external origin"],
                "limits": "HTTP Location responses only; JavaScript/meta-refresh redirects and every URL parsing edge case are not covered."},
    "CWE-639": {"name": "Broken object authorization", "static": "No generic authorization-policy inference",
                "runtime": ["configured identities", "permitted-object baseline", "forbidden-object comparison", "protected-field evidence"],
                "limits": "Requires explicit identity verification, object references and access policy. HTTP success alone is not proof. No automatic business-policy inference."},
    "CWE-798": {"name": "Hard-coded secrets", "static": "Named literal credential candidates in Python and PHP, with redacted values",
                "runtime": [], "limits": "Code only, as specified by the PRD. Name/literal heuristics do not validate credentials or cover all encodings/config formats."},
}


def summarize(analysis, checks):
    rows = []
    families = dict(FAMILIES)
    for weakness in {f.cwe for f in analysis.findings} | {c['cwe'] for c in checks}:
        families.setdefault(weakness, {'name': weakness, 'static': 'Loaded PHP taint rules, if configured',
                            'runtime': ['Loaded HTTP template matchers, if configured'],
                            'limits': 'Template-defined detection; no generic exploit verifier for this CWE.'})
    for cwe, family in families.items():
        selected = [check for check in checks if check["cwe"] == cwe]
        rows.append({"cwe": cwe, **family, "static_candidates": sum(f.cwe == cwe for f in analysis.findings),
                     "runtime_inputs_tested": len(selected),
                     "outcomes": {outcome: sum(check["outcome"] == outcome for check in selected) for outcome in ["verified", "not_reproduced", "inconclusive", "skipped", "error", "template_match"]},
                     "status": "code only by design" if cwe == "CWE-798" else "checks recorded" if selected else "not exercised"})
    return rows
