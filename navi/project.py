"""Repeatable project files, read-only planning, and operational preflight."""
from dataclasses import asdict
import json
import os
from pathlib import Path
import shutil
import uuid

from .ai.config import options as ai_options
from .candidates import native_candidates
from .runtime import load_config
from .static import analyze, project_files
from .model import no_source_analysis


def initialize(path, source=None, target=None, config=None, openapi=None, ai=False):
    path = Path(path).resolve()
    root = Path(source).resolve() if source else None
    if not root and not target: raise ValueError("Provide --target for runtime testing, --source for code analysis, or both.")
    if root and not root.exists(): raise ValueError("Source path does not exist.")
    if path.exists(): raise ValueError("Project file already exists; edit it or choose another --project path.")
    if target:
        from .transport import origin
        from urllib.parse import urlsplit
        origin(target)
        if urlsplit(target).query or urlsplit(target).fragment: raise ValueError("Project target cannot contain a query or fragment.")
    value = {"version": 1, "name": root.name if root else "HTTP target", "key": uuid.uuid4().hex,
             "source": os.path.relpath(root, path.parent) if root else None, "target": target, "output": "artifacts"}
    if ai: value["ai"] = {"enabled": True, "provider": "groq", "model": "openai/gpt-oss-20b", "workflow": "correlation", "max_requests": 5, "max_prompt_tokens": 4000, "max_completion_tokens": 2000}
    if openapi: value["openapi"] = os.path.relpath(Path(openapi).resolve(), path.parent)
    if config: value["config"] = os.path.relpath(Path(config).resolve(), path.parent)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle: json.dump(value, handle, indent=2); handle.write("\n")
    return value


def load_project(path):
    path = Path(path).resolve()
    value = json.loads(path.read_text())
    allowed = {"ai", "version", "name", "key", "source", "target", "config", "output", "openapi"}
    if not isinstance(value, dict) or value.keys() - allowed or value.get("version") != 1:
        raise ValueError("Invalid project file; expected version 1 and documented project fields.")
    if not isinstance(value.get("key"), str) or not value["key"]:
        raise ValueError("Project requires a stable key.")
    if not value.get("source") and not value.get("target"):
        raise ValueError("Project requires a source directory, a target URL, or both.")
    for field in ("source", "target", "config", "output", "name", "openapi"):
        if value.get(field) is not None and (not isinstance(value[field], str) or not value[field]):
            raise ValueError(f"Project {field} must be a nonempty string.")
    for key in ("source", "config", "output", "openapi"):
        if value.get(key): value[key] = str((path.parent / value[key]).resolve())
    from .ai.config import options
    options(value.get("ai"))
    return value


def resolve(args):
    path = getattr(args, "project", None)
    if path is None and not getattr(args, "source", None) and not getattr(args, "target", None) and Path("navi.json").is_file(): path = "navi.json"
    project = load_project(path) if path else {}
    source = getattr(args, "source", None) or project.get("source")
    target = getattr(args, "target", None) or project.get("target")
    if not source and not target: raise ValueError("No target selected. Use scan --target URL, scan --source DIRECTORY, or init --source DIRECTORY --target URL.")
    source = str(Path(source).resolve()) if source else None
    config_path = getattr(args, "config", None) or project.get("config")
    config = load_config(config_path)
    if getattr(args, 'correlation_policy', None):
        config['correlation'] = {**(config.get('correlation') or {}), 'policy': args.correlation_policy}
    scanners = config.setdefault('scanners', {})
    scanners.setdefault('mode', 'templates')
    if getattr(args, 'scanner', None): scanners['mode'] = args.scanner
    for flag, key in [('sast_rules', 'semgrep_rules'), ('dast_templates', 'nuclei_templates')]:
        if getattr(args, flag, None): scanners[key] = [str(Path(p).resolve()) for p in getattr(args, flag)]
    if target:
        config.setdefault("discovery", {"enabled": True, "paths": ["/"], "prefixes": ["/"], "max_pages": 40, "max_candidates": 60})
    if getattr(args, "document_root", None):
        config["php_document_root"] = args.document_root
    if getattr(args, "allow_origin", None):
        origins = config.setdefault("scope", {}).setdefault("allowed_origins", [])
        for value in args.allow_origin:
            if value not in origins: origins.append(value)
    if getattr(args, "allow_method", None):
        methods = config.setdefault("allowed_methods", ["GET"])
        for method in args.allow_method:
            if method not in methods: methods.append(method)
    openapi = getattr(args, "openapi", None) or project.get("openapi")
    if openapi:
        from .openapi import import_spec
        config = import_spec(openapi, config)
    if project.get("ai") is not None: config["ai"] = {**config.get("ai", {}), **project["ai"]}
    if getattr(args, "ai", None) is not None: config.setdefault("ai", {})["enabled"] = args.ai
    if getattr(args, 'ai_provider', None):
        ai = config.setdefault('ai', {})
        ai['provider'] = args.ai_provider
        ai.pop('model', None); ai.pop('api_key_env', None)
    if getattr(args, "ai_model", None): config.setdefault("ai", {})["model"] = args.ai_model
    from .ai.config import options
    options(config.get("ai"))
    from .runtime import validate_scan_options
    validate_scan_options(config)
    return {"source": source, "target": target,
            "config": config, "config_path": config_path,
            "project_key": project.get("key"),
            "output": getattr(args, "output", None) or project.get("output", "artifacts")}


def plan(source, target, config, browser=True):
    from .correlate import options as correlation_options
    analysis = analyze(source, config) if source else no_source_analysis()
    from .route_inputs import align_config
    config = align_config(analysis.routes, config)
    from .templates.config import options as template_options
    from .templates.http import load as load_http, VERIFIERS
    settings = template_options(config)
    manifest, template_gaps, drivers, http_tests = dict(analysis.templates), [], None, []
    if settings['mode'] == 'templates':
        templates, template_gaps, manifest['dast'] = load_http(settings['nuclei_templates'])
        drivers = {VERIFIERS[t.verifier] for t in templates if t.verifier}
        http_tests = [{'id': t.id, 'cwe': t.cwe, 'blocks': len(t.http), 'state': 'planned' if target else 'skipped',
                       'note': 'HTTP matcher signal only; request count depends on discovery and payloads.'} for t in templates if not t.verifier]
    tests = []
    for cwe, binding, skip in native_candidates(analysis, config):
        if drivers is not None and cwe not in drivers: continue
        prerequisites = []
        if cwe == "CWE-79": prerequisites.append("Chromium execution" if browser else "browser disabled: execution proof unavailable")
        if cwe == "CWE-22": prerequisites.append("known boundary-crossing test-file marker in traversal_fixtures")
        if binding.location == "path": prerequisites.append("valid configured path seed")
        tests.append({"cwe": cwe, **asdict(binding), "state": "skipped" if skip or not target else "planned",
                      "reason": skip or ("No target configured." if not target else None), "prerequisites": prerequisites})
    return {"source": str(Path(source).resolve()) if source else None, "target": target, "source_digest": analysis.digest,
            "correlation": correlation_options(config.get('correlation')),
            "routes": [asdict(r) for r in analysis.routes], "static_candidates": len(analysis.findings), "ai": {**ai_options(config.get("ai")), "note": "AI model calls are not made by plan; accepted proposals may add native tests during scan."},
            "function_map": analysis.function_map, "tests": tests, 'templates': manifest, 'http_template_tests': http_tests,
            "discovery": {"enabled": bool(config.get("discovery", {}).get("enabled")),
                          "note": "Runtime discovery may add inputs. Planning does not contact the application."},
            "stored_xss_workflows": len(config.get("stored_xss", [])),
            "authorization_resources": [{k: r.get(k) for k in ("route", "method", "parameter", "location")} for r in config.get("authorization", {}).get("resources", [])],
            "limits": {"max_seconds": config.get("limits", {}).get("max_seconds", 300), "max_requests": config.get("max_requests", 1000)},
            "scope": {"allowed_origins": config.get("scope", {}).get("allowed_origins", [])},
            "build_identity": config.get("build", {}).get("kind", "source_digest") if config.get("build") else "unverified",
            "gaps": [*analysis.gaps, *template_gaps, *config.get("import_gaps", [])], "note": "Plan includes source candidates and selected templates; it sends no test requests and is not a vulnerability report."}


def doctor(source, target, config, database_url=None, browser=True):
    checks = []
    def add(name, status, detail): checks.append({"name": name, "status": status, "detail": detail})
    from .templates.config import options as template_options
    settings = template_options(config)
    if settings['mode'] == 'templates':
        from .templates.php import load as load_php
        from .templates.http import load as load_http
        for name, enabled, loader, paths in [('sast-templates', source, load_php, settings['semgrep_rules']),
                                              ('dast-templates', target, load_http, settings['nuclei_templates'])]:
            if not enabled: continue
            loaded, gaps, manifest = loader(paths)
            add(name, 'error' if not loaded else 'warning' if gaps else 'ok',
                f"Navi interpreter: {len(loaded)} supported rules/templates; {len(gaps)} loading limitations. No external scanner required.")
    try:
        files = project_files(Path(source)) if source else []
        if not source: add("source", "warning", "Target-only mode: no SAST or source correlation; HTTP checks use discovery and configured/API inputs.")
        else: add("source", "ok" if files else "error", f"{len(files)} supported source files; 5000 files / 2 MB per file / 50 MB total limits.")
        if any(p.suffix == ".php" for p in files):
            import subprocess
            executable = shutil.which("php")
            ok = executable and subprocess.run([executable, "-r", "exit(function_exists('token_get_all') ? 0 : 1);"], capture_output=True, timeout=5).returncode == 0
            add("php", "ok" if ok else "error", "PHP tokenizer available." if ok else "Install PHP CLI with tokenizer; target source is never executed by SAST.")
    except (ValueError, OSError) as error: add("source", "error", str(error))
    if target:
        from .transport import Transport
        try:
            transport = Transport(target, timeout=2, max_requests=1, interval=0,
                                  allowed_origins=config.get("scope", {}).get("allowed_origins", []), ca_file=config.get("scope", {}).get("ca_file"))
            response = transport.request("/", "HEAD")
            add("target", "ok", f"Scoped transport received HTTP {response.status}; this does not verify login or test inputs.")
        except Exception as error: add("target", "error", f"Target preflight failed ({type(error).__name__}); check scope, TLS, port, and service availability.")
        if source and not config.get("build"): add("build", "warning", "No deployment identity endpoint: unique source-map links are allowed, with deployment identity marked unverified.")
        if source and config.get("build", {}).get("kind") == "git":
            try:
                from .identity import git_revision
                add("build", "ok", f"Clean local revision: {git_revision(source)}. Runtime equality is checked during scan.")
            except Exception as error: add("build", "warning", f"Clean Git identity unavailable ({type(error).__name__}).")
    if browser and target:
        from .browser import BrowserVerifier
        verifier = BrowserVerifier()
        try: verifier.start(); add("browser", "ok", "Chromium started.")
        except Exception as error: add("browser", "warning", str(error))
        finally: verifier.close()
    from .ai.config import options
    ai = options(config.get("ai"))
    if ai["enabled"]:
        present = bool(os.getenv(ai["api_key_env"]))
        add("ai", "ok" if present else "warning", f"{ai['provider']} {ai['model']}; key environment variable is {'set' if present else 'missing'}. Use ai-check to verify provider access. No source is uploaded by doctor.")
    if database_url:
        try:
            from .store import Store
            if not Store(database_url).health(): raise ValueError("database health failed")
            add("postgresql", "ok", "Connection succeeded; use migrate to apply the schema.")
        except Exception: add("postgresql", "error", "Database connection failed; check DATABASE_URL and PostgreSQL availability.")
    else: add("postgresql", "warning", "Exports-only mode: configure DATABASE_URL for persistent history.")
    return {"ready": not any(c["status"] == "error" for c in checks), "checks": checks}
