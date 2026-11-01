"""Native, source-directed runtime verifiers and explicit authorization-policy checks."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict
import json
import secrets
from urllib.parse import urlsplit

from .control import ScanControl, ScanStopped
from .candidates import native_candidates
from .browser import BrowserUnavailable, BrowserVerifier
from .model import Analysis, Binding, Check, Finding, RULES, fingerprint, gap
from .transport import Transport, TargetError
from .discovery import authenticate, discover, csrf_value, comparison_body


def get_field(value, path: str):
    for key in path.split("."):
        if not isinstance(value, dict) or key not in value:
            return None
        value = value[key]
    return value


def load_config(path: str | None) -> dict:
    if not path:
        return {}
    with open(path, encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("Configuration must be a JSON object.")
    value = resolve_environment(value)
    validate_scan_options(value)
    if value.get("scope", {}).get("ca_file"):
        from pathlib import Path
        value["scope"]["ca_file"] = str((Path(path).resolve().parent / value["scope"]["ca_file"]).resolve())
    from pathlib import Path
    for field in ['semgrep_rules', 'nuclei_templates']:
        if field in value.get('scanners', {}):
            value['scanners'][field] = [str((Path(path).resolve().parent / p).resolve()) for p in value['scanners'][field]]
    return value


def resolve_environment(value):
    import os
    import re
    if isinstance(value, dict):
        if set(value) == {"$env"}:
            name = value["$env"]
            if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                raise ValueError("Invalid environment variable reference.")
            if name not in os.environ: raise ValueError(f"Required environment variable {name} is not set.")
            return os.environ[name]
        return {key: resolve_environment(item) for key, item in value.items()}
    if isinstance(value, list): return [resolve_environment(item) for item in value]
    return value


def validate_scan_options(value):
    if not isinstance(value, dict): raise ValueError("Configuration must be a JSON object.")
    allowed = {"trace", "browser", "laravel", "workflows", "scanners", "import_gaps", "ai", "scope", "limits", "build", "requests", "traversal_fixtures", "authorization", "allowed_methods", "timeout", "max_requests", "interval", "lab", "session", "discovery", "php_routes", "runtime_inputs", "php_switches", "php_platform", "php_document_root", "stored_xss"}
    from .tracing import options as trace_options
    trace_options(value.get('trace'))
    from .browser import options as browser_options
    browser_options(value.get('browser'))
    framework = value.get('laravel', {})
    if not isinstance(framework, dict) or framework.keys() - {'api_prefix'}:
        raise ValueError('laravel accepts api_prefix only.')
    prefix = framework.get('api_prefix', '/api')
    if not isinstance(prefix, str) or (prefix and not prefix.startswith('/')) or any(c in prefix for c in '?#{<>}\\') or '..' in prefix or any(c.isspace() for c in prefix):
        raise ValueError('laravel.api_prefix must be an application-relative path, or an empty string.')
    from .templates.config import options as template_options
    template_options(value)
    unknown = value.keys() - allowed
    if unknown:
        raise ValueError(f"Unknown configuration fields: {', '.join(sorted(unknown))}")
    for name, minimum, maximum in [("timeout", 0.1, 30), ("max_requests", 1, 5000), ("interval", 0, 2)]:
        if name in value and (isinstance(value[name], bool) or not isinstance(value[name], (int, float)) or not minimum <= value[name] <= maximum):
            raise ValueError(f"{name} must be a number between {minimum} and {maximum}.")
    if "max_requests" in value and not isinstance(value["max_requests"], int):
        raise ValueError("max_requests must be an integer.")
    if not isinstance(value.get("requests", {}), dict):
        raise ValueError("requests must map 'METHOD /route' to request data.")
    for route, settings in value.get("requests", {}).items():
        if not isinstance(settings, dict) or settings.keys() - {"workflow", "query", "form", "json", "headers", "path", "csrf", "prepare", "cookies", "form_refresh"}:
            raise ValueError(f"Invalid request settings for {route}.")
        if any(not isinstance(data, dict) for data in settings.values()) or ("json" in settings and "form" in settings):
            raise ValueError(f"Request components must be objects; choose form or JSON for {route}.")
    if not isinstance(value.get("traversal_fixtures", []), list) or any(not isinstance(f, dict) for f in value.get("traversal_fixtures", [])):
        raise ValueError("traversal_fixtures must be a list of objects.")
    if "build" in value and (not isinstance(value["build"], dict) or not isinstance(value["build"].get("path"), str)):
        raise ValueError("build requires an endpoint path.")
    if "authorization" in value:
        spec = value["authorization"]
        if not isinstance(spec, dict) or not isinstance(spec.get("identities", {}), dict) or not isinstance(spec.get("resources", []), list):
            raise ValueError("authorization requires identity and resource policy objects.")
        if any(not isinstance(d, dict) or not isinstance(d.get("headers", {}), dict) for d in spec.get("identities", {}).values()) or any(not isinstance(r, dict) for r in spec.get("resources", [])):
            raise ValueError("Authorization identities and resources must be objects.")
    methods = value.get("allowed_methods", ["GET"])
    if not isinstance(methods, list) or not methods or any(m not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"} for m in methods):
        raise ValueError("allowed_methods must contain supported uppercase HTTP method names.")
    if "lab" in value:
        lab = value["lab"]
        if not isinstance(lab, dict) or not isinstance(lab.get("comparisons", []), list):
            raise ValueError("lab.comparisons must be a list of configured route pairs.")
        for comparison in lab.get("comparisons", []):
            if not isinstance(comparison, dict) or any(not isinstance(comparison.get(key), str) or not comparison[key].startswith("/") for key in ["route", "protected_route"]):
                raise ValueError("A lab comparison needs route and protected_route paths.")
    notes = value.get("import_gaps", [])
    if not isinstance(notes, list) or any(not isinstance(n, dict) or not isinstance(n.get("component"), str) or not isinstance(n.get("reason"), str) for n in notes):
        raise ValueError("import_gaps must be a list of component/reason objects.")
    from .ai.config import options
    options(value.get("ai"))
    import math
    scope = value.get("scope", {})
    if not isinstance(scope, dict) or scope.keys() - {"allowed_origins", "ca_file"}:
        raise ValueError("scope accepts allowed_origins and ca_file.")
    origins = scope.get("allowed_origins", [])
    if not isinstance(origins, list): raise ValueError("scope.allowed_origins must be a list of exact HTTP(S) origins.")
    from .transport import origin
    for item in origins:
        if not isinstance(item, str): raise ValueError("Scope origins must be strings.")
        origin(item)
        parsed = urlsplit(item)
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError("Scope origins cannot contain application paths, queries, or fragments.")
    if "ca_file" in scope and not isinstance(scope["ca_file"], str): raise ValueError("scope.ca_file must be a path.")
    limits = value.get("limits", {})
    if not isinstance(limits, dict) or limits.keys() - {"max_seconds"}: raise ValueError("limits accepts max_seconds.")
    seconds = limits.get("max_seconds", 300)
    if type(seconds) not in {int, float} or not math.isfinite(seconds) or not 1 <= seconds <= 3600:
        raise ValueError("limits.max_seconds must be between 1 and 3600.")
    build = value.get("build", {})
    if build.get("kind", "source_digest") not in {"source_digest", "git"}: raise ValueError("build.kind must be source_digest or git.")
    def local(path):
        return isinstance(path, str) and path.startswith("/") and not path.startswith("//") and not any(c in path for c in "\r\n?#")
    session = value.get("session", {})
    if not isinstance(session, dict) or not isinstance(session.get("cookies", {}), dict): raise ValueError("session requires an object and cookie map.")
    if "login" in session:
        login = session["login"]
        if (not isinstance(login, dict) or not local(login.get("path")) or not local(login.get("verify_path"))
                or not isinstance(login.get("form", {}), dict) or not isinstance(login.get("success_contains"), str) or not login["success_contains"]):
            raise ValueError("session.login needs local path, form, verify_path, and success_contains.")
    if type(session.get('reauthenticate', False)) is not bool or type(session.get('max_reauth', 2)) is not int or not 0 <= session.get('max_reauth', 2) <= 5:
        raise ValueError('Session reauthenticate must be boolean; max_reauth must be between 0 and 5.')
    if session.get('reauthenticate') and not session.get('login'): raise ValueError('Session renewal requires a verified login configuration.')
    def validate_refresh(spec):
        if not isinstance(spec, dict) or spec.keys() - {'path', 'query', 'index', 'id', 'signature', 'overrides'} or not local(spec.get('path')):
            raise ValueError('form_refresh needs a local page path and optional form selector.')
        if type(spec.get('index', 0)) is not int or not 0 <= spec.get('index', 0) < 100:
            raise ValueError('form_refresh.index must be between 0 and 99.')
        if not isinstance(spec.get('query', {}), dict) or not isinstance(spec.get('overrides', {}), dict): raise ValueError('Invalid form refresh values.')
        for name in ['id', 'signature']:
            if spec.get(name) is not None and not isinstance(spec[name], str): raise ValueError('Invalid form selector.')
    workflows = value.get('workflows', [])
    from .workflow_state import validate as validate_workflows
    workflow_ids = validate_workflows(workflows, methods, local, validate_refresh)
    for settings in value.get('requests', {}).values():
        flow = settings.get('workflow')
        if flow is not None and (not isinstance(flow, dict) or set(flow) != {'id'} or not isinstance(flow['id'], str) or flow['id'] not in workflow_ids):
            raise ValueError('Request workflow must reference a configured workflow ID.')
    discovery = value.get("discovery", {})
    if not isinstance(discovery, dict): raise ValueError("discovery must be an object.")
    for name, default, maximum in [("max_pages", 30, 100), ("max_candidates", 60, 200)]:
        setting = discovery.get(name, default)
        if type(setting) is not int or not 1 <= setting <= maximum: raise ValueError(f"discovery.{name} must be between 1 and {maximum}.")
    for name in ("paths", "prefixes"):
        if name in discovery and (not isinstance(discovery[name], list) or not all(local(p) for p in discovery[name])): raise ValueError(f"discovery.{name} requires local paths.")
    for settings in value.get("requests", {}).values():
        if 'form_refresh' in settings: validate_refresh(settings['form_refresh'])
        csrf = settings.get("csrf")
        if csrf and (not local(csrf.get("path")) or not isinstance(csrf.get("field"), str) or csrf.get("location", "form") not in {"form", "query"}): raise ValueError("Invalid request CSRF configuration.")
        if "prepare" in settings and (not local(settings["prepare"].get("path")) or not isinstance(settings["prepare"].get("parameter"), str)): raise ValueError("Invalid session preparation request.")
    routes = value.get("php_routes", [])
    if "php_document_root" in value:
        root = value["php_document_root"]
        if not isinstance(root, str) or not root or root.startswith("/") or ".." in root.split("/"):
            raise ValueError("php_document_root must be relative to the source directory.")
    if not isinstance(routes, list): raise ValueError("php_routes must be a list.")
    for entry in routes:
        if not isinstance(entry, dict) or not local(entry.get("route")): raise ValueError("PHP entries need a local route.")
        for name in ["file", *(["continuation"] if "continuation" in entry else [])]:
            path = entry.get(name)
            if not isinstance(path, str) or path.startswith("/") or ".." in path.split("/") or not path.endswith(".php"): raise ValueError("PHP source mappings must be relative PHP files.")
        if not isinstance(entry.get("methods", ["GET"]), list) or any(m not in {"GET", "POST"} for m in entry.get("methods", [])): raise ValueError("PHP methods must be GET or POST.")
    inputs = value.get("runtime_inputs", [])
    if not isinstance(inputs, list): raise ValueError("runtime_inputs must be a list.")
    for item in inputs:
        if (not isinstance(item, dict) or not local(item.get("route")) or item.get("method", "GET") not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}
                or not isinstance(item.get("parameter"), str) or item.get("location", "query") not in {"query", "form", "json", "path", "header", "cookie", "session"}): raise ValueError("Invalid runtime input.")
    workflows = value.get("stored_xss", [])
    if not isinstance(workflows, list): raise ValueError("stored_xss must contain explicit write/read/cleanup workflows.")
    for workflow in workflows:
        if not isinstance(workflow, dict): raise ValueError("Invalid stored-XSS workflow.")
        for stage in ("write", "read", "cleanup"):
            if not isinstance(workflow.get(stage), dict) or not local(workflow[stage].get("route")): raise ValueError("Stored-XSS workflows require local write/read/cleanup routes.")
        if workflow["write"].get("method", "POST") != "POST" or not workflow["write"].get("parameter") or workflow["write"].get("location", "form") not in {"form", "json"}: raise ValueError("Stored-XSS writes require a POST input.")
        if workflow["cleanup"].get("method", "POST") not in {"POST", "DELETE"}: raise ValueError("Stored-XSS cleanup must use POST or DELETE.")


class Runtime:
    def __init__(self, analysis: Analysis, target: str, config: dict, emit=lambda *args: None, browser=True, transport=None, control=None, source=None, ai_tests=()):
        self.analysis = analysis
        self.ai_tests = list(ai_tests)
        from .route_inputs import align_config
        self.config = align_config(analysis.routes, config)
        config = self.config
        self.emit = emit
        self.control = control or ScanControl(config.get("limits", {}).get("max_seconds", 300))
        self.stop_reason = None
        self.source = source
        self.transport = transport or Transport(target, timeout=float(config.get("timeout", 4)),
                                   max_requests=int(config.get("max_requests", 1000)), interval=float(config.get("interval", 0.01)),
                                   allowed_origins=config.get("scope", {}).get("allowed_origins", []),
                                   ca_file=config.get("scope", {}).get("ca_file"), control=self.control)
        self.browser = BrowserVerifier(browser)
        self.findings: dict[str, Finding] = {}
        self.checks: list[Check] = []
        self.gaps: list[dict] = []
        self.build = {"status": "unverified", "expected": analysis.digest,
                      "reason": "No build identity endpoint configured; source attribution remains provisional because deployment identity is unverified."}
        self.discovered_inputs = []
        self.discovered_pages = []
        self.active_scenario = None
        from .tracing import options as trace_options, TraceTransport
        if trace_options(config.get('trace'))['enabled']:
            self.transport = TraceTransport(self.transport, config['trace'], analysis.digest)
        if config.get('session', {}).get('reauthenticate'):
            from .workflows import SessionGuard
            self.transport = SessionGuard(self.transport, self.config, self.emit)
        from .browser import options as browser_options
        self.browser.options = browser_options(config.get('browser'))
        self.browser.transport = self.transport
        self.template_manifest = {}
        self.http_templates = None
        self.active_template = None
        from .templates.config import options as template_options
        settings = template_options(self.config)
        if settings['mode'] == 'templates':
            from .templates.http import load
            self.http_templates, warnings, self.template_manifest = load(settings['nuclei_templates'])
            self.gaps.extend(warnings)
        from .workflow_state import WorkflowRunner
        self.workflows = WorkflowRunner(self.transport, self.config, self.gaps, self.emit)

    def record(self, check: Check):
        if check.scenario is None: check.scenario = self.active_scenario
        self.checks.append(check)
        self.emit("check", asdict(check))
        if check.outcome in {"inconclusive", "skipped", "error", "template_match"}:
            self.gaps.append(gap("runtime", check.reason, route=check.route, cwe=check.cwe, outcome=check.outcome))

    def request_settings(self, binding):
        if binding.scenario and binding.scenario in self.config.get('_request_scenarios', {}):
            return self.workflows.resolve(self.config['_request_scenarios'][binding.scenario])
        return self.workflows.resolve(self.config.get('requests', {}).get(f'{binding.method} {binding.route}', {}))

    def request(self, binding: Binding, payload=None, identity=None, extra=None):
        self.control.check()
        from .workflows import refresh_form
        settings = self.request_settings(binding)
        settings = refresh_form(self.transport, settings, binding.route, binding.method)
        for name, value in settings.get("cookies", {}).items(): self.transport.set_cookie(name, value)
        preparation = None
        if binding.location == "cookie" and payload is not None:
            from urllib.parse import quote
            self.transport.set_cookie(binding.parameter, quote(str(payload), safe=""))
        if binding.location == "session":
            prepare = settings.get("prepare")
            if not prepare: raise TargetError("Session input requires a configured preparation request.")
            preparation = self.transport.request(prepare["path"], "POST", form={prepare["parameter"]: payload if payload is not None else prepare.get("value", "1")})
            if preparation.status not in {200, 302, 303} or preparation.truncated: raise TargetError("Session preparation failed.")
        csrf = settings.get("csrf")
        if csrf:
            page = self.transport.request(csrf["path"])
            settings.setdefault(csrf.get("location", "form"), {})[csrf["field"]] = csrf_value(page, csrf["field"])
        settings = {k: v for k, v in settings.items() if k in {"query", "form", "json", "headers", "path"}}
        if extra:
            for key, value in extra.items():
                if isinstance(value, dict):
                    settings.setdefault(key, {}).update(value)
        if payload is not None and binding.location not in {"cookie", "session"}:
            key = {"query": "query", "form": "form", "json": "json", "header": "headers", "path": "path"}.get(binding.location)
            if not key or binding.parameter == "*":
                raise TargetError("A concrete supported parameter is required for runtime testing.")
            settings.setdefault(key, {})[binding.parameter] = payload
        response = self.transport.request(binding.route, binding.method, query=settings.get("query"), form=settings.get("form"),
                                      json_body=settings.get("json"), headers=settings.get("headers"), path=settings.get("path"), identity=identity)
        if payload is not None:
            # Record exactly the injected value, including header/path/cookie inputs
            # whose original request metadata deliberately omits sensitive values.
            response.request["tested_input"] = {"location": binding.location, "parameter": binding.parameter,
                                                "value": payload, "route": binding.route, 'scenario': binding.scenario}
        if binding.scenario: response.request['scenario'] = binding.scenario
        if preparation: response.request["preparation"] = preparation.evidence("session input setup")
        return response

    def finding(self, cwe: str, binding: Binding, evidence: list[dict], note: str):
        key = fingerprint("runtime", cwe, binding.route, binding.method, binding.parameter, binding.location)
        if binding.handler == "configured stored-XSS workflow":
            key = fingerprint(key, "stored-write-read")
        title, severity, _ = RULES[cwe]
        finding = self.findings.setdefault(key, Finding(key, "dast", cwe, title, severity, bindings=[binding],
            verification="verified", confidence="runtime evidence", note=note))
        if binding not in finding.bindings: finding.bindings.append(binding)
        finding.evidence.extend(evidence)
        if self.active_template:
            finding.scanner = 'navi-template-proof'
            finding.rule_id = self.active_template.id
            for item in evidence: item.setdefault('template_id', self.active_template.id)
        self.emit("runtime_finding", finding.to_dict())
        return finding

    def check_build(self):
        if self.analysis.digest is None:
            self.build = {"status": "unverified", "expected": None, "reason": "No source supplied; build matching and source correlation are unavailable."}
            self.emit("build", self.build)
            return
        spec = self.config.get("build")
        if not spec:
            self.gaps.append(gap("build", self.build["reason"]))
            self.emit("build", self.build)
            return
        try:
            response = self.transport.request(spec["path"])
            kind = spec.get("kind", "source_digest")
            from .identity import git_revision
            expected = git_revision(self.source) if kind == "git" and self.source else self.analysis.digest if kind == "source_digest" else None
            actual = (response.headers.get(spec["header"].lower()) if spec.get("header") else get_field(response.json(), spec.get("field", "revision" if kind == "git" else "source_digest"))) if response.status == 200 else None
            matched = isinstance(actual, str) and isinstance(expected, str) and secrets.compare_digest(actual, expected)
            status = "matched" if matched else "mismatch" if isinstance(actual, str) else "unverified"
            self.build = {"status": status, "kind": kind, "expected": expected, "observed": actual,
                          "reason": "Application build identity matches the analyzed source." if matched else "Running build could not be matched to this source snapshot; automatic links are withheld."}
        except ScanStopped:
            raise
        except Exception as error:
            self.build = {"status": "unverified", "kind": spec.get("kind", "source_digest"),
                          "reason": f"Build identity check failed ({type(error).__name__}); source links withheld."}
        if self.build["status"] != "matched":
            self.gaps.append(gap("build", self.build["reason"]))
        self.emit("build", self.build)

    def input_seed(self, binding: Binding, default="1"):
        """Use the operator/discovered request value, independent of endpoint names."""
        settings = self.request_settings(binding)
        if binding.location == "session":
            return str(settings.get("prepare", {}).get("value", default))
        location = {"query": "query", "form": "form", "json": "json", "path": "path", "header": "headers", "cookie": "cookies", "session": "prepare"}[binding.location]
        values = settings.get(location, {})
        if binding.location == 'header':
            return str(next((value for name, value in values.items() if name.lower() == binding.parameter.lower()), default))
        return str(values.get(binding.parameter, default))

    def sql(self, binding: Binding):
        seed = self.input_seed(binding)
        baseline = self.request(binding, seed)
        repeat = self.request(binding, seed)
        baseline_body = comparison_body(baseline, seed)
        if baseline.status != 200 or repeat.status != 200 or baseline.truncated or repeat.truncated or baseline_body != comparison_body(repeat, seed):
            return "inconclusive", "SQL comparison requires a stable successful baseline; configure a valid seed.", [baseline.evidence("baseline")]
        nonce = secrets.randbelow(8000) + 1000
        pairs = [(f"{seed}' AND '{nonce}'='{nonce}' -- ", f"{seed}' AND '{nonce}'='{nonce + 1}' -- "),
                 (f"{seed} AND {nonce}={nonce}", f"{seed} AND {nonce}={nonce + 1}"),
                 (f'{seed}" AND "{nonce}"="{nonce}" -- ', f'{seed}" AND "{nonce}"="{nonce + 1}" -- ')]
        observations = [baseline.evidence("baseline")]
        for true_payload, false_payload in pairs:
            true = self.request(binding, true_payload)
            false = self.request(binding, false_payload)
            observations.extend([true.evidence("true condition"), false.evidence("false condition")])
            inputs = (seed, true_payload, false_payload)
            pair_baseline = comparison_body(baseline, seed, inputs)
            true_body, false_body = comparison_body(true, true_payload, inputs), comparison_body(false, false_payload, inputs)
            if true.status == baseline.status and false.status in {200, 404} and true_body == pair_baseline and false_body != true_body and not (true.truncated or false.truncated):
                true2, false2 = self.request(binding, true_payload), self.request(binding, false_payload)
                if true2.status == true.status and false2.status == false.status and comparison_body(true2, true_payload, inputs) == true_body and comparison_body(false2, false_payload, inputs) == false_body and not (true2.truncated or false2.truncated):
                    observations.extend([true2.evidence("repeated true condition"), false2.evidence("repeated false condition")])
                    return "verified", "Repeated boolean SQL conditions changed the result; true controls matched the stable baseline. HTML comparisons omit forms and normalize the reflected submitted input; raw evidence is retained.", observations
        return "not_reproduced", "Supported boolean probes did not establish SQL injection. This does not prove the code safe.", observations

    def xss(self, binding: Binding):
        self.browser.start()
        token = secrets.token_hex(12)
        action = f"document.documentElement.setAttribute('data-navi-proof','{token}')"
        payloads = [f'<svg onload="{action}"></svg>', f'<script>{action}</script>', f'\"><svg onload="{action}"></svg>',
                    f"'><svg onload=\"{action}\"></svg>", f'</textarea><svg onload="{action}"></svg>',
                    f'</option></select><svg onload="{action}"></svg>']
        observations = []
        for variant, payload in zip(["html-event", "script-element", "double-attribute", "single-attribute", "textarea", "select-dom"], payloads):
            response = self.request(binding, payload)
            observations.append({**response.evidence("XSS probe"), "variant": variant})
            if response.truncated or response.headers.get("content-encoding", "identity") not in {"", "identity"}:
                return "inconclusive", "The HTML response was truncated or compressed; complete browser replay was not possible.", observations
            if response.status != 200 or "text/html" not in response.headers.get("content-type", "").lower():
                continue
            # Inline DOM sinks can read the URL even when the marker is absent
            # from server-rendered HTML. Only actual browser execution is proof.
            execution = self.browser.verify(response, token)
            observations[-1]["browser"] = execution
            if execution["executed"]:
                return "verified", "The injected JavaScript executed in isolated Chromium response replay; configured same-origin script fetches use the scoped authenticated transport.", observations
        return "not_reproduced", "No execution observed for reflected or inline DOM probes. Stored XSS and external-script DOM paths need separate flows.", observations

    def traversal(self, binding: Binding):
        fixture = next((f for f in self.config.get("traversal_fixtures", []) if f.get("route") == binding.route
                        and f.get("method", "GET") == binding.method and f.get("parameter") == binding.parameter
                        and f.get("location", "query") == binding.location), None)
        if not fixture or not isinstance(fixture.get("marker"), str) or len(fixture["marker"]) < 12 or not (fixture.get("payload") or fixture.get("payloads")):
            return "inconclusive", "Path verification needs a configured boundary-crossing payload and a unique known test-file marker (at least 12 characters).", []
        marker = fixture["marker"]
        baseline = self.request(binding)
        if marker in baseline.text:
            return "inconclusive", "The configured private-file marker already appears in the baseline; it cannot establish traversal.", [baseline.evidence("baseline")]
        observations = [baseline.evidence("baseline")]
        for index, payload in enumerate(fixture.get("payloads", [fixture.get("payload")])):
            first = self.request(binding, payload)
            observations.append({**first.evidence("boundary-crossing probe"), "variant": f"configured-path-{index+1}"})
            if first.status == 200 and marker in first.text and not first.truncated:
                second = self.request(binding, payload)
                observations.append(second.evidence("repeated probe"))
                if second.status == 200 and marker in second.text and not second.truncated:
                    return "verified", "Repeated requests retrieved the configured marker from the test file outside the permitted directory.", observations
        return "not_reproduced", "The configured traversal variants did not retrieve the private test-file marker.", observations

    def redirect(self, binding: Binding):
        token = secrets.token_hex(8)
        observations = []
        variants = [("absolute", f"https://navi.invalid/proof/{token}"),
                    ("scheme-relative", f"//navi.invalid/proof/{token}")]
        settings = self.request_settings(binding)
        seed = settings.get(binding.location, {}).get(binding.parameter)
        if isinstance(seed, str) and seed.startswith("/") and not seed.startswith("//"):
            parsed = urlsplit(seed)
            variants.append(("observed-destination-path", f"https://navi.invalid{parsed.path}?proof={token}"))
        for variant, payload in variants:
            response = self.request(binding, payload)
            destination = urlsplit(response.headers.get("location", ""))
            observations.append({**response.evidence("redirect destination probe"), "variant": variant})
            if response.status in {301, 302, 303, 307, 308} and destination.hostname == "navi.invalid" and token in (destination.path + destination.query):
                return "verified", "The response accepted an arbitrary external redirect destination. The destination was never requested.", observations
        return "not_reproduced", "Generic external destinations and any observed seed path were not accepted as redirects; untested validation rules may still be vulnerable.", observations

    def command(self, binding: Binding):
        seed = self.input_seed(binding)
        baseline = self.request(binding)
        observations = [baseline.evidence("baseline")]
        if baseline.status != 200 or baseline.truncated:
            return "inconclusive", "Command verification requires a successful baseline.", observations
        for separator in ["; ", "'; ", '\"; ', "|", "\n", "&&", "||"]:
            success = True
            for repeat in range(2):
                marker = "CF_PROOF_" + secrets.token_hex(10)
                encoded = "".join("\\%03o" % ord(char) for char in marker)
                control = self.request(binding, seed + "_navi_control_" + encoded)
                observations.append({**control.evidence("encoded marker without a command"), "negative_control": {"marker_decoded": marker in control.text}})
                if control.truncated or control.status != 200:
                    return "inconclusive", "The non-command decoding control did not return a complete successful response.", observations
                if marker in control.text:
                    return "inconclusive", "The application decoded the marker without a command. Marker output alone cannot establish shell injection here.", observations
                payload = seed + separator + "printf '" + encoded + "' #"
                response = self.request(binding, payload)
                evidence = response.evidence("shell marker probe" if repeat == 0 else "independent marker confirmation")
                evidence["execution_proof"] = {"expected_marker": marker, "marker_in_payload": marker in payload,
                                               "observed": marker in response.text, "operation": "POSIX printf; no file or network side effects"}
                evidence["variant"] = {"|": "pipe", "\n": "newline", "&&": "and", "||": "or"}.get(separator, "separator or quote breakout")
                observations.append(evidence)
                if response.status != 200 or response.truncated or marker not in response.text or marker in baseline.text:
                    success = False; break
            if success:
                return "verified", "Two independent markers were printed by the shell. The decoded markers were absent from the submitted payloads, ruling out plain reflection.", observations
        return "not_reproduced", "Supported POSIX command-separator probes did not produce the execution markers. This does not establish safety for other shell contexts.", observations

    def scan_native(self):
        handlers = {"CWE-89": self.sql, "CWE-79": self.xss, "CWE-22": self.traversal, "CWE-601": self.redirect, "CWE-78": self.command}
        # Native candidates always run first. AI cannot replace or reprioritize
        # baseline coverage, and duplicates discovered at runtime are omitted.
        seen = set()
        candidates = [*native_candidates(self.analysis, self.config, self.discovered_inputs), *self.ai_tests]
        for cwe, binding, skipped in candidates:
            self.active_scenario = binding.scenario
            if self.http_templates is not None:
                from .templates.http import VERIFIERS
                self.active_template = next((t for t in self.http_templates if t.verifier and VERIFIERS[t.verifier] == cwe), None)
                if not self.active_template: continue
            key = (cwe, binding.route, binding.method, binding.location, binding.parameter, binding.scenario)
            if key in seen: continue
            seen.add(key)
            self.control.check()
            if self.transport.count >= self.transport.max_requests and not skipped:
                skipped = 'HTTP request budget exhausted; this test was not run.'
            if skipped:
                self.record(Check(cwe, binding.route, binding.method, binding.parameter, binding.location, "skipped", skipped))
                continue
            self.emit("test_started", {"cwe": cwe, **asdict(binding)})
            try:
                outcome, reason, evidence = handlers[cwe](binding)
            except BrowserUnavailable as error:
                outcome, reason, evidence = "inconclusive", str(error), []
            except ScanStopped:
                raise
            except Exception as error:
                outcome, reason, evidence = "error", f"Verification failed ({type(error).__name__}).", []
            finally:
                self.workflows.close()
            self.record(Check(cwe, binding.route, binding.method, binding.parameter, binding.location, outcome, reason, evidence))
            if outcome == "verified": self.finding(cwe, binding, evidence, reason)
        self.active_template = None
        self.active_scenario = None

    def stored_xss(self):
        for workflow in self.config.get("stored_xss", []):
            write, read, cleanup = (workflow[key] for key in ("write", "read", "cleanup"))
            binding = Binding(write["route"], "POST", write["parameter"], write.get("location", "form"), "configured stored-XSS workflow")
            evidence, outcome, reason = [], "inconclusive", "Stored-XSS prerequisites were not established."
            wrote = False
            interrupted = None
            token = secrets.token_hex(6)
            try:
                if any(method not in self.config.get("allowed_methods", ["GET"]) for method in ["POST", cleanup.get("method", "POST")]):
                    raise TargetError("Stored-XSS write and cleanup methods must be enabled.")
                self.browser.start()  # Do not write anything when browser proof is unavailable.
                reader = Binding(read["route"], "GET", "", "query", "stored output")
                baseline = self.request(reader)
                evidence.append(baseline.evidence("stored-XSS read baseline"))
                if baseline.status != 200 or baseline.truncated or token in baseline.text: raise TargetError("Stored-XSS read baseline is invalid.")
                action = f"document.firstElementChild.dataset.naviProof='{token}'"
                payload = f'<svg onload="{action}">'
                wrote = True
                submitted = self.request(binding, payload)
                evidence.append(submitted.evidence("stored-XSS write; reflection here is not proof"))
                response = self.request(reader)
                evidence.append({**response.evidence("separate stored-XSS read"), "variant": "stored-write-read"})
                if response.status != 200 or response.truncated or "text/html" not in response.headers.get("content-type", ""): raise TargetError("Stored-XSS read did not produce complete HTML.")
                executed = self.browser.verify(response, token)
                evidence[-1]["browser"] = executed
                outcome = "verified" if executed["executed"] else "not_reproduced"
                reason = "Injected JavaScript executed on a separate read after submission; the read request did not carry the marker." if executed["executed"] else "The separate read did not execute the supported stored-XSS probe."
            except (BrowserUnavailable, TargetError) as error:
                reason = str(error)
            except ScanStopped as error:
                interrupted = error
                outcome, reason = "inconclusive", str(error)
            except Exception as error:
                outcome, reason = "error", f"Stored-XSS workflow failed ({type(error).__name__})."
            finally:
                if wrote:
                    # A configured cleanup may complete after cancellation. Limit
                    # this recovery to 15 seconds and at most four extra requests.
                    original_control = self.control
                    transport_control = getattr(self.transport, "control", None)
                    original_budget = getattr(self.transport, "max_requests", None)
                    cleanup_control = ScanControl(15)
                    self.control = cleanup_control
                    if transport_control is not None: self.transport.control = cleanup_control
                    if original_budget is not None: self.transport.max_requests = min(original_budget + 4, self.transport.count + 4)
                    try:
                        cleaned = self.transport.request(cleanup["route"], cleanup.get("method", "POST"), form=cleanup.get("form"), json_body=cleanup.get("json"))
                        evidence.append(cleaned.evidence("configured stored-XSS cleanup"))
                        checked = self.request(Binding(read["route"], "GET", "", "query", "cleanup confirmation"))
                        evidence.append(checked.evidence("cleanup readback"))
                        if cleaned.status not in {200, 204, 302, 303} or checked.status != 200 or token in checked.text:
                            self.gaps.append(gap("cleanup", "Stored-XSS cleanup was not confirmed; inspect the captured test record.", route=read["route"]))
                    except Exception:
                        self.gaps.append(gap("cleanup", "Stored-XSS cleanup failed; inspect the test record.", route=read["route"]))
                    finally:
                        self.control = original_control
                        if transport_control is not None: self.transport.control = transport_control
                        if original_budget is not None: self.transport.max_requests = original_budget
            self.record(Check("CWE-79", binding.route, "POST", binding.parameter, binding.location, outcome, reason, evidence))
            if outcome == "verified": self.finding("CWE-79", binding, evidence, reason)
            if interrupted: raise interrupted

    def authorization(self):
        spec = self.config.get("authorization")
        if not spec:
            self.record(Check("CWE-639", "", "GET", "", "path", "skipped", "No explicit authorization policy supplied; IDOR was not evaluated."))
            return
        identities = spec.get("identities", {})
        if len(identities) < 2 or not spec.get("identity_path") or not spec.get("resources"):
            self.record(Check("CWE-639", "", "GET", "", "path", "inconclusive", "Authorization tests require at least two identities, an identity endpoint, and resource policies."))
            return
        valid = {}
        for name, details in identities.items():
            try:
                response = self.transport.request(spec["identity_path"], headers=details.get("headers", {}), identity=name)
                actual = get_field(response.json(), spec.get("identity_field", "user"))
                if response.status == 200 and actual == details.get("expected_identity", name):
                    valid[name] = details
                else:
                    self.record(Check("CWE-639", spec["identity_path"], "GET", "", "identity", "inconclusive", f"Could not establish effective identity {name}."))
            except ScanStopped:
                raise
            except Exception as error:
                self.record(Check("CWE-639", spec["identity_path"], "GET", "", "identity", "error", f"Identity verification failed for {name}: {error}"))
        for resource in spec.get("resources", []):
            binding = Binding(resource.get("route", ""), resource.get("method", "GET"), resource.get("parameter", ""), resource.get("location", "path"), "")
            allowed = resource.get("allowed")
            expected = resource.get("json_match")
            if binding.method != "GET" or not isinstance(allowed, list) or not allowed or not isinstance(expected, dict) or not expected or resource.get("value") is None or not binding.parameter:
                self.record(Check("CWE-639", binding.route, binding.method, binding.parameter, binding.location, "inconclusive", "Resource policy requires GET, an object reference, allowed identities, and protected JSON field expectations."))
                continue
            if any(name not in valid for name in allowed) or len(valid) != len(identities):
                self.record(Check("CWE-639", binding.route, binding.method, binding.parameter, binding.location, "inconclusive", "Not all identities required by the access matrix were verified."))
                continue
            try:
                def matches(response):
                    if response.status != 200 or response.truncated:
                        return False
                    try:
                        body = response.json()
                        return all(get_field(body, key) == value for key, value in expected.items())
                    except (ValueError, TypeError):
                        return False
                baseline_evidence = []
                good = True
                for name in allowed:
                    response = self.request(binding, resource["value"], identity=name, extra={"headers": valid[name].get("headers", {})})
                    baseline_evidence.append(response.evidence(f"permitted baseline: {name}"))
                    good = good and matches(response)
                if not good:
                    self.record(Check("CWE-639", binding.route, binding.method, binding.parameter, binding.location, "inconclusive", "A permitted identity could not retrieve the expected protected object; access baselines are invalid.", baseline_evidence))
                    continue
                forbidden = [name for name in valid if name not in allowed]
                if not forbidden:
                    self.record(Check("CWE-639", binding.route, binding.method, binding.parameter, binding.location, "not_reproduced", "All configured identities are deliberately permitted for this resource; sharing matched the policy.", baseline_evidence))
                for name in forbidden:
                    response = self.request(binding, resource["value"], identity=name, extra={"headers": valid[name].get("headers", {})})
                    evidence = [*baseline_evidence, response.evidence(f"forbidden identity: {name}")]
                    policy = {"allowed": allowed, "requester": name, "protected_fields": list(expected), "object": resource["value"]}
                    evidence[-1]["policy"] = policy
                    if matches(response):
                        reason = "A verified identity outside the allowed policy received the expected protected object fields."
                        self.finding("CWE-639", binding, evidence, reason)
                        self.record(Check("CWE-639", binding.route, binding.method, binding.parameter, binding.location, "verified", reason, evidence))
                    elif response.status in {401, 403, 404}:
                        self.record(Check("CWE-639", binding.route, binding.method, binding.parameter, binding.location, "not_reproduced", "The forbidden identity was denied access in this scenario.", evidence))
                    else:
                        self.record(Check("CWE-639", binding.route, binding.method, binding.parameter, binding.location, "inconclusive", "The response did not expose the expected object, but explicit denial was not established.", evidence))
            except ScanStopped:
                raise
            except Exception as error:
                self.record(Check("CWE-639", binding.route, binding.method, binding.parameter, binding.location, "error", f"Authorization test failed: {error}"))

    def run(self):
        try:
            self.control.check()
            try:
                authenticate(self.transport, self.config)
                from .workflows import SessionGuard
                if isinstance(self.transport, SessionGuard): self.transport.active = True
            except (OSError, ValueError) as error:
                self.gaps.append(gap("authentication", f"Authenticated scan not run: {type(error).__name__}. Login prerequisites failed."))
                return []
            self.check_build()
            source_paths = [r.path for r in self.analysis.routes if r.provenance != "configured" and "<" not in r.path]
            self.discovered_inputs, self.discovered_pages, discovery_gaps = discover(self.transport, self.config, source_paths, routes=self.analysis.routes)
            self.gaps.extend(discovery_gaps)
            for workflow in self.config.get('workflows', []):
                if not self.config.get('discovery', {}).get('enabled'): break
                try:
                    from .route_inputs import concrete_route
                    state = self.workflows.start(workflow['id'])
                    selected = {**workflow, 'page': concrete_route(workflow['page'], state), '_state': state}
                    inputs, pages, gaps = discover(self.transport, self.config, workflow=selected, routes=self.analysis.routes)
                    self.discovered_inputs.extend(inputs); self.discovered_pages.extend(pages); self.gaps.extend(gaps)
                except (ValueError, OSError) as error:
                    self.gaps.append(gap('workflow', str(error), workflow=workflow['id']))
                finally:
                    self.workflows.close()
            if self.config.get("discovery", {}).get("enabled"):
                self.emit("discovery", {"pages": len(self.discovered_pages), "inputs": len(self.discovered_inputs)})
            self.scan_native()
            if self.http_templates is not None:
                from .templates.http import execute
                execute(self, self.http_templates)
            if not self.checks:
                self.gaps.append(gap("discovery", "No native test inputs were found. Supply an OpenAPI JSON file, configured runtime_inputs, or reachable HTML forms/links."))
            self.stored_xss()
            if self.config.get('authorization'): self.authorization()
        except ScanStopped as error:
            self.stop_reason = error.kind
            self.gaps.append(gap("control", str(error)))
            self.emit("scan_stopped", {"reason": error.kind})
        finally:
            self.workflows.close()
            self.browser.close()
        return list(self.findings.values())
