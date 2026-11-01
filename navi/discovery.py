"""Bounded same-application link/form discovery and HTML response comparison."""

from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, parse_qsl, unquote
import re

from .model import Binding, gap
from .transport import TargetError


TOKEN_FIELDS = {"user_token", "csrf_token", "_csrf", "_token", "csrfmiddlewaretoken"}


class Page(HTMLParser):
    def __init__(self, html):
        super().__init__(convert_charrefs=True)
        self.links, self.forms, self.hidden, self.text = [], [], {}, []
        self.form = None
        self.suppressed = 0
        self.select = None
        self.textarea = None
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
        if tag == "form":
            self.form = {"action": attrs.get("action", ""), "method": attrs.get("method", "GET").upper(), "id": attrs.get('id'), "fields": {}, "candidates": [], "tokens": [], 'hidden': []}
            self.forms.append(self.form)
        if tag in {"form", "script", "style"}: self.suppressed += 1
        name = attrs.get("name")
        if tag == "input" and attrs.get("type", "").lower() == "hidden" and name:
            self.hidden[name] = attrs.get("value", "")
        if not self.form: return
        if tag == "select": self.select = name
        if tag == "option" and self.select:
            if self.select not in self.form["fields"] or "selected" in attrs:
                self.form["fields"][self.select] = attrs.get("value", "")
            if self.select not in self.form["candidates"]: self.form["candidates"].append(self.select)
        if tag not in {"input", "textarea", "button"} or not name or "disabled" in attrs: return
        kind = attrs.get("type", "text").lower()
        if kind in {"file", "reset", "button"}: return
        if kind in {"checkbox", "radio"} and "checked" not in attrs: return
        if kind == "submit" or tag == "button":
            # Only one submit control belongs to a browser submission. Never
            # combine "Sign" and "Clear", which would change the operation.
            if self.form.get("submit_selected") or re.search(r"clear|delete|reset|remove", name, re.I): return
            self.form["submit_selected"] = True
        self.form["fields"][name] = attrs.get("value", "1" if kind == "number" else "")
        if kind == 'hidden': self.form['hidden'].append(name)
        if tag == "textarea": self.textarea = name
        if name.lower() in TOKEN_FIELDS:
            self.form["tokens"].append(name)
        elif kind not in {"hidden", "submit", "password"} and tag != "button":
            self.form["candidates"].append(name)

    def handle_endtag(self, tag):
        if tag == "form": self.form = None
        if tag == "select": self.select = None
        if tag == "textarea": self.textarea = None
        if tag in {"form", "script", "style"}: self.suppressed = max(0, self.suppressed - 1)

    def handle_data(self, data):
        if self.form and self.textarea:
            self.form['fields'][self.textarea] += data
        if not self.suppressed and data.strip(): self.text.append(data.strip())


def local_reference(target, current, reference):
    """Return an application-relative path/query, never a different origin or base."""
    base, result = urlsplit(target), urlsplit(urljoin(current, reference))
    if (result.scheme, result.netloc) != (base.scheme, base.netloc) or result.username or result.password:
        return None
    prefix = base.path.rstrip("/")
    if prefix and not (result.path == prefix or result.path.startswith(prefix + "/")): return None
    path = result.path[len(prefix):] or "/"
    if any(part in {"..", "."} for part in unquote(path).split("/")) or any(c in path for c in "\r\n?#"):
        return None
    return path, dict(parse_qsl(result.query, keep_blank_values=True))


def discover(transport, config, source_paths=(), workflow=None, routes=()):
    from copy import deepcopy
    from .model import fingerprint
    from .workflows import form_signature
    from .route_inputs import route_match
    spec = config.get("discovery", {})
    if not spec.get("enabled"): return [], [], []
    queue = [(path, {}) for path in ([workflow['page']] if workflow else spec.get("paths", ["/"]))]
    pending_source = [(path, {}) for path in dict.fromkeys(source_paths)]
    allowed_prefixes = spec.get("prefixes", ["/"])
    max_pages, max_candidates = spec.get("max_pages", 30), spec.get("max_candidates", 60)
    visited, candidates, pages, gaps = set(), {}, [], []
    discovered_settings = {}
    explicit_settings = deepcopy(config.get('requests', {})) if not workflow else config.get('_explicit_requests', {})
    config.setdefault('_explicit_requests', explicit_settings)
    def permitted(path):
        return (any(path.startswith(prefix) for prefix in allowed_prefixes)
                and not re.search(r"(?:^|/)(?:logout|setup|reset|delete|remove)(?:[./]|$)", path, re.I))
    def candidate(route, method, name, location, settings, scenario=None):
        if name.lower() in TOKEN_FIELDS or len(candidates) >= max_candidates: return
        route, path_values = route_match(routes, route, method)
        if path_values:
            settings = {**settings, 'path': {**settings.get('path', {}), **path_values}}
            scenario = scenario or fingerprint('path', route, method, path_values, settings.get('query', {}))
        if workflow and workflow.get('_state'):
            from .workflow_state import bind_values, bind_path
            settings = deepcopy(settings)
            for component in ('path', 'query', 'form', 'json'):
                if component in settings: settings[component] = bind_values(settings[component], workflow['_state'])
            if settings.get('form_refresh'):
                refresh = settings['form_refresh']
                refresh['path'] = bind_path(refresh['path'], workflow['_state'])
                refresh.pop('signature', None)  # Action IDs change; action/method are checked after refresh.
            settings['workflow'] = {'id': workflow['id']}
        binding = Binding(route, method, name, location, "discovered form or query", provenance="http-discovery", scenario=scenario)
        candidate_key = (route, method, location, name, scenario)
        if candidate_key in candidates: return
        candidates[candidate_key] = binding
        key = (route, method)
        overrides = explicit_settings.get(f'{method} {route}', {})
        selected = deepcopy(settings)
        for component, data in overrides.items():
            selected[component] = {**selected.get(component, {}), **data}
        if scenario:
            config.setdefault('_request_scenarios', {})[scenario] = selected
        if key in discovered_settings: return
        discovered_settings[key] = settings
        seed = config.setdefault("requests", {}).setdefault(f"{method} {route}", {})
        for component, data in settings.items():
            # Explicit seeds take precedence over discovered defaults.
            seed[component] = {**data, **seed.get(component, {})}
    def path_candidates(path, method, settings, scenario=None):
        _, values = route_match(routes, path, method)
        for name in values: candidate(path, method, name, 'path', settings, scenario)
    while (queue or pending_source) and len(visited) < max_pages:
        if not queue: queue.append(pending_source.pop(0))
        route, query = queue.pop(0)
        key = (route, tuple(sorted(query.items())))
        if key in visited or not permitted(route): continue
        visited.add(key)
        try:
            response = transport.request(route, query=query)
            pages.append({"route": route, "status": response.status, **({'workflow': workflow['id']} if workflow else {})})
            if response.status in {301, 302, 303, 307, 308}:
                local = local_reference(transport.target, response.url, response.headers.get("location", ""))
                if local and permitted(local[0]): queue.append(local)
                else: gaps.append(gap("discovery", "Redirect leaves application scope; it was not followed.", route=route))
                continue
            if response.status != 200 or response.truncated or "text/html" not in response.headers.get("content-type", ""):
                gaps.append(gap("discovery", "Page was not successful complete HTML; its forms were not discovered.", route=route))
                continue
            page = Page(response.text)
            path_candidates(route, 'GET', {'query': query})
            for name in query: candidate(route, "GET", name, "query", {"query": query})
            for link in page.links:
                local = local_reference(transport.target, response.url, link)
                if local and permitted(local[0]):
                    path_candidates(local[0], 'GET', {'query': local[1]})
                    for name in local[1]: candidate(local[0], "GET", name, "query", {"query": local[1]})
                    if len(queue) < max_pages * 10: queue.append(local)
            for index, form in enumerate(page.forms):
                local = local_reference(transport.target, response.url, form["action"])
                if not local or not permitted(local[0]) or form["method"] not in config.get("allowed_methods", ["GET"]): continue
                if form["method"] not in {"GET", "POST"}: continue
                location = "query" if form["method"] == "GET" else "form"
                settings = {location: dict(form["fields"])}
                if local[1]: settings["query"] = {**local[1], **settings.get("query", {})}
                # Refresh every hidden control, regardless of its name. Each form
                # keeps a separate scenario instead of borrowing another's values.
                selector = {'path': route, 'query': query, 'index': index, 'id': form.get('id'), 'signature': form_signature(form),
                            'overrides': explicit_settings.get(f"{form['method']} {local[0]}", {})}
                # Identify the submission, not the URL/index where the form was
                # found. / and /index.php commonly expose the exact same form.
                stable_fields = {name: value for name, value in form['fields'].items()
                                 if name.lower() not in TOKEN_FIELDS and not re.search(r'csrf|xsrf|nonce|token', name, re.I)}
                scenario = fingerprint('form', workflow['id'] if workflow else None, local, form['method'], stable_fields)
                settings['form_refresh'] = selector
                if workflow: settings['workflow'] = {'id': workflow['id']}
                path_candidates(local[0], form['method'], settings, scenario)
                for name in form["candidates"]: candidate(local[0], form["method"], name, location, settings, scenario)
        except (OSError, ValueError) as error:
            gaps.append(gap("discovery", f"Discovery stopped for a page ({type(error).__name__}).", route=route))
    if queue or pending_source: gaps.append(gap("discovery", "Page discovery limit reached; remaining links/source scripts were not visited."))
    if len(candidates) >= max_candidates: gaps.append(gap("discovery", "Input discovery limit reached; further inputs were not scheduled."))
    return list(candidates.values()), pages, gaps


def comparison_body(response, submitted, common_values=()):
    """Compare result text without forms/CSRF or a reflected submitted input.

    Raw evidence is retained. Reflection alone collapses to the same value for
    baseline/true/false; it cannot satisfy the independent result differential.
    """
    if "text/html" not in response.headers.get("content-type", "").lower(): return response.body
    text = "\n".join(Page(response.text).text)
    # HTMLParser trims each text node. Trim payloads too, including SQL's
    # required trailing comment space, and normalize the SAME input set in
    # baseline/true/false responses. Otherwise a seed like "1" can corrupt
    # unrelated version/count text in just the baseline and hide a valid proof.
    values = sorted({str(v).strip() for v in (submitted, *common_values) if str(v).strip()}, key=lambda v: (-len(v), v))
    if values:
        expression = r"(?<![\w.])(?:" + "|".join(re.escape(v) for v in values) + r")(?![\w.])"
        text = re.sub(expression, "[submitted input]", text)
    return text.encode()


def csrf_value(response, field):
    if response.status != 200 or response.truncated:
        raise TargetError("Could not fetch a complete CSRF form.")
    value = Page(response.text).hidden.get(field)
    if not value: raise TargetError("Configured CSRF field was absent; the request was not submitted.")
    return value


def authenticate(transport, config):
    session = config.get("session", {})
    login = session.get("login")
    for name, value in session.get("cookies", {}).items(): transport.set_cookie(name, value)
    if login:
        form = dict(login.get("form", {}))
        first = transport.request(login["path"])
        matching = [f for f in Page(first.text).forms if set(form) <= set(f['fields']) and f['method'] == 'POST'
                    and (local_reference(transport.target, first.url, f['action']) or (None,))[0] == login['path']]
        if len(matching) == 1:
            form = {**matching[0]['fields'], **form}
        elif len(matching) > 1:
            raise TargetError('Several login forms match the supplied fields; supply unambiguous login controls.')
        if login.get("csrf_field"): form[login["csrf_field"]] = csrf_value(first, login["csrf_field"])
        transport.request(login["path"], "POST", form=form)
        verified = transport.request(login["verify_path"])
        if verified.status != 200 or verified.truncated or login["success_contains"] not in verified.text:
            raise TargetError("Login could not be verified; authenticated tests were not run.")
