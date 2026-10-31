import hashlib
import re
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import httpx

from app.analysis.routemap import RouteEvidence
from app.analysis.types import FindingInput

MAX_REQUESTS = 150
MAX_RESPONSE_BYTES = 65_536
MAX_EXCERPT_CHARS = 2_000
TIMEOUT_SECONDS = 5.0
SENSITIVE_PARAM = re.compile(r"password|secret|token|auth|cookie|key", re.I)
SQL_ERROR = re.compile(r"SQLSTATE|SQL syntax|PDOException|mysql_.*error|syntax error.*SQL", re.I)


def _normalize_origin(value: str) -> str:
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("target must be a valid configured HTTP origin") from exc
    if (
        parsed.scheme != "http" or not host or parsed.username is not None or parsed.password is not None
        or parsed.path not in ("", "/") or parsed.query or parsed.fragment
    ):
        raise ValueError("target must be a plain HTTP origin")
    host = host.lower().rstrip(".")
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"
    return urlunsplit(("http", netloc, "", "", ""))


def validate_target_url(requested: str, configured: str) -> str:
    allowed = _normalize_origin(configured)
    target = _normalize_origin(requested)
    if target != allowed:
        raise ValueError("target origin must match the configured local application")
    return target


def _route_url_path(path: str) -> str:
    parsed = urlsplit(path)
    if (
        not path.startswith("/") or parsed.scheme or parsed.netloc or parsed.query or parsed.fragment
        or "\\" in path or any(ord(char) < 32 for char in path)
    ):
        raise ValueError("route path is not an in-origin absolute path")
    return parsed.path


def _redact(text: str) -> str:
    return re.sub(r"(?i)(password|token|secret|api[_-]?key)([\"'=:\s]+)([^&\s<>\"']+)", r"\1\2[REDACTED]", text)



async def _response(client: httpx.AsyncClient, url: str, parameter: str, payload: str):
    async with client.stream("GET", url, params={parameter: payload}) as response:
        body = bytearray()
        async for chunk in response.aiter_bytes():
            remaining = MAX_RESPONSE_BYTES - len(body)
            body.extend(chunk[:remaining])
            if len(chunk) > remaining or len(body) >= MAX_RESPONSE_BYTES:
                break
        truncated = len(body) >= MAX_RESPONSE_BYTES
        text = _redact(bytes(body).decode("utf-8", errors="replace"))
        return response, text, truncated

def _probe(cwe: int, marker: str) -> str:
    return {
        89: "'",
        79: f"<script>{marker}</script>",
        78: f";printf {marker}",
        22: "../index.php",
        601: f"http://example.invalid/{marker}",
    }[cwe]


def _oracle(cwe: int, payload: str, marker: str, body: str, headers: httpx.Headers,
            origin: str, baseline_body: str) -> tuple[str | None, str]:
    if cwe == 89 and SQL_ERROR.search(body) and not SQL_ERROR.search(baseline_body):
        match = SQL_ERROR.search(body)
        return match.group(0) if match else "SQL error response", "quote probe caused a new database error response"
    if cwe == 79 and payload in body:
        return payload, "unescaped script probe reflected in response body"
    if cwe == 78 and marker in body and payload not in body:
        return marker, "benign printf marker returned without reflecting the command probe"
    if cwe == 22 and "<?php" in body:
        return "PHP source marker returned", "path probe returned PHP source text"
    if cwe == 601:
        location = headers.get("location")
        if location and marker in location and _is_off_origin(location, origin):
            return location[:500], "probe-controlled off-origin redirect; redirect was not followed"
    return None, "probe produced no vulnerability-specific response evidence"


async def scan_dast(
    routes: list[RouteEvidence],
    target_origin: str,
    allowed_target_origin: str,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> tuple[list[FindingInput], dict, list[dict[str, str]], set[tuple[str, str]]]:
    origin = validate_target_url(target_origin, allowed_target_origin)
    findings: list[FindingInput] = []
    errors: list[dict[str, str]] = []
    tested: set[tuple[str, str]] = set()
    counts = {"requests": 0, "routes_tested": 0, "params_tested": 0, "blocked": 0, "timeouts": 0}
    seen_routes: set[tuple[str, str]] = set()
    rules_not_run = [{"rule": "CWE-798", "reason": "hard-coded secrets are source-only"}]
    marker_prefix = f"CF{uuid4().hex[:10]}"

    async with httpx.AsyncClient(
        transport=transport,
        timeout=TIMEOUT_SECONDS,
        follow_redirects=False,
        trust_env=False,
        headers={"User-Agent": "Navi-local-security-test/0.1"},
    ) as client:
        for route in routes:
            try:
                route_path = _route_url_path(route.path)
            except ValueError:
                counts["blocked"] += 1
                continue
            if route.method != "GET" or route.handler is None or route.confidence == "low":
                continue
            route_path = re.sub(r"\{[A-Za-z_][A-Za-z0-9_]*\}", "1", route_path)
            params = [param for param in route.params if param and not SENSITIVE_PARAM.search(param)]
            for parameter in params:
                counts["params_tested"] += 1
                route_key = (route.method, route.path)
                url = origin + route_path
                baseline_body = ""
                baseline_ready = False
                if counts["requests"] < MAX_REQUESTS:
                    counts["requests"] += 1
                    try:
                        response, baseline_body, _ = await _response(
                            client, url, parameter, f"{marker_prefix}BASE",
                        )
                        baseline_ready = True
                        tested.add(route_key)
                        seen_routes.add(route_key)
                        if response.status_code in {301, 302, 303, 307, 308}:
                            destination = response.headers.get("location", "")
                            if destination and _is_off_origin(destination, origin):
                                counts["blocked"] += 1
                    except httpx.TimeoutException:
                        counts["timeouts"] += 1
                        errors.append({"stage": "dast", "message": f"baseline timeout for {route.method} {route.path}"})
                    except httpx.HTTPError as exc:
                        errors.append({"stage": "dast", "message": f"baseline {type(exc).__name__} for {route.method} {route.path}"})
                else:
                    rules_not_run.append({"rule": "CWE-89", "reason": "no request budget for SQL error baseline"})
                    break

                for cwe in (89, 79, 78, 22, 601):
                    if counts["requests"] >= MAX_REQUESTS:
                        rules_not_run.append({"rule": f"CWE-{cwe}", "reason": "per-scan request limit reached"})
                        break
                    if cwe == 89 and not baseline_ready:
                        rules_not_run.append({"rule": "CWE-89", "reason": "baseline response unavailable"})
                        continue
                    marker = f"{marker_prefix}{cwe}"
                    payload = _probe(cwe, marker)
                    counts["requests"] += 1
                    try:
                        response, response_text, truncated = await _response(client, url, parameter, payload)
                        tested.add(route_key)
                        seen_routes.add(route_key)
                        evidence, oracle = _oracle(
                            cwe, payload, marker, response_text, response.headers, origin, baseline_body,
                        )
                        if response.status_code in {301, 302, 303, 307, 308}:
                            destination = response.headers.get("location", "")
                            if destination and _is_off_origin(destination, origin):
                                counts["blocked"] += 1
                        if evidence is None:
                            continue
                        title = {
                            89: "SQL injection response evidence",
                            79: "Unescaped reflected script input",
                            78: "Command injection response evidence",
                            22: "Path traversal source disclosure evidence",
                            601: "Open redirect response evidence",
                        }[cwe]
                        severity = "critical" if cwe == 78 else "high" if cwe in {89, 79, 22} else "medium"
                        risk = {89: 75, 79: 70, 78: 90, 22: 75, 601: 55}[cwe]
                        request_path = response.request.url.path
                        fingerprint = hashlib.sha256(
                            f"{cwe}|{route.method}|{route.path}|{parameter}".encode()
                        ).hexdigest()
                        findings.append(FindingInput(
                            source="dast", cwe=cwe, title=title, severity=severity, risk=risk,
                            fingerprint=fingerprint, route={"method": route.method, "path": route.path},
                            location=None,
                            dast={
                                "rule_id": f"CWE-{cwe}-DAST",
                                "method": "GET",
                                "url": origin + request_path,
                                "parameter": parameter,
                                "payload": payload,
                                "request": f"GET {request_path}?{parameter}=[probe]",
                                "response": {
                                    "status": response.status_code,
                                    "excerpt": response_text[:MAX_EXCERPT_CHARS],
                                    "truncated": truncated or len(response_text) > MAX_EXCERPT_CHARS,
                                },
                                "evidence": evidence,
                                "oracle": oracle,
                            },
                        ))
                    except httpx.TimeoutException:
                        counts["timeouts"] += 1
                        errors.append({"stage": "dast", "message": f"timeout probing {route.method} {route.path}"})
                    except httpx.HTTPError as exc:
                        errors.append({"stage": "dast", "message": f"{type(exc).__name__} probing {route.method} {route.path}"})
                if counts["requests"] >= MAX_REQUESTS:
                    break
            if counts["requests"] >= MAX_REQUESTS:
                break

    counts["routes_tested"] = len(seen_routes)
    coverage = {**counts, "rules_not_run": rules_not_run}
    return findings, coverage, errors, tested


def _is_off_origin(location: str, origin: str) -> bool:
    try:
        parsed = urlsplit(location)
        if not parsed.scheme and not parsed.netloc:
            return False
        absolute = _normalize_origin(f"{parsed.scheme}://{parsed.netloc}")
    except ValueError:
        return True
    return absolute != origin
