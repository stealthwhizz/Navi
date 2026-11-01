"""Scoped HTTP(S) transport with address pinning, verified TLS, and no redirects."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import http.client
from http.cookiejar import CookieJar, Cookie
from email.message import Message
import ipaddress
import json
import socket
import ssl
import time
import posixpath
from urllib.parse import quote, urlencode, urlsplit, unquote
from urllib.request import Request
from .control import ScanControl


MAX_BODY = 1_000_000


class TargetError(ValueError):
    pass


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes
    url: str
    elapsed_ms: int
    request: dict = field(default_factory=dict)
    truncated: bool = False
    trace: dict | None = None

    @property
    def text(self):
        return self.body.decode("utf-8", errors="replace")

    def json(self):
        return json.loads(self.body)

    def evidence(self, label: str = "observation") -> dict:
        return {
            "label": label, "request": self.request, "status": self.status,
            "response_headers": {k: v for k, v in self.headers.items() if k in {"content-type", "location", "content-security-policy", "x-frame-options"}},
            "body_excerpt": self.text[:1600], "body_sha256": hashlib.sha256(self.body).hexdigest(),
            "body_bytes": len(self.body), "truncated": self.truncated, "elapsed_ms": self.elapsed_ms,
            **({'trace': self.trace} if self.trace is not None else {}),
        }


def origin(target):
    parsed = urlsplit(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise TargetError("Use an HTTP(S) target without URL credentials.")
    if any(ord(char) <= 32 or char == "\\" for char in target):
        raise TargetError("Target origin cannot contain whitespace or backslash.")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return parsed.scheme, parsed.hostname.lower(), port


def decoded_path(path):
    for _ in range(8):
        decoded = unquote(path)
        if decoded == path: break
        path = decoded
    else:
        raise TargetError("Request path contains excessive nested encoding.")
    if any(ord(char) < 32 or char == "\\" for char in path):
        raise TargetError("Request path contains an encoded control or backslash.")
    return path


def validate_target(target: str, allowed_origins=()) -> tuple[str, int, str, str]:
    try:
        parsed = urlsplit(target)
        identity = origin(target)
        if parsed.query or parsed.fragment or any(ord(char) <= 32 or char == "\\" for char in target):
            raise TargetError("Target URL cannot contain a query, fragment, whitespace, or backslash.")
        if any(part in {".", ".."} for part in decoded_path(parsed.path).split("/")):
            raise TargetError("Target base path cannot contain traversal segments.")
        port = identity[2]
        addresses = {item[4][0] for item in socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)}
        if not addresses: raise TargetError("Target did not resolve to an address.")
        local = all(ipaddress.ip_address(address).is_loopback for address in addresses)
        explicit = identity in {origin(value) for value in allowed_origins}
        if not local and not explicit:
            raise TargetError("Non-loopback targets require their exact origin in scope.allowed_origins.")
        if not local and any(ipaddress.ip_address(address).is_loopback or ipaddress.ip_address(address).is_link_local
                             or ipaddress.ip_address(address).is_multicast or ipaddress.ip_address(address).is_unspecified for address in addresses):
            raise TargetError("Target resolves to a mixed local, link-local, multicast, or unspecified address.")
        # Use this numeric address for all connections; never resolve the hostname again.
        pinned = sorted(addresses, key=lambda a: (":" in a, a))[0]
        return pinned, port, parsed.netloc, parsed.path.rstrip("/")
    except (OSError, ValueError) as error:
        if isinstance(error, TargetError):
            raise
        raise TargetError(f"Invalid target: {error}") from error


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, address, port, *, server_hostname, timeout, context):
        super().__init__(address, port, timeout=timeout, context=context)
        self.server_hostname = server_hostname

    def connect(self):
        # Connect only to the pinned IP, but verify the certificate for the
        # configured hostname and send that hostname as TLS SNI.
        http.client.HTTPConnection.connect(self)
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.server_hostname)


class Transport:
    def __init__(self, target: str, timeout: float = 4.0, max_requests: int = 250, interval: float = 0.01,
                 allowed_origins=(), ca_file=None, control=None):
        self.address, self.port, self.host, self.base_path = validate_target(target, allowed_origins)
        self.scheme = urlsplit(target).scheme
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.max_requests = max_requests
        self.interval = interval
        self.count = 0
        self.cookies = CookieJar()
        self.control = control or ScanControl()
        self.tls_context = ssl.create_default_context(cafile=ca_file) if self.scheme == "https" else None

    def set_cookie(self, name, value):
        host = urlsplit(self.target).hostname
        self.cookies.set_cookie(Cookie(0, name, str(value), None, False, host, False, False,
                                      self.base_path or "/", True, False, None, True, None, None, {}))

    def request(self, route: str, method: str = "GET", *, query=None, form=None, json_body=None,
                headers=None, path=None, identity: str | None = None, raw_body=None) -> Response:
        self.control.check()
        if self.count >= self.max_requests:
            raise TargetError(f"Request budget exhausted ({self.max_requests}).")
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}:
            raise TargetError(f"Unsupported HTTP method: {method}")
        if not isinstance(route, str) or not route.startswith("/") or route.startswith("//") or any(c in route for c in "\r\n?#\\"):
            raise TargetError("Route must be an absolute local path without a query or fragment.")
        import re
        path = path or {}
        def substitute(match):
            name = match.group(1).split(":")[-1]
            if name not in path:
                raise TargetError(f"A path value is required for {name} on {route}.")
            return quote(str(path[name]), safe="")
        route_path = re.sub(r"<([^<>]+)>", substitute, route)
        url_path = self.base_path + route_path
        if self.base_path:
            decoded = posixpath.normpath(decoded_path(url_path))
            base = posixpath.normpath(decoded_path(self.base_path))
            if decoded != base and not decoded.startswith(base + "/"):
                raise TargetError("Request path would escape the configured application base path.")
        if query:
            url_path += "?" + urlencode(query, doseq=True)
        supplied = {str(k): str(v) for k, v in (headers or {}).items()}
        if any(k.lower() in {"host", "content-length", "transfer-encoding", "connection", "proxy-authorization"} for k in supplied):
            raise TargetError("Transport control headers cannot be overridden.")
        request_headers = {"Host": self.host, "User-Agent": "Navi/0.4 verification", "Accept-Encoding": "identity", **supplied}
        url = f"{self.scheme}://{self.host}{url_path}"
        cookie_request = Request(url, headers=request_headers)
        self.cookies.add_cookie_header(cookie_request)
        if cookie_request.has_header("Cookie"):
            request_headers = {key: value for key, value in request_headers.items() if key.lower() != "cookie"}
            request_headers["Cookie"] = cookie_request.get_header("Cookie")
        body = None
        if raw_body is not None:
            if form is not None or json_body is not None: raise TargetError('Choose raw, form or JSON request body.')
            if not isinstance(raw_body, (str, bytes)) or len(raw_body) > 65536: raise TargetError('Template request body exceeds its size limit.')
            body = raw_body.encode() if isinstance(raw_body, str) else raw_body
        elif json_body is not None:
            body = json.dumps(json_body).encode()
            request_headers["Content-Type"] = "application/json"
        elif form is not None:
            body = urlencode(form, doseq=True).encode()
            request_headers["Content-Type"] = "application/x-www-form-urlencoded"
        self.count += 1
        if self.interval:
            self.control.wait(self.interval)
        started = time.monotonic()
        timeout = min(self.timeout, self.control.remaining())
        connection = (PinnedHTTPSConnection(self.address, self.port, timeout=timeout,
                      server_hostname=urlsplit(self.target).hostname, context=self.tls_context) if self.scheme == "https"
                      else http.client.HTTPConnection(self.address, self.port, timeout=timeout))
        try:
            connection.request(method, url_path, body=body, headers=request_headers)
            response = connection.getresponse()
            chunks, size = [], 0
            while size <= MAX_BODY:
                self.control.check()
                if getattr(connection, "sock", None): connection.sock.settimeout(min(self.timeout, self.control.remaining()))
                chunk = response.read1(min(65536, MAX_BODY + 1 - size))
                if not chunk: break
                chunks.append(chunk); size += len(chunk)
            data = b"".join(chunks)
            response_headers = {}
            raw_headers = response.getheaders()
            cookie_headers = Message()
            for key, value in raw_headers:
                cookie_headers.add_header(key, value)
            class CookieResponse:
                def info(self): return cookie_headers
            self.cookies.extract_cookies(CookieResponse(), cookie_request)
            for key, value in raw_headers:
                key = key.lower()
                if key in response_headers and key in {"content-security-policy", "content-security-policy-report-only"}:
                    response_headers[key] += ", " + value
                else:
                    response_headers[key] = value
            return Response(response.status, response_headers, data[:MAX_BODY],
                            url, int((time.monotonic() - started) * 1000),
                            {"method": method, "url": url, "query": query or {}, "form": form,
                             "json": json_body, **({'body': raw_body.decode(errors='replace') if isinstance(raw_body, bytes) else raw_body} if raw_body is not None else {}), "headers": {k: "[redacted]" for k in [*supplied, *(["Cookie"] if "Cookie" in request_headers else [])]}, "identity": identity},
                            len(data) > MAX_BODY)
        finally:
            connection.close()
