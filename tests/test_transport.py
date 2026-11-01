import io
import socket

import pytest

from navi.transport import TargetError, Transport, validate_target


@pytest.mark.parametrize("target", ["http://192.168.1.1", "http://8.8.8.8", "http://user:pass@127.0.0.1", "http://127.0.0.1/?x=1", "file:///tmp/test", "http://127.0.0.1/#fragment"])
def test_scope_rejects_nonlocal_or_unsupported_targets(target):
    with pytest.raises(TargetError):
        validate_target(target)


def test_mixed_dns_answers_are_rejected(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(2,1,6,"",("127.0.0.1",80)),(2,1,6,"",("8.8.8.8",80))])
    with pytest.raises(TargetError):
        validate_target("http://localhost")


def test_address_pinned_and_redirect_not_followed(monkeypatch):
    requests = []
    class Connection:
        def __init__(self, address, port, **kwargs):
            assert address == "127.0.0.1"
        def request(self, method, url, **kwargs):
            requests.append((method, url, kwargs))
        def getresponse(self):
            result = io.BytesIO(b"redirect")
            result.status = 302
            result.getheaders = lambda: [("Location", "https://elsewhere.invalid/")]
            return result
        def close(self):
            pass
    monkeypatch.setattr("navi.transport.http.client.HTTPConnection", Connection)
    transport = Transport("http://127.0.0.1:5050", interval=0)
    response = transport.request("/go", query={"next":"https://elsewhere.invalid"})
    assert response.status == 302
    assert len(requests) == 1
    assert response.headers["location"] == "https://elsewhere.invalid/"


@pytest.mark.parametrize("route", ["//elsewhere.invalid", "http://example.com", "/path?url=1", "/x\r\nHost: evil"])
def test_routes_cannot_escape_target(route):
    with pytest.raises(TargetError):
        Transport("http://127.0.0.1").request(route)


def test_host_header_cannot_be_overridden():
    with pytest.raises(TargetError):
        Transport("http://127.0.0.1").request("/", headers={"Host":"elsewhere.invalid"})


def test_missing_path_seed_does_not_send_request():
    transport = Transport("http://127.0.0.1")
    with pytest.raises(TargetError):
        transport.request("/orders/<int:order_id>")
    assert transport.count == 0
