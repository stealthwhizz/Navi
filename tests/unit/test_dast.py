import httpx
import pytest

from app.analysis.dast import scan_dast, validate_target_url
from app.analysis.routemap import RouteEvidence

ORIGIN = "http://127.0.0.1:4280"


def test_target_origin_must_match_configured_local_origin() -> None:
    assert validate_target_url(ORIGIN, ORIGIN) == ORIGIN
    with pytest.raises(ValueError, match="configured"):
        validate_target_url("http://127.0.0.1:4281", ORIGIN)
    with pytest.raises(ValueError, match="configured"):
        validate_target_url("http://example.com", ORIGIN)


def _route(parameter: str = "q") -> RouteEvidence:
    return RouteEvidence(
        "GET", "/search.php", None,
        {"file": "search.php", "name": "search", "line_start": 1, "line_end": 3},
        [parameter], "filesystem", "medium",
    )


@pytest.mark.asyncio
async def test_untrusted_route_and_off_origin_redirect_never_escape_target() -> None:
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return httpx.Response(302, headers={"Location": "http://example.invalid/"})

    transport = httpx.MockTransport(handler)
    routes = [
        _route(),
        RouteEvidence("GET", "//example.invalid/path", None, None, ["q"], "unresolved", "low"),
    ]

    findings, coverage, errors, tested = await scan_dast(routes, ORIGIN, ORIGIN, transport=transport)

    assert findings == []
    assert errors == []
    assert coverage["blocked"] >= 1
    assert coverage["requests"] == len(requested) == 6
    assert all(url.startswith(ORIGIN + "/") for url in requested)
    assert all(httpx.URL(url).host == "127.0.0.1" and httpx.URL(url).port == 4280 for url in requested)
    assert tested == {("GET", "/search.php")}


@pytest.mark.asyncio
async def test_non_destructive_cwe_probes_retain_response_evidence() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        parameter = request.url.params.get("q", "")
        if "<script>" in parameter:
            return httpx.Response(200, text=f"<html>{parameter}</html>")
        if "printf" in parameter:
            return httpx.Response(200, text=parameter.split(" ")[-1])
        return httpx.Response(200, text="safe response")

    findings, coverage, errors, tested = await scan_dast(
        [_route()], ORIGIN, ORIGIN, transport=httpx.MockTransport(handler),
    )

    assert errors == []
    assert {finding.cwe for finding in findings} >= {78, 79}
    assert all(finding.dast["response"]["excerpt"] for finding in findings)
    assert coverage["requests"] == 6
    assert tested == {("GET", "/search.php")}


@pytest.mark.asyncio
async def test_open_redirect_requires_probe_controlled_destination() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        destination = request.url.params.get("next", "")
        if destination.startswith("http://example.invalid/"):
            return httpx.Response(302, headers={"Location": destination})
        return httpx.Response(200, text="normal")

    route = RouteEvidence(
        "GET", "/redirect.php", None,
        {"file": "redirect.php", "name": "redirect", "line_start": 1, "line_end": 3},
        ["next"], "filesystem", "medium",
    )

    findings, _, errors, _ = await scan_dast(
        [route], ORIGIN, ORIGIN, transport=httpx.MockTransport(handler),
    )

    assert errors == []
    assert any(finding.cwe == 601 for finding in findings)


@pytest.mark.asyncio
async def test_request_cap_includes_timeouts(monkeypatch) -> None:
    import app.analysis.dast as dast

    monkeypatch.setattr(dast, "MAX_REQUESTS", 3)

    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timeout", request=request)

    _, coverage, errors, _ = await scan_dast(
        [_route()], ORIGIN, ORIGIN, transport=httpx.MockTransport(timeout),
    )

    assert coverage["requests"] == 3
    assert coverage["timeouts"] == 3
    assert len(errors) == 3


@pytest.mark.asyncio
async def test_sql_error_must_be_new_for_the_injection_probe() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="SQLSTATE syntax error")

    findings, _, _, _ = await scan_dast(
        [_route()], ORIGIN, ORIGIN, transport=httpx.MockTransport(handler),
    )

    assert all(finding.cwe != 89 for finding in findings)


@pytest.mark.asyncio
async def test_command_probe_reflection_is_not_command_execution() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=request.url.params.get("q", ""))

    findings, _, _, _ = await scan_dast(
        [_route()], ORIGIN, ORIGIN, transport=httpx.MockTransport(handler),
    )

    assert all(finding.cwe != 78 for finding in findings)


@pytest.mark.asyncio
async def test_sql_error_after_quote_probe_is_dast_evidence() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("q") == "'":
            return httpx.Response(500, text="SQLSTATE syntax error")
        return httpx.Response(200, text="normal")

    findings, _, errors, _ = await scan_dast(
        [_route()], ORIGIN, ORIGIN, transport=httpx.MockTransport(handler),
    )

    assert errors == []
    assert any(finding.cwe == 89 for finding in findings)
