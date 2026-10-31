from app.analysis.correlate import correlate
from app.analysis.routemap import RouteEvidence
from app.analysis.types import FindingInput

ROUTE = RouteEvidence(
    "GET", "/search.php", None,
    {"name": "search", "file": "search.php", "line_start": 1, "line_end": 10},
    ["term"], "filesystem", "medium",
)


def sast(fingerprint: str, parameter: str, line: int = 4, cwe: int = 79) -> FindingInput:
    return FindingInput(
        source="sast", cwe=cwe, title="XSS", severity="high", risk=70,
        fingerprint=fingerprint, route={"method": "GET", "path": "/search.php"},
        location={"file": "search.php", "line": line},
        sast={
            "rule_id": f"CWE-{cwe}", "file": "search.php", "line_start": line, "line_end": line,
            "snippet": {"start_line": line, "code": "echo $_GET['term'];"}, "highlight_line": line,
            "source": {"expr": f"$_GET['{parameter}']", "type": "request_parameter", "location": f"search.php:{line}"},
            "sink": {"name": "echo", "type": "html_output", "location": f"search.php:{line}"},
            "path": [{"label": "source", "location": f"search.php:{line}", "resolved": True}, {"label": "sink", "location": f"search.php:{line}", "resolved": True}],
            "sanitizers": [],
        },
    )


def dast(fingerprint: str, parameter: str, path: str = "/search.php", cwe: int = 79) -> FindingInput:
    return FindingInput(
        source="dast", cwe=cwe, title="XSS probe reflected", severity="high", risk=70,
        fingerprint=fingerprint, route={"method": "GET", "path": path}, location=None,
        dast={
            "rule_id": f"CWE-{cwe}-DAST", "method": "GET", "url": f"http://127.0.0.1{path}",
            "parameter": parameter, "payload": "<script>marker</script>", "request": f"GET {path}",
            "response": {"status": 200, "excerpt": "marker", "truncated": False},
            "evidence": "marker", "oracle": "probe reflected",
        },
    )


def test_confirmed_requires_matching_cwe_route_code_and_parameter() -> None:
    issues = correlate([sast("s1", "term") , dast("d1", "term")], [ROUTE])

    assert len(issues) == 1
    assert issues[0].status == "confirmed"
    assert issues[0].correlation["accepted"] is True
    assert {check["result"] for check in issues[0].correlation["checks"]} == {"pass"}


def test_parameter_mismatch_stays_separate_and_not_confirmed() -> None:
    issues = correlate([sast("s1", "term"), dast("d1", "other")], [ROUTE])

    assert {issue.status for issue in issues} == {"code_only", "runtime_only"}
    assert all(issue.correlation is None or not issue.correlation["accepted"] for issue in issues)


def test_two_code_candidates_on_same_route_are_not_greedily_mislinked() -> None:
    issues = correlate(
        [sast("s1", "term", line=3), sast("s2", "term", line=7), dast("d1", "term")],
        [ROUTE],
    )

    assert sum(issue.status == "confirmed" for issue in issues) == 0
    assert sum(issue.status == "code_only" for issue in issues) == 2
    assert sum(issue.status == "runtime_only" for issue in issues) == 1


def test_unknown_route_mapping_cannot_be_promoted_to_confirmed() -> None:
    unresolved = RouteEvidence("GET", "/search.php", None, None, ["term"], "unresolved", "low")
    issues = correlate([sast("s1", "term"), dast("d1", "term")], [unresolved])

    assert {issue.status for issue in issues} == {"code_only", "runtime_only"}
    assert all(
        check["result"] != "pass"
        for issue in issues if issue.correlation
        for check in issue.correlation["checks"] if check["name"] == "route_mapping"
    )


def test_unmatched_cwe798_remains_code_only_and_fingerprints_stay_stable() -> None:
    finding = sast("s1", "api_key", cwe=798)
    first = correlate([finding], [ROUTE])
    second = correlate([finding], [ROUTE])

    assert first[0].status == "code_only"
    assert first[0].fingerprint == second[0].fingerprint
