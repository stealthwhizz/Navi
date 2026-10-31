from dataclasses import dataclass
import hashlib
import re

from app.analysis.routemap import RouteEvidence
from app.analysis.types import FindingInput


@dataclass(frozen=True)
class IssueEvidence:
    fingerprint: str
    status: str
    severity: str
    risk: int
    cwe: int
    title: str
    route: dict | None
    location: dict | None
    sast: dict | None
    dast: dict | None
    correlation: dict | None


def _parameter(finding: FindingInput) -> str | None:
    if not finding.sast:
        return None
    match = re.search(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\s*\[\s*['\"]([^'\"]+)['\"]", finding.sast["source"]["expr"])
    return match.group(1) if match else None


def _checks(sast: FindingInput, dast: FindingInput, routes: list[RouteEvidence]) -> list[dict[str, str]]:
    checks: list[dict[str, str]] = []
    checks.append({
        "name": "cwe_compatibility",
        "result": "pass" if sast.cwe == dast.cwe else "fail",
        "detail": f"SAST CWE-{sast.cwe}; DAST CWE-{dast.cwe}",
    })

    if sast.route is None or dast.route is None:
        result, detail = "unknown", "one finding has no route mapping"
    elif sast.route != dast.route:
        result, detail = "fail", "SAST and DAST route references differ"
    else:
        route = next((r for r in routes if r.method == sast.route["method"] and r.path == sast.route["path"]), None)
        if route is None or route.handler is None or route.provenance == "unresolved" or route.confidence == "low":
            result, detail = "unknown", "route does not have a resolved handler mapping"
        elif not sast.location:
            result, detail = "unknown", "SAST finding has no source location"
        elif route.handler["file"] != sast.location["file"] or not (
            route.handler["line_start"] <= sast.location["line"] <= route.handler["line_end"]
        ):
            result, detail = "fail", "source location is outside the mapped handler"
        else:
            result, detail = "pass", "route and source location resolve to the same handler"
    checks.append({"name": "route_mapping", "result": result, "detail": detail})

    if not sast.sast or len(sast.sast.get("path", [])) < 2:
        result, detail = "unknown", "source-to-sink evidence is incomplete"
    elif all(step.get("resolved") for step in sast.sast["path"]):
        result, detail = "pass", "SAST source-to-sink path is resolved"
    else:
        result, detail = "unknown", "SAST source-to-sink path contains unresolved steps"
    checks.append({"name": "code_path", "result": result, "detail": detail})

    sast_parameter = _parameter(sast)
    dast_parameter = (dast.dast or {}).get("parameter")
    if sast_parameter and dast_parameter:
        result = "pass" if sast_parameter == dast_parameter else "fail"
        detail = f"SAST parameter {sast_parameter}; DAST parameter {dast_parameter}"
    else:
        result, detail = "unknown", "parameter name is missing on one side"
    checks.append({"name": "parameter_agreement", "result": result, "detail": detail})

    dast_method = (dast.dast or {}).get("method")
    dast_payload = (dast.dast or {}).get("payload")
    has_oracle = bool((dast.dast or {}).get("evidence"))
    expected_method = (dast.route or {}).get("method")
    if dast_method and expected_method and dast_payload and has_oracle:
        result = "pass" if dast_method == expected_method else "fail"
        detail = "request method and payload-specific runtime evidence are present"
    else:
        result, detail = "unknown", "runtime request or vulnerability-specific evidence is incomplete"
    checks.append({"name": "method_and_input", "result": result, "detail": detail})
    return checks


def _rationale(checks: list[dict[str, str]], accepted: bool) -> str:
    if accepted:
        return "Matching CWE, route-to-handler source location, request parameter, and runtime oracle support the link."
    failures = [check["name"] for check in checks if check["result"] == "fail"]
    unknown = [check["name"] for check in checks if check["result"] == "unknown"]
    if failures:
        return "Not confirmed; evidence conflicts at: " + ", ".join(failures) + "."
    if unknown:
        return "Not confirmed; required evidence is unknown at: " + ", ".join(unknown) + "."
    return "Not confirmed; multiple candidate findings make the link ambiguous."


def _issue(finding: FindingInput, status: str, correlation: dict | None = None) -> IssueEvidence:
    return IssueEvidence(
        fingerprint=finding.fingerprint,
        status=status,
        severity=finding.severity,
        risk=finding.risk,
        cwe=finding.cwe,
        title=finding.title,
        route=finding.route,
        location=finding.location,
        sast=finding.sast,
        dast=finding.dast,
        correlation=correlation,
    )


def correlate(findings: list[FindingInput], routes: list[RouteEvidence]) -> list[IssueEvidence]:
    sast_findings = [finding for finding in findings if finding.source == "sast" and finding.cwe != 798]
    dast_findings = [finding for finding in findings if finding.source == "dast"]
    evaluations: dict[tuple[int, int], list[dict[str, str]]] = {}
    valid_pairs: list[tuple[int, int]] = []
    for si, sast in enumerate(sast_findings):
        for di, dast in enumerate(dast_findings):
            checks = _checks(sast, dast, routes)
            evaluations[(si, di)] = checks
            if all(check["result"] == "pass" for check in checks):
                valid_pairs.append((si, di))

    sast_candidates = {si: [di for pair_si, di in valid_pairs if pair_si == si] for si in range(len(sast_findings))}
    dast_candidates = {di: [si for si, pair_di in valid_pairs if pair_di == di] for di in range(len(dast_findings))}
    matched = {
        (si, di) for si, di in valid_pairs
        if len(sast_candidates[si]) == 1 and len(dast_candidates[di]) == 1
    }
    consumed_sast = {si for si, _ in matched}
    consumed_dast = {di for _, di in matched}
    issues: list[IssueEvidence] = []

    for si, di in sorted(matched):
        sast, dast = sast_findings[si], dast_findings[di]
        checks = evaluations[(si, di)]
        fingerprint = hashlib.sha256(f"paired|{sast.fingerprint}|{dast.fingerprint}".encode()).hexdigest()
        issues.append(IssueEvidence(
            fingerprint=fingerprint, status="confirmed", severity=sast.severity,
            risk=max(sast.risk, dast.risk), cwe=sast.cwe, title=sast.title,
            route=sast.route or dast.route, location=sast.location,
            sast=sast.sast, dast=dast.dast,
            correlation={"accepted": True, "rationale": _rationale(checks, True), "checks": checks},
        ))

    for si, finding in enumerate(sast_findings):
        if si in consumed_sast:
            continue
        same_cwe = [di for di, dast in enumerate(dast_findings) if dast.cwe == finding.cwe]
        candidate = same_cwe[0] if len(same_cwe) == 1 else None
        correlation = None
        if candidate is not None:
            checks = evaluations[(si, candidate)]
            accepted = False
            correlation = {"accepted": accepted, "rationale": _rationale(checks, accepted), "checks": checks}
        elif len(same_cwe) > 1:
            correlation = {
                "accepted": False,
                "rationale": "Not confirmed; multiple runtime candidates make the link ambiguous.",
                "checks": [{"name": "candidate_selection", "result": "unknown", "detail": "multiple same-CWE runtime findings"}],
            }
        issues.append(_issue(finding, "code_only", correlation))

    for di, finding in enumerate(dast_findings):
        if di in consumed_dast:
            continue
        same_cwe = [si for si, sast in enumerate(sast_findings) if sast.cwe == finding.cwe]
        candidate = same_cwe[0] if len(same_cwe) == 1 else None
        correlation = None
        if candidate is not None:
            checks = evaluations[(candidate, di)]
            correlation = {"accepted": False, "rationale": _rationale(checks, False), "checks": checks}
        elif len(same_cwe) > 1:
            correlation = {
                "accepted": False,
                "rationale": "Not confirmed; multiple code candidates make the link ambiguous.",
                "checks": [{"name": "candidate_selection", "result": "unknown", "detail": "multiple same-CWE code findings"}],
            }
        issues.append(_issue(finding, "runtime_only", correlation))

    for finding in findings:
        if finding.source == "sast" and finding.cwe == 798:
            issues.append(_issue(finding, "code_only"))

    status_order = {"confirmed": 0, "code_only": 1, "runtime_only": 2}
    issues.sort(key=lambda issue: (status_order[issue.status], -issue.risk, issue.fingerprint))
    return issues
