from dataclasses import asdict, replace
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app.analysis.correlate import IssueEvidence, correlate
from app.analysis.dast import scan_dast
from app.analysis.routemap import RouteEvidence, build_route_map
from app.analysis.sast import scan_source
from app.analysis.types import FindingInput
from app.models import Finding, Issue, IssueScan, Route, Scan, Suppressed


def _set_phase(factory: sessionmaker, scan_id: str, phase: str, done: int) -> None:
    with factory() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise ValueError("scan no longer exists")
        scan.phase = phase
        scan.progress = {"done": done, "total": 4}
        session.commit()


def _route_data(route: RouteEvidence, issue_count: int) -> dict:
    return {
        "declared_at": route.declared_at,
        "handler": route.handler,
        "params": route.params,
        "provenance": route.provenance,
        "confidence": route.confidence,
        "tested": route.tested,
        "issue_count": issue_count,
    }


def _finding_row(scan_id: str, finding: FindingInput) -> Finding:
    return Finding(
        scan_id=scan_id,
        fingerprint=finding.fingerprint,
        source=finding.source,
        cwe=finding.cwe,
        title=finding.title,
        severity=finding.severity,
        risk=finding.risk,
        evidence={
            "route": finding.route,
            "location": finding.location,
            "sast": finding.sast,
            "dast": finding.dast,
        },
    )


def _save_results(
    factory: sessionmaker,
    scan_id: str,
    routes: list[RouteEvidence],
    findings: list[FindingInput],
    issues: list[IssueEvidence],
    suppressed: list[dict],
    coverage: dict,
) -> None:
    now = datetime.now(UTC)
    with factory() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise ValueError("scan no longer exists")

        issue_counts: dict[tuple[str, str], int] = {}
        for issue in issues:
            if issue.route:
                key = (issue.route["method"], issue.route["path"])
                issue_counts[key] = issue_counts.get(key, 0) + 1
        for route in routes:
            handler_key = ""
            if route.handler:
                handler_key = f"{route.handler['file']}:{route.handler['line_start']}:{route.handler['name']}"
            session.add(Route(
                scan_id=scan_id,
                method=route.method,
                path=route.path,
                handler_key=handler_key,
                data=_route_data(route, issue_counts.get((route.method, route.path), 0)),
            ))

        unique_findings = {finding.fingerprint: finding for finding in findings}
        for finding in unique_findings.values():
            session.add(_finding_row(scan_id, finding))

        counts = {"confirmed": 0, "code_only": 0, "runtime_only": 0, "suppressed": len(suppressed)}
        for evidence in issues:
            issue = session.scalar(select(Issue).where(Issue.fingerprint == evidence.fingerprint))
            if issue is None:
                issue = Issue(
                    fingerprint=evidence.fingerprint,
                    first_seen=now,
                    last_seen=now,
                    status=evidence.status,
                    severity=evidence.severity,
                    risk=evidence.risk,
                    cwe=evidence.cwe,
                    title=evidence.title,
                )
                session.add(issue)
                session.flush()
            else:
                issue.last_seen = now
                issue.status = evidence.status
                issue.severity = evidence.severity
                issue.risk = evidence.risk
                issue.cwe = evidence.cwe
                issue.title = evidence.title
            issue.route = evidence.route
            issue.location = evidence.location
            issue.sast = evidence.sast
            issue.dast = evidence.dast
            issue.correlation = evidence.correlation
            snapshot = session.get(IssueScan, (scan_id, issue.id))
            if snapshot is None:
                snapshot = IssueScan(scan_id=scan_id, issue_id=issue.id)
                session.add(snapshot)
            snapshot.status = evidence.status
            snapshot.severity = evidence.severity
            snapshot.risk = evidence.risk
            snapshot.cwe = evidence.cwe
            snapshot.title = evidence.title
            snapshot.route = evidence.route
            snapshot.location = evidence.location
            snapshot.sast = evidence.sast
            snapshot.dast = evidence.dast
            snapshot.correlation = evidence.correlation
            counts[evidence.status] += 1

        for item in suppressed:
            session.add(Suppressed(scan_id=scan_id, **item))

        scan.counts = counts
        scan.coverage = coverage
        scan.state = "completed"
        scan.phase = None
        scan.progress = None
        scan.finished_at = now
        scan.error = None
        session.commit()


async def run_scan(
    factory: sessionmaker,
    scan_id: str,
    allowed_target_origin: str,
    transport=None,
) -> None:
    with factory() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise ValueError("scan not found")
        source_root = Path(scan.source_root)
        target_origin = scan.target_origin

    _set_phase(factory, scan_id, "routes", 1)
    routes, unresolved, route_skipped = build_route_map(source_root)
    _set_phase(factory, scan_id, "sast", 2)
    sast_findings, suppressed, sast_coverage = scan_source(source_root, routes)
    _set_phase(factory, scan_id, "dast", 3)
    dast_findings, dast_coverage, dast_errors, tested = await scan_dast(
        routes, target_origin, allowed_target_origin, transport=transport,
    )
    routes = [replace(route, tested=(route.method, route.path) in tested) for route in routes]
    _set_phase(factory, scan_id, "correlate", 4)
    findings = sast_findings + dast_findings
    issues = correlate(findings, routes)

    skipped = {(item["path"], item["reason"]): item for item in route_skipped + sast_coverage["files_skipped"]}
    rules_not_run = sast_coverage["rules_not_run"] + dast_coverage.pop("rules_not_run")
    coverage = {
        "frameworks": ["Laravel"] if any(route.provenance == "laravel" for route in routes) else [],
        "files_parsed": sast_coverage["files_parsed"],
        "files_skipped": list(skipped.values()),
        "routes_total": len(routes),
        "routes_unmapped": sum(route.handler is None or route.provenance == "unresolved" for route in routes),
        "unresolved": unresolved,
        "rules_not_run": rules_not_run,
        "dast": dast_coverage,
        "errors": dast_errors,
    }
    _save_results(factory, scan_id, routes, findings, issues, suppressed, coverage)
