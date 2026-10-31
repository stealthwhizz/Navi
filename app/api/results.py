from datetime import datetime

from app.models import Issue, IssueScan


def timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def issue_summary(issue: Issue, snapshot: IssueScan) -> dict:
    return {
        "id": issue.id,
        "fingerprint": issue.fingerprint,
        "status": snapshot.status,
        "severity": snapshot.severity,
        "risk": snapshot.risk,
        "cwe": snapshot.cwe,
        "title": snapshot.title,
        "route": snapshot.route,
        "location": snapshot.location,
    }


def issue_detail(issue: Issue, snapshot: IssueScan, scan_id: str) -> dict:
    return {
        **issue_summary(issue, snapshot),
        "scan_id": scan_id,
        "first_seen": timestamp(issue.first_seen),
        "last_seen": timestamp(issue.last_seen),
        "sast": snapshot.sast,
        "dast": snapshot.dast,
        "correlation": snapshot.correlation,
    }
