import pytest
from pydantic import ValidationError

from app.schemas import IssueDetail, ScanResponse


def test_scan_contract_includes_nullable_progress_and_coverage() -> None:
    scan = ScanResponse(
        id="scan-1",
        state="queued",
        source_root="/workspace/dvwa",
        target_origin="http://127.0.0.1:4280",
        created_at="2026-10-31T10:00:00Z",
        started_at=None,
        finished_at=None,
        phase=None,
        progress=None,
        error=None,
        counts={"confirmed": 0, "code_only": 0, "runtime_only": 0, "suppressed": 0},
        coverage=None,
    )

    assert scan.model_dump()["coverage"] is None
    assert scan.model_dump()["progress"] is None


def test_issue_contract_emits_all_evidence_slots_as_null() -> None:
    issue = IssueDetail(
        id="issue-1",
        fingerprint="fp",
        status="code_only",
        severity="high",
        risk=70,
        cwe=89,
        title="SQL injection",
        route=None,
        location={"file": "login.php", "line": 12},
        scan_id="scan-1",
        first_seen="2026-10-31T10:00:00Z",
        last_seen="2026-10-31T10:00:00Z",
        sast=None,
        dast=None,
        correlation=None,
    )

    assert issue.model_dump()["sast"] is None
    assert issue.model_dump()["dast"] is None
    assert issue.model_dump()["correlation"] is None


def test_issue_rejects_unknown_status() -> None:
    with pytest.raises(ValidationError):
        IssueDetail(
            id="issue-1", fingerprint="fp", status="potential_exposure", severity="low",
            risk=1, cwe=89, title="test", route=None, location=None,
            scan_id="scan-1", first_seen="2026-10-31T10:00:00Z",
            last_seen="2026-10-31T10:00:00Z", sast=None, dast=None, correlation=None,
        )
