from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import case, select
from sqlalchemy.orm import Session

from app.api.deps import get_session
from app.api.results import issue_detail, issue_summary
from app.models import Issue, IssueScan, Scan
from app.schemas import IssueDetail, IssueSummary

router = APIRouter(prefix="/issues", tags=["issues"])


def _require_scan(session: Session, scan_id: str) -> None:
    if session.get(Scan, scan_id) is None:
        raise HTTPException(status_code=404, detail="Scan not found")


@router.get("", response_model=list[IssueSummary])
def list_issues(
    scan_id: str,
    status: Literal["confirmed", "code_only", "runtime_only"] | None = None,
    cwe: int | None = None,
    session: Session = Depends(get_session),
):
    _require_scan(session, scan_id)
    query = select(Issue, IssueScan).join(IssueScan, IssueScan.issue_id == Issue.id).where(IssueScan.scan_id == scan_id)
    if status:
        query = query.where(IssueScan.status == status)
    if cwe is not None:
        query = query.where(IssueScan.cwe == cwe)
    order = case((IssueScan.status == "confirmed", 0), (IssueScan.status == "code_only", 1), else_=2)
    rows = session.execute(query.order_by(order, IssueScan.risk.desc(), Issue.fingerprint)).all()
    return [issue_summary(issue, snapshot) for issue, snapshot in rows]


@router.get("/{issue_id}", response_model=IssueDetail)
def get_issue(issue_id: str, scan_id: str, session: Session = Depends(get_session)):
    rows = session.execute(
        select(Issue, IssueScan)
        .join(IssueScan, IssueScan.issue_id == Issue.id)
        .where(Issue.id == issue_id, IssueScan.scan_id == scan_id)
    ).first()
    if rows is None:
        raise HTTPException(status_code=404, detail="Issue not found")
    issue, snapshot = rows
    return issue_detail(issue, snapshot, snapshot.scan_id)
