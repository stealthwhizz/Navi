from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy import case, select
from sqlalchemy.orm import Session

from app.api.deps import get_session
from app.api.results import issue_detail, issue_summary
from app.api.scans import scan_response
from app.models import Issue, IssueScan, Route, Scan, Suppressed

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/{scan_id}")
def get_report(scan_id: str, session: Session = Depends(get_session)):
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    order = case((IssueScan.status == "confirmed", 0), (IssueScan.status == "code_only", 1), else_=2)
    rows = session.execute(
        select(Issue, IssueScan)
        .join(IssueScan, IssueScan.issue_id == Issue.id)
        .where(IssueScan.scan_id == scan_id)
        .order_by(order, IssueScan.risk.desc(), Issue.fingerprint)
    ).all()
    routes = session.scalars(select(Route).where(Route.scan_id == scan_id).order_by(Route.path, Route.method)).all()
    suppressed = session.scalars(select(Suppressed).where(Suppressed.scan_id == scan_id)).all()
    report = {
        "scan": scan_response(scan),
        "issues": [issue_detail(issue, snapshot, scan_id) for issue, snapshot in rows],
        "routes": [{"method": route.method, "path": route.path, **route.data} for route in routes],
        "suppressed": [
            {"id": row.id, "source": row.source, "cwe": row.cwe, "title": row.title,
             "file": row.file, "line": row.line, "sanitizer": row.sanitizer, "reason": row.reason}
            for row in suppressed
        ],
    }
    return JSONResponse(
        content=report,
        headers={"Content-Disposition": f'attachment; filename="navi-{scan_id}.json"'},
    )
