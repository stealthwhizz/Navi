from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_session
from app.models import Scan, Suppressed
from app.schemas import SuppressedResponse

router = APIRouter(prefix="/suppressed", tags=["suppressed"])


@router.get("", response_model=list[SuppressedResponse])
def list_suppressed(scan_id: str, session: Session = Depends(get_session)):
    if session.get(Scan, scan_id) is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    rows = session.scalars(
        select(Suppressed).where(Suppressed.scan_id == scan_id).order_by(Suppressed.file, Suppressed.line)
    ).all()
    return [
        {"id": row.id, "source": row.source, "cwe": row.cwe, "title": row.title,
         "file": row.file, "line": row.line, "sanitizer": row.sanitizer, "reason": row.reason}
        for row in rows
    ]
