from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.dast import validate_target_url
from app.analysis.php import validate_source_root
from app.api.deps import get_session
from app.models import Scan
from app.schemas import ScanResponse, StartScanRequest, StartScanResponse

router = APIRouter(prefix="/scans", tags=["scans"])


def _timestamp(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat().replace("+00:00", "Z")


def scan_response(scan: Scan) -> dict:
    return {
        "id": scan.id,
        "state": scan.state,
        "source_root": scan.source_root,
        "target_origin": scan.target_origin,
        "created_at": _timestamp(scan.created_at),
        "started_at": _timestamp(scan.started_at),
        "finished_at": _timestamp(scan.finished_at),
        "phase": scan.phase,
        "progress": scan.progress,
        "error": scan.error,
        "counts": scan.counts or {},
        "coverage": scan.coverage,
    }


@router.post("", status_code=status.HTTP_202_ACCEPTED, response_model=StartScanResponse)
def create_scan(payload: StartScanRequest, request: Request, session: Session = Depends(get_session)):
    settings = request.app.state.settings
    try:
        source_root = validate_source_root(Path(payload.source_root), settings.source_root)
        target_origin = validate_target_url(payload.target_origin, settings.allowed_target_origin)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    scan = Scan(
        source_root=str(source_root),
        target_origin=target_origin,
        state="queued",
        counts={"confirmed": 0, "code_only": 0, "runtime_only": 0, "suppressed": 0},
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return {"scan_id": scan.id, "state": "queued"}


@router.get("", response_model=list[ScanResponse])
def list_scans(session: Session = Depends(get_session)):
    scans = session.scalars(select(Scan).order_by(Scan.created_at.desc())).all()
    return [scan_response(scan) for scan in scans]


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: str, session: Session = Depends(get_session)):
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan_response(scan)
