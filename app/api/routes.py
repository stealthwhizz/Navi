from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_session
from app.models import Route, Scan
from app.schemas import RouteResponse

router = APIRouter(prefix="/routes", tags=["routes"])


@router.get("", response_model=list[RouteResponse])
def list_routes(scan_id: str, session: Session = Depends(get_session)):
    if session.get(Scan, scan_id) is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    routes = session.scalars(
        select(Route).where(Route.scan_id == scan_id).order_by(Route.path, Route.method)
    ).all()
    return [{"method": route.method, "path": route.path, **route.data} for route in routes]
