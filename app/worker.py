import asyncio
import time

from sqlalchemy import select, update
from sqlalchemy.orm import sessionmaker

from app.analysis.pipeline import run_scan
from app.models import Scan, now_utc
from app.settings import Settings, get_settings
from app.db import create_session_factory


def claim_next(factory: sessionmaker) -> str | None:
    with factory.begin() as session:
        scan = session.scalar(
            select(Scan)
            .where(Scan.state == "queued")
            .order_by(Scan.created_at)
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        if scan is None:
            return None
        scan.state = "running"
        scan.started_at = now_utc()
        scan.phase = "routes"
        scan.progress = {"done": 0, "total": 4}
        scan.error = None
        return scan.id


def _mark_failed(factory: sessionmaker, scan_id: str, error_type: str) -> None:
    with factory.begin() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            return
        stage = scan.phase or "worker"
        scan.state = "failed"
        scan.phase = None
        scan.progress = None
        scan.finished_at = now_utc()
        scan.error = f"Worker failed: {error_type}"
        coverage = dict(scan.coverage or {})
        errors = list(coverage.get("errors", []))
        errors.append({"stage": stage, "message": error_type})
        coverage["errors"] = errors
        scan.coverage = coverage


def run_once(factory: sessionmaker, settings: Settings, transport=None) -> bool:
    scan_id = claim_next(factory)
    if scan_id is None:
        return False
    try:
        asyncio.run(run_scan(factory, scan_id, settings.allowed_target_origin, transport=transport))
    except Exception as exc:
        _mark_failed(factory, scan_id, type(exc).__name__)
    return True


def recover_interrupted(factory: sessionmaker) -> int:
    with factory.begin() as session:
        result = session.execute(
            update(Scan)
            .where(Scan.state == "running")
            .values(
                state="failed",
                phase=None,
                progress=None,
                finished_at=now_utc(),
                error="Worker restarted while scan was running",
            )
        )
        return result.rowcount or 0


def run_forever(settings: Settings) -> None:
    factory = create_session_factory(settings.database_url)
    recover_interrupted(factory)
    while True:
        if not run_once(factory, settings):
            time.sleep(0.5)


def main() -> None:
    run_forever(get_settings())


if __name__ == "__main__":
    main()
