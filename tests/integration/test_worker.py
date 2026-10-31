from pathlib import Path

import httpx
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import Base, Issue, IssueScan, Route, Scan
from app.settings import Settings
from app.worker import run_once

ORIGIN = "http://127.0.0.1:4280"


def _database(tmp_path: Path):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    settings = Settings(
        database_url="postgresql+psycopg://user:pass@localhost/cyberforge",
        source_root=tmp_path,
        allowed_target_origin=ORIGIN,
    )
    return engine, factory, settings


def test_worker_runs_full_php_pipeline_and_persists_confirmed_issue(tmp_path: Path) -> None:
    source = tmp_path / "dvwa"
    source.mkdir()
    (source / "search.php").write_text("<?php echo $_GET['q'];", encoding="utf-8")
    engine, factory, settings = _database(tmp_path)
    with Session(engine) as session:
        scan = Scan(source_root=str(source), target_origin=ORIGIN, state="queued")
        session.add(scan)
        session.commit()
        scan_id = scan.id

    def target(request: httpx.Request) -> httpx.Response:
        probe = request.url.params.get("q", "")
        return httpx.Response(200, text=f"<html>{probe}</html>" if "<script>" in probe else "safe")

    assert run_once(factory, settings, transport=httpx.MockTransport(target)) is True

    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        issue = session.scalar(select(Issue).where(Issue.cwe == 79))
        snapshot = session.get(IssueScan, (scan_id, issue.id))
        route = session.scalar(select(Route).where(Route.scan_id == scan_id))

        assert scan.state == "completed"
        assert scan.counts == {"confirmed": 1, "code_only": 0, "runtime_only": 0, "suppressed": 0}
        assert scan.coverage["files_parsed"] == 1
        assert scan.coverage["dast"]["requests"] == 6
        assert issue.status == snapshot.status == "confirmed"
        assert snapshot.correlation["accepted"] is True
        assert route.data["tested"] is True
    engine.dispose()


def test_worker_failure_is_not_a_clean_empty_scan(tmp_path: Path) -> None:
    source = tmp_path / "dvwa"
    source.mkdir()
    (source / "index.php").write_text("<?php echo 'safe';", encoding="utf-8")
    engine, factory, settings = _database(tmp_path)
    with Session(engine) as session:
        scan = Scan(source_root=str(source), target_origin="http://127.0.0.1:4281", state="queued")
        session.add(scan)
        session.commit()
        scan_id = scan.id

    assert run_once(factory, settings) is True

    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        assert scan.state == "failed"
        assert scan.error == "Worker failed: ValueError"
        assert scan.coverage["errors"] == [{"stage": "dast", "message": "ValueError"}]
    engine.dispose()
