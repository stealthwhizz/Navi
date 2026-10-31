from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import create_app
from app.models import Base
from app.settings import Settings

ORIGIN = "http://127.0.0.1:4280"


def make_client(tmp_path: Path):
    source = tmp_path / "dvwa"
    source.mkdir()
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    settings = Settings(
        database_url="postgresql+psycopg://user:pass@localhost/cyberforge",
        source_root=tmp_path,
        allowed_target_origin=ORIGIN,
    )
    return TestClient(create_app(settings, factory)), engine, source


def test_scan_enqueue_list_and_detail_match_ui_contract(tmp_path: Path) -> None:
    client, engine, source = make_client(tmp_path)
    with client:
        response = client.post("/scans", json={"source_root": str(source), "target_origin": ORIGIN})
        assert response.status_code == 202
        created = response.json()
        assert created["state"] == "queued"

        scans = client.get("/scans")
        assert scans.status_code == 200
        assert scans.json()[0]["id"] == created["scan_id"]
        assert scans.json()[0]["coverage"] is None
        assert scans.json()[0]["counts"] == {
            "confirmed": 0, "code_only": 0, "runtime_only": 0, "suppressed": 0,
        }

        detail = client.get(f"/scans/{created['scan_id']}")
        assert detail.status_code == 200
        assert detail.json()["target_origin"] == ORIGIN
    engine.dispose()


def test_scan_rejects_out_of_workspace_source_and_unapproved_target(tmp_path: Path) -> None:
    client, engine, source = make_client(tmp_path)
    outside = tmp_path.parent / "outside"
    outside.mkdir()
    with client:
        source_error = client.post("/scans", json={"source_root": str(outside), "target_origin": ORIGIN})
        target_error = client.post("/scans", json={"source_root": str(source), "target_origin": "http://127.0.0.1:4281"})

    assert source_error.status_code == 422
    assert target_error.status_code == 422
    engine.dispose()


def test_missing_scan_redirects_to_same_origin_ui(tmp_path: Path) -> None:
    client, engine, _ = make_client(tmp_path)
    with client:
        assert client.get("/scans/not-a-scan").status_code == 404
        root = client.get("/", follow_redirects=False)
        ui = client.get("/ui/")

    assert root.status_code == 307
    assert root.headers["location"] == "/ui/"
    assert ui.status_code == 200
    engine.dispose()
