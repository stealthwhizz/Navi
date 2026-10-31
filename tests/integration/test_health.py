from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import create_app
from app.settings import Settings


def test_health_reports_api_and_database_ready(tmp_path: Path) -> None:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    factory = sessionmaker(bind=engine)
    settings = Settings(
        database_url="postgresql+psycopg://user:pass@localhost/cyberforge",
        source_root=tmp_path,
        allowed_target_origin="http://127.0.0.1:4280",
    )

    with TestClient(create_app(settings, factory)) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ok"}
    engine.dispose()


def test_health_marks_database_unavailable(tmp_path: Path) -> None:
    def broken_factory():
        raise RuntimeError("database connection failed")

    settings = Settings(
        database_url="postgresql+psycopg://user:pass@localhost/cyberforge",
        source_root=tmp_path,
        allowed_target_origin="http://127.0.0.1:4280",
    )

    with TestClient(create_app(settings, broken_factory)) as client:
        response = client.get("/health")

    assert response.status_code == 503
    assert response.json() == {"status": "degraded", "database": "unavailable"}
