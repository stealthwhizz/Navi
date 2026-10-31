from pathlib import Path

import pytest
from pydantic import ValidationError

from app.settings import Settings


def test_settings_accepts_configured_local_dvwa_origin(tmp_path: Path) -> None:
    settings = Settings(
        database_url="postgresql+psycopg://cyberforge:local-only@localhost/cyberforge",
        source_root=tmp_path,
        allowed_target_origin="http://127.0.0.1:4280",
    )

    assert settings.source_root == tmp_path.resolve()
    assert settings.allowed_target_origin == "http://127.0.0.1:4280"


def test_settings_accepts_compose_host_gateway(tmp_path: Path) -> None:
    settings = Settings(
        database_url="postgresql+psycopg://cyberforge:local-only@localhost/cyberforge",
        source_root=tmp_path,
        allowed_target_origin="http://host.docker.internal:4280",
    )

    assert settings.allowed_target_origin == "http://host.docker.internal:4280"


def test_settings_normalizes_ipv6_loopback_origin(tmp_path: Path) -> None:
    settings = Settings(
        database_url="postgresql+psycopg://cyberforge:local-only@localhost/cyberforge",
        source_root=tmp_path,
        allowed_target_origin="http://[::1]:4280/",
    )

    assert settings.allowed_target_origin == "http://[::1]:4280"


def test_settings_rejects_public_target_origin(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        Settings(
            database_url="postgresql+psycopg://cyberforge:local-only@localhost/cyberforge",
            source_root=tmp_path,
            allowed_target_origin="https://example.com",
        )


def test_settings_rejects_non_postgresql_database_url(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        Settings(
            database_url="sqlite:///cyberforge.db",
            source_root=tmp_path,
            allowed_target_origin="http://127.0.0.1:4280",
        )
