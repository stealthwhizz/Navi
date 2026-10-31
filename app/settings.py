from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CYBERFORGE_", env_file=".env", extra="ignore")

    database_url: str
    source_root: Path
    allowed_target_origin: str

    @field_validator("database_url")
    @classmethod
    def require_postgresql(cls, value: str) -> str:
        if not value.startswith("postgresql+psycopg://"):
            raise ValueError("database_url must use the postgresql+psycopg scheme")
        return value

    @field_validator("source_root")
    @classmethod
    def resolve_source_root(cls, value: Path) -> Path:
        root = value.expanduser().resolve()
        if not root.is_dir():
            raise ValueError("source_root must be an existing directory")
        return root

    @field_validator("allowed_target_origin")
    @classmethod
    def require_local_http_origin(cls, value: str) -> str:
        try:
            parsed = urlsplit(value)
            host = parsed.hostname
            port = parsed.port
        except ValueError as exc:
            raise ValueError("allowed_target_origin must be a valid local HTTP origin") from exc

        if (
            parsed.scheme != "http"
            or not host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("allowed_target_origin must be a local HTTP origin without credentials or path")

        hostname = host.lower().rstrip(".")
        try:
            address = ip_address(hostname)
        except ValueError:
            is_local_name = (
                hostname in {"localhost", "host.docker.internal"}
                or hostname.endswith(".localhost")
                or "." not in hostname
            )
            if not is_local_name:
                raise ValueError("allowed_target_origin host must be local or a Docker service name")
        else:
            if not (address.is_loopback or address.is_private) or address.is_link_local or address.is_unspecified:
                raise ValueError("allowed_target_origin IP must be loopback or private, not link-local/unspecified")

        netloc = f"[{hostname}]" if ":" in hostname else hostname
        if port is not None:
            netloc += f":{port}"
        return urlunsplit(("http", netloc, "", "", ""))

    @property
    def allowed_target_host(self) -> str:
        return urlsplit(self.allowed_target_origin).hostname or ""


def get_settings() -> Settings:
    return Settings()
