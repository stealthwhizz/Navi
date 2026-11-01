from __future__ import annotations

import io
from pathlib import Path
import runpy

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def no_ambient_database(monkeypatch):
    # Integration tests opt in through TEST_DATABASE_URL; never reuse a user's
    # unrelated DATABASE_URL merely because it exists in their shell.
    monkeypatch.delenv("DATABASE_URL", raising=False)
    # Tests must never import real keys or service settings from the user's .env.
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "1")
    monkeypatch.delenv('GROQ_API_KEY', raising=False)
    monkeypatch.delenv('OPENAI_API_KEY', raising=False)


@pytest.fixture
def connect_app(monkeypatch):
    """Exercise real HTTP encoding against Flask in process when socket binding is restricted."""
    def connect(app):
        app.logger.disabled = True
        class Connection:
            def __init__(self, *args, **kwargs):
                pass

            def request(self, method, url, body=None, headers=None):
                result = app.test_client(use_cookies=False).open(url, method=method, data=body, headers=headers)
                self.response = io.BytesIO(result.data)
                self.response.status = result.status_code
                self.response.getheaders = lambda: list(result.headers.items())

            def getresponse(self):
                return self.response

            def close(self):
                pass
        monkeypatch.setattr("navi.transport.http.client.HTTPConnection", Connection)
        return app
    return connect


@pytest.fixture
def shop(connect_app):
    return connect_app(runpy.run_path(str(ROOT / "examples/shop/app.py"))["app"])


@pytest.fixture
def source(tmp_path):
    def write(code: str):
        path = tmp_path / "app.py"
        path.write_text(code)
        return tmp_path
    return write
