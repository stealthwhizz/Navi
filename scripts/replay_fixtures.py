"""Generate reviewable fixture reports without opening a network socket.

Uses the real Flask applications and verifiers via Flask's in-process HTTP client.
Browser execution is disabled explicitly; no browser or database success is simulated.
"""

import io
from pathlib import Path
import runpy
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from navi.engine import scan
from navi.runtime import load_config


def main():
    for name in ["shop", "library"]:
        source = ROOT / "examples" / name
        app = runpy.run_path(str(source / "app.py"))["app"]
        app.logger.disabled = True
        class InProcessConnection:
            def __init__(self, *args, **kwargs):
                pass

            def request(self, method, url, body=None, headers=None):
                response = app.test_client().open(url, method=method, data=body, headers=headers)
                self.response = io.BytesIO(response.data)
                self.response.status = response.status_code
                self.response.getheaders = lambda: list(response.headers.items())

            def getresponse(self):
                return self.response

            def close(self):
                pass
        output = ROOT / "artifacts" / name
        config = load_config(str(source / "policy.json")); config["interval"] = 0
        with patch("navi.transport.http.client.HTTPConnection", InProcessConnection):
            report = scan(source, "http://127.0.0.1:5050", config, output, browser=False)
        print(f"{name}: {report['summary']} · {output / 'report.html'}")
    print("Validation mode: in-process Flask requests; browser disabled; exports only, no PostgreSQL connection.")


if __name__ == "__main__":
    main()
