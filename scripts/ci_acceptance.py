"""Start the real FastAPI/demo services, run full acceptance, and clean up."""

import os
from pathlib import Path
import subprocess
import sys
import time
import runpy
import threading
from tempfile import TemporaryDirectory
import urllib.error
import urllib.request


def main():
    database = os.getenv("TEST_DATABASE_URL") or os.getenv("DATABASE_URL")
    if not database:
        raise SystemExit("TEST_DATABASE_URL or DATABASE_URL is required for full acceptance.")
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))
    artifacts = root / "artifacts" / "acceptance"
    artifacts.mkdir(parents=True,exist_ok=True)
    environment = {**os.environ,"DATABASE_URL":database}
    from showcase_fixture import prepare_showcase
    from werkzeug.serving import make_server
    with TemporaryDirectory(prefix="navi-acceptance-") as temporary, (artifacts / "server.log").open("w") as log:
        source = prepare_showcase(temporary)
        app = runpy.run_path(str(source / "app.py"))["app"]
        target = make_server("127.0.0.1", 5050, app, threaded=True)
        worker = threading.Thread(target=target.serve_forever, daemon=True); worker.start()
        process = subprocess.Popen([sys.executable,"-m","navi","serve","--source",str(source),"--target","http://127.0.0.1:5050","--config",str(source / "policy.json"),"--output",str(artifacts)],cwd=root,env=environment,stdout=log,stderr=subprocess.STDOUT)
        try:
            for _ in range(80):
                if process.poll() is not None:
                    raise RuntimeError("Service exited during startup; see artifacts/acceptance/server.log.")
                try:
                    with urllib.request.urlopen("http://127.0.0.1:8080/health",timeout=1) as response:
                        if response.status == 200:
                            break
                except (OSError, urllib.error.URLError):
                    time.sleep(.25)
            else:
                raise RuntimeError("Service did not become ready; see artifacts/acceptance/server.log.")
            subprocess.run([sys.executable,str(root / "scripts/smoke_api.py")],cwd=root,env=environment,check=True,timeout=300)
        finally:
            target.shutdown(); target.server_close(); worker.join(timeout=5)
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=5)


if __name__ == "__main__":
    main()
