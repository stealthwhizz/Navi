"""FastAPI application; one local scan worker, progressive events, PostgreSQL history."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from dataclasses import dataclass
import os
import secrets
from pathlib import Path
import threading
from urllib.parse import urlsplit
import uuid

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response, RedirectResponse
from pydantic import BaseModel, ConfigDict

from .control import ScanControl
from .engine import scan
from .lab import AccessLab
from .model import fingerprint
from .report import portable_html, sarif
from .runtime import load_config
from .store import Store
from .transport import validate_target


@dataclass
class Settings:
    source: str | None = None
    target: str | None = None
    config_path: str | None = None
    output: str = "artifacts"
    database_url: str | None = None
    browser: bool = True
    project_key: str | None = None
    ai: dict | None = None
    scan_config: dict | None = None
    api_token: str | None = None
    allowed_hosts: tuple[str, ...] = ()
    ui_dir: str | None = None

    @classmethod
    def environment(cls):
        return cls(source=os.getenv("NAVI_SOURCE") or None, target=os.getenv("NAVI_TARGET") or None,
                   ui_dir=os.getenv("NAVI_UI_DIR"), config_path=os.getenv("NAVI_CONFIG"), output=os.getenv("NAVI_OUTPUT", "artifacts"),
                   database_url=os.getenv("DATABASE_URL"), browser=os.getenv("NAVI_BROWSER", "1") != "0", project_key=os.getenv("NAVI_PROJECT_KEY"),
                   ai=({**({"enabled": os.environ["NAVI_AI"] == "1"} if "NAVI_AI" in os.environ else {}), **({"model": os.environ["NAVI_AI_MODEL"]} if "NAVI_AI_MODEL" in os.environ else {})} or None),
                   api_token=os.getenv("NAVI_API_TOKEN"), allowed_hosts=tuple(h.strip() for h in os.getenv("NAVI_ALLOWED_HOSTS", "").split(",") if h.strip()))


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ExperimentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    resource_id: str
    actor: str
    compare: bool = False


def create_app(settings: Settings | None = None) -> FastAPI:
    from .environment import load_environment
    load_environment()
    settings = settings or Settings.environment()
    local_hosts = {"127.0.0.1", "localhost", "::1", "testserver"}
    allowed_hosts = local_hosts | {host.lower() for host in settings.allowed_hosts}
    if any(not host or any(c in host for c in "/@* ") or (":" in host and host != "::1") for host in allowed_hosts):
        raise ValueError("Allowed hosts must be exact hostnames without ports or wildcards.")
    if allowed_hosts - local_hosts and not settings.api_token:
        raise ValueError("Custom dashboard hosts require NAVI_API_TOKEN.")
    if settings.api_token and (len(settings.api_token) < 32 or not settings.api_token.isascii() or any(c.isspace() for c in settings.api_token)):
        raise ValueError("NAVI_API_TOKEN must contain at least 32 ASCII characters without whitespace.")
    from copy import deepcopy
    config = deepcopy(settings.scan_config) if settings.scan_config is not None else load_config(settings.config_path)
    if settings.source is None:
        config.setdefault("discovery", {"enabled": True, "paths": ["/"], "prefixes": ["/"], "max_pages": 20, "max_candidates": 30})
    if settings.ai is not None: config["ai"] = {**config.get("ai", {}), **settings.ai}
    from .runtime import validate_scan_options
    validate_scan_options(config)
    from .ai.config import options as ai_options
    options = ai_options(config.get("ai"))
    project = fingerprint(settings.project_key or (str(Path(settings.source).resolve()) if settings.source else "target-only"), settings.target or "static-only")
    lock = threading.RLock()
    state = {"running": False, "scan_id": None, "report": None, "events": [], "sequence": 0, "error": None, "database": "unconfigured", "control": None}
    store = Store(settings.database_url) if settings.database_url else None
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="navi-scan")

    @asynccontextmanager
    async def lifespan(app):
        if store:
            try:
                store.migrate()
                state["report"] = store.previous(project)
                state["database"] = "connected"
            except Exception:
                state["database"] = "unavailable"
        yield
        with lock:
            if state["control"]: state["control"].cancel()
        executor.shutdown(wait=True, cancel_futures=True)

    app = FastAPI(title="Navi", version="0.3.1", lifespan=lifespan,
                  description="Native security verification against the configured local test application.")
    app.state.scan_state = state
    app.state.settings = settings

    @app.middleware("http")
    async def local_api(request: Request, call_next):
        # Exact Host allowlist, bearer authentication, and explicit browser write intent.
        hostname = request.url.hostname
        if hostname not in allowed_hosts:
            return JSONResponse({"detail": "This Host is not configured for the workspace."}, status_code=400)
        if settings.api_token and not request.url.path.startswith("/ui/") and request.url.path not in {"/", "/style.css", "/app.js", "/health"}:
            supplied = request.headers.get("authorization", "")
            expected_token = "Bearer " + settings.api_token
            if not secrets.compare_digest(supplied.encode(), expected_token.encode()):
                return JSONResponse({"detail": "Workspace access key required."}, status_code=401,
                                    headers={"WWW-Authenticate": "Bearer", "Cache-Control": "no-store"})
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            origin = request.headers.get("origin")
            expected = f"{request.url.scheme}://{request.url.netloc}"
            if origin and origin != expected:
                return JSONResponse({"detail": "Cross-origin scan requests are not accepted."}, status_code=403)
            if request.headers.get("x-navi") != "local-scan":
                return JSONResponse({"detail": "Set X-Navi: local-scan."}, status_code=403)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    def event_callback(event):
        with lock:
            phase = {"scan_started": "sast", "analysis": "sast", "build": "dast", "check": "dast", "correlation_started": "correlate"}.get(event["type"])
            if phase: state["phase"] = phase
            state["sequence"] += 1
            state["events"].append({"sequence": state["sequence"], **event})
            state["events"] = state["events"][-500:]

    def execute(scan_id, control):
        try:
            report = scan(settings.source, settings.target, config, Path(settings.output) / "scans" / scan_id,
                          browser=settings.browser, callback=event_callback, database_url=settings.database_url, scan_id=scan_id, project_key=settings.project_key, control=control)
            with lock:
                state["report"] = report
                state["database"] = "connected" if report["persistence"] == "postgresql" else "unavailable" if store else "unconfigured"
        except Exception as error:
            # Exception messages can contain connection strings or configured credentials.
            with lock:
                state["error"] = f"Scan failed ({type(error).__name__}). Check source/configuration and local target availability."
            event_callback({"scan_id": scan_id, "type": "scan_failed", "data": {"message": state["error"]}})
        finally:
            with lock:
                state["running"] = False

    @app.get("/health")
    def health():
        database = "unconfigured"
        if store:
            try:
                database = "connected" if store.health() else "unavailable"
            except Exception:
                database = "unavailable"
        return JSONResponse({"status": "ok" if database == "connected" else "degraded", "database": database}, status_code=200 if database == "connected" else 503)

    @app.get("/api/state")
    def current_state():
        with lock:
            return {"running": state["running"], "scan_id": state["scan_id"], "report": state["report"], "error": state["error"],
                    "database": state["database"], "source": str(Path(settings.source).resolve()) if settings.source else None, "target": settings.target,
                    "browser_enabled": settings.browser, "ai": {"enabled": options["enabled"], "provider": options["provider"], "model": options["model"], "workflow": options["workflow"], "request_limit": options["max_requests"], "key_configured": bool(os.getenv(options["api_key_env"]))}, "event_sequence": state["sequence"],
                    "cancelling": bool(state["running"] and state["control"] and state["control"].event.is_set())}

    @app.post("/api/scans", status_code=202)
    def start_scan(body: ScanRequest):
        if not settings.source and not settings.target:
            raise HTTPException(422, "Configure an application source directory or target URL before scanning.")
        if settings.target:
            try: validate_target(settings.target, config.get("scope", {}).get("allowed_origins", []))
            except ValueError as error: raise HTTPException(422, str(error)) from None
        with lock:
            if state["running"]:
                raise HTTPException(409, "A scan is already running.")
            scan_id = uuid.uuid4().hex
            control = ScanControl(config.get("limits", {}).get("max_seconds", 300))
            from datetime import datetime, timezone
            state.update(running=True, scan_id=scan_id, error=None, events=[], control=control, phase="sast", started=datetime.now(timezone.utc).isoformat())
            executor.submit(execute, scan_id, control)
        return {"id": scan_id, "status": "running"}

    @app.post("/api/scans/{scan_id}/cancel", status_code=202)
    def cancel_scan(scan_id: str):
        with lock:
            if state["scan_id"] != scan_id or not state["running"]:
                raise HTTPException(409, "That scan is not running.")
            state["control"].cancel()
        return {"id": scan_id, "status": "cancelling"}

    @app.get("/api/events")
    def events(after: int = 0):
        with lock:
            return {"events": [event for event in state["events"] if event["sequence"] > after], "sequence": state["sequence"], "running": state["running"]}

    def latest():
        with lock:
            report = state["report"]
        if not report:
            raise HTTPException(404, "No completed scan yet.")
        return report

    @app.get("/api/scans")
    def history():
        if store:
            try:
                return store.history(project)
            except Exception:
                raise HTTPException(503, "PostgreSQL history is unavailable.")
        report = state["report"]
        return [{"id": report["id"], "started": report["started"], "summary": report["summary"], "status": report["status"]}] if report else []

    @app.get("/api/scans/{scan_id}")
    def get_scan(scan_id: str):
        with lock:
            if state["report"] and state["report"]["id"] == scan_id:
                return state["report"]
            if state["scan_id"] == scan_id and state["running"]:
                return JSONResponse({"id": scan_id, "status": "running"}, status_code=202)
        if store:
            try:
                result = store.get(scan_id)
            except Exception:
                raise HTTPException(503, "PostgreSQL history is unavailable.")
            if result and result["project"] == project:
                return result
        raise HTTPException(404, "Scan not found in this workspace.")

    @app.get("/api/issues")
    def issues(status: str | None = None, cwe: str | None = None):
        return [i for i in latest()["issues"] if (status is None or i["status"] == status) and (cwe is None or i["cwe"] == cwe)]

    @app.get("/api/worklist")
    def worklist():
        report = latest()
        if "worklist" not in report:
            from .worklist import build_worklist
            from copy import deepcopy
            return build_worklist(deepcopy(report))
        return report["worklist"]

    @app.get("/api/ai")
    def ai_review():
        return latest().get("ai", {"enabled": False, "status": "disabled"})

    @app.get("/api/function-map")
    def function_map():
        return latest()["function_map"]

    @app.get("/api/lab")
    def lab_catalog():
        return AccessLab(settings.source, settings.target, config).catalog()

    @app.post("/api/lab/experiments")
    def experiment(body: ExperimentRequest):
        try:
            result = AccessLab(settings.source, settings.target, config, project_key=settings.project_key).experiment(body.resource_id, body.actor, body.compare)
        except ValueError as error:
            raise HTTPException(422, str(error))
        result["persistence"] = "not saved"
        if store:
            try:
                store.migrate()
                result["persistence"] = "postgresql"
                store.save_experiment(result)
            except Exception:
                result["persistence"] = "not saved; PostgreSQL unavailable"
        event_callback({"type": "experiment", "time": result["created"], "data": {"id": result["id"], "outcome": result["before"]["outcome"], "comparison": bool(result["after"])}})
        return result

    @app.get("/api/lab/experiments")
    def experiment_history():
        if not store:
            return []
        try:
            return store.experiments(project)
        except Exception:
            raise HTTPException(503, "Experiment history is unavailable.")

    @app.get("/api/issues/{issue_id}")
    def issue_detail(issue_id: str):
        result = next((i for i in latest()["issues"] if i["id"] == issue_id), None)
        if result is None:
            raise HTTPException(404, "Issue not found.")
        return result

    @app.get("/api/report.json")
    def json_report():
        return JSONResponse(latest(), headers={"Content-Disposition": 'attachment; filename="navi-report.json"'})

    @app.get("/api/report.sarif")
    def sarif_report():
        return JSONResponse(sarif(latest()), headers={"Content-Disposition": 'attachment; filename="navi-report.sarif"'})

    @app.get("/api/report.html")
    def html_report():
        return HTMLResponse(portable_html(latest()), headers={"Content-Disposition": 'attachment; filename="navi-report.html"'})

    from .ui import install_api
    install_api(app, settings, project, state, lock, get_scan, history)
    from fastapi.staticfiles import StaticFiles
    web = Path(__file__).parent / "web"
    bundled_ui = web / 'ui'
    ui_dir = Path(settings.ui_dir) if settings.ui_dir else (bundled_ui if bundled_ui.is_dir() else Path(__file__).resolve().parent.parent / 'UI' / 'out')
    if (ui_dir / 'index.html').is_file():
        app.mount('/ui', StaticFiles(directory=ui_dir, html=True), name='ui')

    @app.get("/", include_in_schema=False)
    def index():
        if (ui_dir / 'index.html').is_file(): return RedirectResponse('/ui/')
        return HTMLResponse('<h1>Navi</h1><p>Build the supplied UI: <code>cd UI &amp;&amp; npm ci &amp;&amp; npm run build</code>, then restart the server.</p>')

    return app
