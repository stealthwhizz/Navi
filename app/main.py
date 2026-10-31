from contextlib import asynccontextmanager
from pathlib import Path
from typing import Callable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from app.api.issues import router as issues_router
from app.api.reports import router as reports_router
from app.api.routes import router as routes_router
from app.api.scans import router as scans_router
from app.api.suppressed import router as suppressed_router
from app.db import create_session_factory
from app.settings import Settings, get_settings

SessionFactory = Callable[[], object]


def create_app(
    settings: Settings | None = None,
    session_factory: SessionFactory | None = None,
    ui_dir: Path = Path("UI/out"),
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if app.state.settings is None:
            app.state.settings = get_settings()
        if app.state.session_factory is None:
            app.state.session_factory = create_session_factory(app.state.settings.database_url)
        yield

    app = FastAPI(title="Navi API", version="0.1.0", lifespan=lifespan)
    app.state.settings = settings
    app.state.session_factory = session_factory
    for router in (scans_router, issues_router, routes_router, suppressed_router, reports_router):
        app.include_router(router)

    @app.get("/", include_in_schema=False)
    def root():
        return RedirectResponse("/ui/")


    @app.get("/health", include_in_schema=True)
    def health(request: Request):
        try:
            with request.app.state.session_factory() as session:
                session.execute(text("SELECT 1"))
        except Exception:
            return JSONResponse(
                status_code=503,
                content={"status": "degraded", "database": "unavailable"},
            )
        return {"status": "ok", "database": "ok"}

    if ui_dir.is_dir():
        app.mount("/ui", StaticFiles(directory=ui_dir, html=True), name="ui")
    return app


app = create_app()
