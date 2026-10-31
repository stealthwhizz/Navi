# Navi

Navi is a project-owned PHP SAST/DAST correlation engine. `tree-sitter-php` provides syntax trees; Navi owns the detection and correlation rules. It does not run scanned PHP source and does not send findings to an AI service.

## Local run

1. Copy `.env.example` to `.env`; set a non-empty `POSTGRES_PASSWORD` and set `CYBERFORGE_SOURCE_PATH` to an existing PHP source directory.
2. Start DVWA locally for development and set `CYBERFORGE_ALLOWED_TARGET_ORIGIN` to the origin reachable from the backend container. The default uses host port 4280 via `host.docker.internal`; configure DVWA's port mapping to match. The source directory and running target must be the same app.
3. Run `docker compose up --build`.
4. Open `http://localhost:8000/ui/`. The API is same-origin; `/health` reports API and PostgreSQL readiness.

To use a shell-managed Python environment instead, install with `uv sync --extra dev`, export `CYBERFORGE_DATABASE_URL`, `CYBERFORGE_SOURCE_ROOT`, and `CYBERFORGE_ALLOWED_TARGET_ORIGIN`, apply `uv run alembic upgrade head`, then start the API with `uv run uvicorn app.main:app --reload` and the worker with `uv run python -m app.worker`.

## Scope and safety

- The API accepts only the exact `CYBERFORGE_ALLOWED_TARGET_ORIGIN`; redirects are never followed. The configured target must be a local/private HTTP origin. Do not configure production or third-party targets.
- Source paths must resolve within `CYBERFORGE_SOURCE_ROOT`; the container mounts the selected source read-only.
- The scored baseline is CWE-89, CWE-79, CWE-78, CWE-22, CWE-601, and CWE-798. IDOR/broken access control and PHP runtime/configuration inventory are not in the scored pipeline. Runtime inventory is a separate optional layer after the scored pipeline is complete.
- `Confirmed`, `Code only`, and `Runtime only` describe issue evidence. A runtime-only issue is not a runtime inventory assertion. Incomplete runtime evidence cannot confirm an issue.
- The organizer-provided application and answer key are not included. DVWA is the local development target; do not report organizer evaluation metrics from DVWA.
