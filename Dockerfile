FROM node:22-bookworm-slim AS frontend
WORKDIR /frontend
COPY UI/package.json UI/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY UI/ ./
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

FROM python:3.13.7-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 NAVI_CHROMIUM=/usr/bin/chromium
RUN apt-get update && apt-get install -y --no-install-recommends chromium php-cli git ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml README.md requirements.runtime.lock ./
COPY navi ./navi
COPY --from=frontend /frontend/out ./navi/web/ui
RUN pip install --no-cache-dir -r requirements.runtime.lock && pip install --no-cache-dir --no-deps . && useradd --create-home --uid 10001 navi && mkdir /app/artifacts && chown navi:navi /app/artifacts
USER navi
EXPOSE 8080
CMD ["python", "-m", "uvicorn", "navi.api:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
