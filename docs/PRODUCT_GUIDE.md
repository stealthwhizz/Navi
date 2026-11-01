# Run Navi against your application

Navi CLI scans default to local PHP taint rules and HTTP templates executed by Navi itself. See [template setup and limitations](TEMPLATES.md); Semgrep and Nuclei are not dependencies.

Navi is a CLI-first security scanner with a FastAPI workspace and PostgreSQL history. Detection, verification, function mapping, and correlation use native rules in this repository. Python's AST and PHP's tokenizer provide syntax; Chromium supplies JavaScript execution evidence. Optional Groq AI defaults to one post-scan request for correlation and per-finding reasoning. Advanced full mode adds source review, test suggestions, remediation and coverage, under the same hard limit of five requests per scan. It cannot replace native proof or source-link requirements. See [AI setup and behavior](AI.md); use `--ai` to enable `openai/gpt-oss-20b`.

The supported source adapters are bounded Python/Flask, procedural PHP, and Laravel. A FastAPI target can be tested through local OpenAPI import, page/form discovery, or configured runtime inputs, but its typed Python endpoint inputs do not yet have a source adapter. JavaScript frameworks, unsupported PHP/Laravel constructs, and arbitrary business rules require additional modeling. Read the [CWE matrix](CWE_TEST_MATRIX.md) before interpreting absence as safety.

Source is optional. Use `scan --target URL` for HTTP discovery or `scan --target URL --openapi openapi.json` for APIs. Verified target-only findings remain Runtime only. The sections below cover API inputs, scope, authentication, and source/build linking.

## Install and initialize

```sh
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[browser]'
python -m playwright install chromium
python -m navi init --source /path/to/application \
  --target http://127.0.0.1:5000 --config /path/to/scan.json
python -m navi doctor --project navi.json
python -m navi plan --project navi.json --save artifacts/plan.json
python -m navi scan --project navi.json --require-complete --fail-on-confirmed-high
```

For a system Python installation with a broken Playwright driver (for example, missing `/usr/share/nodejs/playwright/cli.js` on Kali), use the project environment:

```sh
python3 scripts/setup_environment.py
.venv/bin/python -m navi doctor
.venv/bin/python -m navi scan
.venv/bin/python -m navi serve
```

The default setup installs dependencies into `.venv` and needs internet access; it does not change OS Python packages. The optional `--reuse-installed` recovery mode reuses dependencies already installed for the invoking interpreter. Use the project environment consistently. Playwright driver startup and actual Chromium execution are separate checks.

Install PHP CLI with its tokenizer extension for PHP source analysis. The `doctor` command checks source limits, PHP, a single target HEAD request, Chromium startup, and configured PostgreSQL connectivity. It does not prove authentication or correct seeds. `plan` contacts no target; it lists actual native input/CWE candidates, skipped methods, prerequisites, function map, and configured workflow counts. Live discovery can add inputs later.

The generated project JSON has version, name, stable key, source, target, config, output. Paths are relative to that project file. With no `--source`, `--target`, or `--project`, commands use your `./navi.json` if present. Explicit `--source` or `--target` starts independently; add `--project` when you deliberately want to override a saved project. Projects can omit source for HTTP-only scanning and retain a local `openapi` path. `init --ai` stores the Groq configuration.

Each CLI scan saves `scans/<id>/{report.json,report.html,report.sarif,events.jsonl}` under the output root. The output root also has the latest copies for existing integrations. Archive directories are private to the running OS user. Response excerpts may contain application data; protect the output root and database as security evidence. Configure a retention policy through your existing filesystem/database administration.

## Read and explain results

`scan` shows SAST findings, DAST findings, common format/route mapping, correlation and AI, duplicate merging, then prioritized issues with reasoning. Text and HTML reports follow the same order. Add `--verbose` for every check and reason. `report [report.json]` explains an existing scan without running tests or using Groq; without a path it reads the project's latest report. `--json-events` still emits JSON events on stdout, with the human explanation on stderr.

See [accuracy and tracing](ACCURACY.md), [the report format](ARCHITECTURE.md#report-format), and [CWE coverage](CWE_TEST_MATRIX.md) for verification rules and limitations. AI request count, full-prompt size, and token throughput are separate budgets; HTTP 413/429 are provider failures and do not invalidate completed native proofs.

## API inputs and discovery

Combined and target-only scans discover bounded same-application forms and links. Discovery does not infer API schemas from JavaScript bundles or perform arbitrary SPA/browser login flows. Use a local OpenAPI 3 JSON file or explicit runtime inputs when forms do not expose the application inputs:

```sh
navi plan --target http://127.0.0.1:8000 --openapi openapi.json
navi scan --target http://127.0.0.1:8000 --openapi openapi.json \
  --allow-method POST --config scan.json
```

The importer supports query parameters, scalar path parameters, and flat JSON/form bodies. Bounded local `$ref` references are resolved; external references and document `servers` never change the target or cause network access. OpenAPI YAML, nested/array/composed request schemas, and multipart uploads are unsupported and reported as gaps.

Examples, defaults, and enums can seed requests, but actual valid object IDs and required fields should come from your application. OpenAPI `/api/orders/{id}` becomes `/api/orders/<int:id>` for integer schemas, or `/api/orders/<id>` otherwise. Request settings use that normalized route and uppercase method. For example:

```json
{
  "allowed_methods": ["GET"],
  "discovery": {"enabled": false},
  "requests": {
    "GET /api/orders/<int:id>": {
      "path": {"id": 123},
      "query": {"filter": "open"},
      "headers": {"Authorization": {"$env": "APP_TEST_AUTHORIZATION"}}
    }
  },
  "runtime_inputs": [
    {"route": "/api/orders/<int:id>", "method": "GET", "parameter": "filter", "location": "query"}
  ]
}
```

Set `APP_TEST_AUTHORIZATION` to the complete header value. Route-specific headers are not inherited by crawler requests; use session login/cookies for authenticated discovery or disable discovery and supply API inputs. A login page, nonexistent record, or unstable baseline can make verification inconclusive. See [fresh ID/token workflows](ACCURACY.md#fresh-authenticated-workflows).

## Configure request scope and evidence

A minimal scan configuration for staging:

```json
{
  "scope": {"allowed_origins": ["https://staging.example.com"]},
  "limits": {"max_seconds": 300},
  "timeout": 4,
  "max_requests": 250,
  "interval": 0.05,
  "allowed_methods": ["GET"],
  "build": {"path": "/health/build", "kind": "git", "header": "X-Build-Revision"},
  "requests": {
    "GET /search": {"query": {"q": "notebook"}, "headers": {"Authorization": {"$env": "APP_TEST_AUTHORIZATION"}}}
  },
  "runtime_inputs": [{"route": "/search", "method": "GET", "parameter": "q", "location": "query"}],
  "discovery": {"enabled": true, "paths": ["/"], "prefixes": ["/"], "max_pages": 20, "max_candidates": 30}
}
```

Set `APP_TEST_AUTHORIZATION` to the complete authorization value in the scanner process. Any JSON value of the form `{"$env":"NAME"}` resolves from that environment; missing variables fail configuration. The planner and workspace state do not return request seeds or credentials. Discovery does not automatically inherit route-specific headers: use `session` login/cookies for a crawler session or supply explicit inputs for token-authenticated endpoints.

Loopback targets are accepted by default. Every other target needs its **exact scheme, host, and port** in `scope.allowed_origins`. The target may include an application base path. Connections pin the resolved numeric address, use the original hostname for TLS certificate verification/SNI, ignore proxy environment variables, and do not follow redirects. Private CAs can use `scope.ca_file`, relative to the scan config. TLS verification cannot be disabled. Link-local, unspecified, multicast, and mixed loopback/nonloopback DNS answers are rejected.

Build matching supports:

- `{"path":"/__navi__/build"}`: JSON `source_digest` equal to the startup snapshot digest computed for the exact scanned directory.
- `{"path":"/health/build","kind":"git","field":"revision"}`: JSON revision equal to the **clean, tracked local checkout's full HEAD**.
- `{"path":"/health/build","kind":"git","header":"X-Build-Revision"}`: the same revision from a response header.

The default `prd` policy confirms native runtime proof paired with a unique source-derived CWE/route/method/input match. Select `--correlation-policy strict` (or `"correlation": {"policy": "strict"}` in configuration) to additionally require complete modeled flow, signed operation/input traces, and matching deployment identity. Build matching is optional in PRD mode, but an explicitly configured `build` endpoint must match; enabled tracing with `required: true` must also pass. Missing optional evidence stays unknown. See [accuracy setup](ACCURACY.md). The deployment must report its immutable build identity, never reflect a request value. A source digest covers supported `.py`, `.php`, `.phtml` and `.inc` files (including Blade PHP templates), not dependencies. Git matching requires a clean checkout and is rechecked after scanning. A signed trace authenticates the configured instrumentation; it is not independent attestation of a compromised server.

`requests` supplies valid baseline query/form/JSON/path inputs, route headers, CSRF refresh, and session preparation. Add POST explicitly only for intended test workflows. `traversal_fixtures` requires a known unique marker and boundary-crossing payload for a disposable private test file. `stored_xss` requires write/read/cleanup recipes. `authorization` requires verified identities and explicit resource rules; the engine cannot infer who should own arbitrary business data. See [workflow configuration](ACCURACY.md#fresh-authenticated-workflows) and `examples/shop/policy.json`.

## Budgets, interruption, and CI

`limits.max_seconds` defaults to 300 (range 1–3600). Requests default to 250, bounded response bodies to 1 MB. Source limits are 5000 supported files, 2 MB/file, and 50 MB total. Narrow large monorepos to an application root.

Ctrl-C requests cancellation. The active API scan can be stopped from the dashboard or `POST /api/scans/{id}/cancel`. Completed findings remain in a `partial` report with `stop_reason`. These are cooperative limits: DNS lookup, a single AST parse, and browser/OS calls can finish before the next check. Browser calls have their own timeouts. After a stored-XSS write, the explicitly configured cleanup can use up to 15 extra seconds and four extra requests; failure remains a visible gap. Database connections, lock acquisition, and statements have separate timeouts. Crash recovery and resumable jobs are not implemented.

Exit codes: `0` finished (inspect coverage), `1` high/critical Confirmed issue under the selected correlation policy with `--fail-on-confirmed-high`, `2` configuration/operation failure, `3` incomplete coverage with `--require-complete`, deadline reached, or unmet requested evaluation thresholds; `130` cancelled. Use both scan flags in CI. Use `--fail-on-verified-high` to include high/critical Runtime only proofs in the exit-1 gate, especially for target-only scans.

```sh
python -m navi compare artifacts/scans/OLD/report.json artifacts/scans/NEW/report.json
```

Comparison requires the same project/target. Results are `new`, `still_observed`, and `not_observed`; absence is not proof of a fix.

## PostgreSQL and a protected workspace

```sh
export DATABASE_URL='postgresql://navi:URL_ENCODED_PASSWORD@127.0.0.1:5432/navi'
export NAVI_API_TOKEN="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python -m navi migrate
python -m navi serve --project navi.json
```

Open the URL printed by `serve` and use **Access key**. The default reserves the first available port in 8080–8089; an explicit `--port` must be available, and `--port 0` asks the OS for any available port. Existing listeners are left running. The token stays in the browser tab's memory and is sent as a Bearer header. All evidence endpoints, API operations, and OpenAPI docs require it when configured. The static login shell and minimal health endpoint are public. The API still requires `X-Navi: local-scan` on mutations and rejects cross-origin mutations. For scripted calls include both headers.

To put the workspace behind your HTTPS reverse proxy, use `--host 0.0.0.0 --allowed-host security.example.com`. Nonlocal CLI binding and custom hosts require a token. Forward the configured Host; set token headers for API clients. This is a single shared team workspace, not per-user accounts/RBAC. Run **one worker per instance**; use your CI scheduler for isolated concurrent CLI jobs.

[`compose.workspace.yaml`](../compose.workspace.yaml) runs this workspace and PostgreSQL against your existing app, with read-only source/config mounts and persistent report/database volumes. Set `NAVI_SOURCE_DIR`, `NAVI_SCAN_CONFIG`, `NAVI_TARGET`, `NAVI_PROJECT_KEY`, `NAVI_API_TOKEN`, and a URL-safe `POSTGRES_PASSWORD`, then:

```sh
docker compose -f compose.workspace.yaml up --build -d
```

A target must be reachable **from the container**; a host's loopback application is best scanned by the CLI on the host. Set any environment variables referenced in your scan config on the scanner service as well. For Git matching, the mounted source must contain the tracked checkout metadata; otherwise use a source-digest endpoint. The default `compose.yaml` includes the same product workspace; neither starts the target.

PostgreSQL stores scan JSONB, stable issues, occurrences, and access experiments. Migration is idempotent and transactional. Database failure retains file reports and marks persistence/coverage incomplete. Configure backups and disk capacity using normal PostgreSQL operations.

## Benchmark evaluation

```sh
python -m navi evaluate artifacts/shop/report.json \
  --answer-key examples/answer-keys/shop.json --save artifacts/shop/evaluation.json
```

The evaluator is independent of scanning. Its key requires `version: 1`, `dataset: {name, provenance, partition}`, `complete`, and `cases`. Each case has `id`, `kind` (`paired`, `code_only`, `runtime_only`, or `decoy`), CWE, and source/runtime anchors. A source anchor is exact relative file + line, optionally function. Runtime anchors use route + method + parameter + location. Duplicate operation/input anchors are rejected to prevent inflated recall. See the manually written shop key for the full format.

Source and runtime detections are scored independently; a Confirmed link is correct only if its constituent findings match the same paired case. Crossed links therefore fail even when both scanners have 100% recall. Scores include source/runtime precision and recall, confirmed-link accuracy, paired-link recall, wrong links / Confirmed links, known-decoy issues / all issues, and elapsed scan/report-generation time. A linked decoy is a false alarm, not a link joining two different bugs. Timing includes initial report generation; final database save and export metadata refresh are excluded and identified in `timing_scope`. Missing denominators and unassessed links remain unknown. No unseen score is inferred from a local/provided app. `--require good` / `--require great` uses the evaluator's strict `>` / `<` thresholds and exits 3 when required metrics are absent or fail.

To evaluate a supplied app plus an independent unseen app together, add `--unseen-report /path/to/second/report.json --unseen-answer-key /path/to/second-key.json`. The second key must declare partition `unseen`; reusing the same scan/source snapshot is rejected. Main-app metrics remain separate from the unseen pair score.

A partial key measures only its enumerated cases. Accuracy on other applications requires separately reviewed datasets, including an unseen holdout. `examples/answer-keys/shop.json` is a local regression example; it does not establish external benchmark qualification.
