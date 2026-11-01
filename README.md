# Navi

**Navi is a web application security scanner that combines native static analysis, runtime vulnerability verification, and evidence-based source correlation.**

Analyze Python/Flask, procedural PHP, and Laravel source; test an independently running application; and inspect findings through a CLI, web dashboard, or portable reports. AI-assisted explanations are optional. Version **0.6.0** uses report schema **1.2**.

## What it does

- **Static application security testing (SAST):** tracks request inputs into sensitive operations, with source locations, modeled protections, helper/service propagation, and bounded data-flow graphs.
- **Dynamic application security testing (DAST):** discovers forms and links or imports local OpenAPI inputs, then runs native verification probes against the configured target.
- **Authenticated workflows:** supports login/cookies, fresh form and CSRF controls, request seeds, object creation, ID/token extraction, and cleanup.
- **Source attribution:** connects runtime evidence to source operations using exact input bindings, modeled flow, signed operation/input traces, and deployment identity.
- **Reports and triage:** preserves payloads, controls, source snippets, confidence checks, severity, stable IDs, scan history, and JSON, HTML, text, and SARIF exports.
- **Optional AI review:** Groq or OpenAI can explain existing findings and suggest investigation steps. Model output cannot establish runtime proof or force a source link.

Navi runs its own source analyzers and HTTP verifiers. It does not invoke Semgrep, Nuclei, or ZAP. Its local template interpreters support a documented subset of Semgrep-style PHP rules and Nuclei-style HTTP templates; the bundled starter pack is Navi-authored.

## Vulnerability coverage

| Weakness | Source analysis | Runtime verification |
|---|---|---|
| SQL injection — CWE-89 | Unsafe SQL construction and raw expressions | Repeated boolean comparisons and controls |
| Cross-site scripting — CWE-79 | Unsafe HTML and supported Blade contexts | JavaScript execution in Chromium response replay |
| Command injection — CWE-78 | Shell arguments and modeled quoting | Independent POSIX shell-marker probes |
| Path traversal — CWE-22 | User-controlled file paths | Configured boundary-crossing file and unique marker |
| Open redirect — CWE-601 | User-controlled destinations | Observed redirect to the supplied destination |
| Hard-coded credentials — CWE-798 | Credential-like literal candidates | Credential validity is not tested |
| Object authorization / IDOR — CWE-639 | No general authorization inference | Operator-defined identities, objects, and access rules |

Coverage is bounded. Read the [CWE matrix](docs/CWE_TEST_MATRIX.md), [PHP guide](docs/PHP_ANALYSIS.md), and [Laravel guide](docs/LARAVEL.md) for supported variants and gaps.

## Install

Requirements: Python 3.11+, PHP CLI with its tokenizer for PHP/Laravel analysis, and Chromium for XSS execution checks. Node.js 22+ is needed to build the optional dashboard. PostgreSQL is optional; file reports work without it.

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[browser]'
python -m playwright install chromium
```

For CLI-only source analysis, install with `pip install -e .`. Linux distributions may require browser system packages; see [setup and troubleshooting](docs/PRODUCT_GUIDE.md).

## Run a scan

Start your application separately and supply its URL. Use applications you own or have permission to test.

```sh
# Inspect the plan without contacting the target.
navi plan --source /path/to/application --target http://127.0.0.1:8000

# Combined source analysis and runtime checks.
navi scan --source /path/to/application --target http://127.0.0.1:8000 --no-ai

# Source analysis only.
navi scan --source /path/to/application --no-ai

# Runtime checks for an API without source.
navi scan --target http://127.0.0.1:8000 --openapi /path/to/openapi.json --no-ai

# Inspect a saved report without running another scan.
navi report artifacts/report.json
```

Supply `--config /path/to/scan.json` for authentication, valid input values, workflows, request budgets, and build identity. Start from [the generic configuration](examples/config/generic.json). GET is enabled by default; enable other methods explicitly, such as `--allow-method POST`. Non-loopback targets require their exact origin through `--allow-origin https://staging.example.com`.

For PHP applications serving a subdirectory, add `--document-root public`. For Laravel, pass the repository root. `navi init` saves project settings, `navi doctor` checks prerequisites, `navi compare` compares scans, and `navi evaluate` scores reports against separately supplied answer keys.

## How to interpret results

Runtime verification and source attribution are separate:

| Source-link state | Meaning |
|---|---|
| **Confirmed source link** | Native runtime proof, a complete modeled input-to-sink path, signed exact operation/input traces, and matching deployment identity. Source and runtime findings merge into a Confirmed issue. |
| **Probable source link** | Runtime behavior is verified and a source candidate exists, but attribution evidence is incomplete. Source and runtime findings remain separate. |
| **Runtime only** | No supported source cause was established. Check `verification`: an ordinary HTTP template match is not verified exploitability. |
| **Code only** | A source candidate has no confirmed source/runtime association. |

Optional [Laravel tracing middleware](navi/integrations/laravel/NaviTrace.php) is included. It requires integration at the actual sensitive operations; it does not automatically instrument an application. See [accuracy and tracing setup](docs/ACCURACY.md).

For CI, `--fail-on-verified-high` exits with failure on high/critical verified runtime findings. `--fail-on-confirmed-high` uses the stricter source-link requirement. An unobserved finding on a later scan is not proof of a fix.

## Dashboard and storage

```sh
cd UI
npm ci
npm run build
cd ..
navi serve --source /path/to/application --target http://127.0.0.1:8000
```

The FastAPI service serves the exported dashboard under `/ui/`. It exposes scan progress, cancellation, issue evidence, source routes, and report history. Set `NAVI_API_TOKEN` for protected workspace access. It is a single configured workspace, not a multi-tenant service.

Set `DATABASE_URL` for PostgreSQL history, or use the default filesystem reports. [Docker Compose](compose.workspace.yaml) provides the scanner and PostgreSQL with persistent volumes; it does not start the target application. See the [operating guide](docs/PRODUCT_GUIDE.md) and [UI guide](UI/README.md).

## Optional AI explanations

Copy `.env.example` to your local `.env` and configure `GROQ_API_KEY`, then add `--ai` to a scan. The default model is `openai/gpt-oss-20b`; `--ai-provider openai` selects the alternative provider and its corresponding key. `navi ai-check --offline` checks local credential selection without contacting a provider.

AI is disabled by default. Review uses bounded, redacted context and at most five provider attempts per scan. Native findings remain available if the provider fails. See [AI behavior](docs/AI.md).

## Repository layout

| Path | Contents |
|---|---|
| `navi/` | Scanner engine, analyzers, native verifiers, correlation, CLI/API, reports, storage, templates, and Laravel instrumentation |
| `UI/` | Next.js/React dashboard source and dependency lockfile |
| `tests/` | Unit, regression, and optional integration tests |
| `examples/` | Generic configuration and small intentionally vulnerable/protected test fixtures |
| `benchmarks/` | Hash-pinned external-source answer key and benchmark runner; target checkout supplied separately |
| `scripts/` | Setup, fixture replay, database checks, and CI acceptance helpers |
| `docs/` | Product description, architecture, operation, configuration, and coverage documentation |
| `.github/workflows/` | CI for Python, PHP, Chromium, frontend, and PostgreSQL checks |
| `Dockerfile`, `compose*.yaml` | Container build and workspace deployment |

Local `.env`, `.venv`, project settings, scan reports, build outputs, downloaded targets, and local archives are excluded from Git. The small test fixtures are retained because the test suite uses them; full third-party applications are not bundled.

## Development and validation

```sh
python -m pip install -e '.[test]'
python -m pytest -ra
```

Browser, live HTTP, PHP SQLite, and PostgreSQL checks need their respective prerequisites. Historical validation: **555 passed, 14 skipped** on the available host; see [current validation details](VALIDATION.md). The small reviewed DVWA source sample found four vulnerable operations and reported none of four protected controls. These results do not establish accuracy on unseen applications.

See [contributing](CONTRIBUTING.md), the [documentation index](docs/README.md), and the [architecture and report format](docs/ARCHITECTURE.md).

## License

A project-wide license has not been selected. The bundled template pack includes its own [MIT license](navi/templates/packs/LICENSE); that file does not specify a license for the rest of the repository.
