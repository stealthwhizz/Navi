# Validation

Navi **0.6.0**, report schema **1.2**. Validation recorded on 1 November 2026.

## Python and PHP

The latest full engine run passed **555 tests**, with **14 skipped** and no failures. It covers:

- Native source/rule analysis, runtime verification controls, evidence exports, API behavior, and scan identity.
- Exact source/input bindings, per-input flow graphs, all five injection/file/redirect CWE families, same-line operations, sanitized siblings, unknown flows, trace replay/conflicts, and mandatory matching build identity.
- Authenticated setup, ID/token extraction, failed prerequisites, fresh object IDs after discovery, cancellation, and cleanup.
- Laravel inherited actions, typed services, resource/controller-group routes, FormRequest protections, Eloquent raw expressions, and supported anonymous Blade props.
- A scan-to-report flow executing real SQLite through in-process Flask HTTP, with signed operation/input evidence.
- PHP middleware HMAC interoperability, request-local state, and trace overflow using request/response doubles.
- Precision/recall evaluation, incomplete truth sets, crossed source links, and exclusion of provisional links from confirmed-link scores.

These include real SQL and PHP execution, but in-process HTTP and framework doubles are not live-network or booted-Laravel validation.

## Unavailable integration checks

| Prerequisite | Skipped checks |
|---|---:|
| Working Chromium launch | 11 |
| Permission to listen on a loopback socket | 1 |
| PHP PDO SQLite driver | 1 |
| PostgreSQL configured through `TEST_DATABASE_URL` | 1 |

A booted Laravel deployment was not available. The GitHub Actions workflow provisions the browser, PHP/SQLite, and PostgreSQL for its own integration run; a successful hosted CI run has not been claimed here.

## Frontend and packaging

A static UI export and TypeScript check passed using the cached compatibility toolchain: Next.js 14.2.35, React 18.3.1, Framer Motion 12.42.2, and TypeScript 5.9.3. The checked-in UI declares a Next.js 16 dependency set; installation and build of that exact set remain unvalidated on this host. Browser rendering was not verified.

The engine wheel was built and extracted outside the repository. A source-only scan verified schema 1.2, source-flow evidence, included Laravel middleware, and zero HTTP/AI requests. Generated wheels, exported UI assets, raw scan reports, and historical build logs are local artifacts rather than source-repository contents.

## External-source sample

The [reviewed DVWA source benchmark](benchmarks/README.md) found **4/4 vulnerable SQL/command operations** and reported **0/4 protected controls** in four hash-pinned files. It made no HTTP or AI requests. Its answer key and runner are included; the DVWA checkout is supplied separately.

This is a small, previously available source sample. It does not measure runtime recall, source-link accuracy, full-application coverage, or performance on unseen applications.

## Reproduce

```sh
python -m pip install -e '.[test]'
python -m pytest -ra --junitxml=artifacts/test-results.xml
```

Build the dashboard with `npm ci`, `npm run typecheck`, and `npm run build` in `UI/`. Run `scripts/ci_acceptance.py` only with a test PostgreSQL service and the necessary live HTTP/browser prerequisites; it creates its own disposable target.

For source benchmarking:

```sh
PYTHONPATH=. python benchmarks/run_source.py \
  --source /path/to/DVWA --output artifacts/dvwa-source-benchmark
```

Older saved scans retain their original confirmation semantics. New runs require the stricter [source attribution evidence](docs/ACCURACY.md).

## Repository cleanup verification

The cleaned working directory and a fresh source-only Git checkout each passed **555 tests with 14 prerequisite-related skips**. The fresh-copy run completed in 45.67 seconds. A wheel built from that copy includes the Markdown README and Laravel middleware and excludes test applications, local credentials, reports, and generated UI assets. Relative documentation links and Git whitespace checks pass. The publication file set was also checked for values from the local credential file; none were present.

No external application checkout is required by the test suite. Full third-party targets, historical reports, and local environment files are outside the publication file set.
