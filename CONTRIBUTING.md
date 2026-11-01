# Contributing

Navi's core contract separates source candidates, verified runtime behavior, and source attribution. Changes should preserve that distinction and report unsupported constructs or missing prerequisites as coverage gaps.

## Local setup

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[test]'
python -m playwright install chromium
python -m pytest -ra
```

PHP source tests require PHP CLI and its tokenizer. Live PHP SQL tests also need PDO SQLite. PostgreSQL tests opt in with `TEST_DATABASE_URL`; tests do not use an ambient `DATABASE_URL`. Missing browser or service prerequisites result in explicit skips.

For frontend changes:

```sh
cd UI
npm ci
npm run typecheck
npm run build
```

The checked-in lockfile is the declared frontend dependency set. See [validation](VALIDATION.md) for the toolchain that was available during local verification.

## Test and review expectations

- For detector changes, add meaningful vulnerable variants and closely related protected controls.
- For correlation changes, exercise exact input binding, deployment mismatch, incomplete flow, missing/replayed traces, and ambiguous operations.
- Keep answer keys and application-specific assumptions outside production analyzers and verifiers.
- Do not turn skipped or inconclusive checks into evidence of safety. AI review cannot change native verification or source-link decisions.
- Preserve stable finding IDs, evidence, cancellation behavior, and request/scope limits.
- Keep credentials, real application reports, external target checkouts, virtual environments, and build output out of commits.

The GitHub Actions workflow provisions PostgreSQL, PHP, Chromium, and the frontend before running the tests. `scripts/ci_acceptance.py` then starts a disposable fixture and checks the live API, persistence, runtime proofs, and repeat scans. It requires network sockets and a test database; it is not a command for an arbitrary user deployment.

## Package builds

Build the UI first when producing a wheel that should include the dashboard:

```sh
python -m pip install build
cd UI
npm ci
npm run build
cd ..
mkdir -p navi/web/ui
cp -R UI/out/. navi/web/ui/
python -m build
```

The CLI/API also work from source without a bundled UI. Generated exports and distributions are ignored. Before pushing, inspect `git status` and `git diff --cached`.
