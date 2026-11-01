# Examples and regression fixtures

These small applications are intentionally included because the test suite and acceptance helpers use them. They are not a default scan target and are not included in the installed Python wheel.

| Directory | Purpose |
|---|---|
| `config/generic.json` | Adaptable request/discovery configuration with AI disabled |
| `config/dvwa-low.json` | Authenticated DVWA low-level requests for SQL injection, command injection, and reflected XSS |
| `shop/` | Flask fixture with vulnerable and protected SQL, HTML, file, redirect, and object-authorization paths |
| `library/` | A second Flask/SQLite fixture using different routes and helper-based SQL flow |
| `php_shell/` | Vulnerable and protected PHP command-execution fixtures |
| `answer-keys/` | Evaluation truth for local examples; scanners never consume these keys |

Fixture identities, tokens, marker files, and private-object fields are synthetic test data. Run intentionally vulnerable fixtures only in a controlled local test environment.

To replay the Flask examples without opening a listening socket:

```sh
python scripts/replay_fixtures.py
```

This executes real Flask handlers and native checks through in-process HTTP. It writes ignored reports under `artifacts/`; it does not validate real network transport, browser execution, or PostgreSQL.

Full third-party targets such as DVWA are kept outside this repository. Supply a separate checkout to the [external benchmark runner](../benchmarks/README.md).

For a running DVWA instance, `config/dvwa-low.json` reads `DVWA_USERNAME` and
`DVWA_PASSWORD` from your environment. It obtains a fresh login CSRF token, keeps
the session cookies, selects the `low` security cookie for that session, and checks
the security page before sending probes. It supplies valid baseline values and
the required `Submit` controls to the actual application pages.

```sh
# Use these credentials only if your local DVWA uses its stock demo account.
export DVWA_USERNAME=admin
export DVWA_PASSWORD=password
.venv/bin/python -m navi scan --target http://127.0.0.1:4285 \
  --config examples/config/dvwa-low.json --no-ai
```

Run this command from the repository root after initializing DVWA's database.
Replace the demo credentials if you changed them. Add `--source /path/to/DVWA`
for source analysis too, or replace `--no-ai` with `--ai` for optional AI review.
Without source, discovery is disabled and only the four configured inputs are
tested. With source, source-derived candidates are tested as well. Chromium is
needed to verify reflected XSS. This configuration does not cover other security
levels, stored XSS, traversal, or authorization workflows, and does not supply
deployment identity or sink instrumentation required by the optional strict correlation policy. Default PRD confirmation needs a unique source-derived CWE/route/method/input match and native runtime proof; configuring a runtime input alone does not establish a source link.
