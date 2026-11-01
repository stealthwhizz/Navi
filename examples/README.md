# Examples and regression fixtures

These small applications are intentionally included because the test suite and acceptance helpers use them. They are not a default scan target and are not included in the installed Python wheel.

| Directory | Purpose |
|---|---|
| `config/generic.json` | Adaptable request/discovery configuration with AI disabled |
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
