# PHP scanning without a target-specific profile

The CLI now selects its PHP taint sources/sinks from local template rules. See [template support](TEMPLATES.md) for supported syntax, loading omissions and provenance. The function/include analysis described here supplies the dataflow and source map.

Navi reads PHP source and tests the separately running application. No vulnerable filenames, routes, parameter names, security levels or database branches are built into its target selection. Its vulnerability rules and proof strategies are implemented in Python; PHP's tokenizer supplies syntax, not security findings.

```sh
.venv/bin/python -m navi scan --source /path/to/application \
  --target http://127.0.0.1:8000 --allow-method POST --ai
```

If the server serves `/path/to/application/public`, add `--document-root public`. This is deployment information, not a vulnerability mapping. Omit `--ai` to run all native analysis and proof without a model. Authentication still needs your session/login configuration; the scanner cannot know a new application's credentials.

## Source analysis

1. Tokenize `.php`, `.phtml` and `.inc` files without executing application code. Retain real source lines, snippets and named functions. Embedded HTML and `<?= ... ?>` output are handled.
2. Resolve literal `include`/`require`, `__DIR__`, `__FILE__`, `dirname`, concatenations and known scalar variables/constants. Includes propagate the caller's variables and load function definitions. Recursion and source scope are bounded. Unknown calls and dynamic, ambiguous or unavailable include paths produce coverage gaps; they never become guessed include edges.
3. Treat unreferenced scripts under the document root as possible public entry points. `index.php` also has a directory-index alias. Included libraries are analyzed through callers, and `.inc` files are not assumed to be public PHP routes. Source-only include groups retain findings without URL bindings. Script paths assume conventional file serving; custom rewrites/front controllers require an adapter and are not inferred.
4. Propagate request input through assignments, concatenation, array aliases, in-scope named functions, parameters, returns and included files. Supported sources include PHP request superglobals and literal `filter_input` selectors. Helpers in unrelated, unincluded files do not establish a source flow.
5. Check whether input reaches a SQL operation, HTML output, shell invocation, file operation or Location header without modeled protection. Numeric conversion, parameterized queries, contextual HTML encoding, shell argument quoting and literal file allowlists have different rules. Credential-like literals produce redacted Code only candidates. Unconditional returns/exits stop straight-line analysis.

SAST reports candidates, not execution proof. PHP methods are conservatively modeled as GET/POST; form inputs use POST, and runtime method policy still applies. Branches, dynamic dispatch and language semantics are approximate. Classes/namespaces, framework routing, autoloading, dynamic includes and persistent storage flows are not comprehensively modeled. Lack of a finding does not establish safety or unreachability.

Branch alternatives are joined by retaining common facts and unioning input flows; they are not concatenated as strings. Expression concatenation is tracked separately. String context and exact constant evaluation are limited to 4,096 characters. Losing context retains taint, reports a limitation and prevents contextual encoding/quoting from incorrectly suppressing a candidate. A truncated constant is never treated as a resolved include path. Deadline/cancellation checks run inside PHP statements and expressions.

## Runtime testing

Combined and URL-only scans crawl same-application HTML by default: up to **40 pages and 60 inputs**, with a default **1,000 HTTP requests and 300-second scan deadline**. The crawler starts at the target root, follows same-application links and redirects, and also visits source-derived scripts. It retains actual form values, hidden fields, one submit control and supported CSRF refresh settings. Explicit request seeds take precedence. Conflicting forms at one endpoint are reported as a workflow limitation.

Source candidates that match observed forms/links run first. Other source candidates and discovered inputs are then tested. Candidate deduplication uses CWE, path, method, input location and parameter. Reaching a limit records unfinished tests; it does not label them safe.

| Type | Required runtime evidence |
| --- | --- |
| SQL injection | Stable baseline plus repeated true/false SQL conditions changing results; reflection-normalized HTML comparison |
| XSS | The injected marker actually executes in isolated Chromium replay; missing Chromium means inconclusive |
| Command injection | Two independently encoded random markers execute, with negative decoding/reflection controls |
| Open redirect | Response Location accepts a unique external destination; the destination is never fetched |
| Traversal | Repeated retrieval of a configured disposable file's unique marker from outside the intended boundary |
| Hard-coded credential | Code only; no credential login attempt |

Redirect probes use generic external/scheme-relative URLs and, when available, the local destination observed in a form/query seed. There is no test-specific filename. These are bounded verifier families, not every possible exploit variation. IDOR needs identities and an access policy; stored XSS needs write/read/cleanup workflows; neither is inferred from an HTTP 200.

## Correlation

A Confirmed issue needs runtime proof and exactly one source operation with matching CWE, URL path, method, parameter and input location. The source binding must come from the analyzer, not solely a supplied PHP mapping. Matching source/runtime evidence becomes one issue, with the exact file/line/snippet, request/payload, link explanation and fix. Repeated scans retain the source operation's fingerprint.

Several matching operations remain ambiguous. Deployment identity is reported separately; a configured identity mismatch blocks merging. PHP links are explicitly described as source-map inferences, not runtime instruction traces. Server rewrites or unmodeled dispatch can invalidate a file-layout assumption, so the document root must match the deployment.

Optional Groq analysis explains existing evidence and suggests investigation/fixes. It cannot turn an unverified result or unsupported mapping into Confirmed. The existing five-attempt ceiling, including failed requests, is unchanged.

## Compatibility changes

- `php_routes` no longer filters the source files scanned. Such mappings add operator hypotheses; they do not independently justify automatic merging.
- `php_switches` and `php_platform` remain accepted for old config files but are ignored with a coverage notice. The scanner no longer selects a known training application's execution branch.
- Included-library resolution requires source evidence instead of globally selecting a same-named function.
- Discovery now runs by default in combined scans. Disable it explicitly with `"discovery": {"enabled": false}` when supplying an API-only request plan.

## Validation

`tests/test_php_generalization.py` checks randomized names, nested and ambiguous includes, function scope, input aliases, safe controls, templates, stable IDs and incorrect-link boundaries.

`tests/test_php_acceptance.py` generates a separate PHP application with randomized names and form controls. Its subprocess test executes actual PHP and shell commands, discovers inputs without request seeds, checks protected/reflection controls and repeats the scan. This bridge does not emulate or claim real HTTP header handling.

The same suite has a separate real PHP HTTP server test for discovered POST command injection and an observed-destination redirect. Run it on your machine:

```sh
.venv/bin/python -m pytest tests/test_php_acceptance.py -ra
```

The suite also checks actual PHP/PDO SQLite queries with a discovered, randomized baseline and actual browser execution of PHP-rendered XSS when those dependencies are available. On Debian/Kali, the SQL fixture requires the matching `php-sqlite3` package; the scanner itself does not require that driver to inspect another application's PHP source. XSS execution requires the installed Playwright Chromium browser.

It starts only a temporary test fixture and stops it afterward; this is developer validation, not part of the scanner's target lifecycle. Restricted environments that prohibit listening sockets report that test as skipped. Missing PDO SQLite or Chromium also produce explicit skips. Independent applications and reviewed answer keys are required to measure external recall and wrong-link rates.
