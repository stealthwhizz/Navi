# Laravel source and runtime scans

Point `--source` at the application repository root and `--target` at its running deployment:

```sh
.venv/bin/python -m navi plan --source /path/to/laravel --target http://127.0.0.1:8000 --allow-method POST
.venv/bin/python -m navi scan --source /path/to/laravel --target http://127.0.0.1:8000 --allow-method POST --no-ai
```

Navi detects conventional `routes/` plus `app/Http/Controllers/`, or a Composer requirement for `laravel/framework`. It uses PHP's tokenizer without running Composer, Artisan, controllers or application bootstraps during SAST. `vendor/` is excluded. Framework rules are native and remain enabled in both scanner modes; `--sast-rules` customizes the procedural PHP interpreter, not Laravel rules. HTTP template selection still controls DAST families.

## Supported source paths

- Literal routes in `routes/web.php` and `routes/api.php`: GET, POST, PUT, PATCH, DELETE, HEAD, `match` and `any`.
- Controller arrays (`[OrderController::class, 'show']`), invokable controllers, string `Controller@method` actions and function closures.
- Namespace/import resolution, nested literal prefix groups, and controller groups, inherited actions and statically typed controller/service method calls (including constructor-promoted properties).
- Typed `Illuminate\Http\Request` inputs, direct request properties, the `request()` helper, Request aliases and path parameters. Query, form, JSON, header and cookie locations remain distinct.
- Conventional `resource`/`apiResource` routes, nested resources, `only`/`except` and literal parameter overrides.
- FormRequest `validated()` values and literal validation rules: integer/numeric/boolean protections are modeled; required/string alone do not prevent injection.
- DB facade and Eloquent raw SQL, direct query-builder chains and builder variables. Bound SQL parameters and ordinary builder value bindings are not reported as SQL injection.
- PHP shell functions and string commands passed to `Process::run`; fixed argument arrays and appropriate shell quoting are modeled separately.
- PHP file operations, File facade reads, and `response()->file/download` paths. Standard Flysystem-backed Storage reads enforce a disk boundary; `Storage::path` passed to an unrestricted file operation still carries input taint.
- HTML controller returns/responses and direct view-variable flows into Blade. Escaped text and quoted attributes are distinguished from raw output, unquoted attributes and script contexts. JSON/plain-text responses are not HTML XSS sinks.
- Redirect helper/facade destinations. Fixed local prefixes and named route generation are distinguished from user-controlled external destinations.

The adapter records original file/line/snippet locations, including Blade output locations, with source-derived route bindings. Unresolved controller registrations retain source-only candidates without invented URLs. The default PRD policy confirms native runtime proof matched to one source-derived candidate with the same CWE, route, method, input location, and parameter. Optional strict policy also requires a complete modeled value-flow graph, authenticated operation/input traces, and matching deployed source identity; see [accuracy setup](ACCURACY.md).

`routes/api.php` uses the conventional `/api` prefix. If your application changes it, configure:

```json
{"laravel": {"api_prefix": "/service"}}
```

Observed concrete links/forms can supply path seeds: `/orders/123` maps to a unique source route `/orders/<id>`. OpenAPI converter annotations such as `<int:id>` are aligned to the source spelling when unambiguous.

## Runtime prerequisites

Use your app's valid login/cookies, tokens and request values in `--config`; Navi does not guess credentials. Discovered forms refresh hidden controls before probes. GET is enabled by default; enable POST/PATCH/etc. as needed. Use local OpenAPI JSON when pages do not expose API inputs.

XSS execution proof needs a working Chromium installation:

```sh
.venv/bin/python -m playwright install chromium
```

Traversal proof needs a disposable known file outside the intended public directory. For example, after creating your own test file and choosing a marker of at least 12 characters:

```json
{
  "requests": {"GET /download": {"query": {"file": "welcome.txt"}}},
  "traversal_fixtures": [{
    "route": "/download",
    "parameter": "file",
    "location": "query",
    "payload": "../private-test.txt",
    "marker": "YOUR_UNIQUE_TEST_FILE_MARKER"
  }]
}
```

Use your actual route, parameter, boundary-crossing payload and marker. Without this fixture, source candidates are retained and traversal verification is explicitly inconclusive.

## Limits

This is a bounded source adapter, not a Laravel execution engine. Dynamic resource registration, custom pluralization, route providers/custom route files, optional routes, middleware/policy semantics, implicit model binding, container interface bindings, runtime property mutation and complete framework control flow remain unsupported or approximate. Anonymous self-closing Blade components support direct variable props; slots, class components and arbitrary expressions remain incomplete. Configure the actual API prefix and runtime inputs where automatic discovery is insufficient. A listed route is a source inference, not an execution trace.

Validation includes generated Laravel source fixtures, protected controls, randomized names, and actual PHP controller/shell/file/redirect execution through minimal test-only facade shims. Those shims are not the Laravel framework and are not a live HTTP integration test. Browser, real Laravel deployment and service checks require a capable host; see [validation](../VALIDATION.md).
