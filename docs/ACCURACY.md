# Accuracy configuration and evidence

Runtime verification and source attribution are independent. A real runtime vulnerability remains `verification: verified` when its source cause cannot be established. Each new report records `correlation.policy`, and each issue records `source_link.policy` and `source_link.basis`.

## Correlation policies

The default **`prd`** policy implements the CyberForge PRD's source/runtime matching: native runtime proof, the same CWE, and exactly one source-derived candidate with the same route, HTTP method, input location and parameter. It merges the pair into **Confirmed** without requiring target instrumentation, a complete flow graph, or a build endpoint. This is an evidence-based match, not independently established execution attribution.

The optional **`strict`** policy additionally requires a complete modeled input-to-sink graph, signed version-2 operation/input traces, and matching deployment identity. Select it with `--correlation-policy strict` on `scan` or `serve`, or in scan configuration:

```json
{"correlation": {"policy": "strict"}}
```

Both policies reject ambiguous candidates, operator-only mappings, unsupported stored-XSS source associations, unverified HTTP template matches, known build mismatches and conflicting/rejected traces. An explicitly configured `build` endpoint must match even in PRD mode; enabled tracing with `required: true` must supply valid exact traces. Missing optional evidence is reported as unknown, never as a passed check. Selecting strict does not install instrumentation or enable tracing automatically.

| `source_link.status` | Evidence | Issue behavior |
|---|---|---|
| Confirmed source link | The selected policy's matching requirements pass | Source/runtime evidence merged into Confirmed; policy and basis recorded |
| Probable source link | Reproduced behavior and a unique supported candidate; a required flow, trace or build check is incomplete | Separate verified Runtime only issue and Code only candidate |
| Runtime only | No supported candidate, ambiguity, conflicting traces or mismatched build | Runtime proof retained without a selected source cause |

A standalone source candidate has `source_link.status: Code only`. The `status` field is retained for integrations. Use `--fail-on-verified-high` in CI to gate verified runtime vulnerabilities regardless of source attribution. `--fail-on-confirmed-high` follows the selected correlation policy. AI opinions never promote these states. Existing saved reports are not reclassified; older reports without a policy field retain the semantics under which they were generated.

The graph is built from per-input value propagation in the native analyzers. It records HTTP binding → input read → expressions/helper/service propagation → sensitive operation → associated runtime observations. Unresolved transformations and graph bounds (64 nodes / 128 internal edges per input value) mark paths incomplete. PRD correlation edges are labeled `prd_input_correlation`; only authenticated operation/input observations receive `authenticated_input_attribution` edges. Branch feasibility, aliases, dynamic dispatch and storage flows remain bounded; a complete modeled graph is not proof that every language behavior is understood.

## Fresh authenticated workflows

Use existing `session.login`, cookies, `form_refresh` and OpenAPI input configuration for valid requests. A workflow can create a disposable record, extract its ID/token and substitute those values into probes and cleanup:

```json
{
  "allowed_methods": ["GET", "POST", "DELETE"],
  "workflows": [{
    "id": "order",
    "page": "/orders/<order_id>",
    "steps": [{
      "path": "/orders",
      "method": "POST",
      "json": {"name": "scanner test record"},
      "expect_status": [201],
      "extract": {"order_id": {"json": "data.id"}, "token": {"header": "x-csrf-token"}}
    }],
    "cleanup": [{
      "path": "/orders/<order_id>",
      "method": "DELETE",
      "headers": {"X-CSRF-Token": {"$var": "token"}}
    }]
  }],
  "requests": {
    "GET /orders/<id>": {
      "workflow": {"id": "order"},
      "path": {"id": {"$var": "order_id"}},
      "headers": {"X-CSRF-Token": {"$var": "token"}},
      "query": {"filter": "open"}
    }
  }
}
```

Adapt the paths, success statuses and fields to your application's contract. JSON extraction supports dotted object paths and numeric array indexes; header and hidden-form-field extraction are also supported. Extracted values are bounded scalars. `{"$var":"name"}` preserves the value's type and is an entire JSON value, not string interpolation. Path placeholders use extracted variables or explicit `path_values` in setup/cleanup steps.

Setup runs once for a native check's related probes, then cleanup runs. Missing variables, failed success checks or extraction failures withhold dependent probes. Cleanup gets a separate maximum of four HTTP requests and a 15-second cooperative deadline, including after cancellation; transport timeouts still apply. Cleanup failures appear as coverage gaps. Session renewal may consume those requests. Discovery carries unambiguous extracted IDs into later setup sessions; use explicit request mappings for ambiguous IDs or custom URLs.

`browser: {"external_scripts": true, "max_scripts": 8}` enables bounded GET script fetches through the same scoped authenticated transport. Only the target origin and base path are allowed. CSP is preserved; redirects, other origins and non-script browser traffic remain blocked. This covers some external-script DOM flows, not arbitrary browser login, cookie-dependent JavaScript, XHR or full SPA workflows. With browser verification unavailable, XSS remains inconclusive.

## Laravel runtime instrumentation

The optional [NaviTrace middleware](../navi/integrations/laravel/NaviTrace.php) emits request-bound HMAC traces. Copy it into the application's middleware directory and register it around the tested controller execution using your Laravel version's middleware registration. It stores state on the request, so worker reuse does not carry operations across requests.

Add `config/navi.php` with `trace_key` from a server-side environment variable and `source_digest` from the deployed artifact. For example:

```php
<?php
return [
    'trace_key' => env('NAVI_TRACE_KEY'),
    'source_digest' => env('NAVI_SOURCE_DIGEST'),
];
```

Set the same random shared key of at least 32 bytes in the scanner's `NAVI_TRACE_KEY`. Do not put the key in scan JSON or client-controlled headers. Use the application's normal configuration caching process.

Add a marker at each instrumented sensitive operation, on the branch where the identified input actually reaches that argument:

```php
NaviTrace::record($request, 'OPERATION_ID_PLACEHOLDER',
    'app/Services/Lookup.php', 42, 'CWE-89',
    [['location' => 'query', 'parameter' => 'id']]);
```

Replace the placeholder with the source finding's 20-character `id` from a source-only `navi scan` report, and replace file/line with that finding's exact sink location. Insert markers before generating IDs; replacing a placeholder string preserves token position. Generate a final source-only report after replacements and verify IDs and locations still agree. Deploy those exact files, then set the deployed source digest to the final report's `source_digest`. Keep the digest in deployment configuration to avoid a self-referential source hash. Source IDs can change when surrounding token structure changes: regenerate markers as part of the instrumentation build.

Markers must be developer-controlled and adjacent to the actual operation. Do not mark only controller entry, infer all operations from the requested route, or copy operation IDs/inputs from request headers. The middleware signs what instrumentation records; it is not automatic PHP taint tracking and cannot establish the correctness of a wrongly placed marker.

Expose a build endpoint that returns the artifact's actual immutable digest, such as `{"source_digest":"..."}`, and configure the scan:

```json
{
  "correlation": {"policy": "strict"},
  "build": {"path": "/internal/build", "kind": "source_digest"},
  "trace": {"enabled": true, "required": true, "key_env": "NAVI_TRACE_KEY"}
}
```

The scanner sends a random `X-Navi-Request-ID`. The response contains `X-Navi-Trace` (base64url JSON) and `X-Navi-Trace-Signature` (hex HMAC-SHA256 of that encoded string). Version 2 binds the nonce, HTTP method, concrete path, analyzed source digest, completion flag and up to 32 operations. Each operation includes exact ID, relative file, line, CWE and attributed input location/name. Oversized/truncated, replayed, mismatched or rejected traces cannot confirm links. Version-1 file/line traces are diagnostic only. `required: false` allows PRD matching when traces are absent; strict policy still requires exact execution traces.

A signed trace is trusted execution instrumentation, not an exploit oracle or independent build attestation. Native reproduction is still required. Both the configured build endpoint and the trace digest must agree with scanned source. Do not expose staging source-location evidence unintentionally on a public deployment.

## Independent measurement

Use `navi evaluate report.json --answer-key truth.json` after scanning. Answer keys are consumed only by the evaluator. It reports source/runtime precision, source/runtime recall, confirmed-link accuracy, paired-link recall, wrong-link rate and known-decoy issue share. Probable links are listed separately and never counted as confirmed correct links. A precision score is unavailable when unmatched findings meet an incomplete truth set; do not count unknown findings as correct or false.

For each CWE, include vulnerable cases and closely related protected controls. Include repeated parameter names, helper/service paths, same-line operations, different HTTP locations, unknown transformations, wrong build identities and missing/replayed traces. Ground truth needs independently reviewed operation locations and input bindings. Keep instrumented markers consistent with that review rather than deriving runtime execution claims from scanner candidates.

A separate unseen application must have a different snapshot and an independently produced answer key. Local regression fixtures and hand-authored examples do not establish accuracy on unseen applications. No full-application or unseen runtime precision/recall score is claimed by this change. See [evaluation commands](PRODUCT_GUIDE.md) and [validation results](../VALIDATION.md).

A small [reviewed DVWA source benchmark](../benchmarks/README.md) is included separately from generated regression fixtures. Its pinned sample found four vulnerable SQL/command operations and reported none of four protected controls. These counts cover only the selected files and CWE families; runtime verification and source-link accuracy are unmeasured for that corpus.
