# Templates executed by Navi

Laravel repositories use the native [Laravel adapter](LARAVEL.md) in both scanner modes. The PHP taint template settings below apply to procedural PHP. HTTP templates still select runtime probes for all supported target languages.

Navi 0.4 runs its own PHP taint analyzer and HTTP template interpreter. It does not import, launch, install, or contact Semgrep or Nuclei. PHP CLI provides syntax tokens; PyYAML loads local rules. Browsers remain optional for execution-based XSS proof. Template files are declarative inputs, not standalone detection engines.

## Select a pack

```sh
navi scan --source /path/to/php-app --target http://127.0.0.1:8000 \
  --allow-method POST --ai --ai-provider groq

# Replace the defaults with locally reviewed template files/directories.
navi scan --source /path/to/php-app --target http://127.0.0.1:8000 \
  --sast-rules /path/to/php-rules.yaml --dast-templates /path/to/http-pack \
  --allow-method POST --ai --ai-provider groq
```

`--sast-rules` and `--dast-templates` are repeatable and replace the respective default pack. Scan configuration can persist them:

```json
{
  "scanners": {
    "mode": "templates",
    "semgrep_rules": ["rules/php.yaml"],
    "nuclei_templates": ["rules/http"]
  },
  "ai": {"enabled": true, "provider": "groq", "model": "openai/gpt-oss-20b", "max_requests": 5}
}
```

Paths in this JSON resolve relative to the configuration file; CLI paths resolve from the working directory. Names `semgrep_rules` and `nuclei_templates` identify formats, not executable dependencies. There are no binary/executable settings. Empty lists disable template coverage for that side without silently restoring built-in detectors.

`navi plan` accepts the same selection flags and lists accepted IDs, SHA256 file fingerprints, and unsupported features without target or AI requests. `navi doctor` checks pack readiness. Each scan report retains a `templates` manifest; normal progress prints one count per scanner. The CLI and server launched through it default to templates. Direct Python callers retain native mode for compatibility; pass the configuration above to opt into templates. `--scanner native` selects the existing built-in rules, which also do not use external scanners.

## PHP rule interpretation

Navi parses the rule's sources, sinks and sanitizers, tokenizes PHP, follows assignments and named helper calls/exact includes, and propagates request-input taint. A finding requires an input permitted by that rule to reach its selected sink argument without a modeled protection. Changing a rule changes detection. Source mapping and correlation are still Navi logic.

Example using supported Semgrep-style fields:

```yaml
rules:
  - id: local.php.sql
    languages: [php]
    mode: taint
    message: Request input reaches a SQL operation
    severity: ERROR
    metadata:
      cwe: CWE-89
    pattern-sources:
      - pattern: $_GET[...]
      - pattern: $_POST[...]
    pattern-sinks:
      - patterns:
          - pattern: mysqli_query($DB, $SQL, ...)
          - focus-metavariable: $SQL
    pattern-sanitizers:
      - pattern: intval($VALUE)
```

| PHP feature | Support |
|---|---|
| PHP taint rules with explicit CWE metadata | Supported |
| Request superglobals, literal input selectors, supported `filter_input` | Supported |
| Direct function calls, `$DB->query(...)`, output/include syntax, backticks | Supported; receiver type is not established |
| Metavariable arguments, trailing ellipsis, focused sink argument | Supported; metavariables select arguments rather than full structural matching |
| `pattern-either`, simple pattern plus sink focus | Supported |
| Return-value sanitizer calls | Supported; declarations are trusted and can suppress findings |
| Search/regex-only rules, nested structural patterns, negations, arbitrary constraints, repeated-metavariable equality, side-effect sanitizers, options | Entire rule skipped with a reason |
| Dynamic dispatch, general class/framework routes, arbitrary includes | Existing PHP analysis limitations remain explicit |

This is **not Semgrep compatibility**. Supported patterns are compiled into Navi source/sink semantics, not Semgrep's full matcher. Navi's numeric and context-sensitive escaping models still apply; `escapeshellarg` does not suppress a shell finding in an unsafe interpreter/quoting context. The independent credential-literal detector remains native and labels its scanner accordingly. Python/Flask analysis remains native; these YAML SAST rules apply to PHP only.

## HTTP request interpretation

Ordinary HTTP templates cause actual target requests using Navi's scoped transport. Response matchers decide whether a detection signal is recorded. These do not depend on the native proof-driver extension described below.

```yaml
id: local.reflection-signal
info:
  name: HTML reflection requiring execution validation
  severity: medium
  classification:
    cwe-id: CWE-79
http:
  - path: ["{{BaseURL}}"]
    fuzzing:
      - part: query
        type: replace
        mode: single
        fuzz: ["<probe-{{randstr}}>"]
    matchers:
      - type: word
        words: ["<probe-{{randstr}}>"]
```

| HTTP feature | Support |
|---|---|
| Method/path/headers/body or raw HTTP/1.1 text | Supported; Navi owns connection framing |
| `BaseURL`, `RootURL`, host/path variables, `randstr`, scalar variables, `url_encode(variable)` | Supported |
| One inline payload list, single query/body-input fuzzing, replace/prefix/postfix, exact keys | Supported; discovered method, hidden fields and submit controls are retained |
| Status, word, restricted regex, and/or/negative matchers | Supported |
| DSL comparisons/booleans, `contains`, `contains_all/any`, `len`, case conversion, `regex` | Interpreted by an allowlisted AST; no Python `eval` |
| Indexed responses within a block and `req-condition` | Supported; matching waits until the last request |
| Flow/JavaScript/code/headless/network protocols, extractors, external payload files, cookie-reuse controls, arbitrary DSL/helpers | Entire template skipped with a reason |
| Redirect following, external callbacks or origin/base-path escape | Not executed |

`BaseURL` is the current discovered endpoint (or application root for explicit path lists). `RootURL` stays inside the configured application base, including mounted paths. This deliberately differs from templates that expect access to an entire host. Fuzz templates require the `{{BaseURL}}` path and cannot override the discovered request headers/body. An HTTP method must be enabled in Navi's policy. `stop-at-first-match` stops the current request sequence; other discovered inputs can still be tested. A template with no concrete input does not invent a parameter or payload: the full request URL/body remains its evidence.

Resource limits: 200 YAML files, 256 KiB/file, 4 MiB/pack, directory traversal bounded to 5,000 entries/path, 500 PHP rules/pack, 10 HTTP blocks/template, 10 paths/block, 30 payloads/list, 20 matchers/block, plus Navi's shared request/time budgets. YAML aliases, anchors and duplicate keys are rejected. Regex patterns are limited to 300 characters, one quantifier, no backreferences/lookarounds/repeated groups/counted repeats, and the first 8,192 characters of the selected response part. These bounds limit detection coverage. Unsupported expressions and budget exhaustion are recorded rather than reported as a clean scan.

## Matches, proof, and correlation

The starter pack contains two ordinary HTTP templates (SQL error and HTML reflection signals), plus five **Navi-specific proof drivers** for SQL injection, XSS, shell injection, traversal and redirects. A proof driver declares `info.metadata.navi-verifier`. It selects an existing Navi multi-request verifier; its placeholder HTTP block is not executed. This is an extension, not upstream Nuclei behavior. It preserves the stronger baseline/control/execution checks from earlier Navi versions. Traversal still needs a known test-file marker, browser XSS needs Chromium, and authentication still needs a session. Explicit stored-XSS and object-authorization workflows remain separate native checks.

Command probes and their non-command controls retain the discovered/configured input value, including form fields and session preparation values. They do not force an IP-address prefix. If no seed is available, the generic fallback is `1`; a real application may require a valid seed or authenticated workflow before testing can proceed.

Ordinary template matches retain `verification: template_match` and are displayed as unverified Runtime only signals. Reflection or an error message alone cannot establish exploitability. A source candidate plus a template match stays separate until independent runtime proof exists. Under the default PRD policy, once proof uniquely matches the source CWE, route, method, input location and parameter, Navi creates one Confirmed issue and attaches supporting template evidence. Strict policy additionally requires the flow, trace and build checks described in [accuracy setup](ACCURACY.md). Ambiguous source operations remain unresolved. Repeated scans retain stable IDs; accepted AI advice cannot change proof labels or fabricate a source link.

File/line/snippet, CWE, severity, URL/method/input, payload where known, request/response evidence, reasoning, fixes and prioritized reports are preserved. Exact counts and coverage may differ between packs. No pack guarantees detection of every testcase in an unseen PHP application.

## Provenance and upstream files

All files shipped under `navi/templates/packs/` are **original Navi examples**, licensed under the included MIT license. They have not been copied from the Semgrep registry or ProjectDiscovery repository. Upstream downloads could not be retrieved in this environment because DNS access was unavailable; no upstream commit or compatibility test is claimed.

You can supply selected local YAML files from [Semgrep rules](https://github.com/semgrep/semgrep-rules) or [Nuclei templates](https://github.com/projectdiscovery/nuclei-templates). Review the license at the exact upstream revision, retain its required notices and attribution, and record the revision before redistribution. Do not assume a scanner's license also covers every third-party pack. Run `plan` to see which selected files this interpreter actually supports. General upstream packs contain unsupported features and are not drop-in replacements.
