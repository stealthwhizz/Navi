# AI correlation

Existing projects that explicitly selected OpenAI retain their setting. Add `--ai-provider groq` when scanning to select Groq's default model and key variable together. Explicit OpenAI compatibility remains available through `--ai-provider openai`; the two keys are never substituted for each other. For `ai-check`, select the provider with `--provider` instead.

Enable AI with `--ai` or a project created using `init --ai`. Navi loads `GROQ_API_KEY` from `.env` in the launch directory, without overriding existing environment variables or expanding values. The model defaults to `openai/gpt-oss-20b` on Groq.

## Normal scan

1. Native code analysis maps functions, input flows, and suspicious operations.
2. Native runtime verifiers establish or withhold proof.
3. Native correlation merges supported source/runtime pairs. One Groq request reviews the resulting issues and supplies concise correlation, noise, and priority reasoning.

Every issue has `reasoning.native`; reviewed issues also have `reasoning.ai`. The CLI and supplied UI display these together. An omitted or rejected AI review never removes a finding. Prompt limits can leave some findings unreviewed; the review count is shown explicitly.

AI cannot overwrite native verification, merge ambiguous operations, waive a deployment mismatch, prove unreachability from missing call edges, or declare reproduced runtime behavior safe. Responses must satisfy strict schemas and cite supplied issue, evidence, candidate, and source references. A suggested source location remains an investigation lead when the native cause is unresolved.

## Budgets and failures

- Normal workflow: one correlation request.
- Hard maximum: five attempts per scan, including failed connections; no retries.
- Defaults: 4000 estimated whole-prompt tokens and 2000 completion tokens; estimation is approximate.
- Reported token quotas can cause bounded waiting before the next request.
- HTTP 413 or 429 stops further AI calls. Completed native evidence is retained.
- No key or invalid provider response: native reasoning remains available.

The optional `ai-check` command makes one small, separate provider request using synthetic readiness data; it does not scan an application or measure model quality.

## Data supplied

Groq receives bounded, redacted source excerpts and function/input/evidence references. Raw HTTP bodies, request values, authentication headers, and cookies are not sent as evidence context. Source secret redaction is best effort. Source windows omitted to fit the prompt remain unknown, not evidence that validation is absent.

The API key remains in `.env` or the process environment, never in project JSON. `.env` is excluded from builds. Tests disable real dotenv loading and use synthetic provider responses.

## Advanced opt-in workflow

`ai.workflow: "full"` retains five capabilities: source hypotheses, native-test suggestions, correlation, remediation, and coverage advice. It is not the normal scan flow. Suggested tests use existing native verifiers and scope constraints; model-generated commands and arbitrary payloads cannot be executed. Patches are proposals, never automatically applied or tested.

Source-free scans skip the two source stages. Runtime-only reviews cannot invent source files or code patches. Full native evidence remains in the exported report even when AI advice is unavailable.

## Groq transport

The provider is Groq, using `https://api.groq.com/openai/v1/chat/completions`, JSON output and strict local schema/reference validation. Configure `--ai-model` or `ai.model`; the default is `openai/gpt-oss-20b`. No request is made unless AI is enabled. The key is resolved server-side from `GROQ_API_KEY`; it never reaches the frontend. Error responses are summarized without exposing raw account details or credentials. The UI displays accepted `reasoning.ai` as **AI analysis**, together with provider/model, and explains disabled, unavailable or unreviewed states.

Official provider reference: https://console.groq.com/docs/openai . Documentation retrieval was blocked by DNS in this workspace; implementation validation uses synthetic provider responses, not live account/model access.

## Diagnose unavailable AI

`navi ai-check --offline` reports the selected key variable/source, whether a process value differs from `.env`, and known placeholder/provider-format problems. It makes zero requests and prints no key characters or fingerprint. Plain `navi ai-check` makes one small Groq request without application data. HTTP 401 is authentication rejection, distinct from HTTP 429 rate limits; it requires a valid API credential. The scanner reports both the reason and corrective steps, and preserves native correlation and findings. Restart the server after updating `.env`; process environment values intentionally take precedence.
