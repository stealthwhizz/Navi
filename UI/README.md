# Navi dashboard

The Next.js/React dashboard presents the scanner's FastAPI data: scan progress, cancellation, prioritized issues, source and request evidence, source-link checks, routes, and report history. It has no mock-result fallback.

## Build

Use Node.js 22 or later and the checked-in dependency lockfile:

```sh
npm ci
npm run typecheck
npm run build
```

The static export is generated in `UI/out/` and served under `/ui/`. Node is needed to build or develop the UI, not to serve the exported pages.

From the repository root:

```sh
navi serve --source /path/to/application \
  --target http://127.0.0.1:8000 --config /path/to/scan.json
```

FastAPI finds `UI/out/` in a source checkout or the packaged `navi/web/ui/` directory. `NAVI_UI_DIR` selects another export. Set `NAVI_API_TOKEN` for protected workspace access and enter it in the dashboard's workspace-access control; the token is held in browser memory.

For frontend development, run `npm run dev`; `NAVI_API` can select the local FastAPI backend used by the development proxy.

## API integration

- `/api/scans` starts and cancels scans within the server's configured workspace.
- `/api/ui/scans` supplies history and progress.
- `/api/ui/issues` supplies native/AI reasoning and source/runtime evidence.
- `/api/ui/routes` supplies source mappings and tested inputs.
- `/api/ui/reports/{id}` downloads complete JSON evidence.

The dashboard uses the target, source, authentication, and scope configured at server startup. It does not start the target application. File-backed history works without PostgreSQL. Missing evidence remains explicit, and source attribution is independent of runtime verification.

Build output, dependencies, generated TypeScript declarations, and caches are ignored by Git. See [validation](../VALIDATION.md) for the exact toolchain previously verified; the declared Next.js 16 dependency set requires its own installation/build check.
