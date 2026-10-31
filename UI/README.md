# Navi

Navi's web interface lets you start a scan, watch it run, and review what the engine found and why. Built with Next.js 16, React 19, and TypeScript as a static export (`output: 'export'`). Node is needed only to develop and build; the built files are plain HTML, CSS, and JS that FastAPI serves.

**Status:** screens are built against the shared API contract and use live backend data; the UI contains no mock data. FastAPI serves this static export under `/ui/`. If the backend is unavailable or misconfigured, pages show the API error state.

## Screens

| Page | What it does |
|---|---|
| `/ui/` Dashboard | One scan at a glance: an animated pipeline driven by the backend's actual phase (route discovery, source analysis, runtime testing, evidence correlation, deduplication, final report); real SAST/DAST finding counts converge at correlation when persisted results arrive. During a scan only the reported phase is active; no partial finding stream is published by the API. Also shows scan time against the 15-minute budget and coverage gaps; the issue mix (Confirmed, Code only, Runtime only, Suppressed as safe) as a proportional bar with counts that open the filtered list; "Fix first", the top issues in priority order (confirmed first, then risk) with route and file:line; and issues by vulnerability type for the six PRD CWEs. Polls while a scan runs. With no scans, or with `?new=1`, it shows the new scan form (source directory and test app address, errors under each field). |
| `/ui/issues/` Issues | The prioritised triage list (FR-9): search by title, route, or file; filter by status and CWE; live status and newly confirmed badges while a scan runs; report download once it completes. |
| `/ui/issue/?id=` Issue detail | Why the issue has its status: each correlation check (CWE match, route mapping, code path, parameter, method and input) marked passed, failed, or unknown, with the reason. Code evidence: file, source and sink, snippet with the vulnerable line highlighted, data flow from source to sink with unresolved steps flagged, sanitizers and whether they work for this CWE. Runtime evidence: the request sent with the payload marked, the response with the evidence marked, and why it counts as proof. Copy buttons copy the exact text. |
| `/ui/routes/` Routes | Every discovered route: method and path, handler and line range, where it is declared, parameters read, how it was mapped and how confident, whether DAST tested it, and issue count. Routes without a handler are shown as unresolved, never guessed. Filters: all, without a handler, with issues. |
| `/ui/suppressed/` Suppressed | Findings judged safe, with the sanitizer that covers them and the reason. |
| `/ui/scans/` Scan history | Every scan, newest first, with state, duration, and counts; open one to make it the scan you are viewing. |

A glass sidebar holds the scan picker, the target origin (reads "Testing" while a scan runs), navigation with the issue count, and a "New scan" button. The selected scan stays in the URL (`?scan=`), so every view is shareable. Issue detail opens with "Where to fix" (FR-8): endpoint, parameter, the payload that proved it, and the code line to change.

Every screen handles loading, empty, failed-scan, and API-unreachable states with a message that says what to do next.

## Run it

Requires Node 22 and npm.

```bash
npm install
CYBERFORGE_API=http://127.0.0.1:8000 npm run dev   # open http://localhost:3000/ui/
```

In dev, API paths (`/scans`, `/issues`, `/routes`, `/suppressed`, `/reports`) are proxied to `CYBERFORGE_API` (default `http://127.0.0.1:8000`), so the browser stays same-origin.

```bash
npm run typecheck   # TypeScript only
npm run build       # type check + static export to out/
```

## Serving the build

`npm run build` writes `out/`. Pages live under `/ui` because the API already uses `/routes`, `/suppressed`, `/issues`, and `/scans`. The backend serves it by mounting `out/` at `/ui` after its API routers:

```python
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

app.mount("/ui", StaticFiles(directory="UI/out", html=True), name="ui")

@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse("/ui/")
```

For an API on another origin, build with `NEXT_PUBLIC_CYBERFORGE_API=http://host:port` and enable CORS for the UI origin on the API.

## API contract

The UI reads exactly the JSON shapes in `docs/03-Architecture.md` §4; `lib/types.ts` mirrors them. Change both together.

| Endpoint | Used by |
|---|---|
| `GET /scans` | Scan picker; newest scan is the default |
| `POST /scans` | New scan form; FastAPI 422 field errors are shown under the matching field |
| `GET /scans/{id}` | Live polling while a scan is queued or running |
| `GET /issues?scan_id=&status=&cwe=` | Issue list and filters |
| `GET /issues/{id}?scan_id=` | Issue detail for the selected scan |
| `GET /routes?scan_id=` | Route map |
| `GET /suppressed?scan_id=` | Suppressed findings |
| `GET /reports/{id}` | Report download link |

## Code layout

| Path | Holds |
|---|---|
| `app/` | One `page.tsx` per screen (`page.tsx` is the Overview, `home.module.css` its hero styles); `layout.tsx` (fonts, header); `tokens.css` (theme values); `globals.css` (the sky background and base styles) |
| `components/AppShell.tsx` | Header, navigation, scan picker, and the current scan shared with every page (`useScan()`) |
| `components/ui.tsx`, `ui.module.css` | Shared pieces: status badge, severity meter, scan state, notice, empty state, copy button |
| `components/pipeline/` | Live scan pipeline: backend phase states, SVG connectors, real SAST/DAST metrics and completion-time convergence animation |
| `components/scan/` | Scan status, coverage, new scan form |
| `lib/types.ts` | API contract types |
| `lib/api.ts` | API client and user-facing error messages |
| `lib/useApi.ts` | Load-on-key hook that ignores stale responses |
| `lib/format.ts` | Labels (statuses, CWE names, severities, phases) and formatters |

`AGENTS.md` is generated by `next dev`; leave it.

Styling uses CSS Modules plus the shared tokens. No component library or data-fetching library is used.

## Design rules

The full system is in `docs/02-Design-System.md`; values live only in `app/tokens.css`.

- The look follows a reference landing page: the palette is light, not flat fill. Midnight is the sky, an electric-blue glow and a cantaloupe core rise from the bottom of every screen, and content sits on dark glass panels (90% opaque, blurred) with pill buttons and chips.
- Electric Blue `#0297DE` (`--accent`) only for things you can act on: links, buttons, selected filters, focus ring. Cantaloupe Orange `#FC734D` (`--confirmed`) inside components only for evidence proven by both scanners: the Confirmed badge and row, passed correlation checks, and the evidence of a confirmed issue.
- Severity has no colour: a four-segment meter plus its label, so a critical "code only" issue never looks confirmed. Red and yellow are reserved for system failures and incomplete results.
- Headlines are Instrument Serif. Text is Atkinson Hyperlegible Next, code is Atkinson Hyperlegible Mono, chosen so `0/O`, `1/l/I`, and `rn/m` read exactly in paths and payloads. All fonts are self-hosted by `next/font`.
- Glass opacity is set so every text colour meets WCAG AA even over the brightest part of the glow (measurements in the design system). Text placed directly on the sky uses `--text-on-sky`.
- All text and controls meet WCAG AA contrast. Keyboard focus is always visible, and status is never shown by colour alone. Motion respects reduced-motion settings. Tables stack into labelled rows below 720px.
- API strings (source code, payloads, responses) are untrusted. They are rendered only as React text, never as HTML.
