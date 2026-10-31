import { isActive } from './format';
import type { Scan, ScanPhase } from './types';

export type StageId = 'routes' | 'sast' | 'dast' | 'correlate' | 'dedupe' | 'report';
export type StageState = 'waiting' | 'active' | 'done' | 'failed';

// Order matches the engine (app/analysis/pipeline.py): routes → sast → dast → correlate, then the
// results are deduplicated and persisted in one step that ends with state "completed".
export const STAGES: { id: StageId; label: string; detail: string }[] = [
  { id: 'routes', label: 'Route discovery', detail: 'Maps URLs to PHP handlers' },
  { id: 'sast', label: 'Source analysis', detail: 'Traces request input to dangerous sinks' },
  { id: 'dast', label: 'Runtime testing', detail: 'Probes the running app' },
  { id: 'correlate', label: 'Evidence correlation', detail: 'Links code and runtime findings of the same bug' },
  { id: 'dedupe', label: 'Deduplication', detail: 'One issue per real bug' },
  { id: 'report', label: 'Final report', detail: 'Prioritised and saved' },
];

const PHASE_INDEX: Record<ScanPhase, number> = { routes: 0, sast: 1, dast: 2, correlate: 3 };

/** Where the scan failed, from the worker's recorded error stage; null when the backend did not say. */
function failedIndex(scan: Scan): number | null {
  const stage = scan.coverage?.errors.at(-1)?.stage;
  return stage && stage in PHASE_INDEX ? PHASE_INDEX[stage as ScanPhase] : null;
}

/** Each stage's state, derived only from what the backend reports. */
export function stageStates(scan: Scan): Record<StageId, StageState> {
  const states = Object.fromEntries(STAGES.map((s) => [s.id, 'waiting'])) as Record<StageId, StageState>;
  if (scan.state === 'completed') {
    for (const s of STAGES) states[s.id] = 'done';
    return states;
  }
  const current = scan.state === 'failed' ? failedIndex(scan) : isActive(scan) && scan.phase ? PHASE_INDEX[scan.phase] : null;
  if (current === null) return states;
  STAGES.forEach((s, i) => {
    if (i < current) states[s.id] = 'done';
    else if (i === current) states[s.id] = scan.state === 'failed' ? 'failed' : 'active';
  });
  return states;
}

/** One line of real evidence per stage. Counts exist only after the engine saves results. */
export function stageMetric(scan: Scan, id: StageId, state: StageState): string {
  if (state === 'waiting') return 'Waiting';
  if (state === 'failed') return 'Stopped here';
  if (state === 'active') return id === 'correlate' ? 'Matching CWE, route, and parameter' : 'Running';
  const c = scan.coverage;
  const n = scan.counts;
  switch (id) {
    case 'routes': return c ? `${c.routes_total} routes, ${c.routes_unmapped} unmapped` : 'Done';
    case 'sast': {
      const count = n.confirmed + n.code_only;
      return c ? `${c.files_parsed} files, ${count} ${count === 1 ? 'finding' : 'findings'}` : 'Done';
    }
    case 'dast': {
      const count = n.confirmed + n.runtime_only;
      return c ? `${c.dast.requests} requests, ${count} ${count === 1 ? 'finding' : 'findings'}` : 'Done';
    }
    case 'correlate': return `${n.confirmed} confirmed`;
    case 'dedupe': return `${n.confirmed + n.code_only + n.runtime_only} issues, ${n.suppressed} suppressed`;
    case 'report': return 'Saved';
  }
}
