import {isActive} from './format';
import type {Scan, ScanPhase} from './types';
export type StageId = 'sast' | 'dast' | 'correlate';
export type StageState = 'waiting' | 'active' | 'done' | 'failed';
export const STAGES: {id: StageId; label: string; detail: string}[] = [
  {id: 'sast', label: 'Code analysis', detail: 'Map functions and inspect input flows'},
  {id: 'dast', label: 'Runtime validation', detail: 'Test the running application'},
  {id: 'correlate', label: 'AI correlation', detail: 'Review linked evidence and explain each finding'},
];
const PHASE_INDEX: Record<ScanPhase, number> = {sast: 0, dast: 1, correlate: 2};
export function stageStates(scan: Scan): Record<StageId, StageState> {
  const states = {sast: 'waiting', dast: 'waiting', correlate: 'waiting'} as Record<StageId, StageState>;
  if (scan.state === 'completed') { for (const stage of STAGES) states[stage.id] = 'done'; return states; }
  const phase = scan.phase ?? scan.coverage?.errors.at(-1)?.stage;
  const current = phase && phase in PHASE_INDEX ? PHASE_INDEX[phase as ScanPhase] : null;
  if (current === null) return states;
  STAGES.forEach((stage, i) => {if (i < current) states[stage.id] = 'done'; else if (i === current) states[stage.id] = scan.state === 'failed' ? 'failed' : isActive(scan) ? 'active' : 'waiting';});
  return states;
}
export function stageMetric(scan: Scan, id: StageId, state: StageState): string {
  if (state === 'waiting') return 'Waiting';
  if (state === 'failed') return 'Stopped';
  if (state === 'active') return 'Running';
  if (id === 'sast') return scan.source_root ? `${scan.counts.confirmed + scan.counts.code_only} source findings` : 'Skipped · no source';
  if (id === 'dast') return scan.target_origin ? `${scan.counts.confirmed + scan.counts.runtime_only} runtime proofs` : 'Skipped · no target';
  return `AI ${scan.ai.status} · ${scan.ai.reviewed} reviewed · ${scan.counts.confirmed} linked`;
}
