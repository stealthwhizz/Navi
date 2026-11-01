import type { IssueStatus, Scan, Severity } from './types';

export const STATUS_LABEL: Record<IssueStatus, string> = { confirmed: 'Confirmed', code_only: 'Code only', runtime_only: 'Runtime only' };
export const CWE_NAME: Record<number, string> = { 89: 'SQL injection', 79: 'Cross-site scripting', 78: 'OS command injection', 22: 'Path traversal', 601: 'Open redirect', 798: 'Hard-coded credentials', 639: 'Broken object authorization' };
export const SEVERITY: Record<Severity, { label: string; segments: number }> = {
  critical: { label: 'Critical', segments: 4 }, high: { label: 'High', segments: 3 }, medium: { label: 'Medium', segments: 2 },
  low: { label: 'Low', segments: 1 }, informational: { label: 'Informational', segments: 0 },
};
export const PHASE_LABEL = { sast: 'Analysing source', dast: 'Testing the running app', correlate: 'AI correlation' } as const;

export const isActive = (scan: Scan) => scan.state === 'queued' || scan.state === 'running';

export function hasGaps(scan: Scan): boolean {
  const c = scan.coverage;
  return !!c && [c.errors.length, c.files_skipped.length, c.unresolved.length, c.rules_not_run.length, c.routes_unmapped, c.dast.timeouts, c.dast.blocked].some((n) => n > 0);
}

export function elapsedMs(scan: Scan): number {
  if (!scan.started_at) return 0;
  return (scan.finished_at ? Date.parse(scan.finished_at) : Date.now()) - Date.parse(scan.started_at);
}

export function clock(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  return `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`;
}

const dateFormat = new Intl.DateTimeFormat(undefined, { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
export const when = (iso: string | null) => (iso ? dateFormat.format(new Date(iso)) : '');

// file:line or file:start-end
export function loc(file: string, line?: number | null, end?: number | null): string {
  if (!line) return file;
  return end && end !== line ? `${file}:${line}-${end}` : `${file}:${line}`;
}
