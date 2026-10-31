// Mirrors docs/03-Architecture.md §4 "UI response shapes". Change both together.

export type ScanState = 'queued' | 'running' | 'completed' | 'failed';
export type ScanPhase = 'routes' | 'sast' | 'dast' | 'correlate';
export type IssueStatus = 'confirmed' | 'code_only' | 'runtime_only';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational';
export type CheckResult = 'pass' | 'fail' | 'unknown';

export interface Coverage {
  frameworks: string[];
  files_parsed: number;
  files_skipped: { path: string; reason: string }[];
  routes_total: number;
  routes_unmapped: number;
  unresolved: { kind: string; location: string; detail: string }[];
  rules_not_run: { rule: string; reason: string }[];
  dast: { requests: number; routes_tested: number; params_tested: number; blocked: number; timeouts: number };
  errors: { stage: string; message: string }[];
}

export interface Scan {
  id: string;
  state: ScanState;
  source_root: string;
  target_origin: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  phase: ScanPhase | null;
  progress: { done: number; total: number } | null;
  error: string | null;
  counts: { confirmed: number; code_only: number; runtime_only: number; suppressed: number };
  coverage: Coverage | null;
}

export interface IssueSummary {
  id: string;
  fingerprint: string;
  status: IssueStatus;
  severity: Severity;
  risk: number;
  cwe: number;
  title: string;
  route: { method: string; path: string } | null;
  location: { file: string; line: number } | null;
}

export interface SastEvidence {
  rule_id: string;
  file: string;
  line_start: number;
  line_end: number;
  snippet: { start_line: number; code: string };
  highlight_line: number;
  source: { expr: string; type: string; location: string };
  sink: { name: string; type: string; location: string };
  path: { label: string; location: string; resolved: boolean }[]; // ordered, source to sink inclusive
  sanitizers: { name: string; location: string; effective: boolean; reason: string }[];
}

export interface DastEvidence {
  rule_id: string;
  method: string;
  url: string;
  parameter: string | null;
  payload: string | null;
  request: string;
  response: { status: number; excerpt: string; truncated: boolean };
  evidence: string | null;
  oracle: string;
}

export interface Correlation {
  accepted: boolean;
  rationale: string;
  checks: { name: string; result: CheckResult; detail: string }[];
}

export interface Issue extends IssueSummary {
  scan_id: string;
  first_seen: string;
  last_seen: string;
  sast: SastEvidence | null;
  dast: DastEvidence | null;
  correlation: Correlation | null;
}

export interface Route {
  method: string;
  path: string;
  declared_at: string | null;
  handler: { name: string; file: string; line_start: number; line_end: number } | null;
  params: string[];
  provenance: 'laravel' | 'filesystem' | 'front_controller' | 'fuzzy' | 'unresolved';
  confidence: 'high' | 'medium' | 'low';
  tested: boolean;
  issue_count: number;
}

export interface Suppressed {
  id: string;
  source: 'sast' | 'dast';
  cwe: number;
  title: string;
  file: string;
  line: number;
  sanitizer: string;
  reason: string;
}
