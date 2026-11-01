// Read-only UI projections in navi/ui.py; native reports retain the complete evidence.

export type ScanState = 'queued' | 'running' | 'completed' | 'failed';
export type ScanPhase = 'sast' | 'dast' | 'correlate';
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
  counts: { confirmed: number; code_only: number; runtime_only: number };
  coverage: Coverage | null;
  ai: {status: string; reviewed: number; requests: number};
}

export interface Reasoning {native: string; ai: string | null; ai_status: string; ai_reason?: string | null; ai_provider?: string; ai_model?: string}

export interface IssueSummary {
  reasoning: Reasoning;
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
  path: { label: string; location: string; resolved: boolean | null }[]; // ordered, source to sink inclusive
  sanitizers: { name: string; location: string; effective: boolean; reason: string }[];
}

export interface DastEvidence {
  rule_id: string;
  method: string;
  url: string;
  parameter: string | null;
  location: string | null;
  payload: string | null;
  request: string;
  response: { status: number; excerpt: string; truncated: boolean; headers: Record<string, string> };
  evidence: string | null;
  oracle: string;
  observations: RuntimeObservation[];
}

export interface RuntimeObservation {
  evidence_index: number;
  label: string;
  url: string;
  method: string;
  parameter: string | null;
  location: string | null;
  payload: string | null;
  request: Record<string, unknown>;
  response: DastEvidence['response'];
  browser: Record<string, unknown> | null;
  execution_proof: Record<string, unknown> | null;
  policy: Record<string, unknown> | null;
  variant: string | null;
}

export interface Correlation {
  source_link?: {status: string; operation_id: string | null; missing_evidence: string[]; policy?: 'prd' | 'strict'; basis?: string | null} | null;
  evidence_graph?: {source_flows: {operation_id: string; complete: boolean; nodes: {id: string; kind: string; file?: string; line?: number; label?: string; route?: string; method?: string; parameter?: string}[]}[]} | null;
  accepted: boolean;
  rationale: string;
  checks: { name: string; result: CheckResult; detail: string }[];
}

export interface Issue extends IssueSummary {
  fix: string | null;
  priority: string | null;
  risk_basis: string | null;
  evidence_count: number;
  signals_combined: number;
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
  provenance: 'native' | 'unresolved';
  confidence: 'high' | 'medium' | 'low';
  tested: boolean;
  issue_count: number;
}
