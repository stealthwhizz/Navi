import type { Issue, IssueStatus, IssueSummary, Route, Scan } from './types';

// Empty = same origin (FastAPI serves the UI; `next dev` proxies, see next.config.ts).
const base = (process.env.NEXT_PUBLIC_NAVI_API ?? '').replace(/\/$/, '');
let accessToken = '';
export function setAccessToken(value: string) { accessToken = value; }
const origin = () => base || window.location.origin;

export class ApiError extends Error {
  constructor(message: string, readonly status: number, readonly fields: Record<string, string> = {}) {
    super(message);
  }
}

type Detail = string | { loc?: (string | number)[]; msg: string }[];

function errorFrom(body: { detail?: Detail } | null, status: number, path: string): ApiError {
  const detail = body?.detail;
  if (typeof detail === 'string') return new ApiError(detail, status);
  if (Array.isArray(detail)) {
    const fields: Record<string, string> = {};
    for (const item of detail) {
      const field = item.loc?.at(-1);
      if (typeof field === 'string' && !fields[field]) fields[field] = item.msg;
    }
    return new ApiError(detail.map((item) => item.msg).join(' '), status, fields);
  }
  return new ApiError(`The API at ${origin()} returned ${status} for ${path}. Check that the Navi backend is running.`, status);
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  let res: Response;
  try {
    res = await fetch(base + path, {
      ...init,
      headers: { Accept: 'application/json', ...(init.body ? { 'Content-Type': 'application/json', 'X-Navi': 'local-scan' } : {}), ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}) },
    });
  } catch {
    throw new ApiError(`Can't reach the Navi API at ${origin()}. Start the backend, then reload this page.`, 0);
  }
  const isJson = res.headers.get('content-type')?.includes('application/json') ?? false;
  const body = isJson ? await res.json() : null;
  if (!res.ok) throw errorFrom(body, res.status, path);
  if (!isJson) throw new ApiError(`The API at ${origin()} answered ${path} without JSON. Check that the UI is served by the Navi backend.`, res.status);
  return body as T;
}

const query = (params: Record<string, string | undefined>) => {
  const search = new URLSearchParams(Object.entries(params).filter((e): e is [string, string] => !!e[1]));
  return search.size ? `?${search}` : '';
};

export const api = {
  workspace: () => request<{source: string | null; target: string | null}>('/api/state'),
  scans: () => request<Scan[]>('/api/ui/scans'),
  scan: (scanId: string) => request<Scan>(`/api/ui/scans/${encodeURIComponent(scanId)}`),
  startScan: async () => {
    const result = await request<{id: string}>('/api/scans', {method: 'POST', body: '{}'});
    return {scan_id: result.id};
  },
  cancelScan: (id: string) => request(`/api/scans/${encodeURIComponent(id)}/cancel`, {method: 'POST', body: '{}'}),
  issues: (p: { scanId: string; status?: IssueStatus | ''; cwe?: string }) =>
    request<IssueSummary[]>(`/api/ui/issues${query({ scan_id: p.scanId, status: p.status, cwe: p.cwe })}`),
  issue: (issueId: string, scanId: string) =>
    request<Issue>(`/api/ui/issues/${encodeURIComponent(issueId)}${query({ scan_id: scanId })}`),
  routes: (scanId: string) => request<Route[]>(`/api/ui/routes${query({ scan_id: scanId })}`),
  reportUrl: (scanId: string) => `${base}/api/ui/reports/${encodeURIComponent(scanId)}`,
  downloadReport: async (scanId: string) => {
    const report = await request(`/api/ui/reports/${encodeURIComponent(scanId)}`);
    const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], {type: 'application/json'}));
    const link = document.createElement('a'); link.href = url; link.download = `navi-${scanId}.json`; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  },
};
