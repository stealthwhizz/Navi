import type { Issue, IssueStatus, IssueSummary, Route, Scan, Suppressed } from './types';

// Empty = same origin (FastAPI serves the UI; `next dev` proxies, see next.config.ts).
const base = (process.env.NEXT_PUBLIC_CYBERFORGE_API ?? '').replace(/\/$/, '');
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
  return new ApiError(`The API at ${origin()} returned ${status} for ${path}. Check that the CyberForge backend is running.`, status);
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  let res: Response;
  try {
    res = await fetch(base + path, {
      ...init,
      headers: { Accept: 'application/json', ...(init.body ? { 'Content-Type': 'application/json' } : {}) },
    });
  } catch {
    throw new ApiError(`Can't reach the CyberForge API at ${origin()}. Start the backend, then reload this page.`, 0);
  }
  const isJson = res.headers.get('content-type')?.includes('application/json') ?? false;
  const body = isJson ? await res.json() : null;
  if (!res.ok) throw errorFrom(body, res.status, path);
  if (!isJson) throw new ApiError(`The API at ${origin()} answered ${path} without JSON. Check that the UI is served by the CyberForge backend.`, res.status);
  return body as T;
}

const query = (params: Record<string, string | undefined>) => {
  const search = new URLSearchParams(Object.entries(params).filter((e): e is [string, string] => !!e[1]));
  return search.size ? `?${search}` : '';
};

export const api = {
  scans: () => request<Scan[]>('/scans'),
  scan: (scanId: string) => request<Scan>(`/scans/${encodeURIComponent(scanId)}`),
  startScan: (body: { source_root: string; target_origin: string }) =>
    request<{ scan_id: string; state: 'queued' }>('/scans', { method: 'POST', body: JSON.stringify(body) }),
  issues: (p: { scanId: string; status?: IssueStatus | ''; cwe?: string }) =>
    request<IssueSummary[]>(`/issues${query({ scan_id: p.scanId, status: p.status, cwe: p.cwe })}`),
  issue: (issueId: string, scanId: string) =>
    request<Issue>(`/issues/${encodeURIComponent(issueId)}${query({ scan_id: scanId })}`),
  routes: (scanId: string) => request<Route[]>(`/routes${query({ scan_id: scanId })}`),
  suppressed: (scanId: string) => request<Suppressed[]>(`/suppressed${query({ scan_id: scanId })}`),
  reportUrl: (scanId: string) => `${base}/reports/${encodeURIComponent(scanId)}`,
};
