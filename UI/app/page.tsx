'use client';

import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { useEffect, useRef } from 'react';
import { useScan } from '@/components/AppShell';
import { Icon } from '@/components/Icon';
import { Pipeline } from '@/components/pipeline/Pipeline';
import { Coverage } from '@/components/scan/Coverage';
import { ScanForm } from '@/components/scan/ScanForm';
import { ScanStatus } from '@/components/scan/ScanStatus';
import { Empty, Notice, SeverityMeter, StatusBadge, cx, ui } from '@/components/ui';
import { api } from '@/lib/api';
import { CWE_NAME, STATUS_LABEL, loc } from '@/lib/format';
import type { IssueStatus, IssueSummary, Scan } from '@/lib/types';
import { useApi } from '@/lib/useApi';
import { useLiveScan } from '@/lib/useLiveScan';
import s from './dashboard.module.css';

const FIX_FIRST = 6;

function IssueMix({ scan }: { scan: Scan }) {
  const c = scan.counts;
  const parts: { key: IssueStatus | 'suppressed'; label: string; n: number; seg: string; href: object }[] = [
    { key: 'confirmed', label: STATUS_LABEL.confirmed, n: c.confirmed, seg: s.segConfirmed, href: { pathname: '/issues/', query: { scan: scan.id, status: 'confirmed' } } },
    { key: 'code_only', label: STATUS_LABEL.code_only, n: c.code_only, seg: s.segCode, href: { pathname: '/issues/', query: { scan: scan.id, status: 'code_only' } } },
    { key: 'runtime_only', label: STATUS_LABEL.runtime_only, n: c.runtime_only, seg: s.segRuntime, href: { pathname: '/issues/', query: { scan: scan.id, status: 'runtime_only' } } },
    { key: 'suppressed', label: 'Suppressed as safe', n: c.suppressed, seg: s.segSuppressed, href: { pathname: '/suppressed/', query: { scan: scan.id } } },
  ];
  const total = parts.reduce((sum, p) => sum + p.n, 0);
  return (
    <>
      <div className={s.bar} role="img" aria-label={parts.map((p) => `${p.n} ${p.label}`).join(', ')}>
        {total > 0 && parts.filter((p) => p.n > 0).map((p) => <span key={p.key} className={p.seg} style={{ flexGrow: p.n }} />)}
      </div>
      <ul className={s.legend}>
        {parts.map((p) => (
          <li key={p.key}>
            <Link href={p.href}>
              <strong className={p.key === 'confirmed' && p.n > 0 ? s.confirmedValue : undefined}>{p.n}</strong>
              <span className={s.key}><i className={p.seg} aria-hidden="true" />{p.label}</span>
            </Link>
          </li>
        ))}
      </ul>
    </>
  );
}

function FixFirst({ scan, issues }: { scan: Scan; issues: IssueSummary[] }) {
  if (!issues.length) return <Empty>Nothing to fix in this scan yet.</Empty>;
  return (
    <ol className={s.queue}>
      {issues.slice(0, FIX_FIRST).map((i) => (
        <li key={i.id}>
          <div className={s.title}>
            <Link href={{ pathname: '/issue/', query: { id: i.id, scan: scan.id } }}>{i.title}</Link>
            <span className={s.where}>
              {i.route && <span>{i.route.method} {i.route.path}</span>}
              {i.location && <span>{loc(i.location.file, i.location.line)}</span>}
              {!i.route && !i.location && <span>No route or source location</span>}
            </span>
          </div>
          <span className={s.badges}>
            <StatusBadge status={i.status} />
            <SeverityMeter level={i.severity} />
          </span>
        </li>
      ))}
    </ol>
  );
}

function ByType({ scan, issues }: { scan: Scan; issues: IssueSummary[] }) {
  const count = (cwe: number, status?: IssueStatus) => issues.filter((i) => i.cwe === cwe && (!status || i.status === status)).length;
  const cell = (n: number, hot = false) => <td className={n === 0 ? s.zero : hot ? s.hot : undefined}>{n}</td>;
  return (
    <div className={ui.tableWrap}>
      <table className={cx(ui.table, s.matrix)}>
        <caption className="sr-only">Issues by vulnerability type and status</caption>
        <thead><tr><th scope="col">Type</th><th scope="col">Confirmed</th><th scope="col">Code only</th><th scope="col">Runtime only</th><th scope="col">Total</th></tr></thead>
        <tbody>
          {Object.entries(CWE_NAME).map(([n, name]) => {
            const cwe = Number(n);
            return (
              <tr key={n}>
                <th scope="row">
                  <Link href={{ pathname: '/issues/', query: { scan: scan.id, cwe: n } }}>{name}</Link> <span className="meta">CWE-{n}</span>
                </th>
                {cell(count(cwe, 'confirmed'), true)}{cell(count(cwe, 'code_only'))}{cell(count(cwe, 'runtime_only'))}{cell(count(cwe))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export default function DashboardPage() {
  const { scan, updateScan } = useScan();
  const params = useSearchParams();
  const wantsForm = params.get('new') === '1';
  const formRef = useRef<HTMLDivElement>(null);
  const live = useLiveScan(scan, updateScan);
  const issues = useApi(scan ? `dash:${scan.id}:${live.tick}` : null, () => api.issues({ scanId: scan!.id }));
  // Keep showing the previous list while a live refetch is in flight, so panels don't flash empty on every poll.
  const lastIssues = useRef<{ scanId: string; list: IssueSummary[] } | null>(null);
  if (scan && issues.data) lastIssues.current = { scanId: scan.id, list: issues.data };
  const shownIssues = scan && lastIssues.current?.scanId === scan.id ? lastIssues.current.list : null;

  useEffect(() => {
    if (!wantsForm) return;
    formRef.current?.scrollIntoView({ block: 'start' });
    formRef.current?.querySelector<HTMLInputElement>('input')?.focus({ preventScroll: true });
  }, [wantsForm]);

  const form = (
    <section ref={formRef} id="new-scan" className={cx(ui.panel, s.formPanel, s.full)} aria-labelledby="new-scan-title">
      <h2 id="new-scan-title" className="h3">{scan ? 'New scan' : 'Run your first scan'}</h2>
      <p className="meta">Navi reads the PHP source, tests the running app, and links findings that describe the same bug.</p>
      <ScanForm previous={scan} open />
    </section>
  );

  if (!scan) return <><div className="page-head"><h1>Dashboard</h1></div><div className={s.grid}>{form}</div></>;

  const list = shownIssues ?? [];
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Dashboard</h1>
          <p className="meta"><span className="mono">{scan.source_root}</span> tested against <span className="mono">{scan.target_origin}</span></p>
        </div>
        <div className={s.actions}>
          {scan.state === 'completed' && <a className={cx(ui.btn, ui.quiet)} href={api.reportUrl(scan.id)} download><Icon name="download" />Download report</a>}
          <Link className={cx(ui.btn, ui.quiet)} href={{ pathname: '/issues/', query: { scan: scan.id } }}><Icon name="list" />All issues</Link>
        </div>
      </div>
      <div className={s.grid}>
        {wantsForm && form}
        <section className={cx(ui.panel, s.full)} aria-labelledby="scan-title">
          <div className={ui.panelHead}>
            <h2 id="scan-title" className="h3">Scan pipeline</h2>
            <span className="meta">Driven by the engine&apos;s reported phase; counts arrive when results are saved</span>
          </div>
          <Pipeline scan={scan} />
          <ScanStatus scan={scan} pollError={live.pollError} />
          <p className="sr-only" aria-live="polite">{live.announcement}</p>
          <Coverage scan={scan} />
        </section>
        <section className={cx(ui.panel, s.full)} aria-labelledby="mix-title">
          <h2 id="mix-title" className="h3">Issue mix</h2>
          <IssueMix scan={scan} />
        </section>
        <section className={cx(ui.panel, s.wide)} aria-labelledby="fix-title">
          <div className={ui.panelHead}>
            <h2 id="fix-title" className="h3">Fix first</h2>
            <span className="meta">Confirmed first, then by risk</span>
          </div>
          {issues.error ? <Notice kind="error">{issues.error.message}</Notice> : !shownIssues ? <p className="muted" role="status">Loading issues…</p> : <FixFirst scan={scan} issues={list} />}
        </section>
        <section className={cx(ui.panel, s.narrow)} aria-labelledby="type-title">
          <h2 id="type-title" className="h3">By vulnerability type</h2>
          <ByType scan={scan} issues={list} />
        </section>
      </div>
    </>
  );
}
