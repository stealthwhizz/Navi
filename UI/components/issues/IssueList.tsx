'use client';

import Link from 'next/link';
import { useState } from 'react';
import { CWE_NAME, STATUS_LABEL, hasGaps, isActive, loc } from '@/lib/format';
import type { IssueStatus, IssueSummary, Scan } from '@/lib/types';
import { Icon } from '../Icon';
import { Empty, SeverityMeter, StatusBadge, cx, ui } from '../ui';

export interface IssueFilter { status: IssueStatus | ''; cwe: string }

interface Props {
  scan: Scan;
  issues: IssueSummary[] | null;
  filter: IssueFilter;
  fresh: Set<string>; // newly confirmed during this live scan: their badge animates in once
  onFilter: (next: Partial<IssueFilter>) => void;
}

export function IssueList({ scan, issues, filter, fresh, onFilter }: Props) {
  const [query, setQuery] = useState('');
  const q = query.trim().toLowerCase();
  const shown = issues && q
    ? issues.filter((i) => [i.title, i.route?.path, i.location?.file, `cwe-${i.cwe}`].some((v) => v?.toLowerCase().includes(q)))
    : issues;
  const c = scan.counts;
  const chips: [IssueStatus | '', string, number][] = [
    ['', 'All', c.confirmed + c.code_only + c.runtime_only],
    ['confirmed', STATUS_LABEL.confirmed, c.confirmed],
    ['code_only', STATUS_LABEL.code_only, c.code_only],
    ['runtime_only', STATUS_LABEL.runtime_only, c.runtime_only],
  ];
  return (
    <>
      <div className={ui.filters}>
        <label className={ui.search}>
          <Icon name="search" />
          <span className="sr-only">Search issues</span>
          <input type="search" placeholder="Search title, route, file" value={query} onChange={(e) => setQuery(e.target.value)} />
        </label>
        <div className={ui.chips} role="group" aria-label="Filter by status">
          {chips.map(([value, label, n]) => (
            <button key={value} type="button" className={ui.chip} aria-pressed={filter.status === value} onClick={() => onFilter({ status: value })}>
              {label}<span className={value === 'confirmed' ? ui.countConfirmed : ui.count}>{n}</span>
            </button>
          ))}
        </div>
        <label className="sr-only" htmlFor="cwe">Vulnerability type</label>
        <select id="cwe" className={ui.control} value={filter.cwe} onChange={(e) => onFilter({ cwe: e.target.value })}>
          <option value="">All vulnerability types</option>
          {Object.entries(CWE_NAME).map(([n, name]) => <option key={n} value={n}>CWE-{n} {name}</option>)}
        </select>
        {c.suppressed > 0 && <Link href={{ pathname: '/suppressed/', query: { scan: scan.id } }}>{c.suppressed} suppressed as safe</Link>}
      </div>
      <IssueRows
        scan={scan} issues={shown} filter={filter} fresh={fresh} searching={!!q}
        onFilter={onFilter} onClear={() => { setQuery(''); onFilter({ status: '', cwe: '' }); }}
      />
    </>
  );
}

function IssueRows({ scan, issues, filter, fresh, searching, onClear }: Props & { searching: boolean; onClear: () => void }) {
  if (!issues) return <p className="muted" role="status">Loading issues…</p>;
  if (!issues.length) {
    if (filter.status || filter.cwe || searching) {
      return <Empty action={<button type="button" className={cx(ui.btn, ui.quiet)} onClick={onClear}>Clear search and filters</button>}>No issues match this search and these filters.</Empty>;
    }
    if (isActive(scan)) return <Empty>Findings appear here as the scan runs.</Empty>;
    if (scan.state === 'failed') return <Empty>The scan failed before reporting issues.</Empty>;
    return <Empty>{hasGaps(scan) ? 'This scan reported no issues, but it has coverage gaps. Review them before treating the app as clean.' : 'This scan reported no issues.'}</Empty>;
  }
  return (
    <div className={ui.tableWrap}>
      <table className={cx(ui.table, ui.stackable)}>
        <caption className="sr-only">Issues, confirmed first, then by risk</caption>
        <thead>
          <tr><th scope="col">Status</th><th scope="col">Severity</th><th scope="col">Risk</th><th scope="col">CWE</th><th scope="col">Finding</th><th scope="col">Route</th><th scope="col">Location</th></tr>
        </thead>
        <tbody>
          {issues.map((i) => (
            <tr key={i.id} className={i.status === 'confirmed' ? ui.rowConfirmed : undefined}>
              <td data-label="Status"><StatusBadge status={i.status} isNew={fresh.has(i.id)} /></td>
              <td data-label="Severity"><SeverityMeter level={i.severity} /></td>
              <td data-label="Risk" className={ui.nowrap}>{i.risk.toFixed(1)}</td>
              <td data-label="CWE" className={ui.nowrap}>CWE-{i.cwe}</td>
              <td data-label="Finding"><Link href={{ pathname: '/issue/', query: { id: i.id, scan: scan.id } }}>{i.title}</Link></td>
              <td data-label="Route" className="mono">{i.route ? `${i.route.method} ${i.route.path}` : <span className="muted">Not mapped</span>}</td>
              <td data-label="Location" className="mono">{i.location ? loc(i.location.file, i.location.line) : <span className="muted">No source location</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
