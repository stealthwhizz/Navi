import Link from 'next/link';
import type { ReactNode } from 'react';
import { hasGaps } from '@/lib/format';
import type { Scan } from '@/lib/types';
import { Icon } from '../Icon';
import { cx, ui } from '../ui';
import s from './scan.module.css';

const LIST_CAP = 20; // shortcut: long coverage lists are cut at 20 items; the full list is in the report download

function GapList<T>({ title, items, render }: { title: string; items: T[]; render: (item: T) => ReactNode }) {
  if (!items.length) return null;
  return (
    <div>
      <h4>{title} ({items.length})</h4>
      <ul>{items.slice(0, LIST_CAP).map((item, i) => <li key={i} className="wrap-any">{render(item)}</li>)}</ul>
      {items.length > LIST_CAP && <p className="meta">{items.length - LIST_CAP} more in the report download.</p>}
    </div>
  );
}

// Mentor requirement: every scan states what it could not check, so a partial scan never reads as clean.
export function Coverage({ scan }: { scan: Scan }) {
  const c = scan.coverage;
  if (!c) {
    return <p className={cx('meta', s.section)}>{scan.state === 'failed' ? 'No coverage was recorded: the scan failed before analysis finished.' : 'Coverage appears when the scan finishes.'}</p>;
  }
  const gaps = hasGaps(scan);
  return (
    <details className={cx(ui.disclosure, s.section)}>
      <summary>
        What this scan covered
        {gaps
          ? <span className={cx(ui.badge, ui.badgeWarning)}><Icon name="alert" />Gaps to review</span>
          : <span className={cx(ui.badge, ui.badgeMuted)}><Icon name="check" />No gaps reported</span>}
      </summary>
      <div className={s.grid}>
        <div>
          <h4>Analysed</h4>
          <dl className={ui.facts}>
            <dt>Routing</dt><dd>{c.frameworks.length ? c.frameworks.join(', ') : 'No supported routing pattern detected'}</dd>
            <dt>Files parsed</dt><dd>{c.files_parsed}</dd>
            <dt>Routes</dt>
            <dd>
              {c.routes_total}
              {c.routes_unmapped > 0 && <>, <Link href={{ pathname: '/routes/', query: { scan: scan.id, filter: 'unmapped' } }}>{c.routes_unmapped} without a handler</Link></>}
            </dd>
            <dt>Requests sent</dt><dd>{c.dast.requests}</dd>
            <dt>Tested</dt><dd>{c.dast.routes_tested} routes, {c.dast.params_tested} parameters</dd>
            {c.dast.blocked > 0 && <><dt>Blocked</dt><dd>{c.dast.blocked} out-of-scope requests</dd></>}
            {c.dast.timeouts > 0 && <><dt>Timeouts</dt><dd>{c.dast.timeouts}</dd></>}
          </dl>
        </div>
        <GapList title="Errors" items={c.errors} render={(e) => <><strong>{e.stage}:</strong> {e.message}</>} />
        <GapList title="Files skipped" items={c.files_skipped} render={(f) => <><span className="mono">{f.path}</span>: {f.reason}</>} />
        <GapList title="Unresolved" items={c.unresolved} render={(u) => <>{u.kind} at <span className="mono">{u.location}</span>: {u.detail}</>} />
        <GapList title="Rules not run" items={c.rules_not_run} render={(r) => <><span className="mono">{r.rule}</span>: {r.reason}</>} />
      </div>
    </details>
  );
}
