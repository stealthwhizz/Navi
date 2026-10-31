'use client';

import { useEffect, useRef, useState, type ReactNode } from 'react';
import { Icon } from './Icon';
import { SEVERITY, STATUS_LABEL, hasGaps } from '@/lib/format';
import type { IssueStatus, Scan, Severity } from '@/lib/types';
import s from './ui.module.css';

export const cx = (...names: (string | false | null | undefined)[]) => names.filter(Boolean).join(' ');

export function StatusBadge({ status, isNew = false }: { status: IssueStatus; isNew?: boolean }) {
  if (status === 'confirmed') return <span className={cx(s.badge, s.confirmed, isNew && s.isNew)}><Icon name="check" />Confirmed</span>;
  return <span className={s.badge}><Icon name={status === 'code_only' ? 'code' : 'globe'} />{STATUS_LABEL[status]}</span>;
}

// Severity carries no hue (design system §2): filled segments plus the text label.
export function SeverityMeter({ level }: { level: Severity }) {
  const { label, segments } = SEVERITY[level];
  return (
    <span className={s.sev}>
      <span className={s.meter} aria-hidden="true">{[0, 1, 2, 3].map((i) => <i key={i} className={i < segments ? s.on : undefined} />)}</span>
      {label}
    </span>
  );
}

export function ScanStateLabel({ scan }: { scan: Scan }) {
  if (scan.state === 'failed') return <span className={cx(s.state, s.stateFailed)}><Icon name="x" />Failed</span>;
  if (scan.state === 'queued') return <span className={s.state}><Icon name="clock" />Queued</span>;
  if (scan.state === 'running') return <span className={s.state}><Icon name="running" />Running</span>;
  if (hasGaps(scan)) return <span className={cx(s.state, s.stateGaps)}><Icon name="alert" />Completed with gaps</span>;
  return <span className={s.state}><Icon name="check" />Completed</span>;
}

export function Notice({ kind, children, action }: { kind: 'error' | 'warning'; children: ReactNode; action?: ReactNode }) {
  return (
    <div className={cx(s.notice, s[kind])} role={kind === 'error' ? 'alert' : 'status'}>
      <Icon name={kind === 'error' ? 'x' : 'alert'} />
      <div><p>{children}</p>{action}</div>
    </div>
  );
}

export function Empty({ children, action }: { children: ReactNode; action?: ReactNode }) {
  return <div className={s.empty} role="status"><p>{children}</p>{action}</div>;
}

// Copies the exact evidence string, never rendered markup or line numbers.
export function CopyButton({ text, what }: { text: string; what: string }) {
  const [label, setLabel] = useState('Copy');
  const timer = useRef<number>(undefined);
  useEffect(() => () => window.clearTimeout(timer.current), []);
  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setLabel('Copied');
    } catch {
      setLabel('Copy failed: select the text manually');
    }
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setLabel('Copy'), 2000);
  }
  return (
    <button type="button" className={cx(s.btn, s.quiet, s.small)} onClick={copy} aria-label={`Copy ${what}`}>
      <Icon name="copy" /><span aria-live="polite">{label}</span>
    </button>
  );
}

export { s as ui };
