'use client';
import {useRouter} from 'next/navigation';
import {useState, type FormEvent} from 'react';
import {api} from '@/lib/api';
import {useApi} from '@/lib/useApi';
import type {Scan} from '@/lib/types';
import {Notice, cx, ui} from '../ui';
import s from './scan.module.css';

export function ScanForm({previous, open = !previous}: {previous: Scan | null; open?: boolean}) {
  const router = useRouter();
  const workspace = useApi('workspace', api.workspace);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError(null);
    try { const created = await api.startScan(); router.push(`/issues/?scan=${encodeURIComponent(created.scan_id)}`); }
    catch (error) { setError((error as Error).message); setBusy(false); }
  }
  return <details className={cx(ui.disclosure, s.section)} open={open}><summary>New scan</summary>
    <form className={s.form} onSubmit={submit}>
      <div className={ui.field}><label htmlFor="scan-source">Source directory</label><input id="scan-source" className={cx(ui.control, 'mono')} readOnly value={workspace.data?.source ?? 'Not supplied'} /></div>
      <div className={ui.field}><label htmlFor="scan-target">Running application</label><input id="scan-target" className={cx(ui.control, 'mono')} readOnly value={workspace.data?.target ?? 'Not supplied'} /></div>
      <p className="meta">Uses the source, target and authentication configured when you start Navi.</p>
      <button className={cx(ui.btn, s.submit)} disabled={busy || !workspace.data || (!workspace.data.source && !workspace.data.target)}>{busy ? 'Starting…' : 'Start scan'}</button>
      {(error || workspace.error) && <Notice kind="error">{error || workspace.error?.message}</Notice>}
    </form></details>;
}
