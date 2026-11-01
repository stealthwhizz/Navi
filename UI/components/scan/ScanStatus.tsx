'use client';

import { useEffect, useState } from 'react';
import { PHASE_LABEL, clock, elapsedMs, isActive, when } from '@/lib/format';
import {api} from '@/lib/api';
import type { Scan } from '@/lib/types';
import { Notice, ScanStateLabel, ui } from '../ui';
import s from './scan.module.css';

export function ScanStatus({ scan, pollError }: { scan: Scan; pollError: string | null }) {
  const active = isActive(scan);
  const [cancelling, setCancelling] = useState(false);
  const [cancelError, setCancelError] = useState<string | null>(null);
  const [, tick] = useState(0);
  useEffect(() => {
    if (!active) return;
    const id = window.setInterval(() => tick((n) => n + 1), 1000); // re-render so the elapsed clock advances
    return () => window.clearInterval(id);
  }, [active]);

  const ms = elapsedMs(scan);

  return (
    <>
      <div className={s.line}>
        <ScanStateLabel scan={scan} />
        {active && <button className={ui.btn} disabled={cancelling} onClick={() => {setCancelling(true); void api.cancelScan(scan.id).catch(error => {setCancelError(error.message); setCancelling(false);});}}>{cancelling ? 'Stopping…' : 'Stop scan'}</button>}
        {scan.state === 'running' && scan.phase && <span>{PHASE_LABEL[scan.phase]}</span>}
        {scan.started_at && <span>{clock(ms)} elapsed</span>}
        {scan.state === 'running' && scan.progress && (
          <label className={s.progress}>
            <span className="sr-only">Progress</span>
            <progress max={scan.progress.total} value={scan.progress.done} />
            <span className="meta">{scan.progress.done} of {scan.progress.total}</span>
          </label>
        )}
      </div>
      <dl className={ui.facts}>
        <dt>Source</dt><dd className="mono">{scan.source_root}</dd>
        <dt>Started</dt><dd>{scan.started_at ? when(scan.started_at) : 'Waiting for a worker'}</dd>
        {scan.finished_at && <><dt>Finished</dt><dd>{when(scan.finished_at)}</dd></>}
      </dl>
      {scan.state === 'failed' && (
        <Notice kind="error">{scan.error ? `The scan failed: ${scan.error}` : 'The scan failed without an error message. Check the API logs, then start a new scan.'}</Notice>
      )}
      {cancelError && <Notice kind="error">{cancelError}</Notice>}
      {pollError && <Notice kind="warning">Lost contact with the API: {pollError} Retrying every 2 seconds.</Notice>}
    </>
  );
}
