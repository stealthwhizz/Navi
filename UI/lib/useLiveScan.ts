'use client';

import { useEffect, useState } from 'react';
import { api } from './api';
import { PHASE_LABEL, isActive } from './format';
import type { Scan } from './types';

const POLL_MS = 2000;

export interface LiveScan {
  tick: number; // increments after every successful poll; use it as a refetch key
  pollError: string | null;
  announcement: string; // screen-reader text for state or phase changes
}

function announce(scan: Scan): string {
  const c = scan.counts;
  if (scan.state === 'completed') return `Scan completed: ${c.confirmed} confirmed, ${c.code_only} code only, ${c.runtime_only} runtime only.`;
  if (scan.state === 'failed') return 'Scan failed.';
  return `Scan ${scan.state}${scan.phase ? `: ${PHASE_LABEL[scan.phase]}` : ''}.`;
}

/** Polls GET /scans/{id} every 2s while the scan is queued or running and pushes each result to `updateScan`. */
export function useLiveScan(scan: Scan | null, updateScan: (next: Scan) => void): LiveScan {
  const [tick, setTick] = useState(0);
  const [pollError, setPollError] = useState<string | null>(null);
  const [announcement, setAnnouncement] = useState('');
  const scanId = scan?.id ?? null;
  const active = !!scan && isActive(scan);

  useEffect(() => {
    if (!scanId || !active) return;
    let timer: number;
    let cancelled = false;
    let last = scan;
    const poll = async () => {
      try {
        const next = await api.scan(scanId);
        if (cancelled) return;
        if (next.state !== last?.state || next.phase !== last?.phase) setAnnouncement(announce(next));
        last = next;
        updateScan(next);
        setPollError(null);
        setTick((n) => n + 1);
        if (isActive(next)) timer = window.setTimeout(poll, POLL_MS);
      } catch (err) {
        if (cancelled) return;
        setPollError((err as Error).message);
        timer = window.setTimeout(poll, POLL_MS);
      }
    };
    timer = window.setTimeout(poll, POLL_MS);
    return () => {cancelled = true; window.clearTimeout(timer);};
    // Restart only when the scan or its activity changes, not on every polled update.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId, active]);

  return { tick, pollError, announcement };
}
