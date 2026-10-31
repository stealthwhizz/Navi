'use client';

import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { useEffect, useRef, useState } from 'react';
import { useScan } from '@/components/AppShell';
import { Icon } from '@/components/Icon';
import { IssueList, type IssueFilter } from '@/components/issues/IssueList';
import { ScanStatus } from '@/components/scan/ScanStatus';
import { Empty, Notice, cx, ui } from '@/components/ui';
import { api } from '@/lib/api';
import { isActive, when } from '@/lib/format';
import type { IssueStatus, IssueSummary } from '@/lib/types';
import { useLiveScan } from '@/lib/useLiveScan';

export default function IssuesPage() {
  const { scan, updateScan } = useScan();
  const params = useSearchParams();
  const filter: IssueFilter = { status: (params.get('status') ?? '') as IssueStatus | '', cwe: params.get('cwe') ?? '' };
  const [issues, setIssues] = useState<IssueSummary[] | null>(null);
  const [loadError, setLoadError] = useState<Error | null>(null);
  const [fresh, setFresh] = useState<Set<string>>(new Set());
  const seen = useRef<{ scanId: string; ids: Set<string> } | null>(null);
  const live = useLiveScan(scan, updateScan);
  const scanId = scan?.id ?? null;

  useEffect(() => {
    if (!scanId) return;
    let current = true;
    api.issues({ scanId, status: filter.status, cwe: filter.cwe }).then((list) => {
      if (!current) return;
      const confirmed = list.filter((i) => i.status === 'confirmed').map((i) => i.id);
      const prior = seen.current?.scanId === scanId ? seen.current.ids : null;
      setFresh(new Set(prior ? confirmed.filter((id) => !prior.has(id)) : []));
      seen.current = { scanId, ids: new Set([...(prior ?? []), ...confirmed]) };
      setIssues(list);
      setLoadError(null);
    }, (err: Error) => current && setLoadError(err));
    return () => { current = false; };
  }, [scanId, filter.status, filter.cwe, live.tick]);

  function setFilter(next: Partial<IssueFilter>) {
    const merged = { ...filter, ...next };
    const query = new URLSearchParams();
    if (scanId) query.set('scan', scanId);
    if (merged.status) query.set('status', merged.status);
    if (merged.cwe) query.set('cwe', merged.cwe);
    // Native history update: Next syncs useSearchParams without a navigation, so the pressed control keeps focus.
    window.history.replaceState(null, '', `${window.location.pathname}?${query}`);
  }

  if (!scan) {
    return <><div className="page-head"><h1>Issues</h1></div><section className={ui.panel}><Empty>Issues appear here after your first scan. <Link href="/?new=1">Start a scan</Link>.</Empty></section></>;
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Issues</h1>
          <p className="meta">One issue per real bug, confirmed first, then by risk. Scan from {when(scan.created_at)}.</p>
        </div>
        {scan.state === 'completed' && <a className={cx(ui.btn, ui.quiet)} href={api.reportUrl(scan.id)} download><Icon name="download" />Download report</a>}
      </div>
      <div className="stack">
        {(isActive(scan) || live.pollError) && (
          <section className={ui.panel} aria-label="Live scan">
            <ScanStatus scan={scan} pollError={live.pollError} />
          </section>
        )}
        <p className="sr-only" aria-live="polite">{live.announcement}</p>
        <section className={ui.panel} aria-label="Issue list">
          {loadError ? <Notice kind="error">{loadError.message}</Notice>
            : <IssueList scan={scan} issues={issues} filter={filter} fresh={fresh} onFilter={setFilter} />}
        </section>
      </div>
    </>
  );
}
